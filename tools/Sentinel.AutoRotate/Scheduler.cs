// Scheduled task management. Tasks are registered from XML built with XDocument, so every value is
// escaped by the XML writer. schtasks.exe is invoked by its System32 path with fixed task names.

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Sentinel.AutoRotate;

internal static class Scheduler
{
    public const string BootTask = "SentinelAutoRotate-Boot";
    public const string LogonTask = "SentinelAutoRotate-Logon";

    // Names used by the earlier SentinelAutoRotate release. They run "--rotate", which no longer exists.
    private static readonly string[] LegacyTasks = { "SentinelAutoRotateStartup", "SentinelAutoRotate" };

    private static readonly XNamespace TaskNs = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static bool Exists(string name)
    {
        return Run("/Query /TN \"" + name + "\"", out _) == 0;
    }

    public static void Register(string sid, string exePath)
    {
        Register(BootTask, BuildBootTask(exePath));
        Register(LogonTask, BuildLogonTask(sid, exePath));
    }

    public static void Run(string name)
    {
        int rc = Run("/Run /TN \"" + name + "\"", out string output);
        if (rc != 0) throw new InvalidOperationException("Could not start task " + name + " (schtasks exit " + rc + "): " + output);
    }

    /// <summary>Stops a running task. A task that is not running is not an error.</summary>
    public static void End(string name)
    {
        Run("/End /TN \"" + name + "\"", out _);
    }

    public static void Enable(string name)
    {
        int rc = Run("/Change /TN \"" + name + "\" /ENABLE", out string output);
        if (rc != 0) throw new InvalidOperationException("Could not enable task " + name + ": " + output);
    }

    /// <summary>True when a task from the earlier SentinelAutoRotate release is still registered.</summary>
    public static bool LegacyPresent()
    {
        foreach (string name in LegacyTasks)
        {
            if (Exists(name)) return true;
        }
        return false;
    }

    public static void Disable(string name)
    {
        int rc = Run("/Change /TN \"" + name + "\" /DISABLE", out string output);
        if (rc != 0 && Exists(name)) throw new InvalidOperationException("Could not disable task " + name + ": " + output);
    }

    public static void DeleteAll()
    {
        foreach (string name in new[] { BootTask, LogonTask }.Concat(LegacyTasks))
        {
            if (!Exists(name)) continue;
            int rc = Run("/Delete /TN \"" + name + "\" /F", out string output);
            if (rc != 0) throw new InvalidOperationException("Could not delete task " + name + ": " + output);
        }
    }

    private static void Register(string name, XDocument definition)
    {
        Directory.CreateDirectory(Rotator.StateDirectory);
        string path = Path.Combine(Rotator.StateDirectory, name + "." + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            // Task Scheduler XML is conventionally UTF-16.
            var settings = new XmlWriterSettings { Encoding = Encoding.Unicode, Indent = true };
            using (XmlWriter writer = XmlWriter.Create(path, settings))
            {
                definition.Save(writer);
            }

            int rc = Run("/Create /TN \"" + name + "\" /XML \"" + path + "\" /F", out string output);
            if (rc != 0) throw new InvalidOperationException("Could not register task " + name + " (schtasks exit " + rc + "): " + output);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static XDocument BuildBootTask(string exePath)
    {
        return BuildTask(
            "Resets the target account password to blank once per boot, before sign-in.",
            new XElement(TaskNs + "BootTrigger", new XElement(TaskNs + "Enabled", "true")),
            "S-1-5-18", null,
            exePath, "--boot",
            "PT2M");
    }

    private static XDocument BuildLogonTask(string sid, string exePath)
    {
        return BuildTask(
            "Rotates the target account password every ten minutes while its desktop is signed in.",
            new XElement(TaskNs + "LogonTrigger",
                new XElement(TaskNs + "Enabled", "true"),
                new XElement(TaskNs + "UserId", sid)),
            sid, "InteractiveToken",
            exePath, "--session",
            "PT0S");
    }

    private static XDocument BuildTask(string description, XElement trigger, string userId, string? logonType, string exePath, string argument, string executionLimit)
    {
        var settings = new XElement(TaskNs + "Settings",
            new XElement(TaskNs + "MultipleInstancesPolicy", "IgnoreNew"),
            new XElement(TaskNs + "DisallowStartIfOnBatteries", "false"),
            new XElement(TaskNs + "StopIfGoingOnBatteries", "false"),
            new XElement(TaskNs + "AllowHardTerminate", "true"),
            new XElement(TaskNs + "StartWhenAvailable", "true"),
            new XElement(TaskNs + "RunOnlyIfNetworkAvailable", "false"),
            new XElement(TaskNs + "Enabled", "true"),
            new XElement(TaskNs + "Hidden", "false"),
            new XElement(TaskNs + "RunOnlyIfIdle", "false"),
            new XElement(TaskNs + "WakeToRun", "false"),
            new XElement(TaskNs + "ExecutionTimeLimit", executionLimit),
            new XElement(TaskNs + "Priority", "7"),
            new XElement(TaskNs + "RestartOnFailure",
                new XElement(TaskNs + "Interval", "PT1M"),
                new XElement(TaskNs + "Count", "3")));

        // A null logonType omits the element. Task Scheduler rejects LogonType "ServiceAccount" for
        // S-1-5-18 on this machine ("incorrectly formatted or out of range", line 14), and it does
        // not need the element for SYSTEM.
        var principal = new XElement(TaskNs + "Principal",
            new XAttribute("id", "Author"),
            new XElement(TaskNs + "UserId", userId));
        if (logonType != null)
            principal.Add(new XElement(TaskNs + "LogonType", logonType));
        principal.Add(new XElement(TaskNs + "RunLevel", "HighestAvailable"));

        var doc = new XDocument(
            new XElement(TaskNs + "Task",
                new XAttribute("version", "1.4"),
                new XElement(TaskNs + "RegistrationInfo",
                    new XElement(TaskNs + "Description", description)),
                new XElement(TaskNs + "Triggers", trigger),
                new XElement(TaskNs + "Principals", principal),
                settings,
                new XElement(TaskNs + "Actions",
                    new XAttribute("Context", "Author"),
                    new XElement(TaskNs + "Exec",
                        new XElement(TaskNs + "Command", exePath),
                        new XElement(TaskNs + "Arguments", argument)))));
        return doc;
    }

    private static int Run(string arguments, out string output)
    {
        string schtasks = System.IO.Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        var psi = new ProcessStartInfo(schtasks, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using (Process process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start schtasks.exe."))
        {
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(60000))
            {
                process.Kill();
                throw new TimeoutException("schtasks.exe did not finish within 60 seconds.");
            }
            output = (stdout + stderr).Trim();
            return process.ExitCode;
        }
    }
}
