using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security;

namespace GVPN
{
    /// <summary>
    /// Machine setup GVPN can do for itself (it always runs elevated). Under Sentinel, setup has
    /// already done all of this and controls autostart; standalone GVPN does it on first run.
    /// </summary>
    public static class SelfSetup
    {
        public const string TaskName = "GVPN";

        private static string ExeDir
        {
            get { return Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location); }
        }

        private static string OpenVpnDir
        {
            get { return BundledOpenVpn.Directory ?? BundledOpenVpn.ExtractDir; }
        }

        /// <summary>True when installed by Sentinel setup ({app}\GVPN\GVPN.exe next to {app}\Sentinel.Service.exe).</summary>
        public static bool IsSentinelManaged
        {
            get
            {
                try { return File.Exists(Path.Combine(Path.GetDirectoryName(ExeDir), "Sentinel.Service.exe")); }
                catch { return false; }
            }
        }

        public static bool AdapterExists()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Any(n => string.Equals(n.Name, VpnManager.AdapterName, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Installs the bundled TAP-Windows6 driver and creates the "GVPN TAP" adapter when it is
        /// missing. Uses only the files shipped next to GVPN.exe.
        /// </summary>
        public static bool EnsureTapAdapter(Logger logger)
        {
            if (AdapterExists())
                return true;

            string inf = Path.Combine(OpenVpnDir, @"drivers\tap-windows6\OemVista.inf");
            string tapctl = Path.Combine(OpenVpnDir, @"bin\tapctl.exe");
            if (!File.Exists(inf) || !File.Exists(tapctl))
            {
                logger.Log("Adapter '" + VpnManager.AdapterName + "' missing and bundled TAP driver not found at " + OpenVpnDir);
                return false;
            }

            logger.Log("Installing TAP-Windows6 driver and creating adapter '" + VpnManager.AdapterName + "'...");
            int pnp = Run(Path.Combine(Environment.SystemDirectory, "pnputil.exe"), "/add-driver \"" + inf + "\" /install");
            logger.Log("pnputil exit " + pnp);
            int tap = Run(tapctl, "create --hwid root\\tap0901 --name \"" + VpnManager.AdapterName + "\"");
            logger.Log("tapctl create exit " + tap);

            bool ok = AdapterExists();
            logger.Log(ok ? "Adapter ready" : "Adapter could not be created");
            return ok;
        }

        /// <summary>
        /// Standalone only: an elevated sign-in task for the current user (a Run-key entry cannot
        /// start an elevated app). Re-registered when GVPN.exe has moved.
        /// </summary>
        public static void EnsureSignInTask(Logger logger)
        {
            string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
            try
            {
                dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true));
                service.Connect();
                dynamic folder = service.GetFolder("\\");

                try
                {
                    dynamic existing = folder.GetTask(TaskName);
                    string xml = existing.Xml;
                    if (xml.IndexOf(SecurityElement.Escape(exe), StringComparison.OrdinalIgnoreCase) >= 0)
                        return; // already points at this exe
                }
                catch { /* not registered yet */ }

                string user = SecurityElement.Escape(Environment.UserDomainName + "\\" + Environment.UserName);
                string taskXml =
                    "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                    "<RegistrationInfo><Description>Starts GVPN at sign-in.</Description></RegistrationInfo>" +
                    "<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + user + "</UserId><Delay>PT10S</Delay></LogonTrigger></Triggers>" +
                    "<Principals><Principal id=\"Author\"><UserId>" + user + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" +
                    "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
                    "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>" +
                    "<Actions Context=\"Author\"><Exec><Command>" + SecurityElement.Escape(exe) + "</Command>" +
                    "<WorkingDirectory>" + SecurityElement.Escape(ExeDir) + "</WorkingDirectory></Exec></Actions></Task>";

                // 6 = TASK_CREATE_OR_UPDATE, 3 = TASK_LOGON_INTERACTIVE_TOKEN (no password stored).
                folder.RegisterTask(TaskName, taskXml, 6, null, null, 3, null);
                logger.Log("Sign-in task '" + TaskName + "' registered for " + Environment.UserName);
            }
            catch (Exception ex)
            {
                logger.Log("Could not register sign-in task: " + ex.Message);
            }
        }

        /// <summary>GVPN.exe --uninstall: undo everything GVPN set up on this machine.</summary>
        public static void Uninstall(Logger logger)
        {
            logger.Log("=== GVPN --uninstall ===");
            new KillSwitch(logger, VpnManager.AdapterName).Disable();

            try
            {
                dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true));
                service.Connect();
                service.GetFolder("\\").DeleteTask(TaskName, 0);
                logger.Log("Sign-in task removed");
            }
            catch { /* not registered */ }

            string tapctl = Path.Combine(OpenVpnDir, @"bin\tapctl.exe");
            if (AdapterExists() && File.Exists(tapctl))
                logger.Log("tapctl delete exit " + Run(tapctl, "delete \"" + VpnManager.AdapterName + "\""));
            // The TAP driver package stays: other OpenVPN installs may share it.

            // Standalone: remove the unpacked OpenVPN copy (Sentinel's copy is removed by its uninstaller).
            if (!IsSentinelManaged)
                BundledOpenVpn.RemoveExtracted(logger);
        }

        private static int Run(string file, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true };
                using (var p = Process.Start(psi))
                {
                    if (!p.WaitForExit(120000)) { p.Kill(); return -2; }
                    return p.ExitCode;
                }
            }
            catch
            {
                return -1;
            }
        }
    }
}
