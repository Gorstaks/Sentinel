using System;
using System.Threading;
using System.Windows.Forms;

namespace GVPN
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && string.Equals(args[0], "--uninstall", StringComparison.OrdinalIgnoreCase))
            {
                // Standalone cleanup: kill switch rule, sign-in task, adapter.
                foreach (var p in System.Diagnostics.Process.GetProcessesByName("GVPN"))
                {
                    if (p.Id != System.Diagnostics.Process.GetCurrentProcess().Id)
                        try { p.Kill(); p.WaitForExit(5000); } catch { }
                }
                SelfSetup.Uninstall(new Logger("vpn.log"));
                return;
            }

            // One instance per session: the sign-in task and the Start menu shortcut can both
            // launch GVPN, and two instances would fight over the adapter and kill switch.
            bool createdNew;
            using (var mutex = new Mutex(true, @"Local\GVPN-SingleInstance", out createdNew))
            {
                if (!createdNew)
                    return;

                RemoveLegacyRunKey();

                // Standalone single exe: unpack the embedded OpenVPN client + TAP driver first.
                BundledOpenVpn.EnsureExtracted(new Logger("vpn.log"));

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new VpnTrayApplication());
            }
        }

        /// <summary>
        /// Older builds registered GVPN under HKCU\...\Run. GVPN now requires elevation, which a
        /// Run entry cannot provide (Windows skips it), so Sentinel setup starts GVPN through an
        /// elevated sign-in scheduled task instead. Remove the stale value.
        /// </summary>
        static void RemoveLegacyRunKey()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key != null && key.GetValue("GVPN") != null)
                        key.DeleteValue("GVPN", false);
                }
            }
            catch { /* best effort */ }
        }
    }
}
