using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace GVPN
{
    public partial class VpnTrayApplication : Form
    {
        private const int MonitorIntervalMs = 30000;
        private const int FailoverServers = 5;

        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;
        private Thread vpnMonitorThread;
        private volatile bool isRunning;
        private volatile bool isConnected;
        // Set by "Disconnect": stop auto-reconnecting until the user connects again.
        private volatile bool userDisconnected;
        private readonly Logger logger;
        private readonly VpnManager vpnManager;

        public VpnTrayApplication()
        {
            logger = new Logger("vpn.log");
            logger.Log("=== GVPN " + Application.ProductVersion + " starting" + (SelfSetup.IsSentinelManaged ? " (Sentinel-managed)" : " (standalone)") + " ===");
            vpnManager = new VpnManager(logger);

            // Hidden host form for the tray icon.
            Text = "GVPN";
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            Size = new System.Drawing.Size(0, 0);
            Opacity = 0;
            StartPosition = FormStartPosition.Manual;
            Location = new System.Drawing.Point(-32000, -32000);

            SetupTrayIcon();

            if (!vpnManager.EnsureOpenVpnAvailable())
                logger.Log("WARNING: OpenVPN not available - GVPN cannot connect");
            vpnManager.LogDiagnostics();

            // A kill switch left on by a previous session stays enforced (fail closed).
            if (vpnManager.KillSwitch.IsEnabled)
                vpnManager.KillSwitch.Apply(null);
            UpdateTrayIcon();

            isRunning = true;
            vpnMonitorThread = new Thread(VpnMonitorLoop) { IsBackground = true, Name = "VpnMonitor" };
            vpnMonitorThread.Start();
        }

        private void SetupTrayIcon()
        {
            trayMenu = new ContextMenuStrip();

            var statusItem = new ToolStripMenuItem("Status: Disconnected") { Name = "StatusItem", Enabled = false };
            trayMenu.Items.Add(statusItem);
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add(new ToolStripMenuItem("&Connect...", null, ConnectManual_Click));
            trayMenu.Items.Add(new ToolStripMenuItem("&Disconnect", null, Disconnect_Click));
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add(new ToolStripMenuItem("&Kill Switch: OFF", null, ToggleKillSwitch_Click) { Name = "KillSwitchItem" });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add(new ToolStripMenuItem("&View Logs", null, ViewLogs_Click));
            trayMenu.Items.Add(new ToolStripMenuItem("E&xit", null, Exit_Click));

            trayIcon = new NotifyIcon
            {
                Icon = CreateIcon(false),
                ContextMenuStrip = trayMenu,
                Text = "GVPN - Disconnected",
                Visible = true
            };
            trayIcon.MouseDoubleClick += TrayIcon_DoubleClick;
        }

        private static System.Drawing.Icon CreateIcon(bool connected)
        {
            using (var bitmap = new System.Drawing.Bitmap(16, 16))
            {
                using (var g = System.Drawing.Graphics.FromImage(bitmap))
                using (var brush = new System.Drawing.SolidBrush(connected ? System.Drawing.Color.LimeGreen : System.Drawing.Color.Red))
                {
                    g.Clear(System.Drawing.Color.Transparent);
                    g.FillEllipse(brush, 2, 2, 12, 12);
                }
                return System.Drawing.Icon.FromHandle(bitmap.GetHicon());
            }
        }

        private void UpdateTrayIcon()
        {
            try
            {
                bool ks = vpnManager.KillSwitch.IsEnabled;
                VpnServer server = vpnManager.CurrentServer;
                string status = isConnected && server != null
                    ? "Connected - " + server.IP + " (" + server.Country + ")"
                    : (userDisconnected ? "Disconnected" : "Connecting...");
                if (ks) status += " [Kill Switch]";

                var statusItem = trayMenu.Items["StatusItem"] as ToolStripMenuItem;
                if (statusItem != null) statusItem.Text = "Status: " + status;
                var ksItem = trayMenu.Items["KillSwitchItem"] as ToolStripMenuItem;
                if (ksItem != null) ksItem.Text = "&Kill Switch: " + (ks ? "ON" : "OFF");

                trayIcon.Icon = CreateIcon(isConnected);
                string tip = "GVPN - " + status;
                trayIcon.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip; // NotifyIcon limit
            }
            catch (Exception ex)
            {
                logger.Log("Error updating tray: " + ex.Message);
            }
        }

        private void UpdateTrayIconFromWorker()
        {
            try
            {
                if (IsHandleCreated && !IsDisposed)
                    BeginInvoke((MethodInvoker)UpdateTrayIcon);
            }
            catch (InvalidOperationException) { /* closing */ }
        }

        private void VpnMonitorLoop()
        {
            // One-time machine setup off the UI thread (driver install can take a few seconds).
            try
            {
                SelfSetup.EnsureTapAdapter(logger);
                if (!SelfSetup.IsSentinelManaged)
                    SelfSetup.EnsureSignInTask(logger);
            }
            catch (Exception ex)
            {
                logger.Log("Self-setup error: " + ex.Message);
            }

            while (isRunning)
            {
                try
                {
                    bool wasConnected = isConnected;
                    isConnected = vpnManager.CheckVpnStatus();

                    if (wasConnected && !isConnected)
                        logger.Log("VPN connection lost");

                    if (!isConnected && !userDisconnected)
                    {
                        // Keep retrying whether or not the kill switch is on; with it on, traffic
                        // stays blocked (except to the server being dialled) until this succeeds.
                        isConnected = ReconnectWithFailover();
                    }
                    else if (isConnected && vpnManager.KillSwitch.IsEnabled)
                    {
                        // Re-apply so newly attached adapters (Wi-Fi, USB tether) are covered.
                        vpnManager.KillSwitch.Apply(vpnManager.CurrentServer != null ? vpnManager.CurrentServer.IP : null);
                    }

                    UpdateTrayIconFromWorker();
                }
                catch (Exception ex)
                {
                    logger.Log("Monitor error: " + ex.Message);
                }

                for (int waited = 0; waited < MonitorIntervalMs && isRunning; waited += 500)
                    Thread.Sleep(500);
            }
        }

        private bool ReconnectWithFailover()
        {
            List<VpnServer> servers = vpnManager.GetAllVpnServers();
            if (servers.Count == 0)
            {
                logger.Log("No servers available for failover");
                return false;
            }
            bool ok = vpnManager.ConnectVpnWithFailover(servers, FailoverServers);
            if (!ok && vpnManager.KillSwitch.IsEnabled)
                vpnManager.KillSwitch.Apply(null); // nothing connected: allow no server at all
            return ok;
        }

        private void ConnectManual_Click(object sender, EventArgs e)
        {
            using (var form = new VpnListForm(vpnManager, logger))
                form.ShowDialog();
            isConnected = vpnManager.CheckVpnStatus();
            if (isConnected) userDisconnected = false;
            UpdateTrayIcon();
        }

        private void Disconnect_Click(object sender, EventArgs e)
        {
            logger.Log("Disconnect requested");
            userDisconnected = true;
            vpnManager.DisconnectVpn();
            if (vpnManager.KillSwitch.IsEnabled)
                vpnManager.KillSwitch.Apply(null);
            isConnected = false;
            UpdateTrayIcon();
        }

        private void ToggleKillSwitch_Click(object sender, EventArgs e)
        {
            if (!vpnManager.KillSwitch.IsEnabled)
            {
                VpnServer server = vpnManager.CurrentServer;
                bool ok = vpnManager.KillSwitch.Enable(isConnected && server != null ? server.IP : null);
                MessageBox.Show(ok
                        ? "Kill switch ON.\n\nTraffic that does not go through the VPN tunnel is blocked, including while GVPN reconnects. Exiting GVPN turns it off."
                        : "The kill switch could not be applied. See the GVPN log.",
                    "GVPN Kill Switch", MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Error);
            }
            else
            {
                vpnManager.KillSwitch.Disable();
                MessageBox.Show("Kill switch OFF.\n\nTraffic is no longer forced through the VPN.",
                    "GVPN Kill Switch", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            UpdateTrayIcon();
        }

        private void ViewLogs_Click(object sender, EventArgs e)
        {
            try
            {
                if (File.Exists(logger.FilePath))
                    Process.Start(new ProcessStartInfo("notepad.exe", "\"" + logger.FilePath + "\"") { UseShellExecute = false });
                else
                    MessageBox.Show("Log file not found:\n" + logger.FilePath, "GVPN", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error opening log: " + ex.Message, "GVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Exit_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void TrayIcon_DoubleClick(object sender, MouseEventArgs e)
        {
            VpnServer server = vpnManager.CurrentServer;
            string text = isConnected && server != null
                ? "Connected to " + server.IP + " (" + server.CountryLong + ")"
                : "Not connected";
            trayIcon.ShowBalloonTip(3000, "GVPN", text, ToolTipIcon.Info);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            isRunning = false;
            logger.Log("GVPN exiting");
            vpnManager.DisconnectVpn();
            // Exit from the tray is a deliberate user action: restore the network. On shutdown or
            // sign-out the rule stays (fail closed) and GVPN re-arms it at the next sign-in.
            if (vpnManager.KillSwitch.IsEnabled && e.CloseReason != CloseReason.WindowsShutDown)
                vpnManager.KillSwitch.Disable();
            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }
            base.OnFormClosing(e);
        }
    }
}
