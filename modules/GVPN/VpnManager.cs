using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace GVPN
{
    public class VpnServer
    {
        public string HostName { get; set; }
        public string IP { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public long Score { get; set; }
        public int Ping { get; set; }
        public long Speed { get; set; }
        public string Country { get; set; }
        public string CountryLong { get; set; }
        public int Sessions { get; set; }
        /// <summary>Sanitized OpenVPN config (see ConfigSanitizer).</summary>
        public string Config { get; set; }
    }

    /// <summary>
    /// Manages VPN connections to VPNGate servers through the OpenVPN 2.x client.
    /// openvpn.exe needs admin rights to configure the TAP adapter and routes, so GVPN runs
    /// elevated (requireAdministrator manifest; started at sign-in by an elevated scheduled task).
    /// </summary>
    public class VpnManager
    {
        /// <summary>Name of the TAP adapter Sentinel setup creates for GVPN.</summary>
        public const string AdapterName = "GVPN TAP";

        private const string ServerListUrl = "http://www.vpngate.net/api/iphone/";
        private const int ConnectTimeoutSeconds = 30;

        private readonly Logger logger;
        private readonly object connectionLock = new object();
        private readonly string dataDir;
        private readonly string serverCachePath;
        private string openVpnExePath;
        private Process currentVpnProcess;
        private string currentLogPath;
        private VpnServer currentServer;

        public KillSwitch KillSwitch { get; private set; }

        public VpnServer CurrentServer { get { return currentServer; } }

        public VpnManager(Logger logger)
        {
            this.logger = logger;
            dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Sentinel", "GVPN", "openvpn_configs");
            serverCachePath = Path.Combine(dataDir, "servers.csv");
            try { Directory.CreateDirectory(dataDir); }
            catch (Exception ex) { logger.Log("Warning: could not create " + dataDir + ": " + ex.Message); }

            openVpnExePath = OpenVpnSearchPaths().FirstOrDefault(File.Exists);
            if (openVpnExePath != null)
                logger.Log("Found OpenVPN at: " + openVpnExePath);

            KillSwitch = new KillSwitch(logger, AdapterName);
        }

        /// <summary>
        /// Where openvpn.exe may live, in priority order. Only admin-writable locations are
        /// searched: a user-writable path (e.g. %TEMP%) would let anyone plant an openvpn.exe
        /// that GVPN then runs elevated.
        /// </summary>
        private static string[] OpenVpnSearchPaths()
        {
            string exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            return new[]
            {
                // Bundled by Sentinel setup: {app}\GVPN\openvpn\bin\openvpn.exe
                Path.Combine(exeDir, "openvpn", "bin", "openvpn.exe"),
                // Unpacked by the standalone single-exe build: %ProgramFiles%\GVPN\openvpn
                Path.Combine(BundledOpenVpn.ExtractDir, "bin", "openvpn.exe"),
                // Standard OpenVPN community installs
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenVPN", "bin", "openvpn.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "OpenVPN", "bin", "openvpn.exe")
            };
        }

        public bool EnsureOpenVpnAvailable()
        {
            if (openVpnExePath == null)
                openVpnExePath = OpenVpnSearchPaths().FirstOrDefault(File.Exists);
            if (openVpnExePath != null)
                return true;

            logger.Log("ERROR: OpenVPN not found. Checked:");
            foreach (string p in OpenVpnSearchPaths())
                logger.Log("  - " + p);
            logger.Log("Reinstall Sentinel to restore the bundled OpenVPN client.");
            return false;
        }

        /// <summary>
        /// Fetches the VPNGate server list. Falls back to the last good list when the fetch fails
        /// (for example while the kill switch blocks everything except the VPN server).
        /// CSV columns: HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,
        /// Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
        /// </summary>
        public List<VpnServer> GetAllVpnServers()
        {
            string csv = null;
            try
            {
                using (var client = new WebClient())
                {
                    client.Headers.Add("User-Agent", "GVPN/1.0");
                    csv = client.DownloadString(ServerListUrl);
                }
                try { File.WriteAllText(serverCachePath, csv); } catch { /* cache is optional */ }
            }
            catch (Exception ex)
            {
                logger.Log("Server list fetch failed (" + ex.Message + "); using cached list");
                try { if (File.Exists(serverCachePath)) csv = File.ReadAllText(serverCachePath); }
                catch { /* fall through */ }
            }

            var servers = new List<VpnServer>();
            if (string.IsNullOrEmpty(csv))
            {
                logger.Log("No VPN server list available");
                return servers;
            }

            foreach (string raw in csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == '*' || line[0] == '#')
                    continue;

                string[] f = line.Split(',');
                if (f.Length < 15)
                    continue;

                try
                {
                    IPAddress ip;
                    if (!IPAddress.TryParse(f[1].Trim(), out ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                        continue;

                    string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(f[14].Trim()));
                    int port;
                    string proto;
                    string config = ConfigSanitizer.Sanitize(decoded, ip.ToString(), out port, out proto);
                    if (config == null)
                        continue;

                    int ping;
                    if (!int.TryParse(f[3].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out ping) || ping <= 0)
                        ping = 9999; // VPNGate reports '-' or 0 when unknown
                    long score, speed;
                    int sessions;
                    long.TryParse(f[2].Trim(), out score);
                    long.TryParse(f[4].Trim(), out speed);
                    int.TryParse(f[7].Trim(), out sessions);

                    servers.Add(new VpnServer
                    {
                        HostName = f[0].Trim(),
                        IP = ip.ToString(),
                        Port = port,
                        Protocol = proto,
                        Score = score,
                        Ping = ping,
                        Speed = speed,
                        CountryLong = f[5].Trim(),
                        Country = f[6].Trim(),
                        Sessions = sessions,
                        Config = config
                    });
                }
                catch { /* skip malformed row */ }
            }

            logger.Log("Fetched " + servers.Count + " VPN servers");
            // Lowest ping first; VPNGate's score (uptime/throughput blend) breaks ties.
            return servers.OrderBy(s => s.Ping).ThenByDescending(s => s.Score).ToList();
        }

        /// <summary>
        /// Connects to one server and waits until OpenVPN reports the tunnel is up.
        /// </summary>
        public bool ConnectVpn(VpnServer server)
        {
            if (server == null || string.IsNullOrEmpty(server.Config))
            {
                logger.Log("No server/config provided");
                return false;
            }

            lock (connectionLock)
            {
                if (!EnsureOpenVpnAvailable())
                    return false;

                StopProcess();

                string baseName = server.IP.Replace('.', '_');
                string configFile = Path.Combine(dataDir, baseName + ".ovpn");
                string logFile = Path.Combine(dataDir, baseName + ".log");

                try
                {
                    File.WriteAllText(configFile, server.Config);
                    if (File.Exists(logFile)) File.Delete(logFile);
                }
                catch (Exception ex)
                {
                    logger.Log("Could not write OpenVPN config: " + ex.Message);
                    return false;
                }

                // With the kill switch on, only the server being dialled may be reached.
                if (KillSwitch.IsEnabled)
                    KillSwitch.Apply(server.IP);

                logger.Log("Connecting to " + server.IP + ":" + server.Port + "/" + server.Protocol + " (" + server.Country + ", ping " + server.Ping + "ms)");

                var psi = new ProcessStartInfo
                {
                    FileName = openVpnExePath,
                    Arguments = BuildArguments(configFile, logFile),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = dataDir
                };

                try
                {
                    currentVpnProcess = Process.Start(psi);
                }
                catch (Exception ex)
                {
                    logger.Log("Could not start OpenVPN: " + ex.Message);
                    return false;
                }

                currentLogPath = logFile;
                logger.Log("OpenVPN started (PID " + currentVpnProcess.Id + ")");

                DateTime deadline = DateTime.UtcNow.AddSeconds(ConnectTimeoutSeconds);
                while (DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(500);
                    if (currentVpnProcess.HasExited)
                    {
                        logger.Log("OpenVPN exited with code " + currentVpnProcess.ExitCode + ": " + LastLogLines(logFile, 3));
                        currentVpnProcess = null;
                        return false;
                    }
                    if (TunnelUp(logFile))
                    {
                        currentServer = server;
                        logger.Log("Connected to " + server.IP + " (" + server.CountryLong + ")");
                        FlushDnsCache();
                        return true;
                    }
                }

                logger.Log("Connection to " + server.IP + " timed out after " + ConnectTimeoutSeconds + "s: " + LastLogLines(logFile, 3));
                StopProcess();
                return false;
            }
        }

        private static string BuildArguments(string configFile, string logFile)
        {
            var a = new StringBuilder();
            a.Append("--config ").Append(Quote(configFile));
            // VPNGate servers only offer AES-128-CBC, which DCO cannot carry: use TAP-Windows6
            // on the adapter Sentinel setup created.
            a.Append(" --windows-driver tap-windows6 --dev-node ").Append(Quote(AdapterName));
            a.Append(" --log ").Append(Quote(logFile)).Append(" --verb 3");
            // Fail fast so failover can move on; OpenVPN restarts the tunnel itself on drops.
            a.Append(" --connect-retry-max 1 --connect-timeout 10 --resolv-retry 0");
            // Keep DNS inside the tunnel.
            a.Append(" --block-outside-dns");
            // Only the built-in route/netsh helpers may run, never config-supplied scripts.
            a.Append(" --script-security 1");
            return a.ToString();
        }

        private static string Quote(string s)
        {
            return "\"" + s.Replace("\"", "") + "\"";
        }

        /// <summary>Tries up to maxAttempts servers in order until one connects.</summary>
        public bool ConnectVpnWithFailover(List<VpnServer> servers, int maxAttempts)
        {
            int attempts = Math.Min(maxAttempts, servers.Count);
            for (int i = 0; i < attempts; i++)
            {
                logger.Log("Failover attempt " + (i + 1) + "/" + attempts);
                if (ConnectVpn(servers[i]))
                    return true;
                Thread.Sleep(1000);
            }
            logger.Log("All " + attempts + " failover attempts failed");
            return false;
        }

        public bool DisconnectVpn()
        {
            lock (connectionLock)
            {
                bool wasRunning = currentVpnProcess != null && !currentVpnProcess.HasExited;
                StopProcess();
                currentServer = null;
                if (wasRunning) logger.Log("VPN disconnected");
                return wasRunning;
            }
        }

        /// <summary>
        /// True while OpenVPN runs and its most recent state is "tunnel up". OpenVPN restarts a
        /// dropped tunnel by itself (ping-restart); during that window this returns false.
        /// </summary>
        public bool CheckVpnStatus()
        {
            Process p = currentVpnProcess;
            string log = currentLogPath;
            try
            {
                if (p == null || p.HasExited || log == null)
                    return false;
                return TunnelUp(log);
            }
            catch
            {
                return false;
            }
        }

        private void StopProcess()
        {
            try
            {
                if (currentVpnProcess != null && !currentVpnProcess.HasExited)
                {
                    currentVpnProcess.Kill();
                    currentVpnProcess.WaitForExit(5000);
                }
            }
            catch (Exception ex)
            {
                logger.Log("Error stopping OpenVPN: " + ex.Message);
            }
            currentVpnProcess = null;
        }

        /// <summary>Last "tunnel up" marker in the log is newer than the last restart marker.</summary>
        private static bool TunnelUp(string logFile)
        {
            string text = ReadShared(logFile);
            if (text == null) return false;
            int up = text.LastIndexOf("Initialization Sequence Completed", StringComparison.Ordinal);
            if (up < 0) return false;
            int restart = Math.Max(text.LastIndexOf("Restart pause", StringComparison.Ordinal),
                                   text.LastIndexOf("SIGUSR1", StringComparison.Ordinal));
            return up > restart;
        }

        private static string LastLogLines(string logFile, int count)
        {
            string text = ReadShared(logFile);
            if (string.IsNullOrEmpty(text)) return "(no OpenVPN log)";
            var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            return string.Join(" | ", lines.Skip(Math.Max(0, lines.Length - count)));
        }

        private static string ReadShared(string path)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var sr = new StreamReader(fs))
                    return sr.ReadToEnd();
            }
            catch
            {
                return null;
            }
        }

        private void FlushDnsCache()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "ipconfig.exe"),
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                    p.WaitForExit(5000);
            }
            catch (Exception ex)
            {
                logger.Log("Error flushing DNS: " + ex.Message);
            }
        }

        public void LogDiagnostics()
        {
            logger.Log("=== VPN DIAGNOSTICS ===");
            logger.Log("OpenVPN executable: " + (openVpnExePath ?? "not found"));
            logger.Log("Config dir: " + dataDir);
            logger.Log("Connected: " + CheckVpnStatus());
            logger.Log("Kill switch: " + (KillSwitch.IsEnabled ? "ON" : "OFF"));
            logger.Log("=== END DIAGNOSTICS ===");
        }
    }
}
