using System;
using System.IO;

namespace GVPN
{
    public class Logger
    {
        private string logFilePath;

        public string FilePath { get { return logFilePath; } }
        private object lockObj = new object();

        public Logger(string filename)
        {
            // Use a fixed directory for logs so they're easy to find
            // Try %APPDATA%\Sentinel\GVPN first, fall back to temp
            string logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Sentinel", "GVPN");
            
            try
            {
                if (!Directory.Exists(logDir))
                    Directory.CreateDirectory(logDir);
            }
            catch
            {
                // If we can't create in AppData, use the temp directory
                logDir = Path.GetTempPath();
            }
            
            logFilePath = Path.Combine(logDir, filename);
        }

        public void Log(string message)
        {
            lock (lockObj)
            {
                try
                {
                    string logMessage = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " - " + message;
                    File.AppendAllText(logFilePath, logMessage + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    // Silently fail if logging fails
                    System.Diagnostics.Debug.WriteLine("Logging error: " + ex.Message);
                }
            }
        }
    }
}
