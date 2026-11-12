using System;

namespace Sentinel.Core
{
    public class TelemetryEvent
    {
        public string Type { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
    }

    public class ProcessTelemetry : TelemetryEvent
    {
        /// <summary>OS process creation FILETIME; zero means unavailable, never a new-generation claim.</summary>
        public long CreationTime { get; set; }
        public string ImagePath { get; set; } = string.Empty;
        public int ParentProcessId { get; set; }
        public string ParentProcessName { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
    }

    public class NetworkTelemetry : TelemetryEvent
    {
        public string LocalAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string State { get; set; } = "ESTABLISHED";
    }

    public class FileActivityTelemetry : TelemetryEvent
    {
        public string FilePath { get; set; } = string.Empty;
        public string OperationType { get; set; } = string.Empty; // WRITE, RENAME, DELETE, etc.
        public string? TargetPath { get; set; }
    }

    public class ThreatIntelTelemetry : TelemetryEvent
    {
        public int TargetProcessId { get; set; }
        public string ApiName { get; set; } = string.Empty; // observed API name when known
        public string Protection { get; set; } = string.Empty;
    }

}
