namespace Sentinel.Core
{
    /// <summary>SCM state and authenticated responsiveness are different facts.</summary>
    public static class ServiceAvailability
    {
        public static string State(bool ipcReachable, string controllerState)
        {
            if (ipcReachable) return "Responding";
            switch (controllerState)
            {
                case "Running": return "NotResponding";
                case "StartPending": return "Starting";
                case "StopPending": return "Stopping";
                case "Stopped": return "Stopped";
                default: return "Unknown";
            }
        }
    }
}
