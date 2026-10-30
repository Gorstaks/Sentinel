// Pure decision logic for the rotation loop and password generation.
// No Windows calls here, so the rules can be checked without a desktop session.

using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Sentinel.AutoRotate;

/// <summary>Non-secret installation state, stored as JSON in the protected state directory.</summary>
internal sealed class RotatorState
{
    public bool Installed { get; set; }
    public bool RotationEnabled { get; set; }
    public string Account { get; set; } = string.Empty;
    public string Sid { get; set; } = string.Empty;

    /// <summary>ISO-8601 UTC instant of the boot that the last boot reset belongs to.</summary>
    public string BootUtc { get; set; } = string.Empty;

    /// <summary>True once the blank reset for the current boot succeeded.</summary>
    public bool ResetSucceeded { get; set; }

    /// <summary>ISO-8601 UTC instant when the last boot reset succeeded. Starts the rotation timer.</summary>
    public string ResetUtc { get; set; } = string.Empty;
}

internal enum RotationAction
{
    /// <summary>Installation is missing, disabled, or this session is not the target desktop.</summary>
    Stop,

    /// <summary>The boot reset has not succeeded for the current boot yet.</summary>
    WaitingForReset,

    /// <summary>A new boot reset succeeded; start the ten-minute timer from it.</summary>
    StartTimer,

    /// <summary>Timer running; the interval has not elapsed.</summary>
    Waiting,

    /// <summary>Interval elapsed; set a new random password.</summary>
    Rotate,
}

internal static class RotationPolicy
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);

    // Boot instants computed from tick counts can differ by a few seconds between calls.
    private static readonly TimeSpan BootTolerance = TimeSpan.FromMinutes(2);

    public static RotationAction Decide(RotatorState? state, bool sessionMatches, DateTime currentBootUtc, string? timerToken, TimeSpan elapsed)
    {
        if (state is null || !state.Installed || !state.RotationEnabled || !sessionMatches)
            return RotationAction.Stop;
        if (!state.ResetSucceeded || !IsSameBoot(state.BootUtc, currentBootUtc))
            return RotationAction.WaitingForReset;
        if (!string.Equals(timerToken, state.ResetUtc, StringComparison.Ordinal))
            return RotationAction.StartTimer;
        if (elapsed < Interval)
            return RotationAction.Waiting;
        return RotationAction.Rotate;
    }

    public static bool IsSameBoot(string storedUtc, DateTime currentBootUtc)
    {
        if (string.IsNullOrEmpty(storedUtc)) return false;
        if (!DateTime.TryParse(storedUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime stored))
            return false;
        return Math.Abs((stored.ToUniversalTime() - currentBootUtc.ToUniversalTime()).TotalSeconds) < BootTolerance.TotalSeconds;
    }

    /// <summary>A 48-character password with 256 bits of randomness, always nonempty.</summary>
    public static string NewRandomPassword()
    {
        byte[] bytes = new byte[32];
        try
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return "Aa1!" + Convert.ToBase64String(bytes);
        }
        finally
        {
            Array.Clear(bytes, 0, bytes.Length);
        }
    }
}
