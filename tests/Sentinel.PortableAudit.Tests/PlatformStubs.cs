// Portable tests exercise unchanged production algorithms, never native Windows adapters.
// Throwing stubs ensure these tests cannot accidentally claim Authenticode runtime validation.
using Microsoft.Extensions.Logging;
namespace Sentinel.Core
{
    public static class SecurityValidation
    {
        public static string? GetProcessImagePath(int pid) => throw new PlatformNotSupportedException();
        public static bool VerifyAuthenticodeSignature(string path, ILogger logger) => throw new PlatformNotSupportedException();
    }
    public static class MicrosoftPublisher
    {
        public static bool IsMicrosoftCommonName(string name) => throw new PlatformNotSupportedException();
    }
}
