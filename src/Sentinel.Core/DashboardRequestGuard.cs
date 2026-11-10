using System;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - Request-shape checks for the loopback dashboard. HttpListener's localhost prefix
    /// is not relied on to reject a rebound Host header, and a browser-supplied Origin must be the
    /// dashboard itself. Pure functions so the rules are unit-tested without a listener.
    /// </summary>
    public static class DashboardRequestGuard
    {
        private static readonly string[] AllowedHosts =
        {
            "localhost:19845", "127.0.0.1:19845", "[::1]:19845",
        };

        /// <summary>No external script, frame, form or base target; inline script is required by the single-file UI.</summary>
        public const string ContentSecurityPolicy =
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
            "img-src 'self' data:; connect-src 'self' ws://localhost:19845 ws://127.0.0.1:19845; " +
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

        /// <summary>
        /// Secret-free page served for an unauthenticated GET /. It re-enters with the per-tab
        /// sessionStorage token (stored by the tray launch) exactly once, otherwise asks the user
        /// to reopen the dashboard from the tray icon.
        /// </summary>
        public const string BootstrapHtml =
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sentinel Dashboard</title></head>" +
            "<body style=\"font-family:Segoe UI,sans-serif;background:#202124;color:#e8eaed;padding:24px\">" +
            "<p id=\"m\">Open the dashboard from the Sentinel tray icon.</p>" +
            "<script>(function(){try{var q=window.location.search||'';" +
            "if(q.indexOf('token=')<0){var t=sessionStorage.getItem('sentinel_token');" +
            "if(t){window.location.replace('/?token='+encodeURIComponent(t));}}" +
            "else{sessionStorage.removeItem('sentinel_token');" +
            "document.getElementById('m').textContent='Session expired. Reopen the dashboard from the Sentinel tray icon.';}" +
            "}catch(e){}})();</script></body></html>";

        public static bool IsAllowedHost(string? hostHeader)
        {
            if (string.IsNullOrEmpty(hostHeader)) return false;
            foreach (var allowed in AllowedHosts)
                if (string.Equals(hostHeader, allowed, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        /// <summary>An absent Origin (same-origin navigation, non-browser client) is allowed; a present one must match.</summary>
        public static bool IsAllowedOrigin(string? originHeader)
        {
            if (string.IsNullOrEmpty(originHeader)) return true;
            return string.Equals(originHeader, "http://localhost:19845", StringComparison.OrdinalIgnoreCase)
                || string.Equals(originHeader, "http://127.0.0.1:19845", StringComparison.OrdinalIgnoreCase);
        }
    }
}
