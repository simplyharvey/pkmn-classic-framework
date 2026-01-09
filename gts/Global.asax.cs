using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using GamestatsBase;
using PkmnFoundations.Data;

namespace PkmnFoundations.GTS
{
    public class Global : System.Web.HttpApplication
    {
        // =====================================================
        // RATE LIMITING - Added to prevent spam/flooding
        // =====================================================
        
        // Storage for tracking requests per IP
        private static Dictionary<string, List<DateTime>> _requestLog = 
            new Dictionary<string, List<DateTime>>();
        
        // Storage for temporarily banned IPs
        private static Dictionary<string, DateTime> _bannedIPs = 
            new Dictionary<string, DateTime>();
        
        // Thread safety lock
        private static readonly object _rateLimitLock = new object();
        
        // Cleanup timer
        private static System.Threading.Timer _cleanupTimer;
        
        // Configuration - adjust these values as needed
        private const int MAX_REQUESTS_PER_MINUTE = 60;      // Normal rate limit
        private const int BAN_THRESHOLD = 100;               // Requests in window that trigger temp ban
        private const int BAN_DURATION_MINUTES = 15;         // How long temp ban lasts
        
        // =====================================================
        // EXISTING CODE - Unchanged (except Application_Start)
        // =====================================================

        void Application_Start(object sender, EventArgs e)
        {
            // Code that runs on application startup
            AppStateHelper.Pokedex(Application);
            
            // Start cleanup timer - runs every 5 minutes
            _cleanupTimer = new System.Threading.Timer(
                _ => CleanupRateLimitData(),
                null,
                TimeSpan.FromMinutes(5),
                TimeSpan.FromMinutes(5));
        }

        void Application_End(object sender, EventArgs e)
        {
            //  Code that runs on application shutdown
            
            // Dispose cleanup timer
            if (_cleanupTimer != null)
            {
                _cleanupTimer.Dispose();
                _cleanupTimer = null;
            }
        }

        void Application_Error(object sender, EventArgs e)
        {
            // Code that runs when an unhandled error occurs

        }

        void Session_Start(object sender, EventArgs e)
        {
            // Code that runs when a new session is started

        }

        void Session_End(object sender, EventArgs e)
        {
            // Code that runs when a session ends. 
            // Note: The Session_End event is raised only when the sessionstate mode
            // is set to InProc in the Web.config file. If session mode is set to StateServer 
            // or SQLServer, the event is not raised.

        }

        void Application_BeginRequest(object sender, EventArgs e)
        {
            // =====================================================
            // RATE LIMITING CHECK - Added for security
            // =====================================================
            if (!CheckRateLimit())
            {
                // Request rejected due to rate limiting
                return;
            }
            
            // =====================================================
            // EXISTING URL REWRITE CODE - Unchanged
            // =====================================================
            String pathInfo, query;
            String targetUrl = RewriteUrl(Request.Url.PathAndQuery, out pathInfo, out query);

            if (targetUrl != null)
            {
                Context.RewritePath(targetUrl, pathInfo, query, false);
            }
        }

        void Application_EndRequest(object sender, EventArgs e)
        {
            GamestatsSessionManager.FromContext(Context).PruneSessions();
        }

        // =====================================================
        // EXISTING URL REWRITE METHOD - With bug fix for split.Length checks
        // =====================================================
        public static String RewriteUrl(String url, out String pathInfo, out String query)
        {
            int q = url.IndexOf('?');
            String path;
            pathInfo = "";

            if (q < 0)
            {
                path = url;
                query = "";
            }
            else
            {
                path = url.Substring(0, q);
                query = url.Substring(q + 1);
            }

            // todo: optimize and extend url pattern matching
            // fixme: this doesn't work if the application isn't mounted at root
            String[] split = path.Split('/');
            if (split[0].Length > 0) return null;

            if (split.Length > 2 && split[1] == "pokemondpds" && split[2] == "web")
            {
                pathInfo = "/" + String.Join("/", split, 3, split.Length - 3);
                return VirtualPathUtility.ToAbsolute("~/pokemondpds_web.ashx");
            }
            else if (split.Length > 1 && split[1] == "pokemondpds")
            {
                pathInfo = "/" + String.Join("/", split, 2, split.Length - 2);
                return VirtualPathUtility.ToAbsolute("~/pokemondpds.ashx");
            }
            else if (split.Length > 2 && split[1] == "syachi2ds" && split[2] == "web")
            {
                pathInfo = "/" + String.Join("/", split, 3, split.Length - 3);
                return VirtualPathUtility.ToAbsolute("~/syachi2ds.ashx");
            }
            // BUG FIX: Changed split.Length > 1 to split.Length > 2 (was accessing split[2])
            else if (split.Length > 2 && split[1] == "pokemon" && split[2] == "validate")
            {
                pathInfo = "/pokemon/validate";
                return VirtualPathUtility.ToAbsolute("~/pkvldtprod.ashx");
            }
            // BUG FIX: Changed split.Length > 1 to split.Length > 2 (was accessing split[2])
            else if (split.Length > 2 && split[1] == "dsio" && split[2] == "gw")
            {
                pathInfo = "/dsio/gw";
                return VirtualPathUtility.ToAbsolute("~/pgl.ashx");
            }
            else return null;
        }

        // =====================================================
        // RATE LIMITING METHODS - New security additions
        // =====================================================

        /// <summary>
        /// Checks if the current request should be allowed based on rate limiting.
        /// Returns true if request is allowed, false if rejected.
        /// </summary>
        private bool CheckRateLimit()
        {
            string ip = GetClientIP();
            
            // Skip rate limiting if we couldn't determine IP
            if (ip == null)
            {
                return true;
            }
            
            DateTime now = DateTime.UtcNow;

            lock (_rateLimitLock)
            {
                // Check if IP is temporarily banned
                if (_bannedIPs.ContainsKey(ip))
                {
                    if ((now - _bannedIPs[ip]).TotalMinutes < BAN_DURATION_MINUTES)
                    {
                        RejectRequest(429, "Too many requests. Please try again later.");
                        return false;
                    }
                    else
                    {
                        // Ban expired, remove it
                        _bannedIPs.Remove(ip);
                    }
                }

                // Initialize request log for this IP if needed
                if (!_requestLog.ContainsKey(ip))
                {
                    _requestLog[ip] = new List<DateTime>();
                }

                // Add current request BEFORE checking (so ban threshold can be reached)
                _requestLog[ip].Add(now);
                
                // Clean entries older than 1 minute
                _requestLog[ip].RemoveAll(t => (now - t).TotalMinutes > 1);

                // Check if over rate limit
                if (_requestLog[ip].Count > MAX_REQUESTS_PER_MINUTE)
                {
                    // If way over limit, add to temp ban list
                    if (_requestLog[ip].Count >= BAN_THRESHOLD)
                    {
                        _bannedIPs[ip] = now;
                        LogSecurityEvent(ip, "TEMP_BANNED", _requestLog[ip].Count);
                    }

                    RejectRequest(429, "Rate limit exceeded. Please slow down.");
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Gets the client IP address, accounting for proxies/load balancers.
        /// Returns null if IP cannot be determined (to avoid grouping unknowns).
        /// </summary>
        private string GetClientIP()
        {
            string ip = null;

            // Check for forwarded IP (if behind proxy/load balancer)
            string forwardedFor = Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                // X-Forwarded-For can contain multiple IPs; take the first (original client)
                ip = forwardedFor.Split(',')[0].Trim();
            }

            // Fall back to direct remote address
            if (string.IsNullOrEmpty(ip))
            {
                ip = Request.ServerVariables["REMOTE_ADDR"];
            }

            // Return null instead of "unknown" to avoid grouping all unknowns together
            return string.IsNullOrEmpty(ip) ? null : ip;
        }

        /// <summary>
        /// Rejects a request with the specified status code and message.
        /// Uses CompleteRequest() instead of Response.End() to avoid ThreadAbortException.
        /// </summary>
        private void RejectRequest(int statusCode, string message)
        {
            var context = HttpContext.Current;
            var response = context.Response;

            response.Clear();
            response.StatusCode = statusCode;
            response.StatusDescription = "Too Many Requests";
            response.ContentType = "text/plain";
            response.Write(message);

            // Gracefully short-circuit the pipeline (avoids ThreadAbortException)
            context.ApplicationInstance.CompleteRequest();
        }

        /// <summary>
        /// Logs security events (optional - implement based on your logging setup).
        /// </summary>
        private void LogSecurityEvent(string ip, string eventType, int requestCount)
        {
            // TODO: Implement logging to your preferred system
            // Examples:
            // - Write to Windows Event Log
            // - Write to database
            // - Write to log file
            // 
            // For now, this just writes to debug output
            System.Diagnostics.Debug.WriteLine(
                $"[SECURITY] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} | {eventType} | IP: {ip} | Requests: {requestCount}"
            );
        }

        /// <summary>
        /// Periodic cleanup of old rate limit entries to prevent memory growth.
        /// Called automatically by timer started in Application_Start.
        /// </summary>
        public static void CleanupRateLimitData()
        {
            DateTime now = DateTime.UtcNow;
            
            lock (_rateLimitLock)
            {
                // Clean up old request logs
                var ipsToClear = new List<string>();
                foreach (var kvp in _requestLog)
                {
                    kvp.Value.RemoveAll(t => (now - t).TotalMinutes > 5);
                    if (kvp.Value.Count == 0)
                    {
                        ipsToClear.Add(kvp.Key);
                    }
                }
                foreach (var ip in ipsToClear)
                {
                    _requestLog.Remove(ip);
                }

                // Clean up expired bans
                var bansToRemove = _bannedIPs
                    .Where(kvp => (now - kvp.Value).TotalMinutes >= BAN_DURATION_MINUTES)
                    .Select(kvp => kvp.Key)
                    .ToList();
                foreach (var ip in bansToRemove)
                {
                    _bannedIPs.Remove(ip);
                }
            }
        }
    }
}
```

---

**For the commit message:**

Title: `Fix rate limiting bugs and add cleanup timer`

Extended description:
```
v2 improvements based on code review:
- Fixed BAN_THRESHOLD logic (was unreachable)
- Switched Response.End() to CompleteRequest() (avoids ThreadAbortException)
- Added automatic cleanup timer for memory management
- Fixed split.Length bug in existing RewriteUrl method
- Return null instead of "unknown" for undetectable IPs
