using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
namespace Sentinel.Core
{
    public static class SafeMonitorResolver
    {
        public static System.Collections.Generic.List<IHostedService> Build(
            IServiceProvider sp,
            params (string Name, Func<IServiceProvider, IHostedService> Factory)[] members)
        {
            var logger = sp.GetService<ILogger<MonitorGroup>>();
            var list = new System.Collections.Generic.List<IHostedService>(members.Length);
            foreach (var (name, factory) in members)
            {
                try
                {
                    var m = factory(sp);
                    if (m != null) list.Add(m);
                }
                catch (Exception ex)
                {
                    logger?.LogWarning(
                        "[Startup] Monitor '{Monitor}' could not be constructed on this system and will be skipped (likely a missing OS facility on a stripped-down image): {Error}",
                        name, ex.Message);
                }
            }
            return list;
        }
    }

}
