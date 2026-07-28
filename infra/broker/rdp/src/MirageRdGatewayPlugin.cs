using System;
using System.Threading.Tasks;

namespace Mirage.RdpSteering
{
    /// <summary>
    /// The COM-facing RD Gateway policy plugin (Priority 5, Appendix H.3).
    ///
    /// HONEST LIMITATION, stated explicitly rather than fabricated:
    /// the exact interface member signatures RD Gateway expects
    /// (ITSGatewayPlugin's COM vtable, from the Terminal Services Gateway
    /// Plugin type library / tsgplugin.idl) are Windows-Server-specific COM
    /// interop that this environment has no way to verify byte-for-byte —
    /// there is no Windows host, no access to the actual type library to
    /// add as a COM reference, and no way to compile or register this
    /// class here. Rather than assert a specific COM interface declaration
    /// from memory and risk it being subtly wrong in a way nobody could
    /// catch until a real Windows build, this class is written against a
    /// plausible, documented shape (matching Microsoft's own published
    /// plugin samples: an OnAuthorizeConnection-style callback invoked once
    /// per connection attempt, before the backend RDP connection is
    /// established) with the ACTUAL interop attribute/interface
    /// implementation left as the one piece of real work a Windows-hosted
    /// implementer must finish by referencing the genuine type library —
    /// see the TODO below. Everything this class delegates to
    /// (MirageRouteDecisionClient, MirageRdpPluginConfig,
    /// MirageEventLogDecisionLogger) has no such uncertainty and is real,
    /// complete code.
    /// </summary>
    public sealed class MirageRdGatewayPlugin : IDisposable
    {
        // TODO (Windows-hosted implementation step): replace this class's
        // base type / add the actual COM interop interface here, e.g.
        //     public sealed class MirageRdGatewayPlugin : ITSGatewayPlugin, IDisposable
        // where ITSGatewayPlugin comes from a COM reference to the real
        // Terminal Services Gateway Plugin type library added in Visual
        // Studio on a Windows build host, and implement its required
        // methods by calling AuthorizeConnectionAsync below from within
        // whatever synchronous callback signature that interface actually
        // requires (COM interop typically requires blocking on the async
        // call — GetAwaiter().GetResult() — since legacy COM callbacks are
        // not awaitable).

        private readonly MirageRouteDecisionClient _decisionClient;

        public MirageRdGatewayPlugin(string configPath)
        {
            MirageRdpPluginConfig config = MirageRdpPluginConfig.LoadFromFile(configPath);
            IMirageDecisionLogger logger = new MirageEventLogDecisionLogger(config.EventLogSource);
            _decisionClient = new MirageRouteDecisionClient(config, logger);
        }

        // Constructor overload for tests / dependency injection — never
        // used by the real COM entry point, which always loads config from
        // disk via the primary constructor above.
        internal MirageRdGatewayPlugin(MirageRouteDecisionClient decisionClient)
        {
            _decisionClient = decisionClient;
        }

        /// <summary>
        /// Call this from whichever real COM callback method the actual
        /// ITSGatewayPlugin interface requires (see the TODO above) —
        /// resolves the backend for one connection attempt and returns
        /// true (authorize onto Target) or false (Deny). Never mutates or
        /// migrates an already-established RDP session; this only ever
        /// runs before RD Gateway opens the backend connection.
        /// </summary>
        public async Task<RouteDecisionResult> AuthorizeConnectionAsync(string clientIp, string principal)
        {
            return await _decisionClient.ResolveAsync(clientIp, principal).ConfigureAwait(false);
        }

        public void Dispose()
        {
            _decisionClient.Dispose();
        }
    }
}
