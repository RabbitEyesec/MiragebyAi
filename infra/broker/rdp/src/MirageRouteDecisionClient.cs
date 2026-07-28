using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Mirage.RdpSteering
{
    /// <summary>
    /// The portable RDP steering decision logic (Priority 5, Appendix H.3):
    /// builds the canonical match_key, calls mirage-api's real GET /route
    /// (the exact same endpoint and header contract the HTTP/SSH brokers
    /// already use — see infra/broker/ssh/mirage-route-selector.sh and
    /// tests/integration/test_routing_api.py's RDP-protocol tests), and
    /// fails safe on any timeout or error. Has no COM/RD-Gateway dependency
    /// at all — this class is what MirageRdGatewayPlugin.cs (the actual
    /// COM-facing plugin, WINDOWS_VERIFICATION_REQUIRED) delegates to, and
    /// what tests/MirageRouteDecisionClientTests.cs exercises directly
    /// against a fake HttpMessageHandler ("test harness with a fake
    /// routing API").
    ///
    /// Never claims continuity across a route change: this class answers
    /// "which backend should THIS NEW connection attempt go to" once,
    /// before RD Gateway establishes the backend connection — it has no
    /// concept of, and never touches, an already-established RDP session.
    /// </summary>
    public sealed class MirageRouteDecisionClient : IDisposable
    {
        private readonly MirageRdpPluginConfig _config;
        private readonly IMirageDecisionLogger _logger;
        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;

        public MirageRouteDecisionClient(MirageRdpPluginConfig config, IMirageDecisionLogger logger, HttpMessageHandler? testHandler = null)
        {
            _config = config;
            _logger = logger;
            if (testHandler is null)
            {
                _httpClient = new HttpClient();
                _ownsHttpClient = true;
            }
            else
            {
                // Test seam only — production callers never pass this.
                _httpClient = new HttpClient(testHandler, disposeHandler: false);
                _ownsHttpClient = true;
            }
            _httpClient.Timeout = TimeSpan.FromMilliseconds(config.TimeoutMs);
        }

        /// <summary>
        /// Canonical match_key: RDP|&lt;gateway_listener_id&gt;|&lt;client_ip&gt;|&lt;principal&gt;
        /// — the RDP-protocol instance of the exact same convention the
        /// HTTP broker (nginx) and SSH broker (mirage-route-selector.sh)
        /// already use for their own protocols.
        /// </summary>
        public string BuildMatchKey(string clientIp, string principal)
        {
            return $"RDP|{_config.GatewayListenerId}|{clientIp}|{principal}";
        }

        /// <summary>
        /// Resolves which backend this connection attempt is authorized to
        /// reach. Never throws on a /route failure — always returns a
        /// result, whose DecisionSource distinguishes a real decision from
        /// a fail-safe one, so the caller (and the audit log) can always
        /// tell which happened.
        /// </summary>
        public async Task<RouteDecisionResult> ResolveAsync(string clientIp, string principal, CancellationToken cancellationToken = default)
        {
            string matchKey = BuildMatchKey(clientIp, principal);
            string correlationId = Guid.NewGuid().ToString("D");
            Stopwatch stopwatch = Stopwatch.StartNew();

            try
            {
                string secret = _config.ResolveProxySharedSecret();
                string url = $"{_config.MirageApiUrl.TrimEnd('/')}/route?match_key={Uri.EscapeDataString(matchKey)}&protocol=RDP";

                using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("X-Mirage-Client-Cert-Serial", _config.ClientCertSerial);
                request.Headers.Add("X-Mirage-Proxy-Auth", secret);
                request.Headers.Add("X-Mirage-Correlation-Id", correlationId);

                using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                using JsonDocument document = JsonDocument.Parse(body);
                string upstream = document.RootElement.TryGetProperty("upstream", out JsonElement upstreamElement)
                    ? upstreamElement.GetString() ?? "ENDPOINT"
                    : "ENDPOINT";
                RouteTarget target = upstream == "SANDBOX" ? RouteTarget.Sandbox : RouteTarget.Endpoint;

                RouteDecisionResult result = new RouteDecisionResult(target, correlationId, matchKey, "route-api");
                _logger.LogDecision(correlationId, matchKey, target, "route-api", stopwatch.Elapsed);
                return result;
            }
            catch (Exception exception) when (
                exception is HttpRequestException
                || exception is TaskCanceledException
                || exception is OperationCanceledException
                || exception is JsonException
                || exception is InvalidOperationException)
            {
                _logger.LogError(correlationId, matchKey, exception);
                string decisionSource = (exception is TaskCanceledException || exception is OperationCanceledException)
                    ? "fail-safe-timeout"
                    : "fail-safe-error";
                RouteTarget failSafeTarget = _config.FailSafeTarget == "DENY" ? RouteTarget.Deny : RouteTarget.Endpoint;
                RouteDecisionResult result = new RouteDecisionResult(failSafeTarget, correlationId, matchKey, decisionSource);
                _logger.LogDecision(correlationId, matchKey, failSafeTarget, decisionSource, stopwatch.Elapsed);
                return result;
            }
        }

        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
        }
    }
}
