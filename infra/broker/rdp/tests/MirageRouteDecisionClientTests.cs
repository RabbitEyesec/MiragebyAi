using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Mirage.RdpSteering;
using Xunit;

namespace Mirage.RdpSteering.Tests
{
    /// <summary>
    /// Records every decision/error the client reports, so tests can assert
    /// on both the returned RouteDecisionResult and what got logged —
    /// standing in for MirageEventLogDecisionLogger the same way
    /// Python's _FakeClient stands in for AgentHttpClient elsewhere in this
    /// codebase.
    /// </summary>
    internal sealed class FakeDecisionLogger : IMirageDecisionLogger
    {
        public List<(string CorrelationId, string MatchKey, RouteTarget Target, string DecisionSource)> Decisions { get; } = new();
        public List<(string CorrelationId, string MatchKey, Exception Exception)> Errors { get; } = new();

        public void LogDecision(string correlationId, string matchKey, RouteTarget target, string decisionSource, TimeSpan elapsed)
        {
            Decisions.Add((correlationId, matchKey, target, decisionSource));
        }

        public void LogError(string correlationId, string matchKey, Exception exception)
        {
            Errors.Add((correlationId, matchKey, exception));
        }
    }

    /// <summary>The "fake routing API" test harness Priority 5 asks for —
    /// a scriptable HttpMessageHandler standing in for a real mirage-api
    /// /route endpoint, so these tests never need network access or a live
    /// server.</summary>
    internal sealed class FakeRouteApiHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public List<HttpRequestMessage> Requests { get; } = new();

        public FakeRouteApiHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(_respond(request));
        }
    }

    internal sealed class TimeoutHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);
            throw new TaskCanceledException("should never reach here — the client's own timeout fires first");
        }
    }

    public class MirageRouteDecisionClientTests
    {
        private static MirageRdpPluginConfig MakeConfig(string envVarName, string failSafeTarget = "ENDPOINT", int timeoutMs = 500)
        {
            Environment.SetEnvironmentVariable(envVarName, "test-proxy-shared-secret");
            return new MirageRdpPluginConfig
            {
                MirageApiUrl = "https://mirage-api.test:8000",
                GatewayListenerId = "rdgw-1",
                ClientCertPath = "unused-in-tests.crt",
                ClientKeyPath = "unused-in-tests.key",
                RootCaPath = "unused-in-tests.crt",
                ClientCertSerial = "TEST-SERIAL-0001",
                ProxySharedSecretEnvVar = envVarName,
                TimeoutMs = timeoutMs,
                FailSafeTarget = failSafeTarget,
                EventLogSource = "MirageRdpPluginTests",
            };
        }

        [Fact]
        public void BuildMatchKey_matches_the_canonical_RDP_format()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_1");
            var logger = new FakeDecisionLogger();
            using var client = new MirageRouteDecisionClient(config, logger);

            string matchKey = client.BuildMatchKey("10.0.0.12", "CONTOSO\\alice");

            Assert.Equal("RDP|rdgw-1|10.0.0.12|CONTOSO\\alice", matchKey);
        }

        [Fact]
        public async Task ResolveAsync_returns_Sandbox_when_the_route_api_says_SANDBOX()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_2");
            var logger = new FakeDecisionLogger();
            var handler = new FakeRouteApiHandler(request => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"upstream\":\"SANDBOX\",\"cached\":false}", Encoding.UTF8, "application/json"),
            });
            using var client = new MirageRouteDecisionClient(config, logger, handler);

            RouteDecisionResult result = await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            Assert.Equal(RouteTarget.Sandbox, result.Target);
            Assert.Equal("route-api", result.DecisionSource);
            Assert.NotEmpty(result.CorrelationId);
            Assert.Single(logger.Decisions);
            Assert.Empty(logger.Errors);
        }

        [Fact]
        public async Task ResolveAsync_returns_Endpoint_when_the_route_api_says_ENDPOINT()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_3");
            var logger = new FakeDecisionLogger();
            var handler = new FakeRouteApiHandler(request => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"upstream\":\"ENDPOINT\",\"cached\":false}", Encoding.UTF8, "application/json"),
            });
            using var client = new MirageRouteDecisionClient(config, logger, handler);

            RouteDecisionResult result = await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            Assert.Equal(RouteTarget.Endpoint, result.Target);
            Assert.Equal("route-api", result.DecisionSource);
        }

        [Fact]
        public async Task ResolveAsync_sends_the_exact_header_contract_the_real_route_endpoint_requires()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_4");
            var logger = new FakeDecisionLogger();
            var handler = new FakeRouteApiHandler(request => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"upstream\":\"ENDPOINT\",\"cached\":false}", Encoding.UTF8, "application/json"),
            });
            using var client = new MirageRouteDecisionClient(config, logger, handler);

            await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            HttpRequestMessage sent = Assert.Single(handler.Requests);
            Assert.Equal("TEST-SERIAL-0001", sent.Headers.GetValues("X-Mirage-Client-Cert-Serial").GetEnumerator().Current);
            Assert.Contains("test-proxy-shared-secret", sent.Headers.GetValues("X-Mirage-Proxy-Auth"));
            Assert.True(sent.RequestUri!.Query.Contains("protocol=RDP"));
            Assert.True(sent.RequestUri!.Query.Contains("match_key="));
        }

        [Fact]
        public async Task ResolveAsync_fails_safe_to_Endpoint_on_a_server_error_when_configured_for_ENDPOINT()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_5", failSafeTarget: "ENDPOINT");
            var logger = new FakeDecisionLogger();
            var handler = new FakeRouteApiHandler(request => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            using var client = new MirageRouteDecisionClient(config, logger, handler);

            RouteDecisionResult result = await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            Assert.Equal(RouteTarget.Endpoint, result.Target);
            Assert.Equal("fail-safe-error", result.DecisionSource);
            Assert.Single(logger.Errors);
        }

        [Fact]
        public async Task ResolveAsync_fails_safe_to_Deny_when_configured_for_DENY()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_6", failSafeTarget: "DENY");
            var logger = new FakeDecisionLogger();
            var handler = new FakeRouteApiHandler(request => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            using var client = new MirageRouteDecisionClient(config, logger, handler);

            RouteDecisionResult result = await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            Assert.Equal(RouteTarget.Deny, result.Target);
            Assert.Equal("fail-safe-error", result.DecisionSource);
        }

        [Fact]
        public async Task ResolveAsync_fails_safe_on_timeout_never_hangs_past_the_configured_budget()
        {
            var config = MakeConfig("MIRAGE_TEST_SECRET_7", timeoutMs: 200);
            var logger = new FakeDecisionLogger();
            using var client = new MirageRouteDecisionClient(config, logger, new TimeoutHandler());

            RouteDecisionResult result = await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            Assert.Equal(RouteTarget.Endpoint, result.Target);
            Assert.Equal("fail-safe-timeout", result.DecisionSource);
        }

        [Fact]
        public async Task ResolveAsync_never_returns_Sandbox_as_a_fail_safe_target()
        {
            // Regardless of configuration, a failed /route call must never
            // resolve to SANDBOX — only a REAL, successful decision may.
            var config = MakeConfig("MIRAGE_TEST_SECRET_8", failSafeTarget: "ENDPOINT");
            var logger = new FakeDecisionLogger();
            var handler = new FakeRouteApiHandler(request => new HttpResponseMessage(HttpStatusCode.InternalServerError));
            using var client = new MirageRouteDecisionClient(config, logger, handler);

            RouteDecisionResult result = await client.ResolveAsync("10.0.0.12", "CONTOSO\\alice");

            Assert.NotEqual(RouteTarget.Sandbox, result.Target);
        }
    }
}
