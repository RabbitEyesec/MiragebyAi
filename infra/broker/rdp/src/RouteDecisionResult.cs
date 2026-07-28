namespace Mirage.RdpSteering
{
    public enum RouteTarget
    {
        Endpoint,
        Sandbox,
        Deny,
    }

    /// <summary>
    /// The outcome of one route decision, carrying everything the caller
    /// needs to both act on it (Target) and audit it (CorrelationId,
    /// MatchKey, DecisionSource) — Appendix H.3's "correlation ID, decision
    /// ID, audit event" requirement.
    /// </summary>
    public sealed class RouteDecisionResult
    {
        public RouteTarget Target { get; }

        /// <summary>Generated once per connection attempt, before the
        /// /route call — the join key between this plugin's own Windows
        /// Event Log audit trail and (if the server is ever extended to
        /// echo it back) mirage-api's own audit_events row for the same
        /// decision.</summary>
        public string CorrelationId { get; }

        public string MatchKey { get; }

        /// <summary>"route-api" (a real, live decision), "fail-safe-timeout",
        /// or "fail-safe-error" — never silently indistinguishable from a
        /// real decision.</summary>
        public string DecisionSource { get; }

        public RouteDecisionResult(RouteTarget target, string correlationId, string matchKey, string decisionSource)
        {
            Target = target;
            CorrelationId = correlationId;
            MatchKey = matchKey;
            DecisionSource = decisionSource;
        }
    }
}
