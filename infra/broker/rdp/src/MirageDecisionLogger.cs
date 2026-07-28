using System;
using System.Diagnostics;

namespace Mirage.RdpSteering
{
    /// <summary>
    /// Abstraction over "where decision/audit events get recorded" —
    /// exists specifically so MirageRouteDecisionClient (the portable
    /// decision logic) is unit-testable with an in-memory fake, the same
    /// ADR-0002-style split the Python side of this codebase uses
    /// everywhere (portable logic + a thin, OS-binding-only production
    /// implementation).
    /// </summary>
    public interface IMirageDecisionLogger
    {
        void LogDecision(string correlationId, string matchKey, RouteTarget target, string decisionSource, TimeSpan elapsed);

        void LogError(string correlationId, string matchKey, Exception exception);
    }

    /// <summary>
    /// Real production implementation — writes to the Windows Event Log
    /// under the source named in config (event_log_source), created by
    /// scripts/install-mirage-rdp-plugin.ps1. WINDOWS_VERIFICATION_REQUIRED:
    /// System.Diagnostics.EventLog requires a real Windows host to exercise;
    /// MirageRouteDecisionClient's own tests use a fake IMirageDecisionLogger
    /// instead, so the decision logic itself has real coverage independent
    /// of this class.
    /// </summary>
    public sealed class MirageEventLogDecisionLogger : IMirageDecisionLogger
    {
        private readonly string _sourceName;

        public MirageEventLogDecisionLogger(string sourceName)
        {
            _sourceName = sourceName;
        }

        public void LogDecision(string correlationId, string matchKey, RouteTarget target, string decisionSource, TimeSpan elapsed)
        {
            string message =
                $"MirageRdpDecision correlation_id={correlationId} match_key={matchKey} " +
                $"target={target} decision_source={decisionSource} elapsed_ms={elapsed.TotalMilliseconds:F0}";
            EventLog.WriteEntry(_sourceName, message, EventLogEntryType.Information);
        }

        public void LogError(string correlationId, string matchKey, Exception exception)
        {
            string message =
                $"MirageRdpDecisionError correlation_id={correlationId} match_key={matchKey} " +
                $"exception_type={exception.GetType().Name} message={exception.Message}";
            EventLog.WriteEntry(_sourceName, message, EventLogEntryType.Warning);
        }
    }
}
