# Real-time dashboard runbook

SSE is an invalidation channel backed by `dashboard_realtime_updates`.
Clients retain the last numeric event sequence, reconnect with
`Last-Event-ID`, and reload the selected canonical case after an update.

Investigate stale data in this order:

1. Check `dashboard_projection_offsets` for `gap_detected`.
2. Check the case summary freshness and projection version.
3. Check `dashboard_realtime_updates` sequence continuity.
4. Check NATS consumer lag and dead letters.
5. Rebuild only the affected case through the authenticated rebuild endpoint.

Never clear a gap flag manually. A rebuild must replay the canonical source.
Alerts fire for projection lag and SSE/consumer degradation. Validate reconnect
and duplicate handling with dashboard realtime tests and the dashboard
integration suite.
