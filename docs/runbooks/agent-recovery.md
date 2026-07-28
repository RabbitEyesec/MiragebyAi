# Agent queue recovery

See `docs/architecture/event-delivery.md` for the full delivery model this
runbook assumes.

## Symptom: `queue_depth` in an agent's heartbeat keeps growing

1. Check the agent's own logs for repeated `TelemetrySubmitFailed`/
   `TelemetryAckMismatch` — a genuine network/server outage is expected to
   show a stable-or-shrinking backlog once connectivity returns, since
   `flush_queue()` acks every event immediately as it succeeds.
2. If the backlog isn't shrinking after connectivity is confirmed restored,
   inspect `queue_events` in the agent's local `queue.db` (the head-of-queue
   row, lowest `id` with `status='PENDING'`) — its `last_error` column
   records the most recent failure for that specific event.
3. A stuck head-of-queue row that keeps getting a 409 with "already used by
   a different event" indicates a real conflict (not the crash-recovery
   case migration 0011 handles) — this needs operator investigation, not a
   naive retry-forever.

## Symptom: agent reports `recovered_from_corruption: true` (health/log)

The local SQLite queue file failed to open cleanly and was quarantined to
`queue.db.corrupt-<unix-timestamp>` alongside a fresh, empty queue. This
means:

- Any events that were only in the corrupted file (not yet delivered) are
  gone — there is no way to recover application data from a corrupted
  SQLite file without forensic tooling.
- The quarantined file is NOT deleted automatically — pull it for analysis
  if you need to understand what was lost, then remove it manually once
  done (it will not be picked up again by the running service).
- The sequence counter also reset to whatever `sequence_state` recovers to
  in the fresh file (0) — the server will accept the next event at sequence
  1 from this agent_id as a *lower* sequence than its previously recorded
  `last_sequence`, and will reject it with 409. **A corrupted local queue on
  an already-enrolled agent requires re-enrollment** (a fresh `agent_id`),
  not just a fresh local queue file, or every subsequent submission will
  permanently 409. Treat `recovered_from_corruption` as equivalent to "this
  agent identity's queue state is unrecoverable — re-enroll."

## Symptom: dead-lettered events accumulating

`queue.dead_letter_count()` (surface this in the agent's health/heartbeat if
not already wired) counts events the server told us can never succeed
(currently: HTTP 400, a structurally invalid `event_type`). This should only
ever happen if the agent's own build is sending an event type it isn't
allowed to submit — check `ALLOWED_TELEMETRY_EVENT_TYPES` in
`mirage-agent-ingestion` against the agent's build/version. Dead-lettered
rows are kept on disk (never silently dropped) specifically so they can be
inspected: read `queue_events` directly, filter `status='DEAD_LETTER'`, and
decrypt with the agent's own key (same Fernet key the running service uses)
to inspect exactly what was rejected and why (`last_error`).

## Symptom: local queue file growing on disk despite low `queue_depth`

`vacuum_acked()` reclaims space for `ACKNOWLEDGED` rows but is called
periodically, not on every ack, to avoid `VACUUM`'s I/O cost on the hot
path. If disk usage is a concern, confirm the periodic vacuum is actually
scheduled in the service's main loop; it does not delete `DEAD_LETTER` rows
(deliberately — those are operator-inspectable state, not routine cleanup).

## Exact commands

```sh
make test-agent-delivery   # full local proof: unit + real Postgres/NATS integration test
```
