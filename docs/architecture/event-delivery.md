# Agent event delivery correctness

## The bug this fixes

`EncryptedEventQueue` + `AgentHttpClient.submit_telemetry` + each agent's
`flush_queue()` implement at-least-once delivery from a Windows agent
(MirageSpider today; MirageEndpoint once it has real telemetry) to
`mirage-agent-ingestion`. Before this fix, the local queue's ack bookkeeping
had a real, reproducible correctness gap:

1. `flush_queue()` sent events one at a time within a batch page, but only
   called `queue.ack(acked_ids)` **once, after the whole page finished** —
   not immediately after each individual successful send.
2. The server's only duplicate-submission defense was
   `agents.last_sequence` — a plain "sequence must strictly increase" check,
   returning 409 for anything at or below the last recorded value.

Combine the two: if the process crashed after the server durably committed
events 1..N (each already advanced `last_sequence`, each already returned a
real 202) but *before* the batch-ending `queue.ack()` call executed, every
one of those already-accepted events would still show as `PENDING` locally.
On restart, `flush_queue()` would resend event 1 first — and the server
would reject it with 409 forever, because `last_sequence` had already moved
past it. That 409 caused `flush_queue` to stop immediately (order-preserving
by design), which meant **nothing queued behind that event could ever be
delivered again** — a permanent head-of-queue deadlock triggered by an
ordinary crash-after-send-before-ack, exactly the scenario Priority 2 names
explicitly.

## The fix

**Server (`mirage-agent-ingestion`, migration 0011,
`agent_telemetry_receipts`):** every accepted event's `(agent_id, sequence,
event_id)` is recorded in the same transaction as the `agents.last_sequence`
advance and the NATS publish. On a new submission, the server checks this
table *before* the `last_sequence` comparison:

- No receipt for this `(agent_id, sequence)` → normal path (validate,
  publish, record, advance).
- A receipt exists and its `event_id` matches the submitted one → **this is
  a safe replay**: return the exact same acknowledgement
  (`{"status": "accepted", "event_id": ..., "sequence": ..., "replay":
  true}`), without re-publishing or re-advancing anything.
- A receipt exists but its `event_id` differs → a genuine conflict (two
  different events trying to claim the same sequence number) → 409.

This is what makes retrying a locally-unacknowledged-but-server-accepted
event safe instead of a permanent dead end.

**Client (`AgentHttpClient.submit_telemetry`):** a bare 202 is never treated
as sufficient — the acknowledgement body's `event_id` must match the event
actually submitted, or `TelemetryAckMismatch` is raised instead of returning
normally. A caller can only treat a normal return as "the server durably
accepted exactly this event."

**Client (`SpiderServiceLogic.flush_queue`):** each row is acked
individually, immediately after its own send is confirmed — not
accumulated across the whole batch page. This shrinks the crash window from
"up to `batch_size` events" to "at most one," and the server's idempotent
replay closes even that remaining window. A 400 (structurally invalid event
— e.g. a disallowed `event_type`) is dead-lettered immediately, since
retrying identical bytes can never succeed; every other failure (403, 409,
5xx, network) stops the flush loop at that row, preserving order for the
next retry attempt.

## Queue states

`EncryptedEventQueue` rows move `PENDING → ACKNOWLEDGED` (normal success) or
`PENDING → DEAD_LETTER` (permanent rejection — kept on disk with
`last_error`, never silently discarded). There is no persisted `IN_FLIGHT`
state: only one flush loop ever drains a given local queue file at a time,
so a crash mid-send simply leaves the row `PENDING` again, which is the
correct, safe outcome. `attempts`/`last_error` are tracked on every failure
(dead-lettered or not) for operator visibility. `enqueue()` refuses once
`max_queue_size` pending rows accumulate (`QueueCapacityExceeded`) rather
than growing the on-disk queue without bound. A corrupted queue file (bad
sectors, crash mid-write) is detected on open, quarantined alongside the
live file (`queue.db.corrupt-<timestamp>`), and replaced with a fresh queue
rather than crash-looping the service.

## Tests

- `tests/unit/test_agent_queue.py` — dead-letter, attempt tracking, capacity
  refusal, corrupt-file quarantine-and-recover.
- `tests/unit/test_agent_http_client.py` — acknowledgement identity
  verification (`httpx.MockTransport`, no network).
- `tests/unit/test_spider_service_logic.py` — per-event immediate ack
  (proven by observing `pending_count()` decrease one at a time across
  calls), dead-letter-and-continue on permanent rejection, no-ack on
  acknowledgement mismatch.
- `tests/integration/test_agent_ingestion_api.py::test_telemetry_endpoint_idempotently_replays_the_exact_same_event`
  — the real end-to-end proof, against real Postgres and real NATS
  JetStream: submit an event, "crash" (never touch the local queue), resend
  the byte-identical event three times, confirm every resend returns the
  same successful acknowledgement and exactly one copy was ever published.

Run with `make test-agent-delivery`.

## What this does not (yet) change

The transport remains one event per HTTP request, not a literal multi-event
batch payload. The correctness properties Priority 2 asks for — durable
server-side acceptance before deletion, verified acknowledgement identity,
idempotent replay, dead-letter for permanent failures, ordered retry for
transient ones — all hold under this "batch of one" model. Introducing a
true multi-event batch endpoint (with `accepted_event_ids`/
`rejected_event_ids`/`retryable_event_ids` per request) would change the
wire contract and is a larger, separate change; nothing about today's
per-event idempotent-replay mechanism needs to be redesigned to add it
later.
