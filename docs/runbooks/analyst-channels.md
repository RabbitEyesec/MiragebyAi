# Analyst channels

Directives guide strategy; they do not bypass deterministic policy. Direct
messages require an active case/session, a policy decision, rate limits,
preview-hash integrity, and confirmation for sensitive content. Delivered
messages are tagged `ANALYST_MESSAGE` and acquired as evidence.

## Emergency controls

Platform administrators can disable all channels; investigators or platform
administrators can disable one case. Enablement is platform-admin only. State
changes are audited and delivery rechecks controls immediately before dispatch.

Use the case directive and message endpoints to submit, cancel, preview, create,
confirm, and inspect records. If content or attribution is disputed, disable the
case channel, preserve message evidence and policy/audit rows, and compare the
stored preview hash. Idempotency keys prevent duplicate creation; they do not
authorize a changed payload.

If a delivery fails, retain `FAILED` status and error detail. Never mark a
message delivered without a successful sandbox result and evidence acquisition.
