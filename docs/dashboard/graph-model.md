# Canonical graph model

Node IDs and edge IDs are durable read-model identifiers. Supported node
classes include case, session, endpoint, sandbox, source, observation,
process, network, evidence, artifact, canary, AI proposal, policy decision,
analyst directive, and analyst message. An edge always names its source and
target IDs and carries the same provenance envelope as a node.

Both renderers apply the same `filterGraph` function. Parity requires equal
node count, edge count, node IDs, edge IDs, evidence references, timeline
pivots, output tags, classifications, and AI/analyst overlays. Any mismatch is
a test failure.

Every rendered item links back to its source timeline event and available
evidence. `OBSERVED_FACT`, `DETERMINISTIC_CORRELATION`, `AI_INFERENCE`, and
`ANALYST_NOTE` remain visually distinct. Hostile output is escaped and labelled
`UNTRUSTED_INTRUDER_OUTPUT`.

Steering describes only new supported connections as brokered to the sandbox.
Existing sessions are never displayed as migrated.

```sh
make test-graph-2d
make test-graph-3d
make test-graph-parity
```
