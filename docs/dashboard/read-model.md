# Dashboard read model

Migration `0009_dashboard_read_model` adds the materialized analyst model.
`dashboard_case_summary` is the list/detail header. Timeline rows and graph
rows retain source event IDs, source references, evidence references,
classification, confidence, output tag, permissions, and record version.
`dashboard_projection_offsets` holds per-case sequence position and explicit
gap bounds. `dashboard_realtime_updates` is the resumable SSE ledger.

`DashboardProjector.project_event` is idempotent by event ID. An out-of-order
sequence marks the projection `INCOMPLETE`; it is never silently reordered.
`rebuild_case` deletes only the selected case projection, replays canonical
events deterministically, increments the projection version, and clears a gap
only when the rebuilt source is complete.

Read endpoints:

- `GET /api/v1/dashboard/operations`
- `GET /api/v1/dashboard/cases`
- `GET /api/v1/dashboard/cases/{case_id}`
- evidence, AI, and sandbox submodels under the same case
- `POST /api/v1/dashboard/cases/{case_id}/rebuild`
- `GET /api/v1/dashboard/stream`

Cross-case reads return 404/denial unless the principal has an explicit grant
or a global auditor/administrator role. Validate migrations and behavior with:

```sh
make test-integration
.venv/bin/pytest tests/integration/test_dashboard_read_model.py -v
```
