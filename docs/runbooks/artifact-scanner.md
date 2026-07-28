# Artifact scanner

Uploads are streamed to quarantine, hashed, and scanned by file identification,
ClamAV, YARA, archive controls, and OLE tooling. A missing or timed-out required
adapter produces `FAILED`, never `CLEAN`.

## Operations

Set the upload, expanded-size, member-count, nesting, compression-ratio, and
per-adapter timeout limits from `.env.example`. Keep YARA rules versioned and
refresh the production ClamAV database through the approved update process.
Run `make test-artifacts`; the Prompt 2 E2E image also executes the real scanner
tools against a controlled signature fixture.

Only explicitly approved `INERT` or `CONTROLLED` artifacts may be deployed.
Deployment uses a single-use five-minute download token, rechecks SHA-256 in the
sandbox, and restricts the destination root. Revocation of a deployed artifact
queues `ROLLBACK_ACTION`; investigate `ROLLBACK_FAILED` rather than marking it
revoked manually.

For suspected scanner compromise, disable artifact approval/deployment, retain
quarantine bytes and adapter outputs, rotate rules/databases, and rescan.
Windows execution and observation surfaces are `LAB_VERIFICATION_REQUIRED`.
