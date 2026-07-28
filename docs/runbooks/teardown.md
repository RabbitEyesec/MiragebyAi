# Teardown runbook

Teardown is an exact 25-step, case-scoped, journaled workflow. It blocks new
directives/messages/AI/artifact mutations, concludes collection, verifies
evidence and export, revokes identities, removes only temporary resources
tagged `Project=mirage`, the exact environment, and the exact case, preserves
protected evidence, inventories, then marks the case destroyed.

Plan first:

```sh
./scripts/teardown-dry-run --environment acceptance --case-id CASE_ID \
  --state state.json --journal teardown.json
```

Execute only with the exact confirmation printed by the plan. Any evidence,
export, queue drain, final snapshot, certificate revocation, or inventory
failure blocks destruction. A gap override requires a reason, missing items,
actor, and an ALLOW policy decision.

```sh
make test-teardown
./scripts/verify-teardown --environment acceptance --region us-east-1 \
  --allow-evidence-bucket
```

The local adapter proves order, resume, idempotence, identity rejection, and
zero temporary resources. Real AWS inventory and Windows certificate
reconnection are Profile B.
