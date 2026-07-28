# step-ca Certificate Profiles (Step 3)

Five JWK provisioners, one per certificate profile, each with its own
keypair and its own certificate-duration policy. A one-time enrollment
token is always minted for exactly one provisioner/profile — an agent can
never present an `endpoint`-scoped token and receive a `spider`-profile
certificate, because the token itself is a JWT signed by that provisioner's
key and only that provisioner's key.

| Provisioner name | Profile | Used by | maxTLSCertDuration | minTLSCertDuration | Default |
|---|---|---|---|---|---|
| `mirage-endpoint` | MirageEndpoint | Employee endpoint Windows service (Step 4) | 24h | 1h | 24h |
| `mirage-spider` | MirageSpider | Sandbox observation service (Step 5) | 24h | 1h | 24h |
| `mirage-env-controller` | MirageEnvironmentController | Sandbox mutation service (Step 9b) | 24h | 1h | 24h |
| `mirage-broker-client` | BrokerClient | Nginx/SSH bastion/RD Gateway internal client identity (Stage 3) | 720h (30d) | 24h | 168h (7d) |
| `mirage-internal-control` | InternalControl | mirage-api/worker/outbox-relay/gateway service-to-service mTLS | 720h (30d) | 24h | 168h (7d) |

Short-lived agent certs (endpoint/spider/env-controller) auto-renew before
20% of their lifetime remains (Step 3 rule) — for a 24h cert, that's a
renewal trigger at ~4.8h remaining. Longer-lived broker/internal-control
certs follow the same 20%-remaining rule at their own scale.

`mirage-enrollment` (the provisioner smallstep's Docker image auto-creates
via `DOCKER_STEPCA_INIT_PROVISIONER_NAME`) is retired once
`scripts/bootstrap-step-ca-provisioners` runs — it exists only as the
zero-config bootstrap default before the five real profiles are added, and
is never used to enroll a real agent.

## How a token is minted (Step 3, 10-step sequence)

1. An operator or the control plane calls
   `mirage_agent_ingestion.enrollment.create_enrollment_token(role, sans, expires_in)`.
2. That function signs a JWT with the **role's own provisioner private key**
   (loaded from `mirage/<environment>/step-ca`'s per-profile encrypted JWK —
   see `docs/runbooks/secrets.md`), claims `sub`, `sans`, `iss`=provisioner
   name, `aud`=the CA's `/1.0/sign` URL, `exp`, `nbf`, `jti`.
3. The `jti` is recorded in Postgres `enrollment_tokens` (status=PENDING,
   expires_at) in the same transaction that returns the token — this is
   MIRAGE's own single-use enforcement layer, independent of whatever step-ca
   itself does internally with JWK provisioner tokens (defense in depth: we
   never rely solely on step-ca's own token-reuse semantics).
4. The agent generates its own keypair and CSR locally — the private key
   never leaves the agent.
5. The agent calls `POST /api/v1/enroll` with `{enrollment_token, csr_pem,
   host_fingerprint, build_hash, role}` (schemas/api/enroll_request.v1).
6. mirage-agent-ingestion validates: token exists + unused + unexpired
   (transactional `UPDATE ... WHERE used_at IS NULL AND expires_at > now()`,
   zero rows = reject), `build_hash` is on the allowlist, `host_fingerprint`
   is well-formed.
7. On success, it forwards the CSR + the same JWT to step-ca's `/1.0/sign`
   endpoint — step-ca independently verifies the JWT signature against the
   provisioner's public key and its own claims (expiry, audience), so a
   token that somehow bypassed our Postgres check would still be rejected by
   step-ca itself.
8. step-ca returns a signed short-lived certificate.
9. mirage-agent-ingestion records `(agent_id, role, certificate_serial,
   certificate_profile, build_hash, host_fingerprint, enrolled_at)` in
   Postgres `agents`, and publishes `agent.enrolled`.
10. Every subsequent event/ack from that agent is bound to its certificate
    identity (source_id = agent_id, sequence tracked per identity — Step 1's
    envelope contract).
