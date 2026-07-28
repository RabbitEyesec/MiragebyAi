# AI secret rotation

The worker reads the provider secret through the configured secret resolver and
retains a last-known-good value only in process memory.

## Rotation

1. Create a new provider credential with the same least-privilege limits.
2. Write a new version to the secret referenced by `AI_PROVIDER_SECRET_ARN`.
3. Restart one worker and verify a bounded health request, telemetry, and budget
   accounting without logging the credential.
4. Roll workers gradually, then revoke the old provider credential.
5. Record secret-version metadata and rotation time; never record the value.

If retrieval fails, stop the rollout. Existing processes may temporarily use
their last-known-good secret; fresh processes fail closed or use the
deterministic fallback. For suspected exposure, set
`AI_ALLOW_EXTERNAL_PROVIDER=false`, revoke first, and investigate usage before
creating a replacement.
