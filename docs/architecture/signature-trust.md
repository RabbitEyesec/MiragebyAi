# Signature trust model

## The rule

A signed Mirage package — release ZIP, installation report, evidence
export, case report package, or acceptance package — must never establish
its own trust root. Verification must always compare a signature against a
public key sourced from **outside** the package under verification. A
package's own embedded key (`public-keys/release-signing.pem`,
`public-key.pem`, `acceptance-public-key.pem`) is informational signer
metadata only — useful for looking up a fingerprint, never usable as the
trust decision by itself.

## The attack this defends against

An attacker who can modify a signed package (compromised object store,
intercepted download, malicious mirror) can also generate a new RSA keypair,
re-sign the modified manifest with it, and embed their own public key at the
path the format expects. If the verifier's rule is "use the embedded key when
no other key is given," the forged package verifies as `valid: true` — the
signature check is real, but it is checking the file against a key the
attacker controls, which proves nothing.

## The fix: `libs/mirage_common/trust_anchor.py`

`resolve_trusted_key()` is the single shared resolution path used by every
verifier (`verify_release`, `verify_install_report`, `verify_export_package`,
`verify_report_package`, `verify_acceptance_package`):

1. **Explicit key wins.** If the caller passes an explicit trusted key
   (`--public-key` / `public_key_pem=`), that exact key is used — no lookup,
   no ambiguity.
2. **Otherwise, resolve from a trust store.** A directory of independently
   distributed `*.pem` public keys (default `$MIRAGE_TRUST_STORE_DIR`, or
   `/etc/mirage/trust/release-keys`). The package's embedded key is used
   *only* to compute a SHA-256 fingerprint, which must match a file already
   present in that directory. **The key bytes actually used for cryptographic
   verification come from the trust store, never from the package.**
3. **Revocation.** A `revoked.json` file in the trust store directory lists
   fingerprints that must be rejected even if otherwise present.
4. **Rotation.** The trust store may hold multiple valid keys (old + new)
   simultaneously — verification succeeds against whichever one matches.
5. **Fail closed.** If neither an explicit key nor a populated trust store is
   configured, verification fails with `"no external trust anchor
   configured"` rather than silently trusting the embedded key. This is the
   behavior change from the pre-remediation code, which defaulted to trusting
   the embedded key when no override was given.

## Internal self-checks are not exempt from the rule, they're just already compliant

Several build pipelines (`mirage-report-worker`'s exporter/reporter,
`libs/mirage_common/acceptance.py`'s `run_local_acceptance`) verify their own
output immediately after signing it, as a build-time sanity check ("did the
signing step work"). These pass the *actual key the process just used to
sign* explicitly (`signer.public_key_pem()`, or the public key
`_sign_package` returns) — this is legitimate because the caller already
possesses that key directly, not because it read it back out of the archive
afterward. It is not a substitute for an operator independently trusting that
key out of band, and none of these call sites are reachable from outside the
signing process itself.

## Where this changed real behavior

- `services/mirage-api/mirage_api/prompt3.py`'s report-verification endpoint
  (`POST /cases/{case_id}/reports/{report_id}/verify`) now requires a
  configured trust store in the environment `mirage-api` runs in — it no
  longer succeeds by trusting whatever key is embedded in the stored package.
  Operationally, deployments must populate `/etc/mirage/trust/release-keys/`
  (or `$MIRAGE_TRUST_STORE_DIR`) with the persistent report-signing key's
  public counterpart.
- `scripts/acceptance-repeat`'s independent re-verification of an externally
  orchestrated Profile B package (`verify_acceptance_package(package)`, no
  explicit key) has the same new requirement.
- `libs/mirage_common/acceptance.py`'s package builders now accept an
  optional `--signing-key` / `signing_key=` parameter. Without it, a
  throwaway RSA key is generated per build (as before) — fine for local
  synthetic acceptance runs, but such a package's signature is tamper
  evidence within that single build only, never a real signer identity an
  operator can trust later. Real Profile B acceptance runs should always
  pass a persistent `--signing-key`.

## Tests

`tests/unit/test_signature_trust.py` — unit coverage of
`resolve_trusted_key()` (fail-closed default, explicit-key precedence,
fingerprint matching, revocation, rotation) plus two full end-to-end
adversarial scenarios: an attacker forges a release package and an
acceptance package, each re-signed with the attacker's own key and carrying
the attacker's own embedded public key, and both are rejected by a verifier
configured with the real trust store. Run with `make test-signature-trust`.
