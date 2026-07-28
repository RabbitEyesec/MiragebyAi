# Release verification

Obtain the release ZIP and the release signer's public key **over an
independent channel from the ZIP itself** — never extract the trusted key
from inside the package you are about to verify. See
`docs/architecture/signature-trust.md` for why this matters and the full
trust model.

```bash
scripts/verify-release mirage-release.zip --public-key release-signing.pem
```

Or, if you maintain a standing trust store (recommended for repeated
verification — supports key rotation and revocation without re-distributing
a key file every time):

```bash
mkdir -p /etc/mirage/trust/release-keys
cp release-signing.pem /etc/mirage/trust/release-keys/
scripts/verify-release mirage-release.zip
# or: scripts/verify-release mirage-release.zip --trust-store /path/to/trust-dir
```

`scripts/verify-release` **fails closed** if neither `--public-key` nor a
populated trust store (`$MIRAGE_TRUST_STORE_DIR` or
`/etc/mirage/trust/release-keys` by default) is available — it will not
silently fall back to trusting whatever public key happens to be embedded
inside the ZIP. The same applies to `scripts/verify-install-report`,
`scripts/verify-evidence-export`, `scripts/verify-report-package`, and
`acceptance-verify`.

The verifier rejects duplicate, missing, unexpected, modified, or
signature-mismatched members. Confirm the package SHA-256, manifest SHA-256,
SBOM, container digest list, contract/migration manifests, known limitations,
upgrade instructions, and rollback instructions before installation.

Windows MSI compilation and Authenticode verification are only PASS when the
Windows result JSON records them as such. A source-only bundle does not imply
that images were pushed or installers were signed.
