# Mirage server installer

Run on supported Ubuntu with the verified release unpacked:

```bash
source .venv/bin/activate
python scripts/verify-release release.zip --public-key release-signing.pem
python scripts/test-clean-install validate \
  --environment production --config config/production.yaml \
  --package release.zip --preflight-only
python scripts/install-server --environment production --config config/production.yaml \
  --package release.zip --dry-run
sudo --preserve-env=PATH,MIRAGE_TLS_BOOTSTRAP_RECIPE,MIRAGE_ADMIN_BOOTSTRAP_RECIPE,MIRAGE_ENROLMENT_RECIPE,MIRAGE_SYNTHETIC_RECIPE,MIRAGE_INSTALL_REPORT_SIGNING_KEY_FILE,MIRAGE_INSTALL_REPORT_OUTPUT \
  python scripts/install-server --environment production --config config/production.yaml \
  --package release.zip --journal /var/lib/mirage/install-journal.json \
  --execute-internal
```

Secrets are supplied through protected files, stdin, workload identity, or secret
references in configuration—never command arguments. Resume uses the mode-0600
journal. Upgrade, repair, status, rollback, and uninstall use the corresponding
operation; rollback/uninstall require `--confirm mirage:<environment>`. Evidence
resources are not removed by the server uninstaller.

The mutating steps for TLS bootstrap, initial administrator, one-time enrolment,
synthetic transaction, and rollback accept only protected mode-0600 JSON argv
recipes through `MIRAGE_*_RECIPE` file-path variables. The signed report uses
the external mode-0600 key named by
`MIRAGE_INSTALL_REPORT_SIGNING_KEY_FILE`; never put that key in the release.
Verify the resulting report independently:

```bash
python scripts/verify-install-report /var/lib/mirage/install-report.zip
```

The report covers the installer/package/configuration hashes, container digest
inventory, SBOM hashes, migration and contract manifests, service health,
synthetic result, installation time, host fingerprint, signer fingerprint, and
RSA-PSS signature.
