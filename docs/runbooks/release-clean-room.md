# Release clean-room verification

## The bug this closes

Every release script (`scripts/install-server`, `upgrade-server`,
`rollback-server`, `uninstall-server`, `verify-install-report`) does
`from mirage_common... import ...` / `from mirage_contracts... import ...`.
Before this fix, neither package existed anywhere in the release ZIP as
installable code — only as things the ORIGINAL source repository's editable
install (`pip install -e .`) happened to already provide on the machine
that built the release. Reproduced directly: a fresh virtualenv, with no
knowledge of this repository, cannot `import mirage_common` at all. Every
release script would fail with `ModuleNotFoundError` on any real target
server, which had never run `pip install -e .` against this source tree —
exactly the standalone-release requirement this was violating.

## The fix

`build_release()` (`libs/mirage_common/release.py`) now builds a real wheel
of the whole `mirage` distribution (`pip wheel . --no-deps`) and includes it
in the release ZIP at `packages/mirage-<version>-py3-none-any.whl`. A new
script, `scripts/install-mirage-package`, creates (or reuses) a dedicated
virtualenv and installs that wheel into it — this is now the server
installer's first `install`-operation step (`python-package`, before
`deploy`), because every later step's `.venv/bin/python scripts/...` command
depends on it.

## Verifying a release is genuinely standalone

```sh
make test-release-clean-room
```

This builds a real release ZIP from the current source tree, then —
working from an **isolated copy of only the extracted ZIP contents**, using
a **brand-new virtualenv** that has never had this repository's editable
install run against it — proves:

1. `mirage_common` is NOT importable before the wheel is installed (confirms
   the test setup is genuinely clean, not accidentally reusing this repo's
   own `.venv`).
2. `scripts/install-mirage-package` (run with only the clean-room's files
   and the fresh venv, no reference to this repository's path) succeeds.
3. `mirage_common` becomes importable afterward, resolving from the fresh
   venv — never from this repository's path.
4. `scripts/install-server --help` actually runs.

## Manual clean-room check

To reproduce by hand (e.g. on a real disposable VM):

```sh
make build-release RELEASE_SIGNING_KEY=/path/to/key.pem
mkdir /tmp/clean-room && cd /tmp/clean-room
unzip /path/to/dist/mirage-*.zip -d extracted
cd extracted
python3 -m venv .venv
.venv/bin/python scripts/install-mirage-package --venv .venv
.venv/bin/python scripts/install-server --help
```

If any step above fails with `ModuleNotFoundError`, the release is not
standalone — do not ship it.

## What's still lab work

Container image digests, WiX-compiled endpoint/sandbox MSIs, and a real
clean-host Ubuntu install/upgrade/rollback/repair/uninstall lifecycle remain
`WINDOWS_VERIFICATION_REQUIRED`/`AWS_VERIFICATION_REQUIRED` — this runbook
covers the Python-package standalone-ness gap specifically, not full
production acceptance.
