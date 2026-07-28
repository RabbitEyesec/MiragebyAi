"""Schema registry: maps (kind, type_name) -> {major_version: compiled schema}.

Reads from the schemas/ directory BUNDLED inside this package
(mirage_contracts/schemas/), not from the repository-root /schemas directly —
that bundled copy is produced by `scripts/generate-contracts` (`make
generate-contracts`), so a built/installed mirage_contracts wheel is
self-contained (works inside a Docker image with no repo checkout present).
The repository-root /schemas/ tree remains the single hand-edited source of
truth; `make validate-contracts` fails CI if the bundled copy has drifted
from it (see scripts/generate-contracts and scripts/validate-contracts).

File naming convention read here: `<type_name>.v<major>.schema.json`
(e.g. `agent.heartbeat.v1.schema.json`). The envelope schemas
(`envelope.schema.json`, unversioned filename) are handled separately.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from mirage_contracts.errors import MalformedSchemaVersionError

_BUNDLED_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"

_VERSIONED_FILENAME_RE = re.compile(r"^(?P<type_name>[a-z][a-z0-9_.]*)\.v(?P<major>[0-9]+)\.schema\.json$")

SCHEMA_VERSION_RE = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)$")


def parse_schema_version(schema_version: str) -> tuple[int, int]:
    m = SCHEMA_VERSION_RE.match(schema_version)
    if not m:
        raise MalformedSchemaVersionError(schema_version)
    return int(m.group("major")), int(m.group("minor"))


class SchemaRegistry:
    """Loads and caches JSON Schemas + jsonschema validators for a given kind
    ('events' or 'commands'), keyed by (type_name, major_version).
    """

    def __init__(self, kind: str, schemas_dir: Path | None = None) -> None:
        if kind not in ("events", "commands", "api"):
            raise ValueError(f"unknown kind: {kind!r}")
        self.kind = kind
        self._dir = (schemas_dir or _BUNDLED_SCHEMAS_DIR) / kind
        self._validators: dict[tuple[str, int], Draft202012Validator] = {}
        self._raw: dict[tuple[str, int], dict] = {}
        self._envelope_validator: Draft202012Validator | None = None
        self._load()

    def _load(self) -> None:
        if not self._dir.is_dir():
            return
        for path in sorted(self._dir.glob("*.schema.json")):
            schema = json.loads(path.read_text())
            if path.name == "envelope.schema.json":
                self._envelope_validator = Draft202012Validator(schema)
                continue
            m = _VERSIONED_FILENAME_RE.match(path.name)
            if not m:
                continue  # e.g. unversioned api/error.schema.json — loaded on demand by name
            key = (m.group("type_name"), int(m.group("major")))
            self._validators[key] = Draft202012Validator(schema)
            self._raw[key] = schema

    @property
    def envelope_validator(self) -> Draft202012Validator:
        assert self._envelope_validator is not None, f"no envelope.schema.json bundled for kind={self.kind!r}"
        return self._envelope_validator

    def supported_majors(self, type_name: str) -> set[int]:
        return {major for (name, major) in self._validators if name == type_name}

    def get_validator(self, type_name: str, major: int) -> Draft202012Validator | None:
        return self._validators.get((type_name, major))

    def get_raw_schema(self, type_name: str, major: int) -> dict | None:
        return self._raw.get((type_name, major))

    def known_type_names(self) -> set[str]:
        return {name for (name, _major) in self._validators}


def load_unversioned_schema(kind: str, filename: str, schemas_dir: Path | None = None) -> dict:
    """Load a standalone (non-versioned) schema, e.g. schemas/api/error.schema.json."""
    d = (schemas_dir or _BUNDLED_SCHEMAS_DIR) / kind / filename
    return json.loads(d.read_text())


events_registry = SchemaRegistry("events")
commands_registry = SchemaRegistry("commands")
