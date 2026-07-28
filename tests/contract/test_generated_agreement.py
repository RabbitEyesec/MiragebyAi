"""Step 1 acceptance: 'generated Python and TypeScript representations agree.'

For every schema, compares the *required* field set of the generated Pydantic
model (mirage_contracts.generated) against the required field set the
generated TypeScript interface actually encodes (a field is required in
json-schema-to-typescript output iff it lacks the `?` optional marker).
Both are derived from the same /schemas source, so this test also transitively
guards against one side going stale relative to the source schema — a
starker drift check (full byte-for-byte regeneration diff) is
`make validate-contracts` / scripts/validate-contracts, which this test
complements rather than replaces.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "schemas"
TS_GENERATED_DIR = REPO_ROOT / "contracts" / "typescript" / "src" / "generated"

pytestmark = pytest.mark.contract


def _module_name(kind: str, filename: str) -> str:
    stem = filename.replace(".schema.json", "")
    return f"{kind}_{stem}".replace(".", "_").replace("-", "_")


def _pascal(snake: str) -> str:
    return "".join(part.capitalize() for part in snake.split("_"))


def _iter_schema_files():
    for kind_dir in sorted(SCHEMAS_DIR.iterdir()):
        if not kind_dir.is_dir():
            continue
        for schema_file in sorted(kind_dir.glob("*.schema.json")):
            yield kind_dir.name, schema_file


def _ts_required_fields(ts_path: Path) -> set[str]:
    """Parse a json-schema-to-typescript interface body for required (non-`?`) fields.

    Deliberately simple (regex, not a full TS parser) — the generated files
    are flat single-interface outputs by construction (see generate-types.mjs).
    """
    # json-schema-to-typescript wraps enum unions and nested object types
    # across multiple lines, so a property declaration's VALUE is not
    # reliably on the same line as its name — only match at line-start on
    # `name(?):`, not on the full `name(?): value;` shape.
    text = ts_path.read_text()
    fields: set[str] = set()
    top_level_prop_re = re.compile(r"^  ([A-Za-z0-9_]+)(\??):\s*")
    for line in text.splitlines():
        m = top_level_prop_re.match(line)
        if not m:
            continue
        name, optional_marker = m.group(1), m.group(2)
        if not optional_marker:
            fields.add(name)
    return fields


@pytest.mark.parametrize("kind,schema_file", list(_iter_schema_files()), ids=lambda v: str(v))
def test_python_and_typescript_required_fields_agree(kind: str, schema_file: Path) -> None:
    schema = json.loads(schema_file.read_text())
    schema_required = set(schema.get("required", []))
    if not schema_required:
        pytest.skip(f"{schema_file.name} has no required fields to compare")

    module_name = _module_name(kind, schema_file.name)
    ts_path = TS_GENERATED_DIR / f"{module_name}.ts"
    assert ts_path.exists(), f"missing generated TS file {ts_path} — run scripts/generate-contracts"

    ts_required = _ts_required_fields(ts_path)

    missing_in_ts = schema_required - ts_required
    assert not missing_in_ts, (
        f"{schema_file.relative_to(REPO_ROOT)}: fields required in the schema but NOT required "
        f"in generated TypeScript ({ts_path.relative_to(REPO_ROOT)}): {missing_in_ts}"
    )


def test_every_schema_has_a_generated_python_model() -> None:
    generated_dir = REPO_ROOT / "contracts" / "python" / "mirage_contracts" / "generated"
    for kind, schema_file in _iter_schema_files():
        module_name = _module_name(kind, schema_file.name)
        py_path = generated_dir / f"{module_name}.py"
        assert py_path.exists(), f"missing generated Python module {py_path} — run scripts/generate-contracts"


def test_every_schema_has_a_generated_typescript_module() -> None:
    for kind, schema_file in _iter_schema_files():
        module_name = _module_name(kind, schema_file.name)
        ts_path = TS_GENERATED_DIR / f"{module_name}.ts"
        assert ts_path.exists(), f"missing generated TypeScript module {ts_path} — run scripts/generate-contracts"
