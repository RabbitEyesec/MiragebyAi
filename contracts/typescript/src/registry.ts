/**
 * Schema registry: mirrors contracts/python/mirage_contracts/registry.py.
 * Reads JSON Schemas bundled under src/schemas/{events,commands,api}/ at
 * runtime (populated by `make generate-contracts` / scripts/generate-contracts,
 * copied verbatim from the repository-root /schemas/ source of truth).
 */
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import path from "node:path";
import type { ValidateFunction } from "ajv";

// Minimal shape of what this module actually calls on an Ajv instance — kept
// narrow deliberately (see below for why these are loaded via createRequire
// rather than a static default import).
interface AjvLike {
  compile(schema: object): ValidateFunction;
}
interface Ajv2020Constructor {
  new (opts?: { allErrors?: boolean; strict?: boolean }): AjvLike;
}

// ajv/ajv-formats ship CJS builds whose default-export interop under
// moduleResolution=NodeNext is ambiguous across TS/Node versions (ajv's
// package.json declares no "exports" map and no "type", so TS's NodeNext
// implied-format detection for its .d.ts disagrees with the ESM `export
// default` syntax that .d.ts actually uses, and types the default binding as
// the whole module namespace instead of the constructable class). Loading
// via createRequire sidesteps that resolution entirely — a plain runtime CJS
// require, typed narrowly against only the surface this file uses.
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as unknown as Ajv2020Constructor;
const addFormats = require("ajv-formats") as unknown as (ajv: AjvLike) => void;
import { MalformedSchemaVersionError } from "./errors.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BUNDLED_SCHEMAS_DIR = path.join(__dirname, "schemas");

const VERSIONED_FILENAME_RE = /^(?<typeName>[a-z][a-z0-9_.]*)\.v(?<major>[0-9]+)\.schema\.json$/;
export const SCHEMA_VERSION_RE = /^(?<major>[0-9]+)\.(?<minor>[0-9]+)$/;

export function parseSchemaVersion(schemaVersion: string): [number, number] {
  const m = SCHEMA_VERSION_RE.exec(schemaVersion);
  if (!m || !m.groups) {
    throw new MalformedSchemaVersionError(schemaVersion);
  }
  return [Number(m.groups.major), Number(m.groups.minor)];
}

function makeAjv() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv;
}

export class SchemaRegistry {
  readonly kind: "events" | "commands" | "api";
  private validators = new Map<string, ValidateFunction>(); // key: `${typeName}@${major}`
  private raw = new Map<string, object>();
  private envelopeValidator: ValidateFunction | null = null;
  private ajv = makeAjv();

  constructor(kind: "events" | "commands" | "api", schemasDir: string = BUNDLED_SCHEMAS_DIR) {
    this.kind = kind;
    const dir = path.join(schemasDir, kind);
    if (!existsSync(dir)) return;
    for (const filename of readdirSync(dir).sort()) {
      if (!filename.endsWith(".schema.json")) continue;
      const schema = JSON.parse(readFileSync(path.join(dir, filename), "utf-8"));
      if (filename === "envelope.schema.json") {
        this.envelopeValidator = this.ajv.compile(schema);
        continue;
      }
      const m = VERSIONED_FILENAME_RE.exec(filename);
      if (!m || !m.groups) continue;
      const key = `${m.groups.typeName}@${m.groups.major}`;
      this.validators.set(key, this.ajv.compile(schema));
      this.raw.set(key, schema);
    }
  }

  getEnvelopeValidator(): ValidateFunction {
    if (!this.envelopeValidator) {
      throw new Error(`no envelope.schema.json bundled for kind=${this.kind}`);
    }
    return this.envelopeValidator;
  }

  supportedMajors(typeName: string): Set<number> {
    const out = new Set<number>();
    for (const key of this.validators.keys()) {
      const [name, major] = key.split("@");
      if (name === typeName) out.add(Number(major));
    }
    return out;
  }

  getValidator(typeName: string, major: number): ValidateFunction | undefined {
    return this.validators.get(`${typeName}@${major}`);
  }
}

export const eventsRegistry = new SchemaRegistry("events");
export const commandsRegistry = new SchemaRegistry("commands");
