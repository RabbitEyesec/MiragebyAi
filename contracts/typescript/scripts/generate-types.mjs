#!/usr/bin/env node
// Generates contracts/typescript/src/generated/*.ts from
// contracts/typescript/src/schemas/**/*.schema.json via json-schema-to-typescript.
// DO NOT HAND-EDIT the output — regenerate with `npm run generate` (or
// `make generate-contracts` from the repo root).
import { compile } from "json-schema-to-typescript";
import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, "..");
const SCHEMAS_DIR = path.join(PKG_ROOT, "src", "schemas");
const OUT_DIR = path.join(PKG_ROOT, "src", "generated");

function moduleName(kind, filename) {
  const stem = filename.replace(/\.schema\.json$/, "");
  return `${kind}_${stem}`.replace(/\./g, "_").replace(/-/g, "_");
}

function pascal(snake) {
  return snake.split("_").filter(Boolean).map((s) => s[0].toUpperCase() + s.slice(1)).join("");
}

async function main() {
  if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });

  const exports = [];
  for (const kind of readdirSync(SCHEMAS_DIR)) {
    const kindDir = path.join(SCHEMAS_DIR, kind);
    for (const filename of readdirSync(kindDir).sort()) {
      if (!filename.endsWith(".schema.json")) continue;
      const schemaPath = path.join(kindDir, filename);
      const schema = JSON.parse(readFileSync(schemaPath, "utf-8"));
      const name = moduleName(kind, filename);
      const typeName = pascal(name);
      const ts = await compile(schema, typeName, {
        bannerComment: "/* eslint-disable */\n/** Generated from " + path.relative(PKG_ROOT, schemaPath) + " — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */",
        additionalProperties: false,
        style: { semi: true, singleQuote: false },
      });
      writeFileSync(path.join(OUT_DIR, `${name}.ts`), ts);
      exports.push(name);
    }
  }

  const indexLines = [
    "/** Barrel for all generated types. DO NOT HAND-EDIT. */",
    ...exports.map((n) => `export * from "./${n}.js";`),
    "",
  ];
  writeFileSync(path.join(OUT_DIR, "index.ts"), indexLines.join("\n"));
  console.log(`Generated ${exports.length} TypeScript modules into ${path.relative(PKG_ROOT, OUT_DIR)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
