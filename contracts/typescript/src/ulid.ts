/**
 * Canonical uppercase ULID generation and validation.
 * Mirrors contracts/python/mirage_contracts/ulid.py byte-for-byte
 * (same pattern; see ARCHITECTURE_DECISIONS.md ADR-0010).
 */
import { ulid as generateRawUlid } from "ulid";

export const ULID_PATTERN = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

export function generateUlid(): string {
  return generateRawUlid().toUpperCase();
}

export function isValidUlid(value: unknown): value is string {
  return typeof value === "string" && ULID_PATTERN.test(value);
}

export function requireValidUlid(value: unknown, field = "id"): string {
  if (!isValidUlid(value)) {
    throw new Error(`${field} is not a canonical uppercase ULID: ${JSON.stringify(value)}`);
  }
  return value;
}
