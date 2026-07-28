/**
 * RFC3339 UTC timestamps with millisecond precision, canonical 'Z' suffix.
 * Mirrors contracts/python/mirage_contracts/timestamps.py.
 */
export const RFC3339_MS_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

export function nowRfc3339Ms(): string {
  return toRfc3339Ms(new Date());
}

export function toRfc3339Ms(date: Date): string {
  return date.toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export function isValidRfc3339Ms(value: unknown): value is string {
  if (typeof value !== "string" || !RFC3339_MS_PATTERN.test(value)) {
    return false;
  }
  const parsed = Date.parse(value);
  return !Number.isNaN(parsed);
}
