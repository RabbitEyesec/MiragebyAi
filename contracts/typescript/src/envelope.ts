/**
 * High-level validate/construct API for event and command envelopes.
 * Mirrors contracts/python/mirage_contracts/envelope.py.
 */
import { createHash } from "node:crypto";
import type { ValidateFunction, ErrorObject } from "ajv";
import {
  EnvelopeValidationError,
  IntegrityMismatchError,
  PayloadTooLargeError,
  PayloadValidationError,
  UnknownCommandTypeError,
  UnknownEventTypeError,
  UnsupportedSchemaVersionError,
} from "./errors.js";
import { commandsRegistry, eventsRegistry, parseSchemaVersion } from "./registry.js";
import { generateUlid } from "./ulid.js";
import { nowRfc3339Ms } from "./timestamps.js";

export const MAX_PAYLOAD_BYTES = 256 * 1024;

export function canonicalJsonBytes(obj: unknown): Buffer {
  return Buffer.from(canonicalStringify(obj), "utf-8");
}

function canonicalStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalStringify).join(",")}]`;
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify((obj as Record<string, unknown>)[k])}`);
  return `{${parts.join(",")}}`;
}

export function sha256Hex(obj: unknown): string {
  return createHash("sha256").update(canonicalJsonBytes(obj)).digest("hex");
}

function formatErrors(errors: ErrorObject[] | null | undefined): string[] {
  return (errors ?? []).map((e) => `${e.instancePath || "<root>"}: ${e.message}`);
}

export interface ValidatedEvent {
  envelope: Record<string, unknown>;
  payload: Record<string, unknown>;
  eventType: string;
  majorVersion: number;
}

export interface ValidatedCommand {
  envelope: Record<string, unknown>;
  params: Record<string, unknown>;
  commandType: string;
  majorVersion: number;
}

export function validateEvent(instance: Record<string, unknown>, supportedMajors?: Set<number>): ValidatedEvent {
  const envelopeValidator: ValidateFunction = eventsRegistry.getEnvelopeValidator();
  if (!envelopeValidator(instance)) {
    throw new EnvelopeValidationError(formatErrors(envelopeValidator.errors));
  }

  const payload = instance.payload as Record<string, unknown>;
  const payloadBytes = canonicalJsonBytes(payload).length;
  if (payloadBytes > MAX_PAYLOAD_BYTES) {
    throw new PayloadTooLargeError(payloadBytes);
  }

  const expectedSha256 = sha256Hex(payload);
  const actualSha256 = (instance.integrity as Record<string, unknown>).sha256 as string;
  if (expectedSha256 !== actualSha256) {
    throw new IntegrityMismatchError(actualSha256, expectedSha256);
  }

  const eventType = instance.event_type as string;
  const [major] = parseSchemaVersion(instance.schema_version as string);

  const registeredMajors = eventsRegistry.supportedMajors(eventType);
  if (registeredMajors.size === 0) {
    throw new UnknownEventTypeError(eventType);
  }
  const allowed = supportedMajors ?? registeredMajors;
  if (!allowed.has(major)) {
    throw new UnsupportedSchemaVersionError(eventType, instance.schema_version as string, [...allowed]);
  }

  const payloadValidator = eventsRegistry.getValidator(eventType, major)!;
  if (!payloadValidator(payload)) {
    throw new PayloadValidationError(eventType, formatErrors(payloadValidator.errors));
  }

  return { envelope: instance, payload, eventType, majorVersion: major };
}

export function validateCommand(instance: Record<string, unknown>, supportedMajors?: Set<number>): ValidatedCommand {
  const envelopeValidator = commandsRegistry.getEnvelopeValidator();
  if (!envelopeValidator(instance)) {
    throw new EnvelopeValidationError(formatErrors(envelopeValidator.errors));
  }

  const commandType = instance.command_type as string;
  const [major] = parseSchemaVersion(instance.schema_version as string);

  const registeredMajors = commandsRegistry.supportedMajors(commandType);
  if (registeredMajors.size === 0) {
    throw new UnknownCommandTypeError(commandType);
  }
  const allowed = supportedMajors ?? registeredMajors;
  if (!allowed.has(major)) {
    throw new UnsupportedSchemaVersionError(commandType, instance.schema_version as string, [...allowed]);
  }

  const params = instance.params as Record<string, unknown>;
  const paramsValidator = commandsRegistry.getValidator(commandType, major)!;
  if (!paramsValidator(params)) {
    throw new PayloadValidationError(commandType, formatErrors(paramsValidator.errors));
  }

  return { envelope: instance, params, commandType, majorVersion: major };
}

export interface BuildEventArgs {
  eventType: string;
  schemaVersion: string;
  payload: Record<string, unknown>;
  sourceId: string;
  sequence: number;
  actorType: string;
  classification: string;
  caseId?: string | null;
  sessionId?: string | null;
  eventId?: string;
  eventTime?: string;
}

export function buildEvent(args: BuildEventArgs): Record<string, unknown> {
  const now = nowRfc3339Ms();
  return {
    event_id: args.eventId ?? generateUlid(),
    event_type: args.eventType,
    schema_version: args.schemaVersion,
    event_time: args.eventTime ?? now,
    ingest_time: now,
    case_id: args.caseId ?? null,
    session_id: args.sessionId ?? null,
    source_id: args.sourceId,
    sequence: args.sequence,
    actor_type: args.actorType,
    integrity: { sha256: sha256Hex(args.payload) },
    classification: args.classification,
    payload: args.payload,
  };
}
