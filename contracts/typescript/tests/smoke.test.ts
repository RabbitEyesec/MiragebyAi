import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildEvent,
  validateEvent,
  validateCommand,
  generateUlid,
  isValidUlid,
  UnsupportedSchemaVersionError,
  EnvelopeValidationError,
  PayloadValidationError,
  PayloadTooLargeError,
} from "../dist/index.js";

test("buildEvent + validateEvent round-trip (current version)", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "1.1",
    payload: {
      agent_id: "agent-1",
      role: "ENDPOINT",
      build_hash: "a".repeat(64),
      version: "1.0.0",
      certificate_serial: "1",
      uptime_seconds: 10,
      health_state: "HEALTHY",
      queue_depth: 3,
    },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  });
  const result = validateEvent(evt);
  assert.equal(result.eventType, "agent.heartbeat");
  assert.equal(result.majorVersion, 1);
});

test("validateEvent accepts previous-version instance (1.0, no queue_depth)", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "1.0",
    payload: {
      agent_id: "agent-1",
      role: "ENDPOINT",
      build_hash: "a".repeat(64),
      version: "1.0.0",
      certificate_serial: "1",
      uptime_seconds: 10,
      health_state: "HEALTHY",
    },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  });
  const result = validateEvent(evt);
  assert.equal(result.majorVersion, 1);
});

test("validateEvent rejects unsupported major schema_version", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "2.0",
    payload: { agent_id: "a", role: "ENDPOINT", build_hash: "a".repeat(64), version: "1.0.0", certificate_serial: "1", uptime_seconds: 1, health_state: "HEALTHY" },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  });
  assert.throws(() => validateEvent(evt), UnsupportedSchemaVersionError);
});

test("validateEvent rejects unknown envelope field", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "1.1",
    payload: { agent_id: "a", role: "ENDPOINT", build_hash: "a".repeat(64), version: "1.0.0", certificate_serial: "1", uptime_seconds: 1, health_state: "HEALTHY" },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  }) as Record<string, unknown>;
  evt.unexpected_field = "nope";
  assert.throws(() => validateEvent(evt), EnvelopeValidationError);
});

test("validateEvent rejects invalid event_id (not canonical ULID)", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "1.1",
    payload: { agent_id: "a", role: "ENDPOINT", build_hash: "a".repeat(64), version: "1.0.0", certificate_serial: "1", uptime_seconds: 1, health_state: "HEALTHY" },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  }) as Record<string, unknown>;
  evt.event_id = "not-a-ulid";
  assert.throws(() => validateEvent(evt), EnvelopeValidationError);
});

test("validateEvent rejects oversized payload", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "1.1",
    payload: {
      agent_id: "a".repeat(300000), // pushes payload over 256KB; agent_id maxLength constraint is bypassed by direct payload validation order? size check runs first
      role: "ENDPOINT",
      build_hash: "a".repeat(64),
      version: "1.0.0",
      certificate_serial: "1",
      uptime_seconds: 1,
      health_state: "HEALTHY",
    },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  });
  assert.throws(() => validateEvent(evt), PayloadTooLargeError);
});

test("validateEvent rejects payload missing required field", () => {
  const evt = buildEvent({
    eventType: "agent.heartbeat",
    schemaVersion: "1.1",
    payload: { agent_id: "a", role: "ENDPOINT", build_hash: "a".repeat(64), version: "1.0.0", certificate_serial: "1", uptime_seconds: 1 },
    sourceId: "agent-1",
    sequence: 1,
    actorType: "ENDPOINT_AGENT",
    classification: "INTERNAL",
  });
  assert.throws(() => validateEvent(evt), PayloadValidationError);
});

test("generateUlid produces canonical uppercase ULIDs", () => {
  const id = generateUlid();
  assert.ok(isValidUlid(id));
  assert.equal(id, id.toUpperCase());
  assert.equal(id.length, 26);
});

test("validateCommand accepts a well-formed sandbox command", () => {
  const cmd = {
    command_id: generateUlid(),
    command_type: "sandbox.command",
    schema_version: "1.0",
    case_id: generateUlid(),
    sandbox_id: "sandbox-1",
    expected_state_version: 1,
    issued_by: "ANALYST",
    policy_decision_id: generateUlid(),
    params: { action_type: "TEST_FILE_PLACEMENT" },
    expires_at: "2026-07-25T00:00:00.000Z",
  };
  const result = validateCommand(cmd);
  assert.equal(result.commandType, "sandbox.command");
});
