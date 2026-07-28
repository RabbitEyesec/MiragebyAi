/**
 * Typed contract-validation errors. Mirrors
 * contracts/python/mirage_contracts/errors.py — same error_code strings so a
 * dashboard (Stage 9, not built in Prompt 1) and backend agree on the wire.
 */
export class ContractError extends Error {
  errorCode = "CONTRACT_ERROR";
  context: Record<string, unknown>;

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message);
    this.name = new.target.name;
    this.context = context;
  }
}

export class UnsupportedSchemaVersionError extends ContractError {
  override errorCode = "UNSUPPORTED_SCHEMA_VERSION";
  constructor(typeName: string, schemaVersion: string, supportedMajors: number[]) {
    super(
      `${typeName} schema_version ${schemaVersion} has unsupported major version (supported: ${supportedMajors.sort()})`,
      { typeName, schemaVersion, supportedMajors },
    );
  }
}

export class MalformedSchemaVersionError extends ContractError {
  override errorCode = "MALFORMED_SCHEMA_VERSION";
  constructor(schemaVersion: unknown) {
    super(`schema_version is not '<major>.<minor>': ${JSON.stringify(schemaVersion)}`, { schemaVersion });
  }
}

export class UnknownEventTypeError extends ContractError {
  override errorCode = "UNKNOWN_EVENT_TYPE";
  constructor(eventType: string) {
    super(`no schema registered for event_type=${eventType}`, { eventType });
  }
}

export class UnknownCommandTypeError extends ContractError {
  override errorCode = "UNKNOWN_COMMAND_TYPE";
  constructor(commandType: string) {
    super(`no schema registered for command_type=${commandType}`, { commandType });
  }
}

export class EnvelopeValidationError extends ContractError {
  override errorCode = "ENVELOPE_VALIDATION_ERROR";
  errors: string[];
  constructor(errors: string[]) {
    super(`envelope failed validation: ${JSON.stringify(errors)}`, { errors });
    this.errors = errors;
  }
}

export class PayloadValidationError extends ContractError {
  override errorCode = "PAYLOAD_VALIDATION_ERROR";
  errors: string[];
  constructor(typeName: string, errors: string[]) {
    super(`payload for ${typeName} failed validation: ${JSON.stringify(errors)}`, { typeName, errors });
    this.errors = errors;
  }
}

export class IntegrityMismatchError extends ContractError {
  override errorCode = "INTEGRITY_MISMATCH";
  constructor(expected: string, actual: string) {
    super(`integrity.sha256 ${expected} does not match computed payload hash ${actual}`, { expected, actual });
  }
}

export class PayloadTooLargeError extends ContractError {
  override errorCode = "PAYLOAD_TOO_LARGE";
  static readonly MAX_BYTES = 256 * 1024;
  constructor(actualBytes: number) {
    super(`payload is ${actualBytes} bytes, exceeds the ${PayloadTooLargeError.MAX_BYTES}-byte cap`, {
      actualBytes,
      maxBytes: PayloadTooLargeError.MAX_BYTES,
    });
  }
}
