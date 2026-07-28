/* eslint-disable */
/** Generated from src/schemas/api/error.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Standard error response body for every Mirage HTTP API (Appendix F). Never includes secret values or raw untrusted intruder content.
 */
export interface ApiErrorEnvelope {
  /**
   * Stable machine-readable code, e.g. VALIDATION_ERROR, UNSUPPORTED_SCHEMA_VERSION, UNAUTHORIZED, ROUTE_UNAVAILABLE.
   */
  error_code: string;
  message: string;
  correlation_id: string;
  http_status: number;
  /**
   * Optional structured detail (e.g. field-level validation errors). Never a secret or raw intruder payload.
   */
  details?: {} | null;
}
