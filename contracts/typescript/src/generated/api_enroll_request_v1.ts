/* eslint-disable */
/** Generated from src/schemas/api/enroll_request.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * POST /api/v1/enroll request body (Appendix F, Step 3). One-time token + CSR + host fingerprint + build hash.
 */
export interface EnrollRequest {
  enrollment_token: string;
  role: "ENDPOINT" | "SPIDER" | "ENV_CONTROLLER" | "BROKER_CLIENT" | "INTERNAL_CONTROL";
  csr_pem: string;
  host_fingerprint: string;
  build_hash: string;
}
