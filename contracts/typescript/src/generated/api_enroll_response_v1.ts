/* eslint-disable */
/** Generated from src/schemas/api/enroll_response.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * POST /api/v1/enroll response body (Appendix F, Step 3). Returns a short-lived certificate; never returns the CA private key.
 */
export interface EnrollResponse {
  agent_id: string;
  certificate_pem: string;
  certificate_chain_pem: string;
  certificate_serial: string;
  not_after: string;
}
