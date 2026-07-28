/* eslint-disable */
/** Generated from src/schemas/events/evidence.verification_failed.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface EvidenceVerificationFailedV1 {
  evidence_id: string;
  case_id: string;
  verification_id: string;
  status: "FAILED" | "MISSING" | "HASH_MISMATCH";
  expected_sha256: string;
  calculated_sha256?: string | null;
  reason: string;
  error?: string | null;
}
