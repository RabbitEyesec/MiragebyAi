/* eslint-disable */
/** Generated from src/schemas/events/evidence.verified.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface EvidenceVerifiedV1 {
  evidence_id: string;
  case_id: string;
  verification_id: string;
  status: "VERIFIED";
  sha256: string;
  reason: string;
}
