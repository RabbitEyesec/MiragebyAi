/* eslint-disable */
/** Generated from src/schemas/events/evidence.created.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface EvidenceCreatedV1 {
  evidence_id: string;
  case_id: string;
  evidence_type: string;
  sha256: string;
  size_bytes: number;
  s3_key: string;
  s3_version_id: string;
  verification_status: "PENDING";
}
