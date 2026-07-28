# Threat-model verification

Trust boundaries are the browser/BFF, OIDC issuer, API, NATS, PostgreSQL,
workers, evidence object store/KMS/time authority, endpoint agents, sandbox
agents/controller, canary edge, and analyst channels. The platform assumes a
controlled lab; it does not authorise testing unrelated systems.

Verified locally: deny-by-default roles; case-object access; encrypted
HTTP-only sessions; PKCE; Origin plus double-submit CSRF; fixed API upstream;
path normalisation; schema rejection; parameterised SQL; escaped hostile
display text; no `dangerouslySetInnerHTML`; archive bounds; artifact
quarantine; prompt/tool isolation; canary source classification; proxy shared
secret plus certificate serial; immutable evidence hashes; single-use report
downloads; non-root images; release/package tamper detection; installer source
secret scans.

Requires lab evidence: Windows certificate-store protections and Authenticode,
revocation across real Windows agents, AWS IAM/KMS/S3 Object Lock, external
canary controls, real network-policy enforcement, and Profile B compromise
recovery. These remain `LAB_VERIFICATION_REQUIRED`.
