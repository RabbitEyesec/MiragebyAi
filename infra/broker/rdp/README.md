# Step 8d — RDP broker (Windows RD Gateway)

**Update (Priority 5 remediation):** a real engineering scaffold now exists
under `src/`, `tests/`, `config/`, and `scripts/` — see
`docs/architecture/rdp-steering.md` for what's real/tested versus what
remains `WINDOWS_VERIFICATION_REQUIRED`. The section below (the original
Prompt 1 design record) is still accurate about WHY a compiled COM plugin
is unavoidable; it predates the scaffold.

Appendix H.3: "The RD Gateway is the public endpoint. Mirage selects
employee or sandbox desktop before the backend RDP connection is
established. NLA, certificate, gateway policy, user mapping, resolution,
graphics policy, clipboard, drive redirection, audio, printer and reconnect
are locked per scenario."

## Why the COM plugin registration step specifically stays lab-only

Unlike the HTTP broker (Nginx `auth_request`, portable, containerizable —
Step 8b) and the SSH broker (OpenSSH `ForceCommand`, portable,
containerizable — Step 8c), Windows RD Gateway's backend-selection
mechanism is **not** a config file or a shell script. RD Gateway's dynamic
per-connection authorization/target-selection point is a COM-based plugin
interface — `ITSGatewayPlugin` / `IRDGPolicyEngine` (Terminal Services
Gateway Plugin API) — implemented as a compiled .NET/C++ DLL registered
with the Gateway service, invoked by RD Gateway itself at connection time
to decide which backend a session is authorized to reach.

There is no Windows host anywhere in this environment (see
ARCHITECTURE_DECISIONS.md, KNOWN_ISSUES.md throughout this build), and a
COM plugin DLL cannot be meaningfully authored, compiled, or reviewed for
correctness without one. Writing a stand-in "selector script" the way
`infra/broker/ssh/mirage-route-selector.sh` does for OpenSSH would not be
real — RD Gateway does not execute shell scripts as part of its
authorization pipeline, so such a script could never actually run in this
role. Per this project's own rule against fabricated success, this
directory documents the real design instead of shipping code that could
never be exercised as designed.

## The real design (for the lab build)

1. **RD Gateway role + CAP/RAP.** Standard `RDS-Gateway` Windows feature
   install. A single Connection Authorization Policy (CAP) requiring NLA
   and a specific AD group; a Resource Authorization Policy (RAP) is
   **not** used for the dynamic employee/sandbox choice — RAPs are static
   allow-lists, and §6.1's mechanism ("mirage-api owns routing_decisions
   and exposes /route... broker calls /route before backend established")
   requires a per-connection, live decision, which only the plugin
   interface can make.

2. **Custom Gateway plugin** (new work, not yet started — tracked here,
   not fabricated): a small .NET class implementing `IRDGPolicyEngine`
   (`Microsoft.TerminalServices.Gateway` plugin surface), registered via
   `TSGatewayPluginConfig`. Its `OnAuthorizeResourceAccess`/equivalent
   callback:
   - Builds the real §6.1 match_key: `RDP|<gateway-listener-id>|<client-ip>|<authenticated-principal>`.
   - Calls `GET /route` (Step 8a) with the SAME mTLS/proxy-header contract
     every other broker uses, over plain HTTPS from the Gateway host (this
     leg does not need a shell process, so it does not hit the SSH
     broker's environment-inheritance problem documented in
     `mirage-route-selector.sh` — a compiled plugin process has normal,
     stable access to whatever configuration it was given at registration
     time).
   - Returns the resolved backend (employee or sandbox RD host) as the
     session's authorized target, once, before the backend RDP connection
     is established — matching "backend chosen once, before establishment"
     (Step 8b/8c/8d's shared rule) and Appendix H.3's own acceptance
     wording exactly.

3. **Per-scenario locks** (NLA, certificate, user mapping, resolution,
   graphics policy, clipboard, drive redirection, audio, printer, reconnect)
   are RD Gateway / RDP host Group Policy settings, applied identically to
   both the employee and sandbox RDP hosts so a client cannot fingerprint
   which one they landed in via connection-parameter differences alone —
   this is the RDP-specific instance of the same "consistent across both
   upstreams" requirement Appendix H.1 states explicitly for the HTTP
   broker.

## Status

`LAB_VERIFICATION_REQUIRED` in full — see REQUIREMENTS_TRACEABILITY.md
(S3-8D-001) and LAB_EXECUTION_CHECKLIST.md for the concrete steps once a
real Windows Server + RD Gateway role + Step 9a's golden sandbox AMI exist.
Nothing here is stubbed as passing; this document is the honest record of
what's designed versus what's built.
