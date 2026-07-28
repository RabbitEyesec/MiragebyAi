# RDP steering (Priority 5)

## What is real and locally verified

The RDP-protocol instance of the SAME `/route` decision contract the HTTP
(nginx) and SSH (`mirage-route-selector.sh`) brokers already use for real:

- **Canonical match key**: `RDP|<gateway_listener_id>|<client_ip>|<principal>`
  — proven correct against the actual running `mirage-api` `/route`
  endpoint by `tests/integration/test_routing_api.py::test_route_resolves_rdp_match_key_to_endpoint_by_default`
  and `::test_steer_then_route_returns_sandbox_for_rdp_match_key` (real
  Postgres, real enrolled `BROKER_CLIENT` identity, real HTTP headers — no
  mocks).
- **The portable decision client** (`infra/broker/rdp/src/MirageRouteDecisionClient.cs`):
  builds that match key, calls `/route` with the exact
  `X-Mirage-Client-Cert-Serial`/`X-Mirage-Proxy-Auth` header contract,
  generates a correlation ID per connection attempt, times out per a
  configured budget, and fails safe to `ENDPOINT` or `DENY` (never
  `SANDBOX`) on any error. Has zero COM/Windows dependency — it is
  ordinary, portable .NET code.
- **Configuration schema** (`infra/broker/rdp/config/rdp-plugin-config.schema.json`):
  validated Draft 2020-12 JSON Schema; the proxy shared secret is always an
  environment-variable *name*, never a literal value in the file itself.
- **Test harness with a fake routing API**
  (`infra/broker/rdp/tests/MirageRouteDecisionClientTests.cs`): a scriptable
  `HttpMessageHandler` standing in for `/route`, covering sandbox/endpoint
  resolution, the exact header contract, fail-safe-to-ENDPOINT,
  fail-safe-to-DENY, timeout handling, and "never resolves to SANDBOX on
  failure."
- **PowerShell install/uninstall scripts**
  (`infra/broker/rdp/scripts/*.ps1`): validate the config, create/remove
  the Windows Event Log source, stage the plugin assembly — everything up
  to the actual COM registration call.
- **Static verification**: `tests/unit/test_rdp_steering_scaffold.py`
  proves the config schema is valid and its example validates, every
  scaffold file exists, the C# source's match-key format string and header
  names are byte-for-byte what the live `/route` contract test above
  proves correct (so the two can never silently drift apart), and neither
  the source nor the install script ever treats `SANDBOX` as a fail-safe
  option.

## What is honestly still WINDOWS_VERIFICATION_REQUIRED

**The actual COM registration.** RD Gateway's per-connection
authorization/backend-selection point is `ITSGatewayPlugin` — a COM
interface from the Terminal Services Gateway Plugin type library,
registered via `TSGatewayPluginConfig`. This environment has no Windows
host, no .NET SDK, and no access to that type library to add as a COM
reference — so `MirageRdGatewayPlugin.cs`'s exact interface implementation
is left as an explicit, documented `TODO` rather than an invented interop
signature that could be subtly wrong in a way nobody here could catch. The
`.csproj` files cannot be restored or built in this environment either;
they are real, reviewable MSBuild project files, not exercised.

Also lab-only: Connection/Resource Authorization Policy (CAP/RAP)
configuration on a real RD Gateway role, NLA/certificate/user-mapping Group
Policy locks applied identically to both RDP targets, and the actual
Windows Event Log entries the plugin would produce.

## Why this split is the honest one

Everything listed as "real" above is ordinary, portable code with no
Windows/COM dependency, and is exercised for real (against a live
`mirage-api`, or against a fake HTTP handler). Everything listed as
lab-only is *inherently* Windows/COM-specific — there is no portable stand-
in for a COM type library the way there is for a config file or a shell
script, which is exactly why `infra/broker/rdp/README.md` originally
shipped a design document instead of fabricated code. This scaffold adds
every part of that design that COULD be made real without a Windows host,
and is explicit, not silent, about the one part that still needs one.

## Exact commands

```sh
.venv/bin/pytest tests/unit/test_rdp_steering_scaffold.py -v
.venv/bin/pytest tests/integration/test_routing_api.py -v -k rdp
```

On a real Windows build host, once the COM interop TODO is resolved:

```powershell
dotnet test infra/broker/rdp/tests/MirageRdpPlugin.Tests.csproj
dotnet build infra/broker/rdp/src/MirageRdpPlugin.csproj -c Release
infra/broker/rdp/scripts/install-mirage-rdp-plugin.ps1 `
    -PluginAssemblyPath <path-to-built-dll> -ConfigPath <path-to-config>
```
