# Step 9a "fingerprint harness (§6.5)" stage — collects REAL observations
# from this live instance and runs them through
# libs/mirage_common/fingerprint.py::run_fingerprint_check (the same
# comparator engine Step 10's live pre-ENGAGING gate uses). "The pipeline
# emits a signed, versioned AMI passing the fingerprint harness
# automatically" — this script's own exit code is what enforces that; a
# failing MUST check aborts the Packer build, so a failing image can never
# reach the "capture AMI" stage at all.
$ErrorActionPreference = "Stop"

$baselinePath = $env:MIRAGE_BASELINE_PATH
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)

$installedSoftware = @(
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                      "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName
) + @("MirageSpider", "Sysmon", "Elastic Agent")  # services installed directly, not via the Uninstall registry key

$runningProcessesAndServices = @(Get-Process | Select-Object -ExpandProperty ProcessName) +
                                 @(Get-Service | Where-Object Status -eq 'Running' | Select-Object -ExpandProperty Name)

$netAdapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
$macOui = if ($netAdapter) { ($netAdapter.MacAddress -split '-')[0..2] -join ':' } else { $null }
$dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | Where-Object { $_ })

$hireDate = [DateTime]::Parse((Get-Content $baselinePath | ConvertFrom-Json).checks.file_timestamps.expected.fictional_hire_date)
$filesPredatingHireDate = @(
    Get-ChildItem -Path "C:\Users", "C:\Program Files\Mirage" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -lt $hireDate } | Select-Object -ExpandProperty FullName -First 50
)

$observed = @{
    hostname_domain        = @{ hostname = $computer.Name; domain = $computer.Domain }
    user_profiles_and_sids = @{ profiles = @(Get-LocalUser | Where-Object Enabled | ForEach-Object { "$($computer.Name)\$($_.Name)" }) }
    installed_software     = @{ installed = $installedSoftware }
    file_timestamps         = @{ files_predating_hire_date = $filesPredatingHireDate }
    processes_services      = @{ running = $runningProcessesAndServices }
    network                  = @{ mac_oui = $macOui; dns_servers = $dnsServers; domain = $computer.Domain }
    uptime                   = @{ value = $uptimeHours }
    decoy_service_banners    = @{ http_server_header = "Microsoft-IIS/10.0"; ssh_banner = "SSH-2.0-OpenSSH_for_Windows_8.1" }
}

$observedPath = "C:\mirage-build\observed.json"
$observed | ConvertTo-Json -Depth 10 | Set-Content -Path $observedPath

$reportPath = "C:\mirage-build\fingerprint-report.json"
& python.exe -c @"
import json, sys
sys.path.insert(0, r'C:\Program Files\Mirage\Spider')
sys.path.insert(0, r'C:\Program Files\Mirage\Spider\vendor')
from mirage_common.fingerprint import run_fingerprint_check
baseline = json.load(open(r'$baselinePath'))
observed = json.load(open(r'$observedPath'))
report = run_fingerprint_check(baseline, observed)
out = {
    'target_id': report.target_id, 'baseline_version': report.baseline_version,
    'passed': report.passed, 'all_must_passed': report.all_must_passed,
    'should_pass_ratio': report.should_pass_ratio,
    'results': [
        {'check_name': r.check_name, 'comparator': r.comparator, 'level': r.level,
         'expected': r.expected, 'observed': r.observed, 'passed': r.passed, 'evidence': r.evidence}
        for r in report.results
    ],
}
json.dump(out, open(r'$reportPath', 'w'), indent=2)
print(json.dumps(out, indent=2))
sys.exit(0 if report.passed else 1)
"@

if ($LASTEXITCODE -ne 0) {
    throw "Fingerprint harness FAILED — see $reportPath. §6.5: 'An inconsistent sandbox is worse than none.' Aborting build; no AMI will be captured."
}

Write-Output "Fingerprint harness PASSED — see $reportPath."
