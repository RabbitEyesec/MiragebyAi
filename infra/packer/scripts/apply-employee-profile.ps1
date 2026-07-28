# Step 9a "employee profile" stage: makes the golden image LOOK like a
# real employee's machine — hostname/domain, a local user profile, and
# (implicitly, since this build itself runs after $env:MIRAGE_FICTIONAL_HIRE_DATE)
# no build artifact predates the fictional hire date §6.5 checks for,
# because nothing on this image existed before this build ran.
$ErrorActionPreference = "Stop"

$baseline = Get-Content $env:MIRAGE_BASELINE_PATH | ConvertFrom-Json
$hostnameDomain = $baseline.checks.hostname_domain.expected
$userProfiles = $baseline.checks.user_profiles_and_sids.expected.profiles

Rename-Computer -NewName $hostnameDomain.hostname -Force

$employeeUser = ($userProfiles[0] -split '\\')[-1]
$securePassword = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
New-LocalUser -Name $employeeUser -Password $securePassword -FullName "Employee01" -Description "Mirage fictional employee profile" -PasswordNeverExpires
Add-LocalGroupMember -Group "Users" -Member $employeeUser

Write-Output "Employee profile applied: hostname=$($hostnameDomain.hostname) domain=$($hostnameDomain.domain) user=$employeeUser"
Write-Output "NOTE: Rename-Computer requires a restart to take effect — the calling .pkr.hcl template's build block must include a windows-restart provisioner immediately after this script for the fingerprint harness stage to observe the new hostname."
