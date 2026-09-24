<#
.SYNOPSIS
    Produces real duplicate-password groups from Active Directory and ships the
    results to Microsoft Sentinel, without ever exporting a hash or a password.

.DESCRIPTION
    Neither Microsoft Entra ID nor Defender for Identity exposes password hashes
    or a hash-comparison result to Log Analytics, so "which accounts share a
    password" cannot be answered by KQL alone. DSInternals can answer it against
    on-premises Active Directory by comparing NT hashes locally and reporting
    only the resulting GROUPINGS.

    This script:
      * reads account data either from an offline ntds.dit copy (preferred) or
        via directory replication,
      * runs Test-PasswordQuality entirely in memory,
      * emits ONLY account names, a synthetic group id, and finding labels,
      * optionally uploads to a Log Analytics custom table via the Logs
        Ingestion API, feeding the "Password Reuse" tab of the
        AccountSharingVisibility workbook.

    Hashes and passwords are never written to disk, to the console, or to
    Sentinel. The synthetic GroupId is a per-run ordinal and carries no
    information about the password itself.

.PARAMETER Mode
    Database    - read an offline ntds.dit copy. No replication traffic, and
                  nothing that resembles DCSync. STRONGLY PREFERRED.
    Replication - pull account data over DRSR from a live DC.

    IMPORTANT: Replication mode issues the same directory-replication calls that
    DCSync uses. Defender for Identity is very likely to raise "Suspected DCSync
    attack (replication of directory services)" against the account running it.
    If you must use it, agree the source host and account with the SOC first and
    file a documented suppression - do not silently exclude it, and do not let
    this become the exception that hides a real DCSync.

.PARAMETER WeakPasswordHashesSortedFile
    Optional path to the Have I Been Pwned NTLM hash list, ordered by hash.
    Enables the WeakPassword finding (password appears in a public breach
    corpus). The file is read locally; nothing is sent anywhere.

.EXAMPLE
    # Preferred: offline, on a DC, against a VSS snapshot
    .\Collect-ADPasswordQuality.ps1 -Mode Database `
        -DatabasePath C:\Snapshot\Windows\NTDS\ntds.dit `
        -OutputPath C:\Temp\pwquality.json

.EXAMPLE
    # With Sentinel upload
    .\Collect-ADPasswordQuality.ps1 -Mode Database -DatabasePath C:\Snapshot\Windows\NTDS\ntds.dit `
        -DceUri https://my-dce-abcd.eastus-1.ingest.monitor.azure.com `
        -DcrImmutableId dcr-0123456789abcdef0123456789abcdef `
        -StreamName Custom-ADPasswordQuality_CL `
        -TenantId <guid> -ClientId <guid> -ClientSecret <secret>

.NOTES
    Requires the DSInternals module:  Install-Module DSInternals -Scope AllUsers
    Run as a scheduled task monthly. Treat any output file as Highly Confidential
    and delete it after upload - it names every account sharing a credential.
#>

[CmdletBinding()]
param(
    [ValidateSet('Database', 'Replication')]
    [string] $Mode = 'Database',

    # --- Database mode ---
    [string] $DatabasePath,
    [string] $LogPath,
    [string] $BootKey,

    # --- Replication mode ---
    [string] $Server,
    [string] $NamingContext,
    [pscredential] $Credential,

    # --- Optional breach corpus ---
    [string] $WeakPasswordHashesSortedFile,

    # --- Output ---
    [string] $OutputPath,

    # --- Optional Sentinel upload (Logs Ingestion API) ---
    [string] $DceUri,
    [string] $DcrImmutableId,
    [string] $StreamName = 'Custom-ADPasswordQuality_CL',
    [string] $TenantId,
    [string] $ClientId,
    [string] $ClientSecret
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

# --------------------------------------------------------------- prerequisites
if (-not (Get-Module -ListAvailable -Name DSInternals)) {
    throw "The DSInternals module is not installed. Run: Install-Module DSInternals -Scope AllUsers"
}
Import-Module DSInternals -ErrorAction Stop
Write-Ok "DSInternals $((Get-Module DSInternals).Version) loaded"

# ------------------------------------------------------------------ collection
Write-Step "Reading account data in $Mode mode"

if ($Mode -eq 'Replication') {
    Write-Warn "Replication mode performs the same directory-replication calls as DCSync."
    Write-Warn "Defender for Identity will very likely alert on the account running this."
    Write-Warn "Confirm the SOC has an agreed, documented suppression for this host and account."
    if (-not $Server) { throw "-Server is required in Replication mode." }

    $splat = @{ All = $true; Server = $Server }
    if ($NamingContext) { $splat['NamingContext'] = $NamingContext }
    if ($Credential)    { $splat['Credential']    = $Credential }
    $accounts = Get-ADReplAccount @splat
    $domainLabel = $Server
}
else {
    if (-not $DatabasePath) { throw "-DatabasePath is required in Database mode." }
    if (-not (Test-Path $DatabasePath)) { throw "ntds.dit not found at $DatabasePath" }

    $splat = @{ All = $true; DatabasePath = $DatabasePath }
    if ($LogPath) { $splat['LogPath'] = $LogPath }
    if ($BootKey) { $splat['BootKey'] = $BootKey }
    else {
        Write-Warn "No -BootKey supplied. Secret attributes stay encrypted and duplicate detection cannot run."
        Write-Warn "Retrieve it from the SYSTEM hive of the same snapshot: Get-BootKey -SystemHivePath <path>"
        throw "-BootKey is required for password quality analysis."
    }
    $accounts = Get-ADDBAccount @splat
    $domainLabel = Split-Path $DatabasePath -Leaf
}

$accountArray = @($accounts)
Write-Ok "Read $($accountArray.Count) accounts"

# -------------------------------------------------------------------- analysis
Write-Step "Comparing NT hashes in memory (nothing is written to disk)"

$tpqSplat = @{}
if ($WeakPasswordHashesSortedFile) {
    if (-not (Test-Path $WeakPasswordHashesSortedFile)) {
        throw "Weak password hash file not found: $WeakPasswordHashesSortedFile"
    }
    $tpqSplat['WeakPasswordHashesSortedFile'] = $WeakPasswordHashesSortedFile
    Write-Ok "Breach corpus enabled - WeakPassword finding will be populated"
}

$result = $accountArray | Test-PasswordQuality @tpqSplat

# Release account objects (they hold hash material) as early as possible.
$accounts = $null
$accountArray = $null
[System.GC]::Collect()

# ------------------------------------------------------------------- shape rows
$now = (Get-Date).ToUniversalTime().ToString('o')
$rows = [System.Collections.Generic.List[object]]::new()

# Duplicate password groups: the actual answer to "who shares a password".
$g = 0
foreach ($grp in $result.DuplicatePasswordGroups) {
    $g++
    $gid = 'DUP-{0:D4}' -f $g
    foreach ($acct in $grp) {
        $rows.Add([pscustomobject]@{
            TimeGenerated = $now
            Finding       = 'DuplicatePasswordGroup'
            GroupId       = $gid
            Account       = [string]$acct
            Domain        = $domainLabel
            GroupSize     = @($grp).Count
        })
    }
}
Write-Ok "$g duplicate-password group(s) covering $(($rows | Measure-Object).Count) account(s)"

# Single-account findings. Names only - no hash material of any kind.
$singleFindings = @(
    'WeakPassword', 'ClearTextPassword', 'LMHash', 'EmptyPassword',
    'PasswordNotRequired', 'PasswordNeverExpires', 'AESKeysMissing',
    'PreAuthNotRequired', 'DESEncryptionOnly', 'SmartCardUsersWithPassword',
    'DelegatableAdmins', 'Kerberoastable'
)
foreach ($f in $singleFindings) {
    if (-not ($result.PSObject.Properties.Name -contains $f)) { continue }
    foreach ($acct in $result.$f) {
        $rows.Add([pscustomobject]@{
            TimeGenerated = $now
            Finding       = $f
            GroupId       = ''
            Account       = [string]$acct
            Domain        = $domainLabel
            GroupSize     = 1
        })
    }
}

$result = $null
[System.GC]::Collect()

Write-Ok "$($rows.Count) total records prepared (no hashes, no passwords)"

# ----------------------------------------------------------------- local output
if ($OutputPath) {
    $rows | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Ok "Written to $OutputPath"
    Write-Warn "This file names every account sharing a credential. Treat as Highly Confidential and delete after upload."
}

# -------------------------------------------------------------- Sentinel upload
if ($DceUri -and $DcrImmutableId) {
    if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
        throw "Upload requires -TenantId, -ClientId and -ClientSecret."
    }
    Write-Step "Uploading to Log Analytics via the Logs Ingestion API"

    $tokenBody = @{
        client_id     = $ClientId
        scope         = 'https://monitor.azure.com//.default'
        client_secret = $ClientSecret
        grant_type    = 'client_credentials'
    }
    $token = (Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $tokenBody -ContentType 'application/x-www-form-urlencoded').access_token

    $uri = "$($DceUri.TrimEnd('/'))/dataCollectionRules/$DcrImmutableId/streams/$StreamName" +
           "?api-version=2023-01-01"
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    $batchSize = 500
    $sent = 0
    for ($i = 0; $i -lt $rows.Count; $i += $batchSize) {
        $batch = $rows[$i..([Math]::Min($i + $batchSize - 1, $rows.Count - 1))]
        $body = ConvertTo-Json -InputObject @($batch) -Depth 4 -Compress
        Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body | Out-Null
        $sent += $batch.Count
        Write-Host "    uploaded $sent / $($rows.Count)" -ForegroundColor DarkGray
    }
    Write-Ok "Upload complete - query ADPasswordQuality_CL in Sentinel"
}
else {
    Write-Warn "No DCE/DCR supplied - skipping upload. Supply -DceUri and -DcrImmutableId to feed the workbook."
}

Write-Host ""
Write-Ok "Done. The workbook's Password Reuse tab will surface these under 'Ground truth'."
