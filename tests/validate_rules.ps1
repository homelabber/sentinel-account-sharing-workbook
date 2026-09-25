<#
.SYNOPSIS
    Parses and semantically analyses the KQL in every analytics rule.

.DESCRIPTION
    Same two-layer check the workbook queries get, applied to rules/*.yaml:

      1. Syntax, via Microsoft's own Kusto grammar.
      2. Column and function resolution against the declared Entra / Defender XDR
         / Sentinel table schemas.

    Analytics rules are self-contained - they carry their own 'let' declarations
    instead of workbook {Parameter} placeholders - so nothing is substituted here.

    Run tests\fetch-parser.ps1 once first.
#>
[CmdletBinding()]
param(
    [switch] $SyntaxOnly
)

$RepoRoot = Split-Path -Parent $PSScriptRoot
$dll = Join-Path $RepoRoot 'kqllib\lib\net6.0\Kusto.Language.dll'
if (-not (Test-Path $dll)) {
    Write-Host "[!] Kusto parser not found. Run: .\tests\fetch-parser.ps1" -ForegroundColor Red
    exit 1
}
Add-Type -Path $dll

# --- Sentinel / Defender XDR table schemas (columns referenced by these rules) ---
# Kept in step with tests\semantic.ps1; a rule may only use columns declared here.
$schemas = @{
  'SigninLogs' = 'TimeGenerated:datetime, UserPrincipalName:string, UserId:string, UserDisplayName:string, IPAddress:string, ResultType:string, ResultDescription:string, AppDisplayName:string, AppId:string, ClientAppUsed:string, AuthenticationRequirement:string, ConditionalAccessStatus:string, CorrelationId:string, Id:string, DeviceDetail:dynamic, LocationDetails:dynamic, Status:dynamic, MfaDetail:dynamic, AuthenticationDetails:dynamic, AuthenticationProcessingDetails:dynamic, RiskLevelDuringSignIn:string, RiskLevelAggregated:string, RiskState:string, RiskEventTypes_V2:dynamic, AutonomousSystemNumber:int, UserAgent:string, UserType:string, AuthenticationProtocol:string, IncomingTokenType:string, UniqueTokenIdentifier:string, ResourceDisplayName:string, Category:string, OperationName:string, Type:string'
  'AADNonInteractiveUserSignInLogs' = 'TimeGenerated:datetime, UserPrincipalName:string, UserId:string, UserDisplayName:string, IPAddress:string, ResultType:string, ResultDescription:string, AppDisplayName:string, AppId:string, ClientAppUsed:string, AuthenticationRequirement:string, ConditionalAccessStatus:string, CorrelationId:string, Id:string, DeviceDetail:dynamic, LocationDetails:dynamic, Status:dynamic, AutonomousSystemNumber:int, UserAgent:string, UserType:string, AuthenticationProtocol:string, IncomingTokenType:string, UniqueTokenIdentifier:string, ResourceDisplayName:string, Category:string, Type:string'
  'AuditLogs' = 'TimeGenerated:datetime, OperationName:string, Category:string, Result:string, ResultDescription:string, ResultReason:string, InitiatedBy:dynamic, TargetResources:dynamic, AdditionalDetails:dynamic, CorrelationId:string, LoggedByService:string, AADOperationType:string, Identity:string, Type:string'
  'AADUserRiskEvents' = 'TimeGenerated:datetime, UserPrincipalName:string, UserId:string, UserDisplayName:string, RiskEventType:string, RiskLevel:string, RiskState:string, RiskDetail:string, IpAddress:string, Location:string, DetectionTimingType:string, Activity:string, Source:string, ActivityDateTime:datetime, Type:string'
  'IdentityLogonEvents' = 'TimeGenerated:datetime, Timestamp:datetime, ActionType:string, Application:string, LogonType:string, Protocol:string, FailureReason:string, AccountUpn:string, AccountName:string, AccountDomain:string, AccountSid:string, AccountObjectId:string, AccountDisplayName:string, DeviceName:string, DeviceType:string, OSPlatform:string, IPAddress:string, Port:string, DestinationDeviceName:string, DestinationIPAddress:string, DestinationPort:string, TargetDeviceName:string, TargetAccountDisplayName:string, Location:string, ISP:string, ReportId:string, AdditionalFields:dynamic, Type:string'
  'IdentityDirectoryEvents' = 'TimeGenerated:datetime, Timestamp:datetime, ActionType:string, Application:string, TargetAccountUpn:string, TargetAccountDisplayName:string, TargetDeviceName:string, Protocol:string, AccountName:string, AccountDomain:string, AccountUpn:string, AccountSid:string, AccountObjectId:string, AccountDisplayName:string, DeviceName:string, IPAddress:string, Port:string, DestinationDeviceName:string, DestinationIPAddress:string, DestinationPort:string, Location:string, ISP:string, ReportId:string, AdditionalFields:dynamic, Type:string'
  'IdentityQueryEvents' = 'TimeGenerated:datetime, Timestamp:datetime, ActionType:string, Application:string, QueryType:string, QueryTarget:string, Query:string, Protocol:string, AccountName:string, AccountDomain:string, AccountUpn:string, AccountSid:string, AccountObjectId:string, AccountDisplayName:string, DeviceName:string, IPAddress:string, Port:string, DestinationDeviceName:string, DestinationIPAddress:string, DestinationPort:string, Location:string, ISP:string, ReportId:string, AdditionalFields:dynamic, Type:string'
  'IdentityInfo' = 'TimeGenerated:datetime, AccountTenantId:string, AccountObjectId:string, AccountUPN:string, AccountDisplayName:string, AccountName:string, AccountDomain:string, AccountSID:string, AccountCloudSID:string, GroupMembership:dynamic, AssignedRoles:dynamic, IsAccountEnabled:bool, Manager:string, JobTitle:string, Department:string, UserType:string, City:string, Country:string, OnPremisesDistinguishedName:string, EmployeeId:string, MailAddress:string, RiskLevel:string, UserAccountControl:string, BlastRadius:string, ChangeSource:string, SourceSystem:string, Type:string'
  'DeviceLogonEvents' = 'TimeGenerated:datetime, Timestamp:datetime, DeviceId:string, DeviceName:string, ActionType:string, LogonType:string, AccountDomain:string, AccountName:string, AccountSid:string, IsLocalAdmin:bool, Protocol:string, RemoteDeviceName:string, RemoteIP:string, RemoteIPType:string, RemotePort:string, InitiatingProcessAccountName:string, InitiatingProcessAccountDomain:string, InitiatingProcessFileName:string, InitiatingProcessCommandLine:string, ReportId:string, AdditionalFields:dynamic, Type:string'
  'DeviceProcessEvents' = 'TimeGenerated:datetime, Timestamp:datetime, DeviceId:string, DeviceName:string, ActionType:string, FileName:string, FolderPath:string, SHA256:string, ProcessCommandLine:string, ProcessId:int, AccountDomain:string, AccountName:string, AccountSid:string, InitiatingProcessAccountName:string, InitiatingProcessAccountDomain:string, InitiatingProcessFileName:string, InitiatingProcessCommandLine:string, ReportId:string, AdditionalFields:dynamic, Type:string'
  'DeviceEvents' = 'TimeGenerated:datetime, Timestamp:datetime, DeviceId:string, DeviceName:string, ActionType:string, FileName:string, FolderPath:string, SHA256:string, ProcessCommandLine:string, AccountDomain:string, AccountName:string, AccountSid:string, RemoteIP:string, RemoteUrl:string, InitiatingProcessAccountName:string, InitiatingProcessAccountDomain:string, InitiatingProcessFileName:string, InitiatingProcessCommandLine:string, ReportId:string, AdditionalFields:dynamic, Type:string'
  'SecurityAlert' = 'TimeGenerated:datetime, AlertName:string, AlertSeverity:string, Description:string, ProviderName:string, ProductName:string, ProductComponentName:string, VendorName:string, Status:string, CompromisedEntity:string, Entities:string, Tactics:string, Techniques:string, ExtendedProperties:string, SystemAlertId:string, StartTime:datetime, EndTime:datetime, Type:string'
  'BehaviorAnalytics' = 'TimeGenerated:datetime, UserPrincipalName:string, UserName:string, ActivityType:string, ActionType:string, ActivityInsights:dynamic, UsersInsights:dynamic, DevicesInsights:dynamic, InvestigationPriority:int, SourceIPAddress:string, SourceIPLocation:string, SourceDevice:string, EventSource:string, Type:string'
  'SecurityEvent' = 'TimeGenerated:datetime, EventID:int, Account:string, AccountType:string, Computer:string, TargetUserName:string, TargetDomainName:string, TargetSid:string, SubjectUserName:string, SubjectDomainName:string, LogonType:int, IpAddress:string, WorkstationName:string, Activity:string, Type:string'
  'ADPasswordQuality_CL' = 'TimeGenerated:datetime, Finding_s:string, GroupId_s:string, Account_s:string, Domain_s:string, GroupSize_d:real, Type:string'
}

$tables = New-Object System.Collections.Generic.List[Kusto.Language.Symbols.TableSymbol]
foreach ($n in $schemas.Keys) {
    $tables.Add([Kusto.Language.Symbols.TableSymbol]::new($n, "(" + $schemas[$n] + ")"))
}
$db      = [Kusto.Language.Symbols.DatabaseSymbol]::new('SentinelWs', $tables.ToArray())
$cluster = [Kusto.Language.Symbols.ClusterSymbol]::new('sentinel', @($db))
$globals = [Kusto.Language.GlobalState]::Default.WithCluster($cluster).WithDatabase($db)

# --- minimal YAML reader -----------------------------------------------------
# Only what this repo's rule files use: top-level 'key: value' and a literal
# block scalar for 'query: |'. Avoids a PowerShell YAML module dependency.
function Get-RuleQuery($path) {
    $lines  = Get-Content $path
    $name   = ''
    $query  = New-Object System.Collections.Generic.List[string]
    $inQ    = $false
    $indent = 0
    foreach ($line in $lines) {
        if (-not $inQ) {
            if ($line -match '^name:\s*(.+)$') { $name = $Matches[1].Trim() }
            if ($line -match '^query:\s*\|\s*$') { $inQ = $true; $indent = 0 }
            continue
        }
        if ($line.Trim() -eq '') { $query.Add(''); continue }
        $lead = $line.Length - $line.TrimStart().Length
        if ($indent -eq 0) { $indent = $lead }
        if ($lead -lt $indent) { $inQ = $false; continue }
        $query.Add($line.Substring($indent))
    }
    [pscustomobject]@{
        File  = Split-Path -Leaf $path
        Name  = $name
        Query = ($query -join "`n").Trim()
    }
}

$ruleDir = Join-Path $RepoRoot 'rules'
$rules   = @(Get-ChildItem -Path $ruleDir -Filter '*.yaml' | Sort-Object Name | ForEach-Object { Get-RuleQuery $_.FullName })

if ($rules.Count -eq 0) {
    Write-Host "[!] No rules found in $ruleDir" -ForegroundColor Red
    exit 1
}

$mode = if ($SyntaxOnly) { 'Syntax' } else { 'Syntax + semantic' }
Write-Host "$mode analysis of $($rules.Count) analytics rules`n" -ForegroundColor Cyan

$bad = 0
$totalIssues = 0
foreach ($r in $rules) {
    if ([string]::IsNullOrWhiteSpace($r.Query)) {
        $bad++
        Write-Host "FAIL  $($r.File)  --  no query block found" -ForegroundColor Red
        continue
    }

    $code = if ($SyntaxOnly) {
        [Kusto.Language.KustoCode]::Parse($r.Query)
    } else {
        [Kusto.Language.KustoCode]::ParseAndAnalyze($r.Query, $globals)
    }
    $diags = if ($SyntaxOnly) { @($code.GetSyntaxDiagnostics()) } else { @($code.GetDiagnostics()) }

    if ($diags.Count -gt 0) {
        $bad++
        $totalIssues += $diags.Count
        Write-Host "ISSUES  $($r.File)  --  $($r.Name)" -ForegroundColor Red
        foreach ($d in $diags) {
            $line = ($r.Query.Substring(0, [Math]::Min($d.Start, $r.Query.Length)) -split "`n").Count
            $s = [Math]::Max(0, $d.Start - 40)
            $len = [Math]::Min(90, $r.Query.Length - $s)
            Write-Host ("   L{0}: {1}" -f $line, $d.Message) -ForegroundColor Yellow
            Write-Host ("        >> {0}" -f (($r.Query.Substring($s, $len)) -replace "`r?`n", ' ~ ')) -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    else {
        Write-Host "ok      $($r.File)" -ForegroundColor Green
    }
}

Write-Host ""
if ($bad -eq 0) {
    Write-Host "ALL $($rules.Count) RULE QUERIES CLEAN" -ForegroundColor Green
} else {
    Write-Host "$bad of $($rules.Count) rules have issues   (total diagnostics: $totalIssues)" -ForegroundColor Red
}
exit $bad
