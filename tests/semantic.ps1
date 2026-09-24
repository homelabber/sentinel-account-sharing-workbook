$RepoRoot = Split-Path -Parent $PSScriptRoot
Add-Type -Path (Join-Path $RepoRoot 'kqllib\lib\net6.0\Kusto.Language.dll')

# --- Sentinel / Defender XDR table schemas (columns referenced by this workbook) ---
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
  'BehaviorAnalytics' = 'TimeGenerated:datetime, UserPrincipalName:string, UserName:string, UseryPrincipalName:string, ActivityType:string, ActionType:string, ActivityInsights:dynamic, UsersInsights:dynamic, DevicesInsights:dynamic, InvestigationPriority:int, SourceIPAddress:string, SourceIPLocation:string, SourceDevice:string, EventSource:string, Type:string'
  'SecurityEvent' = 'TimeGenerated:datetime, EventID:int, Account:string, AccountType:string, Computer:string, TargetUserName:string, TargetDomainName:string, TargetSid:string, SubjectUserName:string, SubjectDomainName:string, LogonType:int, IpAddress:string, WorkstationName:string, Activity:string, Type:string'
  'ADPasswordQuality_CL' = 'TimeGenerated:datetime, Finding_s:string, GroupId_s:string, Account_s:string, Domain_s:string, GroupSize_d:real, Type:string'
}

$tables = New-Object System.Collections.Generic.List[Kusto.Language.Symbols.TableSymbol]
foreach ($n in $schemas.Keys) {
  $tables.Add([Kusto.Language.Symbols.TableSymbol]::new($n, "(" + $schemas[$n] + ")"))
}
$db = [Kusto.Language.Symbols.DatabaseSymbol]::new('SentinelWs', $tables.ToArray())
$cluster = [Kusto.Language.Symbols.ClusterSymbol]::new('sentinel', @($db))
$globals = [Kusto.Language.GlobalState]::Default.WithCluster($cluster).WithDatabase($db)

$wb = Get-Content (Join-Path $RepoRoot 'AccountSharingVisibility.workbook.json') -Raw | ConvertFrom-Json
$subs = @{
  '{TimeRange}'='between (datetime(2026-09-17) .. datetime(2026-09-24))'; '{ConcurrencyWindow}'='15m'
  '{MaxIPs}'='8'; '{MaxDevices}'='3'; '{MaxCountries}'='2'; '{MaxUsersPerDevice}'='4'
  '{MaxOnPremHosts}'='5'; '{DormantDays}'='90'; '{MinScore}'='15'
  '{ExcludedUsers}'='none@example.invalid'; '{TargetUser}'='someone@contoso.com'
  '{RotationWindow}'='10m'; '{MinSyncedRotations}'='2'; '{MinBulkReset}'='5'
  '{MaxAccountsPerHost}'='3'; '{MinCohortSize}'='3'
}

function Get-Queries($node) {
  $out = @()
  if ($node.type -eq 3 -and $node.content.version -eq 'KqlItem/1.0') {
    $out += [pscustomobject]@{ Name=$node.name; Query=$node.content.query }
  }
  if ($node.type -eq 12) { foreach ($i in $node.content.items) { $out += Get-Queries $i } }
  if ($node.type -eq 9) {
    foreach ($p in $node.content.parameters) {
      if ($p.queryType -eq 0 -and $p.query) { $out += [pscustomobject]@{ Name="param:$($p.name)"; Query=$p.query } }
    }
  }
  $out
}

$queries = @(); foreach ($item in $wb.items) { $queries += Get-Queries $item }
Write-Host "Semantic analysis of $($queries.Count) queries against $($schemas.Count) table schemas`n" -ForegroundColor Cyan

$bad = 0; $totalIssues = 0
foreach ($q in $queries) {
  $text = $q.Query; foreach ($k in $subs.Keys) { $text = $text.Replace($k, $subs[$k]) }
  $code = [Kusto.Language.KustoCode]::ParseAndAnalyze($text, $globals)
  $diags = @($code.GetDiagnostics())
  if ($diags.Count -gt 0) {
    $bad++; $totalIssues += $diags.Count
    Write-Host "ISSUES  $($q.Name)" -ForegroundColor Red
    foreach ($d in $diags) {
      $line = ($text.Substring(0,[Math]::Min($d.Start,$text.Length)) -split "`n").Count
      $s = [Math]::Max(0,$d.Start-40); $len=[Math]::Min(90,$text.Length-$s)
      Write-Host ("   L{0}: {1}" -f $line,$d.Message) -ForegroundColor Yellow
      Write-Host ("        >> {0}" -f (($text.Substring($s,$len)) -replace "`r?`n",' ~ ')) -ForegroundColor DarkGray
    }
    Write-Host ""
  } else { Write-Host "ok      $($q.Name)" -ForegroundColor Green }
}
Write-Host "`nQueries with issues: $bad / $($queries.Count)   (total diagnostics: $totalIssues)" -ForegroundColor $(if($bad){'Red'}else{'Green'})
