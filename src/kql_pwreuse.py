# -*- coding: utf-8 -*-
"""Password-reuse approximation.

Neither Entra ID nor Defender for Identity exposes password hashes or a
hash-comparison result to Log Analytics, so identical-password detection is not
directly queryable. These queries approximate it three ways:

  * temporal correlation  - accounts whose passwords are always changed together
  * custody correlation   - one operator/host demonstrably holding many credentials
  * ground-truth ingest   - optional DSInternals NT-hash grouping in a custom table
"""

# ---------------------------------------------------------------------------
# 1. Accounts whose password changes are repeatedly synchronised.
#    A single coincidence is meaningless; repeated co-occurrence across several
#    independent rotations is strong evidence of a shared secret.
# ---------------------------------------------------------------------------
SYNC_PASSWORD_CHANGES = r"""
let changes = union isfuzzy=true
    (IdentityDirectoryEvents
        | where TimeGenerated {TimeRange}
        | where ActionType has "Password changed" or ActionType has "Password reset"
        | extend Account = tolower(coalesce(TargetAccountUpn, AccountUpn))
        | extend Actor = tolower(coalesce(AccountUpn, ""))
        | project TimeGenerated, Account, Actor, Src = "On-prem AD"),
    (AuditLogs
        | where TimeGenerated {TimeRange}
        | where OperationName has_any ("Reset user password", "Change user password", "Reset password")
        | extend Account = tolower(tostring(TargetResources[0].userPrincipalName))
        | extend Actor = tolower(tostring(InitiatedBy.user.userPrincipalName))
        | project TimeGenerated, Account, Actor, Src = "Entra ID")
    | where isnotempty(Account);
let buckets = changes
    | extend Slot = bin(TimeGenerated, {RotationWindow})
    | summarize Actor = any(Actor) by Account, Slot;
let totals = buckets | summarize TotalRotations = dcount(Slot) by Account;
buckets
| join kind=inner (buckets | project Slot, Account2 = Account, Actor2 = Actor) on Slot
| where strcmp(Account, Account2) < 0
| summarize SyncedRotations = dcount(Slot),
            SameActorCount = countif(Actor == Actor2 and isnotempty(Actor)),
            Actors = make_set_if(Actor, isnotempty(Actor), 5),
            ExampleWindows = make_set(Slot, 8)
    by Account, Account2
| where SyncedRotations >= {MinSyncedRotations}
| join kind=leftouter totals on Account
| join kind=leftouter (totals | project Account2 = Account, TotalRotations2 = TotalRotations) on Account2
| extend MinRotations = min_of(coalesce(TotalRotations, 0), coalesce(TotalRotations2, 0))
| extend SyncRatio = round(100.0 * SyncedRotations / max_of(MinRotations, 1), 1)
| extend Confidence = case(SyncRatio >= 100 and SyncedRotations >= 3, "High - every rotation of both accounts is simultaneous",
                           SyncRatio >= 80  and SyncedRotations >= 2, "Medium-High - rotations almost always simultaneous",
                           SyncRatio >= 50, "Medium - rotations frequently simultaneous",
                           "Low - some overlap, likely coincidental bulk activity")
| extend Interpretation = "Accounts rotated together on every cycle are usually maintained as one credential. This does not prove the passwords are identical, but it proves they are managed as a single secret - which carries the same blast radius."
| project AccountA = Account, AccountB = Account2, Confidence, SyncRatio, SyncedRotations,
          TotalRotationsA = TotalRotations, TotalRotationsB = TotalRotations2,
          SameActorCount, Actors, ExampleWindows, Interpretation
| sort by SyncRatio desc, SyncedRotations desc
"""

# ---------------------------------------------------------------------------
# 2. One actor resetting many passwords inside a single short window.
#    Bulk resets are overwhelmingly done to a common temporary value.
# ---------------------------------------------------------------------------
BULK_RESET = r"""
union isfuzzy=true
    (IdentityDirectoryEvents
        | where TimeGenerated {TimeRange}
        | where ActionType has "Password reset" or ActionType has "Password changed"
        | extend Account = tolower(coalesce(TargetAccountUpn, AccountUpn)),
                 Actor = tolower(coalesce(AccountUpn, "")),
                 Host = DeviceName
        | project TimeGenerated, Account, Actor, Host, Src = "On-prem AD"),
    (AuditLogs
        | where TimeGenerated {TimeRange}
        | where OperationName has_any ("Reset user password", "Change user password", "Reset password")
        | extend Account = tolower(tostring(TargetResources[0].userPrincipalName)),
                 Actor = tolower(tostring(InitiatedBy.user.userPrincipalName)),
                 Host = tostring(InitiatedBy.user.ipAddress)
        | project TimeGenerated, Account, Actor, Host, Src = "Entra ID")
| where isnotempty(Account) and isnotempty(Actor)
| where Actor != Account
| summarize AccountsReset = dcount(Account), Accounts = make_set(Account, 30),
            Resets = count(), Hosts = make_set_if(Host, isnotempty(Host), 5),
            Sources = make_set(Src, 3)
    by Actor, Window = bin(TimeGenerated, {RotationWindow})
| where AccountsReset >= {MinBulkReset}
| extend Assessment = case(AccountsReset >= 20, "Large bulk reset - a single temporary password almost certainly applied estate-wide",
                           AccountsReset >= 8,  "Bulk reset - verify each account received a unique value",
                           "Small batch reset - check for a shared temporary password")
| extend FollowUp = "Confirm whether the reset tool generates per-account values or a single shared one, and whether 'change at next logon' was enforced."
| project Window, Actor, Assessment, AccountsReset, Resets, Sources, Hosts, Accounts, FollowUp
| sort by AccountsReset desc
"""

# ---------------------------------------------------------------------------
# 3. Accounts that lock out together.
#    A stale credential cached in a script, mapped drive or service will lock
#    every account it is configured against, simultaneously, from one source.
# ---------------------------------------------------------------------------
CORRELATED_LOCKOUTS = r"""
let lockouts = union isfuzzy=true
    (IdentityLogonEvents
        | where TimeGenerated {TimeRange}
        | where ActionType == "LogonFailed"
        | where FailureReason has_any ("locked", "Locked", "LockedOut", "account is locked")
        | extend Account = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
        | project TimeGenerated, Account, Source = coalesce(DeviceName, IPAddress), Src = "MDI"),
    (SecurityEvent
        | where TimeGenerated {TimeRange}
        | where EventID == 4740
        | extend Account = tolower(TargetUserName)
        | project TimeGenerated, Account, Source = tostring(column_ifexists("TargetDomainName", "")), Src = "Security 4740")
    | where isnotempty(Account);
lockouts
| summarize Accounts = dcount(Account), AccountList = make_set(Account, 25),
            Events = count(), Sources = make_set_if(Source, isnotempty(Source), 10)
    by Window = bin(TimeGenerated, {RotationWindow})
| where Accounts >= 2
| extend Assessment = case(Accounts >= 5, "Many accounts locked in one window - a single cached credential is being replayed for all of them, or a spray is in progress",
                           "Small set of accounts locked together - classic signature of one shared password stored in automation")
| extend Discriminator = "If the same small set locks together repeatedly, it is a shared stored credential. If the set is large and changes each time, it is a password spray - cross-check the Red-Team tab."
| project Window, Assessment, Accounts, Events, Sources, AccountList, Discriminator
| sort by Window desc
"""

# ---------------------------------------------------------------------------
# 4. Credential custody: one host or operator authenticating as many identities.
#    Not identical passwords, but identical blast radius - one person holds N
#    working credentials.
# ---------------------------------------------------------------------------
CREDENTIAL_CUSTODY = r"""
IdentityLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| where isnotempty(DeviceName)
| extend Account = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| where isnotempty(Account)
| where AccountName !endswith "$"
| summarize Accounts = dcount(Account), AccountList = make_set(Account, 30),
            Logons = count(), LogonTypes = make_set(LogonType, 8),
            Protocols = make_set_if(Protocol, isnotempty(Protocol), 5),
            Windows = dcount(bin(TimeGenerated, {RotationWindow})),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by SourceHost = DeviceName
| where Accounts > {MaxAccountsPerHost}
| extend AccountsPerWindow = round(1.0 * Accounts / max_of(Windows, 1), 2)
| extend Assessment = case(Accounts >= 15, "Host authenticates as many identities - jump box, admin workstation, or a single operator holding a large credential set",
                           Accounts >= 6,  "Host holds several working credentials - verify against a named owner",
                           "Moderate credential custody")
| extend Interpretation = "Whoever operates this host can authenticate as every account listed. Whether those accounts share one password or several, the practical exposure is the same and the containment action is identical."
| project SourceHost, Assessment, Accounts, Logons, AccountsPerWindow, LogonTypes, Protocols, AccountList, Interpretation, FirstSeen, LastSeen
| sort by Accounts desc
"""

# ---------------------------------------------------------------------------
# 5. Provisioning cohorts: same naming stem, never rotated.
#    Accounts created as a batch and never changed still hold their common
#    provisioning password.
# ---------------------------------------------------------------------------
PROVISIONING_COHORT = r"""
let rotated = union isfuzzy=true
    (IdentityDirectoryEvents
        | where TimeGenerated > ago(365d)
        | where ActionType has "Password changed" or ActionType has "Password reset"
        | extend Account = tolower(coalesce(TargetAccountUpn, AccountUpn))
        | where isnotempty(Account)
        | summarize LastRotation = max(TimeGenerated) by Account),
    (AuditLogs
        | where TimeGenerated > ago(365d)
        | where OperationName has_any ("Reset user password", "Change user password")
        | extend Account = tolower(tostring(TargetResources[0].userPrincipalName))
        | where isnotempty(Account)
        | summarize LastRotation = max(TimeGenerated) by Account)
    | summarize LastRotation = max(LastRotation) by Account;
IdentityInfo
| where TimeGenerated > ago(30d)
| extend Account = tolower(AccountUPN)
| where isnotempty(Account)
| summarize arg_max(TimeGenerated, AccountDisplayName, IsAccountEnabled, Department, AssignedRoles) by Account
| where IsAccountEnabled == true
| join kind=leftouter rotated on Account
| where isnull(LastRotation)
| extend Local = tostring(split(Account, "@")[0])
| extend Stem = extract(@"^([A-Za-z]{3,}?)[-._]?[0-9]*$", 1, Local)
| extend Stem = iff(isempty(Stem), extract(@"^([A-Za-z]{3,})", 1, Local), Stem)
| where isnotempty(Stem) and strlen(Stem) >= 3
| summarize CohortSize = dcount(Account), Accounts = make_set(Account, 30),
            Privileged = countif(coalesce(array_length(todynamic(tostring(AssignedRoles))), 0) > 0),
            Departments = make_set_if(Department, isnotempty(Department), 8)
    by Stem
| where CohortSize >= {MinCohortSize}
| extend Assessment = case(Privileged > 0, "Unrotated provisioning cohort containing privileged accounts - treat as urgent",
                           CohortSize >= 10, "Large unrotated cohort - almost certainly still on a common provisioning password",
                           "Unrotated cohort sharing a naming stem")
| extend Caveat = "Absence of a rotation event may mean the password is genuinely unchanged, or simply that the change predates log retention. Confirm against pwdLastSet before acting."
| project Stem, Assessment, CohortSize, Privileged, Departments, Accounts, Caveat
| sort by Privileged desc, CohortSize desc
"""

# ---------------------------------------------------------------------------
# 6. Leaked-credential co-occurrence. Multiple accounts flagged from the same
#    breach ingest often means one credential appearing under several identities.
# ---------------------------------------------------------------------------
LEAKED_COOCCURRENCE = r"""
AADUserRiskEvents
| where TimeGenerated {TimeRange}
| where RiskEventType =~ "leakedCredentials"
| extend Account = tolower(UserPrincipalName)
| where isnotempty(Account)
| summarize Accounts = dcount(Account), AccountList = make_set(Account, 30),
            Events = count(), RiskLevels = make_set(RiskLevel, 5)
    by Window = bin(TimeGenerated, 1d)
| where Accounts >= 2
| extend Assessment = "Multiple accounts flagged as leaked in the same ingest window. Where these accounts belong to one person or one team, the same credential is very likely in use across all of them."
| project Window, Accounts, Events, RiskLevels, AccountList, Assessment
| sort by Accounts desc
"""

# ---------------------------------------------------------------------------
# 7. Ground truth, if the optional DSInternals feed is deployed.
#    The collector reports only group membership - never hashes or passwords.
# ---------------------------------------------------------------------------
DSINTERNALS_GROUPS = r"""
ADPasswordQuality_CL
| where TimeGenerated {TimeRange}
| where Finding_s == "DuplicatePasswordGroup"
| summarize arg_max(TimeGenerated, *) by GroupId_s, Account_s
| summarize GroupSize = dcount(Account_s), Accounts = make_set(Account_s, 40),
            Collected = max(TimeGenerated), Domain = any(Domain_s)
    by GroupId_s
| where GroupSize > 1
| extend Assessment = case(GroupSize >= 10, "Ten or more accounts share one password - systemic, likely a provisioning or imaging default",
                           GroupSize >= 3,  "Several accounts share one password",
                           "Two accounts share one password")
| project GroupId = GroupId_s, Domain, Assessment, GroupSize, Accounts, Collected
| sort by GroupSize desc
"""

DSINTERNALS_FINDINGS = r"""
ADPasswordQuality_CL
| where TimeGenerated {TimeRange}
| where Finding_s != "DuplicatePasswordGroup"
| summarize arg_max(TimeGenerated, *) by Finding_s, Account_s
| summarize Accounts = dcount(Account_s), AccountList = make_set(Account_s, 30),
            Collected = max(TimeGenerated)
    by Finding = Finding_s
| extend Severity = case(Finding in ("ClearTextPassword", "EmptyPassword", "LMHash"), "Critical",
                         Finding in ("WeakPassword", "PasswordNotRequired", "PreAuthNotRequired", "DESEncryptionOnly"), "High",
                         Finding in ("PasswordNeverExpires", "AESKeysMissing", "SmartCardUsersWithPassword"), "Medium",
                         "Informational")
| project Finding, Severity, Accounts, AccountList, Collected
| sort by Severity asc, Accounts desc
"""

DATA_AVAILABILITY = r"""
let probe = (T:string) { T };
union isfuzzy=true
  (SigninLogs                      | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "SigninLogs",                      Feeds = "Overview, Concurrency, Fan-Out, Hygiene, Generic"),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "AADNonInteractiveUserSignInLogs", Feeds = "Token replay, non-interactive activity"),
  (AuditLogs                       | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "AuditLogs",                       Feeds = "MFA registration, password resets"),
  (AADUserRiskEvents               | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "AADUserRiskEvents",               Feeds = "Risk component of the score, leaked credentials"),
  (IdentityLogonEvents             | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "IdentityLogonEvents",             Feeds = "On-Prem AD tab, NTLM analysis"),
  (IdentityDirectoryEvents         | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "IdentityDirectoryEvents",         Feeds = "Password activity, group changes"),
  (IdentityQueryEvents             | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "IdentityQueryEvents",             Feeds = "Directory enumeration / pre-Kerberoasting"),
  (IdentityInfo                    | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "IdentityInfo",                    Feeds = "Account attributes, dormancy, privilege"),
  (DeviceLogonEvents               | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "DeviceLogonEvents",               Feeds = "Local Accounts tab"),
  (DeviceProcessEvents             | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "DeviceProcessEvents",             Feeds = "Credential hunting, RDP shadowing"),
  (DeviceEvents                    | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "DeviceEvents",                    Feeds = "LSASS access"),
  (SecurityAlert                   | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "SecurityAlert",                   Feeds = "Alert panels, honeytokens"),
  (BehaviorAnalytics               | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "BehaviorAnalytics",               Feeds = "UEBA panel"),
  (SecurityEvent                   | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "SecurityEvent",                   Feeds = "Correlated lockouts (4740)"),
  (ADPasswordQuality_CL            | where TimeGenerated {TimeRange} | summarize Rows = count() | extend TableName = "ADPasswordQuality_CL",            Feeds = "Password Reuse ground truth (optional)")
| extend Status = case(Rows > 0, "Data present", "EMPTY - table exists but no rows in this time range")
| project TableName, Status, Rows, Feeds
| sort by Rows desc, TableName asc
"""

ABSENT_TABLES = r"""
let expected = dynamic(["SigninLogs","AADNonInteractiveUserSignInLogs","AuditLogs","AADUserRiskEvents",
    "IdentityLogonEvents","IdentityDirectoryEvents","IdentityQueryEvents","IdentityInfo",
    "DeviceLogonEvents","DeviceProcessEvents","DeviceEvents","SecurityAlert","BehaviorAnalytics",
    "SecurityEvent","ADPasswordQuality_CL"]);
let present = union isfuzzy=true
  (SigninLogs | take 1 | extend T = "SigninLogs"), (AADNonInteractiveUserSignInLogs | take 1 | extend T = "AADNonInteractiveUserSignInLogs"),
  (AuditLogs | take 1 | extend T = "AuditLogs"), (AADUserRiskEvents | take 1 | extend T = "AADUserRiskEvents"),
  (IdentityLogonEvents | take 1 | extend T = "IdentityLogonEvents"), (IdentityDirectoryEvents | take 1 | extend T = "IdentityDirectoryEvents"),
  (IdentityQueryEvents | take 1 | extend T = "IdentityQueryEvents"), (IdentityInfo | take 1 | extend T = "IdentityInfo"),
  (DeviceLogonEvents | take 1 | extend T = "DeviceLogonEvents"), (DeviceProcessEvents | take 1 | extend T = "DeviceProcessEvents"),
  (DeviceEvents | take 1 | extend T = "DeviceEvents"), (SecurityAlert | take 1 | extend T = "SecurityAlert"),
  (BehaviorAnalytics | take 1 | extend T = "BehaviorAnalytics"), (SecurityEvent | take 1 | extend T = "SecurityEvent"),
  (ADPasswordQuality_CL | take 1 | extend T = "ADPasswordQuality_CL")
  | summarize Tables = make_set(T, 30);
present
| extend Missing = set_difference(expected, Tables)
| mv-expand TableName = Missing to typeof(string)
| extend Status = "NOT PRESENT - connector not deployed to this workspace"
| project TableName, Status
| sort by TableName asc
"""

DSINTERNALS_FRESHNESS = r"""
ADPasswordQuality_CL
| summarize LastCollected = max(TimeGenerated), Records = count(), Domains = dcount(Domain_s)
| extend Status = case(isnull(LastCollected), "Not deployed - the optional DSInternals feed has no data. Panels below will be empty; the behavioural approximations above work without it.",
                       LastCollected > ago(8d),  "Healthy - collected within the last week",
                       LastCollected > ago(31d), "Stale - last collection over a week ago",
                       "Very stale - last collection over a month ago")
| project Status, LastCollected, Records, Domains
"""
