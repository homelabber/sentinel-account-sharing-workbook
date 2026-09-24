# -*- coding: utf-8 -*-
"""KQL for credential hygiene, generic/service accounts, on-prem AD, local
accounts, red-team tradecraft and the single-account drilldown."""

# ================================================================ CREDENTIAL HYGIENE

SHARED_MFA_METHOD = r"""
AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has_any ("security info", "StrongAuthentication", "authentication method", "Update user")
| extend Target = tolower(tostring(TargetResources[0].userPrincipalName))
| where isnotempty(Target)
| mv-expand mp = TargetResources[0].modifiedProperties
| extend PropName = tostring(mp.displayName), NewVal = tostring(mp.newValue)
| where PropName has_any ("PhoneNumber", "AlternativePhoneNumber", "StrongAuthenticationUserDetails",
                          "StrongAuthenticationPhoneAppDetail", "Email", "VoiceOnlyPhoneNumber")
| extend Raw = replace_string(replace_string(replace_string(NewVal, '"', ''), '[', ''), ']', '')
| extend Method = trim(@"[\s\\]+", Raw)
| where isnotempty(Method) and Method !in ("", "null", "[]")
| extend MethodType = case(PropName has "Phone", "Phone number", PropName has "Email", "Email address",
                           PropName has "PhoneApp", "Authenticator device", PropName)
| summarize AccountsSharing = dcount(Target), Accounts = make_set(Target, 25),
            Registrations = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by MethodType, Method
| where AccountsSharing > 1
| extend Assessment = case(AccountsSharing >= 5, "One recovery factor controls many accounts - high risk",
                           AccountsSharing >= 3, "Shared recovery factor - investigate",
                           "Two accounts share a factor - often a legitimate second account, verify")
| project MethodType, Method, AccountsSharing, Assessment, Registrations, Accounts, FirstSeen, LastSeen
| sort by AccountsSharing desc
"""

THIRD_PARTY_MFA_REG = r"""
AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has_any ("security info", "authentication method", "StrongAuthentication")
| extend Actor  = tolower(tostring(InitiatedBy.user.userPrincipalName))
| extend Target = tolower(tostring(TargetResources[0].userPrincipalName))
| where isnotempty(Actor) and isnotempty(Target)
| where Actor != Target
| where Actor !endswith "#EXT#" and Actor !has "sync_"
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, Target, OperationName, Result, ActorIP,
          CorrelationId, ActorRoles = tostring(column_ifexists("AADOperationType",""))
| sort by TimeGenerated desc
"""

PASSWORD_ACTIVITY = r"""
union isfuzzy=true
  (IdentityDirectoryEvents
     | where TimeGenerated {TimeRange}
     | where ActionType has_any ("Password changed", "Password reset", "Account Password Never Expires changed",
                                 "Account Password Not Required changed", "Account Expired changed")
     | extend UserPrincipalName = tolower(coalesce(AccountUpn, TargetAccountUpn))
     | project TimeGenerated, UserPrincipalName, Source = "On-prem AD (MDI)", ActionType,
               Actor = tolower(coalesce(column_ifexists("AccountUpn",""), "")),
               Device = DeviceName, Details = tostring(AdditionalFields)),
  (AuditLogs
     | where TimeGenerated {TimeRange}
     | where OperationName has_any ("Reset user password", "Change user password", "Reset password (self-service)")
     | extend UserPrincipalName = tolower(tostring(TargetResources[0].userPrincipalName))
     | project TimeGenerated, UserPrincipalName, Source = "Entra ID", ActionType = OperationName,
               Actor = tolower(tostring(InitiatedBy.user.userPrincipalName)),
               Device = "", Details = tostring(Result))
| where isnotempty(UserPrincipalName)
| extend SelfService = iff(Actor == UserPrincipalName or isempty(Actor), "Self / unknown", "Administrative")
| sort by TimeGenerated desc
"""

PASSWORD_STALENESS = r"""
let changed = IdentityDirectoryEvents
    | where TimeGenerated > ago(365d)
    | where ActionType has "Password changed" or ActionType has "Password reset"
    | extend UserPrincipalName = tolower(coalesce(AccountUpn, TargetAccountUpn))
    | where isnotempty(UserPrincipalName)
    | summarize LastPasswordChange = max(TimeGenerated) by UserPrincipalName;
IdentityInfo
| where TimeGenerated {TimeRange}
| extend UserPrincipalName = tolower(AccountUPN)
| where isnotempty(UserPrincipalName)
| summarize arg_max(TimeGenerated, AccountDisplayName, Department, IsAccountEnabled, AssignedRoles, UserAccountControl = tostring(column_ifexists("UserAccountControl","")))
    by UserPrincipalName
| join kind=leftouter changed on UserPrincipalName
| extend PasswordAgeDays = iff(isnull(LastPasswordChange), -1, toint(datetime_diff('day', now(), LastPasswordChange)))
| extend PasswordNeverExpires = UserAccountControl has "DONT_EXPIRE_PASSWD" or UserAccountControl has "DONT_EXPIRE_PASSWORD"
| extend PasswordNotRequired   = UserAccountControl has "PASSWD_NOTREQD"
| extend Privileged = coalesce(array_length(todynamic(tostring(AssignedRoles))), 0) > 0
| where PasswordNeverExpires or PasswordNotRequired or PasswordAgeDays > {DormantDays} or PasswordAgeDays == -1
| extend Finding = case(PasswordNotRequired, "PASSWD_NOTREQD set - password may be blank",
                        PasswordNeverExpires and Privileged, "Privileged account with non-expiring password",
                        PasswordNeverExpires, "Non-expiring password - classic shared-credential pattern",
                        PasswordAgeDays == -1, strcat("No password change seen in retention window"),
                        strcat("Password unchanged for ", PasswordAgeDays, " days"))
| project UserPrincipalName, AccountDisplayName, Finding, PasswordAgeDays, LastPasswordChange,
          PasswordNeverExpires, PasswordNotRequired, Privileged, IsAccountEnabled, Department, UserAccountControl
| sort by PasswordNotRequired desc, Privileged desc, PasswordAgeDays desc
"""

WEAK_AUTH_SURFACE = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
union isfuzzy=true
  (SigninLogs | where TimeGenerated {TimeRange} | extend SignInClass = "Interactive"),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | extend SignInClass = "NonInteractive")
| where ResultType == 0
| extend UserPrincipalName = tolower(UserPrincipalName)
| where isnotempty(UserPrincipalName) and not(UserPrincipalName has_any (excl))
| extend IsLegacy = ClientAppUsed in ("Other clients","IMAP4","POP3","SMTP","MAPI","Exchange ActiveSync","Authenticated SMTP","Exchange Web Services","Exchange Online PowerShell")
| extend IsSingleFactor = AuthenticationRequirement =~ "singleFactorAuthentication"
| summarize SignIns = count(),
            LegacyAuth = countif(IsLegacy),
            SingleFactor = countif(IsSingleFactor),
            DistinctIPs = dcount(IPAddress),
            LegacyClients = make_set_if(ClientAppUsed, IsLegacy, 10),
            Apps = make_set(AppDisplayName, 12),
            LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where LegacyAuth > 0 or SingleFactor > 0
| extend SingleFactorPct = round(100.0 * SingleFactor / SignIns, 1)
| extend Assessment = case(LegacyAuth > 0, "Legacy auth in use - password can be replayed without MFA, the single biggest enabler of silent account sharing",
                           SingleFactorPct > 80, "Almost entirely single-factor - shared password would be undetectable",
                           "Partial single-factor usage")
| project UserPrincipalName, Assessment, LegacyAuth, SingleFactor, SingleFactorPct, SignIns, DistinctIPs, LegacyClients, Apps, LastSeen
| sort by LegacyAuth desc, SingleFactor desc
"""

LEAKED_CREDS = r"""
AADUserRiskEvents
| where TimeGenerated {TimeRange}
| where RiskEventType in~ ("leakedCredentials", "passwordSpray", "anomalousToken", "tokenIssuerAnomaly", "adminConfirmedUserCompromised")
| extend UserPrincipalName = tolower(UserPrincipalName)
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, RiskState, RiskDetail,
          IpAddress, Location = tostring(Location), DetectionTimingType, Activity, Source
| sort by TimeGenerated desc
"""

# ================================================================ GENERIC / SERVICE ACCOUNTS

GENERIC_INVENTORY = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
let genericRx = @"(?i)(^|[._\-])(svc|service|shared|generic|common|team|group|dept|admin|administrator|adm|test|tst|temp|tmp|training|train|demo|kiosk|lobby|frontdesk|reception|scanner|scan|printer|print|copier|fax|conf|conference|room|guest|intern|contractor|vendor|support|helpdesk|sql|oracle|backup|batch|task|sched|robot|bot|rpa|automation|integration|api|app|monitor|nagios|zabbix|splunk|jenkins|build|deploy)([._\-]|[0-9]|@|$)";
let sig = union isfuzzy=true
    (SigninLogs | where TimeGenerated {TimeRange} | where ResultType == 0
        | extend SignInClass = "Interactive",
                 Country  = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
                 DeviceId = tostring(parse_json(tostring(DeviceDetail)).deviceId)
        | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, SignInClass, Country, DeviceId),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | where ResultType == 0
        | extend SignInClass = "NonInteractive",
                 Country  = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
                 DeviceId = tostring(parse_json(tostring(DeviceDetail)).deviceId)
        | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, SignInClass, Country, DeviceId)
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | where isnotempty(UserPrincipalName) and not(UserPrincipalName has_any (excl));
let usage = sig
    | summarize SignIns = count(), Interactive = countif(SignInClass == "Interactive"),
                IPs = dcount(IPAddress), Countries = dcountif(Country, isnotempty(Country)),
                Devices = dcountif(DeviceId, isnotempty(DeviceId) and DeviceId != "00000000-0000-0000-0000-000000000000"),
                Apps = make_set(AppDisplayName, 12), LastSeen = max(TimeGenerated)
      by UserPrincipalName;
let ident = IdentityInfo
    | where TimeGenerated {TimeRange}
    | extend UserPrincipalName = tolower(AccountUPN)
    | where isnotempty(UserPrincipalName)
    | summarize arg_max(TimeGenerated, AccountDisplayName, Department, JobTitle, Manager, UserType, IsAccountEnabled, AssignedRoles)
      by UserPrincipalName
    | project-away TimeGenerated;
usage
| join kind=leftouter ident on UserPrincipalName
| extend NameMatch = UserPrincipalName matches regex genericRx
| extend NoOwner = isempty(tostring(Manager)) or tostring(Manager) in ("", "[]", "null")
| extend NoJobTitle = isempty(JobTitle)
| extend Privileged = coalesce(array_length(todynamic(tostring(AssignedRoles))), 0) > 0
| extend NonHumanSignals = toint(NameMatch) + toint(NoOwner) + toint(NoJobTitle) + toint(Interactive == 0)
| where NonHumanSignals >= 2
| extend Classification = case(NameMatch and Interactive > 0, "Generic-named account used interactively - shared human use",
                               NameMatch and Interactive == 0, "Service account - non-interactive only (expected)",
                               NoOwner and NoJobTitle, "Unowned account - no manager, no title",
                               "Multiple non-human signals - review")
| extend Risk = case(Classification startswith "Generic-named account used interactively" and Privileged, "Critical",
                     Classification startswith "Generic-named account used interactively", "High",
                     Privileged, "High", "Medium")
| project UserPrincipalName, AccountDisplayName, Classification, Risk, NonHumanSignals,
          Interactive, SignIns, IPs, Devices, Countries, Privileged, NoOwner, NoJobTitle,
          Department, JobTitle, IsAccountEnabled, Apps, LastSeen
| sort by Risk asc, IPs desc
"""

SERVICE_ACCT_INTERACTIVE = r"""
let genericRx = @"(?i)(^|[._\-])(svc|service|shared|generic|admin|administrator|adm|backup|batch|task|sched|sql|oracle|robot|bot|rpa|automation|integration|api|monitor|jenkins|build|deploy)([._\-]|[0-9]|@|$)";
union isfuzzy=true
  (SigninLogs
     | where TimeGenerated {TimeRange} | where ResultType == 0
     | extend UserPrincipalName = tolower(UserPrincipalName)
     | where UserPrincipalName matches regex genericRx
     | project TimeGenerated, UserPrincipalName, Source = "Entra interactive",
               LogonKind = strcat(ClientAppUsed, " / ", AppDisplayName),
               Host = tostring(DeviceDetail.displayName), IP = IPAddress,
               Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion))),
  (IdentityLogonEvents
     | where TimeGenerated {TimeRange} | where ActionType == "LogonSuccess"
     | where LogonType in ("Interactive", "Remote interactive")
     | extend UserPrincipalName = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
     | where UserPrincipalName matches regex genericRx
     | project TimeGenerated, UserPrincipalName, Source = "On-prem AD (MDI)",
               LogonKind = LogonType, Host = coalesce(DeviceName, TargetDeviceName), IP = IPAddress, Location = "")
| summarize Events = count(), Hosts = dcountif(Host, isnotempty(Host)), IPs = dcountif(IP, isnotempty(IP)),
            HostList = make_set_if(Host, isnotempty(Host), 20), IPList = make_set_if(IP, isnotempty(IP), 20),
            Kinds = make_set(LogonKind, 10), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserPrincipalName, Source
| extend Assessment = case(Hosts >= 5, "Interactive use from many hosts - this is a shared human credential, not a service account",
                           Hosts >= 2, "Interactive use from multiple hosts - verify",
                           "Interactive use - service accounts should not log on interactively")
| project UserPrincipalName, Source, Assessment, Events, Hosts, IPs, Kinds, HostList, IPList, FirstSeen, LastSeen
| sort by Hosts desc, Events desc
"""

DORMANT_ACCOUNTS = r"""
let cutoff = ago({DormantDays}d);
let activity = union isfuzzy=true
    (SigninLogs | where TimeGenerated > ago(365d) | where ResultType == 0
        | extend UserPrincipalName = tolower(UserPrincipalName) | project TimeGenerated, UserPrincipalName, Src = "Entra interactive"),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(365d) | where ResultType == 0
        | extend UserPrincipalName = tolower(UserPrincipalName) | project TimeGenerated, UserPrincipalName, Src = "Entra non-interactive"),
    (IdentityLogonEvents | where TimeGenerated > ago(365d) | where ActionType == "LogonSuccess"
        | extend UserPrincipalName = tolower(AccountUpn) | project TimeGenerated, UserPrincipalName, Src = "On-prem AD")
    | where isnotempty(UserPrincipalName)
    | summarize LastActivity = max(TimeGenerated), Sources = make_set(Src, 5) by UserPrincipalName;
IdentityInfo
| where TimeGenerated > ago(30d)
| extend UserPrincipalName = tolower(AccountUPN)
| where isnotempty(UserPrincipalName)
| summarize arg_max(TimeGenerated, AccountDisplayName, Department, JobTitle, Manager, IsAccountEnabled, AssignedRoles, UserType, OnPremDN = tostring(column_ifexists("OnPremisesDistinguishedName","")))
    by UserPrincipalName
| join kind=leftouter activity on UserPrincipalName
| extend DaysInactive = iff(isnull(LastActivity), 999, toint(datetime_diff('day', now(), LastActivity)))
| where DaysInactive >= {DormantDays}
| where IsAccountEnabled == true
| extend Privileged = coalesce(array_length(todynamic(tostring(AssignedRoles))), 0) > 0
| extend NoOwner = isempty(tostring(Manager)) or tostring(Manager) in ("", "[]", "null")
| extend Risk = case(Privileged, "Critical - dormant privileged account",
                     NoOwner, "High - dormant and unowned",
                     "Medium - dormant")
| project UserPrincipalName, AccountDisplayName, Risk, DaysInactive, LastActivity, Sources,
          IsAccountEnabled, Privileged, NoOwner, Department, JobTitle, UserType, OnPremDN
| sort by Privileged desc, DaysInactive desc
"""

# ================================================================ ON-PREM AD (MDI)

MDI_HOST_FANOUT = r"""
IdentityLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| extend UserPrincipalName = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| where isnotempty(UserPrincipalName)
| summarize Logons = count(),
            SourceHosts = dcountif(DeviceName, isnotempty(DeviceName)),
            TargetHosts = dcountif(TargetDeviceName, isnotempty(TargetDeviceName)),
            SourceIPs = dcountif(IPAddress, isnotempty(IPAddress)),
            LogonTypes = make_set(LogonType, 10),
            Protocols = make_set_if(Protocol, isnotempty(Protocol), 8),
            SourceHostList = make_set_if(DeviceName, isnotempty(DeviceName), 25),
            TargetHostList = make_set_if(TargetDeviceName, isnotempty(TargetDeviceName), 25),
            Apps = make_set_if(Application, isnotempty(Application), 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserPrincipalName, AccountName, AccountDomain
| where SourceHosts > {MaxOnPremHosts} or TargetHosts > {MaxOnPremHosts}
| extend Assessment = case(SourceHosts >= 20, "Very wide host fan-out - shared credential or automation",
                           SourceHosts >= 10, "Wide host fan-out - investigate",
                           "Moderate fan-out - compare to peers in the same department")
| project UserPrincipalName, AccountName, AccountDomain, Assessment, SourceHosts, TargetHosts, SourceIPs,
          Logons, LogonTypes, Protocols, SourceHostList, TargetHostList, Apps, FirstSeen, LastSeen
| sort by SourceHosts desc
"""

MDI_CONCURRENT_HOSTS = r"""
IdentityLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive", "Remote interactive", "Network", "Batch", "Service")
| extend UserPrincipalName = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| where isnotempty(UserPrincipalName)
| extend Host = coalesce(DeviceName, TargetDeviceName)
| where isnotempty(Host)
| summarize Hosts = dcount(Host), IPs = dcountif(IPAddress, isnotempty(IPAddress)),
            HostList = make_set(Host, 20), IPList = make_set_if(IPAddress, isnotempty(IPAddress), 20),
            LogonTypeList = make_set(LogonType, 8), Logons = count()
    by UserPrincipalName, WindowStart = bin(TimeGenerated, {ConcurrencyWindow})
| where Hosts >= 3
| extend Severity = case(Hosts >= 8, "High", Hosts >= 5, "Medium", "Low")
| project WindowStart, UserPrincipalName, Severity, Hosts, IPs, Logons, LogonTypeList, HostList, IPList
| sort by WindowStart desc, Hosts desc
"""

MDI_LOGON_TYPES = r"""
IdentityLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| extend UserPrincipalName = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| where isnotempty(UserPrincipalName)
| summarize Count = count() by LogonType, Protocol = coalesce(Protocol, "Unknown")
| sort by Count desc
"""

MDI_NTLM = r"""
IdentityLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| extend UserPrincipalName = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| where isnotempty(UserPrincipalName)
| summarize Total = count(), Ntlm = countif(Protocol =~ "Ntlm"), Kerberos = countif(Protocol =~ "Kerberos"),
            NtlmHosts = dcountif(DeviceName, Protocol =~ "Ntlm" and isnotempty(DeviceName)),
            NtlmHostList = make_set_if(DeviceName, Protocol =~ "Ntlm" and isnotempty(DeviceName), 20),
            LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where Ntlm > 0
| extend NtlmPct = round(100.0 * Ntlm / Total, 1)
| where NtlmPct > 20 or NtlmHosts >= 5
| extend Assessment = "NTLM authenticates with the password hash only - a hash copied to a second machine is indistinguishable from the real user. High NTLM share plus host fan-out is a credential-sharing or pass-the-hash indicator."
| project UserPrincipalName, NtlmPct, Ntlm, Kerberos, Total, NtlmHosts, NtlmHostList, Assessment, LastSeen
| sort by NtlmHosts desc, NtlmPct desc
"""

MDI_SENSITIVE_GROUPS = r"""
IdentityDirectoryEvents
| where TimeGenerated {TimeRange}
| where ActionType has_any ("Group Membership changed", "Security group membership", "added to group", "removed from group")
| extend Actor = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| extend Target = tolower(coalesce(TargetAccountUpn, TargetAccountDisplayName))
| extend GroupName = tostring(AdditionalFields.["TO.GROUP"]), FromGroup = tostring(AdditionalFields.["FROM.GROUP"])
| project TimeGenerated, ActionType, Actor, Target, GroupName, FromGroup, DeviceName, IPAddress, AdditionalFields
| sort by TimeGenerated desc
"""

MDI_ALERTS = r"""
SecurityAlert
| where TimeGenerated {TimeRange}
| where ProductName has_any ("Microsoft Defender for Identity", "Azure Advanced Threat Protection",
                             "Azure Active Directory Identity Protection", "Microsoft Entra ID Protection",
                             "Microsoft Defender XDR", "Microsoft 365 Defender")
| project TimeGenerated, AlertName, AlertSeverity, ProductName, Status, Description,
          CompromisedEntity, Tactics, Techniques, ExtendedProperties, Entities, SystemAlertId
| sort by TimeGenerated desc
"""

# ================================================================ LOCAL ACCOUNTS (MDE)

LOCAL_ACCOUNT_REUSE = r"""
DeviceLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| where isnotempty(AccountName)
| extend IsLocal = tolower(AccountDomain) == tolower(tostring(split(DeviceName, ".")[0]))
      or AccountDomain in~ ("", "NT AUTHORITY", "Window Manager", "Font Driver Host")
      or AccountSid startswith "S-1-5-21" and tolower(AccountDomain) == tolower(tostring(split(DeviceName, ".")[0]))
| where IsLocal
| where AccountName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1", "ANONYMOUS LOGON", "defaultuser0")
| summarize Devices = dcount(DeviceName), Logons = count(),
            DeviceList = make_set(DeviceName, 30),
            DistinctSids = dcount(AccountSid),
            RemoteLogons = countif(isnotempty(RemoteIP)),
            RemoteIPs = dcountif(RemoteIP, isnotempty(RemoteIP)),
            RemoteIPList = make_set_if(RemoteIP, isnotempty(RemoteIP), 20),
            LogonTypes = make_set(LogonType, 8),
            AdminLogons = countif(IsLocalAdmin == true),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by AccountName
| where Devices > 1
| extend Assessment = case(RemoteLogons > 0 and Devices >= 5,
                             "Same local account name authenticating remotely across many hosts - identical local password (no LAPS) and active lateral use",
                           Devices >= 10, "Same local account name on many hosts - almost certainly a common imaged password. Deploy Windows LAPS.",
                           RemoteLogons > 0, "Local account used over the network - local accounts should never authenticate remotely",
                           "Same local account name present on multiple hosts - verify LAPS randomisation")
| project AccountName, Assessment, Devices, DistinctSids, Logons, AdminLogons, RemoteLogons, RemoteIPs,
          LogonTypes, DeviceList, RemoteIPList, FirstSeen, LastSeen
| sort by Devices desc
"""

LOCAL_ADMIN_REMOTE = r"""
DeviceLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive", "Batch", "Service")
| where isnotempty(RemoteIP) or isnotempty(RemoteDeviceName)
| where IsLocalAdmin == true
| extend Account = strcat(AccountDomain, "\\", AccountName)
| summarize Logons = count(), TargetDevices = dcount(DeviceName), SourceHosts = dcountif(RemoteDeviceName, isnotempty(RemoteDeviceName)),
            SourceIPs = dcountif(RemoteIP, isnotempty(RemoteIP)),
            TargetList = make_set(DeviceName, 25), SourceList = make_set_if(RemoteDeviceName, isnotempty(RemoteDeviceName), 25),
            SourceIPList = make_set_if(RemoteIP, isnotempty(RemoteIP), 25),
            LogonTypes = make_set(LogonType, 6), LastSeen = max(TimeGenerated)
    by Account, AccountSid
| extend Assessment = case(TargetDevices >= 10, "Admin credential sprayed across the estate - classic shared-admin-password lateral movement",
                           TargetDevices >= 3, "Admin credential reused across several hosts",
                           "Remote admin logon")
| project Account, AccountSid, Assessment, TargetDevices, SourceHosts, SourceIPs, Logons, LogonTypes,
          TargetList, SourceList, SourceIPList, LastSeen
| sort by TargetDevices desc
"""

LOCAL_SHARED_WORKSTATION = r"""
DeviceLogonEvents
| where TimeGenerated {TimeRange}
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive", "RemoteInteractive", "CachedInteractive")
| where AccountName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1")
| extend Account = tolower(strcat(AccountDomain, "\\", AccountName))
| summarize Accounts = dcount(Account), Logons = count(), AccountList = make_set(Account, 30),
            LogonTypes = make_set(LogonType, 5), LastSeen = max(TimeGenerated)
    by DeviceName
| where Accounts > {MaxUsersPerDevice}
| extend Assessment = case(Accounts >= 15, "Likely kiosk/shared terminal - confirm it is sanctioned and monitored",
                           Accounts >= 5, "Multi-user endpoint - verify against asset inventory",
                           "Moderate multi-user endpoint")
| project DeviceName, Assessment, Accounts, Logons, LogonTypes, AccountList, LastSeen
| sort by Accounts desc
"""

# ================================================================ RED TEAM TRADECRAFT

RT_CRED_THEFT_ALERTS = r"""
SecurityAlert
| where TimeGenerated {TimeRange}
| where AlertName has_any ("pass-the-hash", "Pass-the-Hash", "pass-the-ticket", "Pass-the-Ticket",
                           "Overpass-the-hash", "Golden Ticket", "Silver Ticket", "Kerberoast",
                           "AS-REP", "DCSync", "DCShadow", "Directory Services Replication",
                           "credential", "Credential", "LSASS", "lsass", "Honeytoken", "honeytoken",
                           "Brute force", "Password spray", "password spray", "NTLM relay",
                           "Suspected identity theft", "Remote code execution attempt",
                           "Malicious request of Data Protection API", "Skeleton Key", "Exchange Server ActiveSync",
                           "Token", "token replay", "Anomalous token")
| extend Technique = case(
      AlertName has_any ("pass-the-hash", "Pass-the-Hash", "Overpass"), "T1550.002 Pass-the-Hash",
      AlertName has_any ("pass-the-ticket", "Pass-the-Ticket"), "T1550.003 Pass-the-Ticket",
      AlertName has_any ("Golden Ticket", "Silver Ticket"), "T1558 Forged Kerberos Tickets",
      AlertName has_any ("Kerberoast", "AS-REP"), "T1558.003 Kerberoasting / AS-REP Roasting",
      AlertName has_any ("DCSync", "Replication"), "T1003.006 DCSync",
      AlertName has_any ("LSASS", "lsass", "Data Protection API"), "T1003.001 LSASS / DPAPI",
      AlertName has_any ("Password spray", "password spray", "Brute force"), "T1110 Brute Force / Spray",
      AlertName has_any ("Honeytoken", "honeytoken"), "Honeytoken - decoy credential touched",
      AlertName has_any ("Token", "token replay", "Anomalous"), "T1539/T1550.001 Token theft & replay",
      "Other credential access")
| project TimeGenerated, AlertSeverity, AlertName, Technique, ProductName, CompromisedEntity,
          Status, Tactics, Description, SystemAlertId
| sort by TimeGenerated desc
"""

RT_KERBEROAST = r"""
IdentityQueryEvents
| where TimeGenerated {TimeRange}
| where ActionType in ("SAMR query", "LDAP query", "DNS query")
| extend Actor = tolower(coalesce(AccountUpn, strcat(AccountName, "@", AccountDomain)))
| where isnotempty(Actor)
| summarize Queries = count(), QueryTypes = make_set(ActionType, 5),
            TargetsEnumerated = dcountif(QueryTarget, isnotempty(QueryTarget)),
            Sample = make_set_if(Query, isnotempty(Query), 10),
            Hosts = dcountif(DeviceName, isnotempty(DeviceName)),
            HostList = make_set_if(DeviceName, isnotempty(DeviceName), 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Actor, Protocol = coalesce(Protocol, "")
| where TargetsEnumerated >= 20 or Queries >= 200
| extend Assessment = "High-volume directory enumeration. This is the reconnaissance step before Kerberoasting, targeted password attacks, or building a list of shared/service accounts to attack."
| project Actor, Protocol, Assessment, Queries, TargetsEnumerated, Hosts, QueryTypes, HostList, Sample, FirstSeen, LastSeen
| sort by TargetsEnumerated desc
"""

RT_LSASS = r"""
DeviceEvents
| where TimeGenerated {TimeRange}
| where ActionType in ("OpenProcessApiCall", "ReadProcessMemoryApiCall", "ProcessPrimaryTokenModified",
                       "NamedPipeEvent", "LsassDumpDetected", "SensitiveCredentialMemoryRead")
| where FileName =~ "lsass.exe" or tostring(AdditionalFields) has "lsass"
| project TimeGenerated, DeviceName, ActionType, FileName,
          Initiator = InitiatingProcessFileName, InitiatorCmd = InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain, AdditionalFields
| sort by TimeGenerated desc
"""

RT_CRED_HUNTING = r"""
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd has_any ("findstr /si password", "findstr /s /i pass", "unattend.xml", "sysprep.inf",
                     "get-credential", "convertto-securestring", "cmdkey /list", "cmdkey /add",
                     "vaultcmd", "net user /domain", "dsquery user", "reg query hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon",
                     "defaultpassword", "-encodedcommand", "invoke-mimikatz", "sekurlsa", "lsadump",
                     "procdump", "comsvcs.dll, minidump", "rundll32 comsvcs", "secretsdump",
                     "laZagne", "seatbelt", "sharphound", "rubeus", "certipy", "adfind",
                     "psexec", "wmic /node:", "enter-pssession", "new-pssession")
| extend Tradecraft = case(
      Cmd has_any ("invoke-mimikatz","sekurlsa","lsadump","procdump","comsvcs","secretsdump","lazagne"), "Credential dumping",
      Cmd has_any ("rubeus","certipy"), "Kerberos / certificate abuse",
      Cmd has_any ("sharphound","adfind","dsquery user","net user /domain","seatbelt"), "Directory / credential reconnaissance",
      Cmd has_any ("cmdkey","vaultcmd","get-credential","convertto-securestring"), "Stored credential access",
      Cmd has_any ("findstr /si password","findstr /s /i pass","unattend.xml","sysprep.inf","defaultpassword"), "Password hunting in files/registry",
      Cmd has_any ("psexec","wmic /node:","enter-pssession","new-pssession"), "Lateral movement with reused credentials",
      "Suspicious command")
| project TimeGenerated, DeviceName, Tradecraft, AccountDomain, AccountName,
          FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
"""

RT_TOKEN_REPLAY = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
AADNonInteractiveUserSignInLogs
| where TimeGenerated {TimeRange}
| where ResultType == 0
| where isnotempty(UniqueTokenIdentifier)
| extend UserPrincipalName = tolower(UserPrincipalName)
| where isnotempty(UserPrincipalName) and not(UserPrincipalName has_any (excl))
| extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city)
| summarize IPs = dcount(IPAddress), ASNs = dcountif(AutonomousSystemNumber, isnotempty(AutonomousSystemNumber)),
            Countries = dcountif(Country, isnotempty(Country)),
            IPList = make_set(IPAddress, 15), CountryList = make_set_if(Country, isnotempty(Country), 10),
            Apps = make_set(AppDisplayName, 10), TokenType = any(tostring(column_ifexists("IncomingTokenType",""))),
            Uses = count(), FirstUse = min(TimeGenerated), LastUse = max(TimeGenerated)
    by UserPrincipalName, UniqueTokenIdentifier
| where IPs > 1
| extend Assessment = case(Countries > 1, "Same refresh/session token used from multiple countries - token theft (AiTM) or deliberate session sharing",
                           ASNs > 1, "Same token used across different networks - copied session or proxy",
                           "Same token from multiple IPs in one network - often NAT churn, lower confidence")
| project UserPrincipalName, Assessment, IPs, ASNs, Countries, Uses, TokenType, UniqueTokenIdentifier,
          IPList, CountryList, Apps, FirstUse, LastUse
| sort by Countries desc, IPs desc
"""

RT_DEVICE_CODE = r"""
SigninLogs
| where TimeGenerated {TimeRange}
| extend Protocol = tostring(column_ifexists("AuthenticationProtocol", ""))
| where Protocol in~ ("deviceCode", "ropc")
| extend UserPrincipalName = tolower(UserPrincipalName)
| extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city)
| summarize SignIns = count(), Successes = countif(ResultType == 0), IPs = dcount(IPAddress),
            Countries = dcountif(Country, isnotempty(Country)),
            IPList = make_set(IPAddress, 15), CountryList = make_set_if(Country, isnotempty(Country), 10),
            Apps = make_set(AppDisplayName, 10), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserPrincipalName, Protocol
| extend Assessment = case(Protocol =~ "deviceCode", "Device code flow - a user can complete sign-in for a code generated on someone else's machine. Both a phishing technique and the easiest consensual way to hand a session to another person.",
                           "Resource Owner Password Credentials - the raw password is submitted to the app, so it must be known to whoever runs it. Should be blocked outright.")
| project UserPrincipalName, Protocol, Assessment, SignIns, Successes, IPs, Countries, IPList, CountryList, Apps, FirstSeen, LastSeen
| sort by Successes desc
"""

RT_SPRAY_VS_STUFFING = r"""
SigninLogs
| where TimeGenerated {TimeRange}
| where ResultType != 0
| extend UserPrincipalName = tolower(UserPrincipalName)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Failures = count(), TargetedAccounts = dcount(UserPrincipalName),
            FailureCodes = make_set(ResultType, 10),
            Accounts = make_set(UserPrincipalName, 25),
            Countries = make_set_if(Country, isnotempty(Country), 5),
            Apps = make_set(AppDisplayName, 8),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by IPAddress, ASN = tostring(column_ifexists("AutonomousSystemNumber",""))
| where TargetedAccounts >= 5 or Failures >= 50
| extend Pattern = case(TargetedAccounts >= 20 and Failures / TargetedAccounts <= 3, "Password spray - few attempts against many accounts",
                        TargetedAccounts <= 3 and Failures >= 50, "Brute force - many attempts against few accounts",
                        "Credential stuffing - reused credential list")
| project IPAddress, ASN, Pattern, TargetedAccounts, Failures, Countries, FailureCodes, Apps, Accounts, FirstSeen, LastSeen
| sort by TargetedAccounts desc
"""

RT_RDP_SHADOW = r"""
union isfuzzy=true
  (DeviceProcessEvents
     | where TimeGenerated {TimeRange}
     | extend Cmd = tolower(ProcessCommandLine)
     | where Cmd has_any ("mstsc /shadow", "/shadow:", "quser", "qwinsta", "tscon ", "rwinsta",
                          "reg add", "fdenytsconnections", "maxinstancecount")
     | where Cmd has_any ("shadow", "tscon", "fdenytsconnections", "quser", "qwinsta")
     | project TimeGenerated, DeviceName, Source = "Process", AccountName, AccountDomain,
               Detail = ProcessCommandLine, Extra = InitiatingProcessCommandLine),
  (DeviceLogonEvents
     | where TimeGenerated {TimeRange}
     | where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
     | summarize Sessions = count(), Sources = dcountif(RemoteIP, isnotempty(RemoteIP)),
                 SourceList = make_set_if(RemoteIP, isnotempty(RemoteIP), 15)
         by DeviceName, AccountName, AccountDomain, Win = bin(TimeGenerated, {ConcurrencyWindow})
     | where Sources >= 2
     | project TimeGenerated = Win, DeviceName, Source = "Concurrent RDP",
               AccountName, AccountDomain,
               Detail = strcat("Same account held RDP sessions from ", Sources, " distinct source IPs in one window"),
               Extra = tostring(SourceList))
| sort by TimeGenerated desc
"""

RT_MDI_HONEYTOKEN = r"""
union isfuzzy=true
  (SecurityAlert
     | where TimeGenerated {TimeRange}
     | where AlertName has "oneytoken"
     | project TimeGenerated, Signal = "MDI honeytoken alert", Detail = AlertName,
               Entity = CompromisedEntity, Severity = AlertSeverity, Extra = Description),
  (IdentityLogonEvents
     | where TimeGenerated {TimeRange}
     | where tostring(AdditionalFields) has "Honeytoken" or tostring(AdditionalFields) has "honeytoken"
     | project TimeGenerated, Signal = "Honeytoken logon activity", Detail = ActionType,
               Entity = coalesce(AccountUpn, AccountName), Severity = "Medium", Extra = tostring(AdditionalFields))
| sort by TimeGenerated desc
"""

RT_UEBA = r"""
BehaviorAnalytics
| where TimeGenerated {TimeRange}
| where isnotempty(UserPrincipalName)
| extend UserPrincipalName = tolower(UserPrincipalName)
| extend Insights = tostring(ActivityInsights)
| where Insights has_any ("FirstTimeUserConnectedFromCountry", "FirstTimeUserConnectedViaISP",
                          "FirstTimeUserLoggedOnToDevice", "FirstTimeUserAccessedResource",
                          "CountryUncommonlyConnectedFromAmongPeers", "ISPUncommonlyUsedAmongPeers",
                          "ActionUncommonlyPerformedByUser", "FirstTimeUserUsedApp")
| summarize Anomalies = count(), MaxPriority = max(InvestigationPriority),
            Types = make_set(ActivityType, 10),
            Insights = make_set(Insights, 8),
            Devices = make_set_if(tostring(DevicesInsights), isnotempty(tostring(DevicesInsights)), 5),
            SourceIPs = make_set_if(SourceIPAddress, isnotempty(SourceIPAddress), 15),
            LastSeen = max(TimeGenerated)
    by UserPrincipalName
| sort by MaxPriority desc, Anomalies desc
"""

# ================================================================ DRILLDOWN

DRILL_TIMELINE = r"""
let u = tolower("{TargetUser}");
union isfuzzy=true
  (SigninLogs | where TimeGenerated {TimeRange} | where tolower(UserPrincipalName) == u
     | project TimeGenerated, Source = "Entra interactive", Result = iff(ResultType == 0, "Success", strcat("Fail ", ResultType)),
               IP = IPAddress, Where = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
               Device = tostring(DeviceDetail.displayName), Client = ClientAppUsed, App = AppDisplayName,
               Detail = strcat(AuthenticationRequirement, " | ", tostring(DeviceDetail.operatingSystem), " | ", tostring(DeviceDetail.browser))),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | where tolower(UserPrincipalName) == u
     | project TimeGenerated, Source = "Entra non-interactive", Result = iff(ResultType == 0, "Success", strcat("Fail ", ResultType)),
               IP = IPAddress, Where = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
               Device = tostring(DeviceDetail.displayName), Client = ClientAppUsed, App = AppDisplayName,
               Detail = tostring(column_ifexists("UniqueTokenIdentifier",""))),
  (IdentityLogonEvents | where TimeGenerated {TimeRange} | where tolower(AccountUpn) == u
     | project TimeGenerated, Source = "On-prem AD (MDI)", Result = ActionType, IP = IPAddress, Where = "",
               Device = coalesce(DeviceName, TargetDeviceName), Client = LogonType, App = Application,
               Detail = strcat(coalesce(Protocol,""), " -> ", coalesce(TargetDeviceName,""))),
  (AuditLogs | where TimeGenerated {TimeRange}
     | where tolower(tostring(TargetResources[0].userPrincipalName)) == u or tolower(tostring(InitiatedBy.user.userPrincipalName)) == u
     | project TimeGenerated, Source = "Entra audit", Result = tostring(Result), IP = tostring(InitiatedBy.user.ipAddress),
               Where = "", Device = "", Client = Category, App = OperationName,
               Detail = strcat("actor=", tostring(InitiatedBy.user.userPrincipalName)))
| sort by TimeGenerated desc
"""

DRILL_IP_SUMMARY = r"""
let u = tolower("{TargetUser}");
union isfuzzy=true
  (SigninLogs | where TimeGenerated {TimeRange} | where ResultType == 0 | where tolower(UserPrincipalName) == u
     | extend K = "Interactive",
              Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
              City    = tostring(parse_json(tostring(LocationDetails)).city),
              Device  = tostring(parse_json(tostring(DeviceDetail)).displayName),
              OS      = tostring(parse_json(tostring(DeviceDetail)).operatingSystem),
              Browser = tostring(parse_json(tostring(DeviceDetail)).browser),
              Trust   = tostring(parse_json(tostring(DeviceDetail)).trustType),
              ASN     = tostring(column_ifexists("AutonomousSystemNumber", ""))
     | project TimeGenerated, IPAddress, AppDisplayName, K, Country, City, Device, OS, Browser, Trust, ASN),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | where ResultType == 0 | where tolower(UserPrincipalName) == u
     | extend K = "NonInteractive",
              Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
              City    = tostring(parse_json(tostring(LocationDetails)).city),
              Device  = tostring(parse_json(tostring(DeviceDetail)).displayName),
              OS      = tostring(parse_json(tostring(DeviceDetail)).operatingSystem),
              Browser = tostring(parse_json(tostring(DeviceDetail)).browser),
              Trust   = tostring(parse_json(tostring(DeviceDetail)).trustType),
              ASN     = tostring(column_ifexists("AutonomousSystemNumber", ""))
     | project TimeGenerated, IPAddress, AppDisplayName, K, Country, City, Device, OS, Browser, Trust, ASN)
| summarize SignIns = count(), Days = dcount(bin(TimeGenerated, 1d)),
            Devices = make_set_if(Device, isnotempty(Device), 10),
            OSList = make_set_if(OS, isnotempty(OS), 6), Browsers = make_set_if(Browser, isnotempty(Browser), 6),
            Apps = make_set(AppDisplayName, 10), Kinds = make_set(K, 3),
            Managed = countif(isnotempty(Trust)),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by IPAddress, City, Country, ASN
| extend ManagedPct = round(100.0 * Managed / SignIns, 1)
| sort by SignIns desc
"""

DRILL_HOURLY = r"""
let u = tolower("{TargetUser}");
union isfuzzy=true
  (SigninLogs | where TimeGenerated {TimeRange} | where ResultType == 0 | where tolower(UserPrincipalName) == u
     | extend Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
     | project TimeGenerated, Country),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | where ResultType == 0 | where tolower(UserPrincipalName) == u
     | extend Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
     | project TimeGenerated, Country)
| where isnotempty(Country)
| summarize SignIns = count() by Country, Hour = bin(TimeGenerated, 1h)
| sort by Hour asc
"""

DRILL_ALERTS = r"""
let u = tolower("{TargetUser}");
SecurityAlert
| where TimeGenerated {TimeRange}
| where tolower(Entities) has u or tolower(CompromisedEntity) has u or tolower(ExtendedProperties) has u
| project TimeGenerated, AlertName, AlertSeverity, ProductName, Status, Tactics, Description, SystemAlertId
| sort by TimeGenerated desc
"""

DRILL_LIST = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
union isfuzzy=true
  (SigninLogs | where TimeGenerated {TimeRange} | where ResultType == 0),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | where ResultType == 0)
| extend UserPrincipalName = tolower(UserPrincipalName)
| where isnotempty(UserPrincipalName) and not(UserPrincipalName has_any (excl))
| summarize Cnt = count() by UserPrincipalName
| sort by Cnt desc
| project value = UserPrincipalName, label = UserPrincipalName
| take 2000
"""
