# -*- coding: utf-8 -*-
"""KQL for the Overview / scorecard, concurrency and fan-out tabs."""

# ---------------------------------------------------------------- shared prelude
# Re-used building blocks. Kept as one string so every query is self-contained
# (workbooks do not share 'let' statements between query items).
PRELUDE = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
let genericRx = @"(?i)(^|[._\-])(svc|service|shared|generic|common|team|group|dept|admin|administrator|adm|test|tst|temp|tmp|training|train|demo|kiosk|lobby|frontdesk|reception|scanner|scan|printer|print|copier|fax|conf|conference|room|guest|intern|contractor|vendor|support|helpdesk|sql|oracle|backup|batch|task|sched|robot|bot|rpa|automation|integration|api|app|monitor|nagios|zabbix|splunk|jenkins|build|deploy)([._\-]|[0-9]|@|$)";
// Dynamic fields are unpacked inside each leg. Unpacking after a union fails
// with "Failed to resolve expression 'DeviceDetail.deviceId'" because the
// unioned column is no longer statically known to be dynamic.
let sig = union isfuzzy=true
    (SigninLogs
        | where TimeGenerated {TimeRange}
        | where ResultType == 0
        | extend SignInClass  = "Interactive",
                 DeviceId     = tostring(parse_json(tostring(DeviceDetail)).deviceId),
                 DeviceDisplay= tostring(parse_json(tostring(DeviceDetail)).displayName),
                 OSName       = tostring(parse_json(tostring(DeviceDetail)).operatingSystem),
                 BrowserName  = tostring(parse_json(tostring(DeviceDetail)).browser),
                 TrustType    = tostring(parse_json(tostring(DeviceDetail)).trustType),
                 Country      = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
                 City         = tostring(parse_json(tostring(LocationDetails)).city),
                 ASN          = tostring(column_ifexists("AutonomousSystemNumber", ""))
        | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed,
                  AuthenticationRequirement, SignInClass, DeviceId, DeviceDisplay, OSName,
                  BrowserName, TrustType, Country, City, ASN),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated {TimeRange}
        | where ResultType == 0
        | extend SignInClass  = "NonInteractive",
                 DeviceId     = tostring(parse_json(tostring(DeviceDetail)).deviceId),
                 DeviceDisplay= tostring(parse_json(tostring(DeviceDetail)).displayName),
                 OSName       = tostring(parse_json(tostring(DeviceDetail)).operatingSystem),
                 BrowserName  = tostring(parse_json(tostring(DeviceDetail)).browser),
                 TrustType    = tostring(parse_json(tostring(DeviceDetail)).trustType),
                 Country      = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
                 City         = tostring(parse_json(tostring(LocationDetails)).city),
                 ASN          = tostring(column_ifexists("AutonomousSystemNumber", ""))
        | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed,
                  AuthenticationRequirement, SignInClass, DeviceId, DeviceDisplay, OSName,
                  BrowserName, TrustType, Country, City, ASN)
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | where isnotempty(UserPrincipalName)
    | where not(UserPrincipalName has_any (excl))
    | extend DeviceId = iff(DeviceId == "00000000-0000-0000-0000-000000000000", "", DeviceId);
"""

# ---------------------------------------------------------------- overview tiles
TILES = PRELUDE + r"""
let totalUsers = toscalar(sig | summarize dcount(UserPrincipalName));
let multiIp = toscalar(sig
    | summarize IPs = dcount(IPAddress) by UserPrincipalName
    | where IPs > {MaxIPs} | count);
let multiDev = toscalar(sig
    | summarize D = dcountif(DeviceId, isnotempty(DeviceId)) by UserPrincipalName
    | where D > {MaxDevices} | count);
let multiGeo = toscalar(sig
    | summarize C = dcountif(Country, isnotempty(Country)) by UserPrincipalName
    | where C > {MaxCountries} | count);
let concur = toscalar(sig
    | summarize IPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, {ConcurrencyWindow})
    | where IPs >= 3
    | distinct UserPrincipalName | count);
let generic = toscalar(sig
    | where UserPrincipalName matches regex genericRx
    | distinct UserPrincipalName | count);
let sharedDev = toscalar(sig
    | where isnotempty(DeviceId)
    | summarize U = dcount(UserPrincipalName) by DeviceId
    | where U > {MaxUsersPerDevice} | count);
let legacy = toscalar(sig
    | where ClientAppUsed in ("Other clients","IMAP4","POP3","SMTP","MAPI","Exchange ActiveSync","Authenticated SMTP","Exchange Web Services","Exchange Online PowerShell")
    | distinct UserPrincipalName | count);
datatable(Ord:int, Metric:string)
[
    1, "Accounts observed",
    2, "Above IP fan-out threshold",
    3, "Above device fan-out threshold",
    4, "Above country fan-out threshold",
    5, "Concurrent-session accounts",
    6, "Generic / service-named accounts",
    7, "Devices used by many accounts",
    8, "Accounts using legacy auth"
]
| extend Value = case(Ord == 1, totalUsers, Ord == 2, multiIp, Ord == 3, multiDev,
                      Ord == 4, multiGeo, Ord == 5, concur, Ord == 6, generic,
                      Ord == 7, sharedDev, legacy)
| sort by Ord asc
| project Metric, Value
"""

# ---------------------------------------------------------------- scorecard
SCORECARD = PRELUDE + r"""
let base = sig
    | summarize
        SignIns          = count(),
        DistinctIPs      = dcount(IPAddress),
        DistinctASNs     = dcountif(ASN, isnotempty(ASN)),
        DistinctCountries= dcountif(Country, isnotempty(Country)),
        DistinctCities   = dcountif(City, isnotempty(City)),
        DistinctDevices  = dcountif(DeviceId, isnotempty(DeviceId)),
        DistinctOS       = dcountif(OSName, isnotempty(OSName)),
        DistinctBrowsers = dcountif(BrowserName, isnotempty(BrowserName)),
        UnmanagedPct     = round(100.0 * countif(isempty(TrustType)) / count(), 1),
        LegacyAuthHits   = countif(ClientAppUsed in ("Other clients","IMAP4","POP3","SMTP","MAPI","Exchange ActiveSync","Authenticated SMTP","Exchange Web Services","Exchange Online PowerShell")),
        SingleFactorHits = countif(AuthenticationRequirement =~ "singleFactorAuthentication"),
        ActiveDays       = dcount(bin(TimeGenerated, 1d)),
        FirstSeen        = min(TimeGenerated),
        LastSeen         = max(TimeGenerated),
        TopCountries     = make_set_if(Country, isnotempty(Country), 8)
      by UserPrincipalName;
let concur = sig
    | summarize WinIPs = dcount(IPAddress), WinCountries = dcountif(Country, isnotempty(Country)), WinDevices = dcountif(DeviceId, isnotempty(DeviceId))
        by UserPrincipalName, Win = bin(TimeGenerated, {ConcurrencyWindow})
    | summarize ConcurrentWindows  = countif(WinIPs >= 3),
                MaxIPsPerWindow    = max(WinIPs),
                MultiGeoWindows    = countif(WinCountries >= 2),
                MaxDevicesPerWindow= max(WinDevices)
      by UserPrincipalName;
let risk = materialize(AADUserRiskEvents
    | where TimeGenerated {TimeRange}
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | summarize ImpossibleTravel = countif(RiskEventType has "mpossibleTravel"),
                LeakedCredential = countif(RiskEventType =~ "leakedCredentials"),
                AnomalousToken   = countif(RiskEventType in~ ("anomalousToken","tokenIssuerAnomaly")),
                UnfamiliarSignIn = countif(RiskEventType =~ "unfamiliarFeatures"),
                PasswordSpray    = countif(RiskEventType =~ "passwordSpray")
      by UserPrincipalName);
let replay = AADNonInteractiveUserSignInLogs
    | where TimeGenerated {TimeRange}
    | where ResultType == 0 and isnotempty(UniqueTokenIdentifier)
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | summarize TokIPs = dcount(IPAddress) by UserPrincipalName, UniqueTokenIdentifier
    | where TokIPs > 1
    | summarize ReplayedTokens = count(), MaxIPsPerToken = max(TokIPs) by UserPrincipalName;
let onprem = IdentityLogonEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "LogonSuccess"
    | where isnotempty(AccountUpn)
    | extend UserPrincipalName = tolower(AccountUpn)
    | summarize OnPremSourceHosts = dcountif(DeviceName, isnotempty(DeviceName)),
                OnPremSourceIPs   = dcountif(IPAddress, isnotempty(IPAddress)),
                OnPremTargetHosts = dcountif(TargetDeviceName, isnotempty(TargetDeviceName)),
                RemoteInteractive = countif(LogonType =~ "Remote interactive"),
                NtlmLogons        = countif(Protocol =~ "Ntlm")
      by UserPrincipalName;
let ident = IdentityInfo
    | where TimeGenerated {TimeRange}
    | extend UserPrincipalName = tolower(AccountUPN)
    | where isnotempty(UserPrincipalName)
    | summarize arg_max(TimeGenerated, AccountDisplayName, Department, JobTitle, UserType, IsAccountEnabled, AssignedRoles, Manager)
      by UserPrincipalName
    | project-away TimeGenerated;
base
| join kind=leftouter concur  on UserPrincipalName
| join kind=leftouter risk    on UserPrincipalName
| join kind=leftouter replay  on UserPrincipalName
| join kind=leftouter onprem  on UserPrincipalName
| join kind=leftouter ident   on UserPrincipalName
| extend GenericName = UserPrincipalName matches regex genericRx
| extend Privileged  = coalesce(array_length(todynamic(tostring(AssignedRoles))), 0) > 0
| extend
    s_ip      = toint(min_of(20, DistinctIPs       * 20 / max_of({MaxIPs}, 1))),
    s_dev     = toint(min_of(15, DistinctDevices   * 15 / max_of({MaxDevices}, 1))),
    s_geo     = toint(min_of(15, DistinctCountries * 15 / max_of({MaxCountries}, 1))),
    s_concur  = toint(min_of(20, coalesce(ConcurrentWindows, 0) * 4 + coalesce(MultiGeoWindows, 0) * 6)),
    s_risk    = toint(min_of(15, coalesce(ImpossibleTravel,0)*5 + coalesce(LeakedCredential,0)*8 + coalesce(AnomalousToken,0)*6 + coalesce(UnfamiliarSignIn,0)*2)),
    s_replay  = toint(min_of(10, coalesce(ReplayedTokens, 0) * 3)),
    s_hyg     = toint(min_of(10, iff(LegacyAuthHits > 0, 5, 0) + iff(SingleFactorHits > 0, 3, 0) + iff(UnmanagedPct > 50, 2, 0))),
    s_name    = toint(iff(GenericName, 10, 0)),
    s_onprem  = toint(min_of(10, coalesce(OnPremSourceHosts, 0) / 2))
| extend SharingScore = min_of(100, s_ip + s_dev + s_geo + s_concur + s_risk + s_replay + s_hyg + s_name + s_onprem)
| extend Band = case(SharingScore >= 70, "1 - Critical", SharingScore >= 50, "2 - High", SharingScore >= 30, "3 - Medium", SharingScore >= 15, "4 - Low", "5 - Informational")
| extend Drivers = strcat_array(set_difference(pack_array(
        iff(s_concur >= 8,  strcat("concurrent-sessions(", ConcurrentWindows, ")"), ""),
        iff(s_ip     >= 8,  strcat("ip-fanout(", DistinctIPs, ")"), ""),
        iff(s_dev    >= 8,  strcat("device-fanout(", DistinctDevices, ")"), ""),
        iff(s_geo    >= 8,  strcat("geo-fanout(", DistinctCountries, ")"), ""),
        iff(s_risk   >= 5,  "entra-risk", ""),
        iff(s_replay >= 3,  strcat("token-replay(", ReplayedTokens, ")"), ""),
        iff(s_name   >  0,  "generic-name", ""),
        iff(s_hyg    >= 5,  "weak-auth", ""),
        iff(s_onprem >= 5,  strcat("onprem-host-fanout(", OnPremSourceHosts, ")"), "")),
        dynamic([""])), ", ")
| where SharingScore >= {MinScore}
| project UserPrincipalName, AccountDisplayName, SharingScore, Band, Drivers,
          Department, JobTitle, Privileged, GenericName, IsAccountEnabled,
          SignIns, ActiveDays, DistinctIPs, DistinctASNs, DistinctDevices,
          DistinctCountries, DistinctCities, DistinctOS, DistinctBrowsers,
          ConcurrentWindows, MaxIPsPerWindow, MultiGeoWindows,
          ImpossibleTravel, LeakedCredential, AnomalousToken, PasswordSpray,
          ReplayedTokens, OnPremSourceHosts, OnPremTargetHosts, RemoteInteractive, NtlmLogons,
          LegacyAuthHits, SingleFactorHits, UnmanagedPct, TopCountries, FirstSeen, LastSeen
| sort by SharingScore desc, DistinctIPs desc
"""

BAND_CHART = PRELUDE + r"""
sig
| summarize DistinctIPs = dcount(IPAddress),
            DistinctDevices = dcountif(DeviceId, isnotempty(DeviceId)),
            DistinctCountries = dcountif(Country, isnotempty(Country))
    by UserPrincipalName
| extend Score = min_of(100,
      toint(min_of(40, DistinctIPs * 40 / max_of({MaxIPs},1))) +
      toint(min_of(30, DistinctDevices * 30 / max_of({MaxDevices},1))) +
      toint(min_of(30, DistinctCountries * 30 / max_of({MaxCountries},1))))
| extend Band = case(Score >= 70, "1 - Critical", Score >= 50, "2 - High", Score >= 30, "3 - Medium", Score >= 15, "4 - Low", "5 - Informational")
| summarize Accounts = dcount(UserPrincipalName) by Band
| sort by Band asc
"""

TREND = PRELUDE + r"""
sig
| summarize IPs = dcount(IPAddress), Devices = dcountif(DeviceId, isnotempty(DeviceId)), Countries = dcountif(Country, isnotempty(Country))
    by UserPrincipalName, Day = bin(TimeGenerated, 1d)
| summarize ["Accounts over IP threshold"]      = dcountif(UserPrincipalName, IPs > {MaxIPs}),
            ["Accounts over device threshold"]  = dcountif(UserPrincipalName, Devices > {MaxDevices}),
            ["Accounts over country threshold"] = dcountif(UserPrincipalName, Countries > {MaxCountries})
    by Day
| sort by Day asc
"""

# ---------------------------------------------------------------- concurrency
CONCURRENT_SESSIONS = PRELUDE + r"""
sig
| summarize IPs = dcount(IPAddress), Countries = dcountif(Country, isnotempty(Country)),
            Devices = dcountif(DeviceId, isnotempty(DeviceId)), ASNs = dcountif(ASN, isnotempty(ASN)),
            SignIns = count(),
            IPList = make_set(IPAddress, 15), CountryList = make_set_if(Country, isnotempty(Country), 10),
            CityList = make_set_if(City, isnotempty(City), 10), DeviceList = make_set_if(DeviceDisplay, isnotempty(DeviceDisplay), 10),
            AppList = make_set(AppDisplayName, 10), ClientList = make_set(ClientAppUsed, 8)
    by UserPrincipalName, WindowStart = bin(TimeGenerated, {ConcurrencyWindow})
| where IPs >= 3 or (IPs >= 2 and Countries >= 2)
| extend Severity = case(Countries >= 3 or IPs >= 6, "High", Countries >= 2 or IPs >= 4, "Medium", "Low")
| project WindowStart, UserPrincipalName, Severity, IPs, ASNs, Countries, Devices, SignIns,
          IPList, CountryList, CityList, DeviceList, AppList, ClientList
| sort by WindowStart desc, IPs desc
"""

CONCURRENT_ROLLUP = PRELUDE + r"""
sig
| summarize IPs = dcount(IPAddress), Countries = dcountif(Country, isnotempty(Country))
    by UserPrincipalName, Win = bin(TimeGenerated, {ConcurrencyWindow})
| where IPs >= 3 or (IPs >= 2 and Countries >= 2)
| summarize OverlapWindows = count(), MaxIPs = max(IPs), MaxCountries = max(Countries),
            FirstOverlap = min(Win), LastOverlap = max(Win), DaysWithOverlap = dcount(bin(Win, 1d))
    by UserPrincipalName
| extend Persistence = case(DaysWithOverlap >= 10, "Persistent - likely shared", DaysWithOverlap >= 3, "Recurring - investigate", "Sporadic")
| sort by OverlapWindows desc
"""

GEO_VELOCITY = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
SigninLogs
| where TimeGenerated {TimeRange}
| where ResultType == 0
| extend UserPrincipalName = tolower(UserPrincipalName)
| where isnotempty(UserPrincipalName) and not(UserPrincipalName has_any (excl))
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude),
         Lon = toreal(LocationDetails.geoCoordinates.longitude),
         City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Lat) and isnotnull(Lon)
| project TimeGenerated, UserPrincipalName, IPAddress, Lat, Lon, City, Country, AppDisplayName, UserAgent = tostring(column_ifexists("UserAgent",""))
| sort by UserPrincipalName asc, TimeGenerated asc
| extend pUser = prev(UserPrincipalName), pTime = prev(TimeGenerated), pLat = prev(Lat), pLon = prev(Lon),
         pIP = prev(IPAddress), pCity = prev(City), pCountry = prev(Country)
| where pUser == UserPrincipalName
| extend DistanceKm = round(geo_distance_2points(pLon, pLat, Lon, Lat) / 1000.0, 1)
| extend ElapsedHours = round(todouble(datetime_diff('second', TimeGenerated, pTime)) / 3600.0, 4)
| where DistanceKm > 150 and ElapsedHours >= 0
| extend RequiredSpeedKmh = iff(ElapsedHours <= 0.0, 999999.0, round(DistanceKm / ElapsedHours, 0))
| where RequiredSpeedKmh > 900
| extend Verdict = case(RequiredSpeedKmh > 5000, "Physically impossible - concurrent use or proxy",
                        RequiredSpeedKmh > 1500, "Impossible without flight - very likely shared",
                        "Faster than commercial flight - review")
| project TimeGenerated, UserPrincipalName, Verdict, RequiredSpeedKmh, DistanceKm, ElapsedHours,
          FromCity = pCity, FromCountry = pCountry, FromIP = pIP,
          ToCity = City, ToCountry = Country, ToIP = IPAddress, AppDisplayName, UserAgent
| sort by TimeGenerated desc
"""

# ---------------------------------------------------------------- fan-out
DEVICE_SHARED_BY_USERS = PRELUDE + r"""
sig
| where isnotempty(DeviceId)
| summarize Users = dcount(UserPrincipalName), SignIns = count(),
            UserList = make_set(UserPrincipalName, 30),
            LastSeen = max(TimeGenerated), Days = dcount(bin(TimeGenerated, 1d))
    by DeviceId, DeviceDisplay, OSName, TrustType
| where Users > {MaxUsersPerDevice}
| extend DeviceClass = case(isempty(TrustType), "Unmanaged / BYOD", TrustType)
| extend Assessment = case(Users >= 15, "Kiosk / shared workstation - confirm intent",
                           Users >= 5,  "Multi-user endpoint - verify",
                           "Low fan-out")
| project DeviceDisplay, DeviceId, DeviceClass, OSName, Users, SignIns, Days, Assessment, UserList, LastSeen
| sort by Users desc
"""

USER_DEVICE_FANOUT = PRELUDE + r"""
sig
| summarize Devices = dcountif(DeviceId, isnotempty(DeviceId)),
            ManagedDevices = dcountif(DeviceId, isnotempty(DeviceId) and isnotempty(TrustType)),
            UnmanagedSignIns = countif(isempty(TrustType)),
            OSTypes = dcountif(OSName, isnotempty(OSName)),
            Browsers = dcountif(BrowserName, isnotempty(BrowserName)),
            SignIns = count(),
            DeviceList = make_set_if(DeviceDisplay, isnotempty(DeviceDisplay), 20),
            OSList = make_set_if(OSName, isnotempty(OSName), 10),
            BrowserList = make_set_if(BrowserName, isnotempty(BrowserName), 10)
    by UserPrincipalName
| where Devices > {MaxDevices} or OSTypes >= 3
| extend UnmanagedDevices = Devices - ManagedDevices
| extend Assessment = case(OSTypes >= 4 and Devices > {MaxDevices}, "Heterogeneous OS + high device count - strong sharing indicator",
                           OSTypes >= 3, "Multiple OS families - possible sharing",
                           "High device count - verify device refresh or BYOD")
| project UserPrincipalName, Assessment, Devices, ManagedDevices, UnmanagedDevices, OSTypes, Browsers, SignIns, DeviceList, OSList, BrowserList
| sort by Devices desc
"""

NETWORK_FANOUT = PRELUDE + r"""
sig
| summarize SignIns = count(), IPs = dcount(IPAddress),
            ASNs = dcountif(ASN, isnotempty(ASN)),
            Countries = dcountif(Country, isnotempty(Country)),
            Cities = dcountif(City, isnotempty(City)),
            ASNList = make_set_if(ASN, isnotempty(ASN), 15),
            CountryList = make_set_if(Country, isnotempty(Country), 15),
            CityList = make_set_if(City, isnotempty(City), 20)
    by UserPrincipalName
| where IPs > {MaxIPs} or Countries > {MaxCountries} or ASNs >= 4
| extend Assessment = case(Countries > {MaxCountries} and ASNs >= 4, "Geographically and network dispersed - strong sharing indicator",
                           ASNs >= 5, "Many distinct networks - check VPN/mobile churn before escalating",
                           Countries > {MaxCountries}, "Multi-country usage - verify travel or offshore staff",
                           "High IP churn - often mobile or CGNAT, low on its own")
| project UserPrincipalName, Assessment, IPs, ASNs, Countries, Cities, SignIns, CountryList, ASNList, CityList
| sort by Countries desc, ASNs desc
"""

UA_DIVERSITY = r"""
let excl = split(tolower("{ExcludedUsers}"), ",");
SigninLogs
| where TimeGenerated {TimeRange}
| where ResultType == 0
| extend UserPrincipalName = tolower(UserPrincipalName)
| where isnotempty(UserPrincipalName) and not(UserPrincipalName has_any (excl))
| extend UA = tostring(column_ifexists("UserAgent", ""))
| where isnotempty(UA)
| summarize UserAgents = dcount(UA), SignIns = count(), UAList = make_set(UA, 15), LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where UserAgents >= 4
| sort by UserAgents desc
"""
