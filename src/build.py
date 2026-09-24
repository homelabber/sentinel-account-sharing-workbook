# -*- coding: utf-8 -*-
"""Builds the 'Account & Credential Sharing' Microsoft Sentinel workbook."""
import json, os, uuid, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules
import kql_overview as O
import kql_detail as D
import kql_pwreuse as P
import help_text as H
import help_tabs as HT

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
WS = "microsoft.operationalinsights/workspaces"


def gid(seed):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "acctshare/" + seed))


def text(md, name):
    return {"type": 1,
            "content": {"json": md},
            "name": name}


def query(q, name, title=None, gridsettings=None, viz="table", size=0, chart=None):
    """Build a KqlItem.

    'gridsettings' is deliberately the 4th positional parameter: table panels
    are the common case and pass it positionally. Putting 'viz' there caused
    every grid dict to be interpreted as the visualization name, producing
    "Unable to find visualization: [object Object]" in the portal.
    """
    c = {"version": "KqlItem/1.0",
         "query": q.strip(),
         "size": size,
         "timeContext": {"durationMs": 0},
         "queryType": 0,
         "resourceType": WS,
         "visualization": viz}
    if title:
        c["title"] = title
    if gridsettings:
        c["gridSettings"] = gridsettings
    if chart:
        c["chartSettings"] = chart
    return {"type": 3, "content": c, "name": name}


def heat(col, palette="red"):
    return {"columnMatch": col, "formatter": 8,
            "formatOptions": {"palette": palette}}


def bar(col, palette="blue"):
    return {"columnMatch": col, "formatter": 4,
            "formatOptions": {"palette": palette}}


def grid(formatters=None, sort=None, rows=None):
    g = {"formatters": formatters or []}
    if sort:
        g["sortBy"] = [{"itemKey": sort[0], "sortOrder": sort[1]}]
    if rows:
        g["rowLimit"] = rows
    return g


def group(name, tab, items):
    return {"type": 12,
            "content": {"version": "NotebookGroup/1.0", "groupType": "editable",
                        "items": items},
            "conditionalVisibility": {"parameterName": "SelectedTab",
                                      "comparison": "isEqualTo", "value": tab},
            "name": "grp-" + name}


def collapsible(title, name, md, expanded=False):
    """A collapsible help section.

    Schema verified against 270 expandable groups in the shipping Azure-Sentinel
    workbooks: content.expandable + content.expanded + content.title, with
    styleSettings.showBorder on the outer item.
    """
    return {"type": 12,
            "content": {"version": "NotebookGroup/1.0", "groupType": "editable",
                        "title": title,
                        "expandable": True,
                        "expanded": expanded,
                        "items": [text(md, name + "-body")]},
            "styleSettings": {"showBorder": True},
            "name": name}


def tabhelp(tab, md):
    """Standard collapsed help header for a tab."""
    return collapsible("How to read this tab", "help-" + tab, md, expanded=False)


def param(name, label, ptype, **kw):
    p = {"id": gid("p-" + name), "version": "KqlParameterItem/1.0",
         "name": name, "label": label, "type": ptype}
    p.update(kw)
    return p


def dropdown(name, label, pairs, default, description=None):
    """A JSON-backed dropdown, matching the schema Microsoft actually ships.

    Verified against all 280 jsonData dropdowns in the Azure-Sentinel workbook
    repository: every single one uses 'jsonData' and NONE sets 'queryType'.
    Setting queryType makes the portal treat the parameter as a query to run,
    which leaves the pill stuck on <unset> behind a spinner forever.
    """
    p = param(name, label, 2,
              isRequired=True,
              value=default,
              jsonData=jsondd(pairs, default),
              typeSettings={"additionalResourceOptions": [],
                            "showDefault": False})
    if description:
        p["description"] = description
    return p


def jsondd(pairs, default=None):
    out = []
    for v, l in pairs:
        item = {"value": v, "label": l}
        if v == default:
            item["selected"] = True
        out.append(item)
    return json.dumps(out)


# --------------------------------------------------------------------- header
HEADER = text(
    "# Account & Credential Sharing — Identity Visibility for the SOC\n"
    "Correlates **Microsoft Defender for Identity** (on-premises Active Directory), "
    "**Microsoft Entra ID** sign-in, risk and audit data, **Defender for Endpoint** logon telemetry "
    "and **UEBA** into one view of who is sharing accounts, passwords and sessions — plus the "
    "red-team tradecraft used to obtain and reuse other people's credentials.\n\n"
    "> **Account sharing is never *proven* by telemetry — it is inferred.** Every panel produces an "
    "**indicator**; the Overview score is a transparent, weighted roll-up of those indicators. Treat "
    "a high score as a triage queue, not a verdict.\n\n"
    "**New here? Open _Start here_ below.** Unsure what a threshold does? Open _Parameter reference_ — "
    "every pill is explained, including when to raise or lower it.",
    "header")

HELPBLOCK = [
    collapsible("Start here — how to use this workbook", "help-quickstart", H.QUICKSTART, expanded=False),
    collapsible("Understanding the sharing score and Drivers", "help-score", H.READING_SCORE),
    collapsible("Parameter reference — what every threshold does, and when to change it",
                "help-params", H.PARAM_REF),
    collapsible("Glossary — fan-out, geo-velocity, NTLM, token replay, honeytokens…",
                "help-glossary", H.GLOSSARY),
    collapsible("Investigating a hit — triage questions and building an evidence pack",
                "help-triage", H.TRIAGE),
    collapsible("Known false positives — check these before you escalate",
                "help-fp", H.FALSE_POSITIVES),
]

PARAMS = {
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "crossComponentResources": [],
        "parameters": [
            param("TimeRange", "Time range", 4,
                  isRequired=True,
                  value={"durationMs": 604800000},
                  typeSettings={"selectableValues": [
                      {"durationMs": 86400000}, {"durationMs": 172800000},
                      {"durationMs": 604800000}, {"durationMs": 1209600000},
                      {"durationMs": 2592000000}, {"durationMs": 7776000000}],
                      "allowCustom": True}),
            dropdown("ConcurrencyWindow", "Concurrency window",
                     [("5m", "5 minutes"), ("15m", "15 minutes"),
                      ("30m", "30 minutes"), ("1h", "1 hour")], "15m",
                     "How close two sign-ins must be to count as concurrent."),
            dropdown("MaxIPs", "IP fan-out threshold",
                     [("3", "3"), ("5", "5"), ("8", "8"), ("12", "12"), ("20", "20")], "8",
                     "Distinct source IPs per account before it is flagged."),
            dropdown("MaxDevices", "Device fan-out threshold",
                     [("2", "2"), ("3", "3"), ("5", "5"), ("8", "8")], "3",
                     "Distinct registered devices per account before it is flagged."),
            dropdown("MaxCountries", "Country fan-out threshold",
                     [("1", "1"), ("2", "2"), ("3", "3"), ("5", "5")], "2",
                     "Distinct countries per account before it is flagged."),
            dropdown("MaxUsersPerDevice", "Accounts-per-device threshold",
                     [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8"), ("15", "15")], "4",
                     "Distinct accounts on one device before it is flagged. Raise for genuine kiosks."),
            dropdown("MaxOnPremHosts", "On-prem host fan-out threshold",
                     [("3", "3"), ("5", "5"), ("10", "10"), ("20", "20")], "5",
                     "Distinct AD hosts one account authenticates from before it is flagged."),
            dropdown("DormantDays", "Dormant / stale threshold",
                     [("30", "30 days"), ("45", "45 days"), ("60", "60 days"),
                      ("90", "90 days"), ("180", "180 days")], "90",
                     "Inactivity before an enabled account counts as dormant."),
            dropdown("MinScore", "Minimum sharing score",
                     [("0", "Show all"), ("15", "15 — Low and above"),
                      ("30", "30 — Medium and above"), ("50", "50 — High and above"),
                      ("70", "70 — Critical only")], "15",
                     "Filters the Overview scorecard."),
            param("ExcludedUsers", "Exclude accounts (comma separated, substring match)", 1,
                  isRequired=True, value="none@example.invalid",
                  description="Break-glass, scanners, backup/RMM service accounts. "
                              "Substring match. Leave the placeholder to exclude nothing.",
                  typeSettings={"paramValidationRules": []}),
            dropdown("RotationWindow", "Password-rotation correlation window",
                     [("5m", "5 minutes"), ("10m", "10 minutes"), ("30m", "30 minutes"),
                      ("1h", "1 hour"), ("1d", "1 day")], "10m",
                     "How close two password changes must be to count as synchronised."),
            dropdown("MinSyncedRotations", "Minimum synchronised rotations",
                     [("2", "2 — permissive"), ("3", "3 — balanced"),
                      ("4", "4 — strict"), ("5", "5 — very strict")], "2",
                     "Independent rotations that must coincide before a pair is reported."),
            dropdown("MinBulkReset", "Bulk-reset account threshold",
                     [("3", "3"), ("5", "5"), ("10", "10"), ("20", "20")], "5",
                     "Accounts reset by one actor in one window before it is flagged."),
            dropdown("MaxAccountsPerHost", "Credential-custody threshold",
                     [("2", "2"), ("3", "3"), ("5", "5"), ("10", "10")], "3",
                     "Distinct identities authenticating from one host before it is flagged."),
            dropdown("MinCohortSize", "Provisioning-cohort minimum size",
                     [("2", "2"), ("3", "3"), ("5", "5"), ("10", "10")], "3",
                     "Accounts sharing a naming stem before the cohort is reported."),
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": WS},
    "name": "parameters"}

TABS = [
    ("overview", "Overview & Score"),
    ("concurrency", "Concurrent Sessions"),
    ("fanout", "Device & Location Fan-Out"),
    ("hygiene", "Credential Hygiene"),
    ("pwreuse", "Password Reuse"),
    ("generic", "Generic & Service Accounts"),
    ("onprem", "On-Prem AD (MDI)"),
    ("local", "Local Accounts (MDE)"),
    ("redteam", "Red-Team Tradecraft"),
    ("drill", "Account Drilldown"),
    ("coverage", "Coverage & Limits"),
]

TABITEM = {
    "type": 11,
    "content": {
        "version": "LinkItem/1.0",
        "style": "tabs",
        "links": [{"id": gid("tab-" + k), "cellValue": "SelectedTab",
                   "linkTarget": "parameter", "linkLabel": lbl,
                   "subTarget": k, "style": "link",
                   "preText": "", "postText": ""} for k, lbl in TABS]},
    "name": "tabs"}

# 'SelectedTab' is written by the tab strip above, but it must also be declared
# with a default or nothing is selected on first load and the page renders blank.
TABSTATE = {
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
            param("SelectedTab", "Selected tab", 1,
                  isRequired=False, value="overview",
                  isHiddenWhenLocked=True,
                  typeSettings={"paramValidationRules": []})],
        "style": "pills",
        "queryType": 0,
        "resourceType": WS},
    "name": "tabstate"}

# ===================================================================== OVERVIEW
overview = [
    tabhelp("overview", HT.OVERVIEW),
    text("**Triage queue.** Work Critical and High first, read **Drivers** before the counts, then "
         "pivot to *Account Drilldown* for anything you intend to act on.", "ov-txt"),
    query(O.TILES, "ov-tiles", "Estate summary", viz="tiles", size=3,
          chart={"showMetrics": False, "showLegend": False}),
    query(O.SCORECARD, "ov-score", "Account sharing scorecard",
          grid(formatters=[heat("SharingScore"), bar("DistinctIPs"), bar("DistinctDevices"),
                           bar("DistinctCountries"), bar("ConcurrentWindows"),
                           bar("OnPremSourceHosts")],
               sort=("SharingScore", 2))),
    query(O.BAND_CHART, "ov-band", "Accounts by risk band", viz="barchart", size=1),
    query(O.TREND, "ov-trend", "Accounts breaching thresholds over time", viz="timechart", size=1),
]

# ================================================================== CONCURRENCY
concurrency = [
    tabhelp("concurrency", HT.CONCURRENCY),
    text("**The strongest evidence available.** Session overlap finds the same account on multiple "
         "IPs in one window; geo-velocity computes the implied travel speed between consecutive "
         "sign-ins. Check IP and ASN detail before escalating — VPN split-tunnelling and mobile "
         "hand-off both produce overlap.", "cc-txt"),
    query(O.CONCURRENT_ROLLUP, "cc-roll", "Accounts with repeated session overlap",
          grid(formatters=[bar("OverlapWindows"), heat("MaxIPs"), heat("MaxCountries")],
               sort=("OverlapWindows", 2))),
    query(O.CONCURRENT_SESSIONS, "cc-win", "Overlapping session windows (evidence detail)",
          grid(formatters=[heat("IPs"), heat("Countries")], sort=("WindowStart", 2))),
    query(O.GEO_VELOCITY, "cc-geo", "Geo-velocity violations (computed, not licence dependent)",
          grid(formatters=[heat("RequiredSpeedKmh")], sort=("TimeGenerated", 2))),
]

# ====================================================================== FAN-OUT
fanout = [
    tabhelp("fanout", HT.FANOUT),
    text("**Fan-out runs in two directions.** One account across many devices suggests several "
         "people; one device across many accounts is either a sanctioned kiosk or someone collecting "
         "credentials. **OS diversity is the signal to trust** — raw IP counts inflate easily.",
         "fo-txt"),
    query(O.USER_DEVICE_FANOUT, "fo-user", "One account → many devices",
          grid(formatters=[heat("Devices"), heat("OSTypes"), bar("UnmanagedDevices")],
               sort=("Devices", 2))),
    query(O.DEVICE_SHARED_BY_USERS, "fo-dev", "One device → many accounts",
          grid(formatters=[heat("Users"), bar("SignIns")], sort=("Users", 2))),
    query(O.NETWORK_FANOUT, "fo-net", "Network and geographic dispersion",
          grid(formatters=[heat("Countries"), heat("ASNs"), bar("IPs")], sort=("Countries", 2))),
    query(O.UA_DIVERSITY, "fo-ua", "User-agent diversity per account",
          grid(formatters=[heat("UserAgents")], sort=("UserAgents", 2))),
]

# ====================================================================== HYGIENE
hygiene = [
    tabhelp("hygiene", HT.HYGIENE),
    text("**Which credentials are structurally easy to share?** The shared-MFA panel is the "
         "highest-value item — one factor covering several accounts is the closest thing to a hard "
         "shared-credential fact the platform exposes.\n\n"
         "> **No duplicate-password panel here.** Password hashes and comparison results are not "
         "exposed to Log Analytics, and MDI's Password protection page does not compare accounts to "
         "each other. See the **Password Reuse** tab for how far that can be pushed.", "hy-txt"),
    query(D.SHARED_MFA_METHOD, "hy-mfa", "One authentication factor registered against multiple accounts",
          grid(formatters=[heat("AccountsSharing")], sort=("AccountsSharing", 2))),
    query(D.THIRD_PARTY_MFA_REG, "hy-3p", "MFA / security info registered by someone other than the account owner",
          grid(sort=("TimeGenerated", 2))),
    query(D.PASSWORD_STALENESS, "hy-stale", "Non-expiring, not-required and never-changed passwords",
          grid(formatters=[heat("PasswordAgeDays")], sort=("PasswordAgeDays", 2))),
    query(D.WEAK_AUTH_SURFACE, "hy-weak", "Legacy and single-factor authentication surface",
          grid(formatters=[heat("LegacyAuth"), heat("SingleFactorPct")], sort=("LegacyAuth", 2))),
    query(D.LEAKED_CREDS, "hy-leak", "Leaked-credential, spray and anomalous-token risk detections",
          grid(sort=("TimeGenerated", 2))),
    query(D.PASSWORD_ACTIVITY, "hy-pw", "Password change and reset activity (Entra + on-prem AD)",
          grid(sort=("TimeGenerated", 2))),
]

# ====================================================================== GENERIC
generic = [
    tabhelp("generic", HT.GENERIC),
    text("**Accounts nobody owns are the ones that get shared.** Classification uses evidence — "
         "generic naming, no manager, no job title, no interactive sign-ins — not name matching "
         "alone. The row type that matters most is a **generic-named account logging on "
         "interactively**: that is a shared human credential regardless of what it is called.",
         "gn-txt"),
    query(D.GENERIC_INVENTORY, "gn-inv", "Non-human / shared account inventory",
          grid(formatters=[heat("NonHumanSignals"), bar("IPs"), bar("Devices")],
               sort=("NonHumanSignals", 2))),
    query(D.SERVICE_ACCT_INTERACTIVE, "gn-int", "Service-named accounts logging on interactively",
          grid(formatters=[heat("Hosts")], sort=("Hosts", 2))),
    query(D.DORMANT_ACCOUNTS, "gn-dorm", "Enabled but dormant accounts (threshold is tunable above)",
          grid(formatters=[heat("DaysInactive")], sort=("DaysInactive", 2))),
]

# ====================================================================== PWREUSE
PW_TIERS = """
### The constraint, stated precisely

Microsoft Entra ID and Defender for Identity hold password material but expose **no hash, no
plaintext, and no hash-comparison result** to Log Analytics. Defender for Identity's own Password
protection page offers four views — Password Hygiene, Password Policies, Leaked Credentials and
Exposed Passwords — and **none of them compares two accounts' passwords to each other**. So the
direct question cannot be answered in KQL.

It *can* be answered three other ways, in descending order of fidelity.

---

### Tier 1 — Ground truth (optional feed, exact answer)

`DSInternals`' `Test-PasswordQuality` compares NT hashes **locally, inside your own domain** and
returns `DuplicatePasswordGroups` — the literal list of accounts sharing a password. The bundled
`Collect-ADPasswordQuality.ps1` runs it on a schedule and ships **only the groupings** to
`ADPasswordQuality_CL`; no hash or password ever leaves memory. Supply the Have I Been Pwned NTLM
corpus and you also get per-account breached-password findings.

> **Run it against an offline `ntds.dit` snapshot, not via replication.** Replication mode issues the
> same DRSR calls as DCSync and Defender for Identity will alert on it. If you genuinely need
> replication mode, agree the host and account with the SOC and file a *documented* suppression —
> never a silent exclusion, or you have built the blind spot a real DCSync will hide in.

This covers on-premises AD only. **For cloud-only identities there is no equivalent at any price** —
the hashes are not exportable, so Tier 2 is the ceiling there.

### Tier 2 — Behavioural proxies (no extra deployment)

These do not prove two passwords are byte-identical. They prove something operationally equivalent:
**the credentials are managed as a single secret, or held by a single operator.** For containment and
policy purposes that is the same finding, and it should be reported in those terms rather than as
"these accounts share a password".

### Tier 3 — What to stop chasing

Entra Password Protection tells you a password was *rejected* for being banned, never what it *is*.
Password-spray patterns reveal the attacker's guesses, not your users' actual values. Neither
approximates reuse; don't build on them.
"""

pwreuse = [
    tabhelp("pwreuse", HT.PWREUSE),
    collapsible("Why identical-password detection is not directly queryable — and the three tiers "
                "that get closest", "help-pwtiers", PW_TIERS, expanded=False),
    text("**Tier 2 proxies do not prove two passwords are identical.** They prove the credentials "
         "are *managed as one secret* or *held by one operator* — for containment, the same finding. "
         "Tier 1 ground truth needs the optional DSInternals collector.", "pw-txt"),

    text("### Temporal correlation\n"
         "Two accounts changing password in the same ten-minute window once is coincidence. Two "
         "accounts whose password changes coincide on **every single rotation** are being maintained as "
         "one credential — that is what `SyncRatio` measures. A ratio of 100% across three or more "
         "independent rotations is about as close to proof as behavioural telemetry gets.", "pw-t1"),
    query(P.SYNC_PASSWORD_CHANGES, "pw-sync", "Accounts whose passwords are always rotated together",
          grid(formatters=[heat("SyncRatio"), bar("SyncedRotations")], sort=("SyncRatio", 2))),
    query(P.BULK_RESET, "pw-bulk", "Bulk password resets by a single actor",
          grid(formatters=[heat("AccountsReset")], sort=("AccountsReset", 2))),
    query(P.CORRELATED_LOCKOUTS, "pw-lock", "Accounts that lock out together",
          grid(formatters=[heat("Accounts")], sort=("Window", 2))),

    text("### Custody correlation\n"
         "A different framing of the same exposure. If one host authenticates as fifteen identities, "
         "whoever operates it holds fifteen working credentials. Whether those are one password or "
         "fifteen is almost irrelevant to the response — the containment action and the blast radius "
         "are identical.", "pw-t2"),
    query(P.CREDENTIAL_CUSTODY, "pw-cust", "Hosts authenticating as many distinct identities",
          grid(formatters=[heat("Accounts")], sort=("Accounts", 2))),
    query(P.PROVISIONING_COHORT, "pw-cohort", "Unrotated provisioning cohorts sharing a naming stem",
          grid(formatters=[heat("CohortSize"), heat("Privileged")], sort=("CohortSize", 2))),
    query(P.LEAKED_COOCCURRENCE, "pw-leak", "Accounts flagged as leaked in the same ingest window",
          grid(formatters=[heat("Accounts")], sort=("Accounts", 2))),

    text("### Ground truth — DSInternals feed\n"
         "Empty unless `Collect-ADPasswordQuality.ps1` is deployed. When populated, these are not "
         "approximations: each group is a set of accounts whose NT hashes are byte-identical.", "pw-t3"),    query(P.DSINTERNALS_FRESHNESS, "pw-fresh", "Feed status"),
    query(P.DSINTERNALS_GROUPS, "pw-dup", "Confirmed duplicate-password groups",
          grid(formatters=[heat("GroupSize")], sort=("GroupSize", 2))),
    query(P.DSINTERNALS_FINDINGS, "pw-find", "Confirmed per-account password findings",
          grid(formatters=[bar("Accounts")], sort=("Severity", 1))),
]

# ======================================================================= ONPREM
onprem = [
    tabhelp("onprem", HT.ONPREM),
    text("**Entra logs stop at the cloud edge; this is what happens inside.** Host fan-out is the "
         "cleanest signal in the workbook — no CGNAT, no mobile churn, no geolocation guesswork. "
         "**NTLM share** matters doubly: it authenticates with the hash alone, making it both a "
         "sharing enabler and the precondition for pass-the-hash.", "op-txt"),
    query(D.MDI_HOST_FANOUT, "op-fan", "Account → source/target host fan-out",
          grid(formatters=[heat("SourceHosts"), heat("TargetHosts"), bar("Logons")],
               sort=("SourceHosts", 2))),
    query(D.MDI_CONCURRENT_HOSTS, "op-conc", "Same account authenticated from multiple hosts in one window",
          grid(formatters=[heat("Hosts")], sort=("WindowStart", 2))),
    query(D.MDI_NTLM, "op-ntlm", "NTLM reliance and NTLM host spread",
          grid(formatters=[heat("NtlmPct"), heat("NtlmHosts")], sort=("NtlmHosts", 2))),
    query(D.MDI_LOGON_TYPES, "op-types", "Logon type and protocol distribution", viz="piechart", size=1),
    query(D.MDI_SENSITIVE_GROUPS, "op-grp", "Group membership changes (privilege sharing)",
          grid(sort=("TimeGenerated", 2))),
    query(D.MDI_ALERTS, "op-alert", "Identity alerts (MDI / Entra ID Protection / XDR)",
          grid(sort=("TimeGenerated", 2))),
]

# ======================================================================== LOCAL
local = [
    tabhelp("local", HT.LOCAL),
    text("**Invisible to both MDI and Entra** — a local SAM account never touches a domain controller "
         "or the cloud, so this comes from Defender for Endpoint. The classic finding is one local "
         "account name across many machines: a golden-image or helpdesk password identical "
         "estate-wide. **The fix is Windows LAPS**, not detection.", "lo-txt"),
    query(D.LOCAL_ACCOUNT_REUSE, "lo-reuse", "Same local account name across multiple devices",
          grid(formatters=[heat("Devices"), bar("RemoteLogons")], sort=("Devices", 2))),
    query(D.LOCAL_ADMIN_REMOTE, "lo-admin", "Local administrator credentials used remotely",
          grid(formatters=[heat("TargetDevices")], sort=("TargetDevices", 2))),
    query(D.LOCAL_SHARED_WORKSTATION, "lo-ws", "Endpoints with many distinct interactive accounts",
          grid(formatters=[heat("Accounts")], sort=("Accounts", 2))),
]

# ====================================================================== REDTEAM
ATTACK_TABLE = """
Every technique below exists specifically to make one credential usable by a second party — which is
why credential-theft tradecraft belongs in a workbook about account sharing.

| Technique | What it achieves | Where it surfaces here |
|---|---|---|
| Pass-the-Hash / Overpass-the-Hash (T1550.002) | Reuse a password hash without ever knowing the password | MDI alerts · NTLM panel |
| Pass-the-Ticket / Golden & Silver Ticket (T1550.003, T1558) | Reuse or forge Kerberos material | MDI alerts |
| Kerberoasting / AS-REP Roasting (T1558.003) | Crack service-account passwords offline — the accounts most likely to already be shared | Directory enumeration · MDI alerts |
| DCSync (T1003.006) | Pull every credential in the domain from a DC | MDI alerts |
| LSASS / DPAPI dumping (T1003.001) | Harvest credentials and tokens from memory | MDE process & API telemetry |
| AiTM proxy phishing & token theft (T1539, T1550.001) | Steal the session, bypassing MFA entirely | Token replay · anomalous token |
| Device code phishing (T1566) | Have the victim complete sign-in for the attacker's session | Device code flow panel |
| Password spray / stuffing (T1110) | Find accounts whose password is already known or reused | Spray vs. stuffing panel |
| Credential hunting in files, registry and vaults (T1552) | Find passwords in scripts, unattend files and credential managers | Command-line telemetry |
| RDP session hijack / shadowing (T1563.002) | Take over a live session with no credential at all | RDP shadow panel |

**Sharing or compromise?** Sharing is *stable and routine* — the same second location, week after
week. Compromise is *new and abrupt*, usually with token replay or Entra risk detections alongside.
They need different responses: one is a policy conversation, the other is an incident. Getting this
wrong wastes the investigation and can tip off an attacker.
"""

redteam = [
    tabhelp("redteam", HT.REDTEAM),
    collapsible("Technique reference — what each attack achieves and where it surfaces here",
                "help-attack", ATTACK_TABLE, expanded=False),
    text("**Sharing and theft are the same telemetry with different intent.** An adversary holding "
         "your credential is functionally sharing your account. **Honeytokens are the only "
         "zero-false-positive signal here** — if that panel is empty, none are configured.",
         "rt-txt"),
    query(D.RT_CRED_THEFT_ALERTS, "rt-alerts", "Credential access and reuse alerts, mapped to ATT&CK",
          grid(sort=("TimeGenerated", 2))),
    query(D.RT_TOKEN_REPLAY, "rt-token", "Session / refresh token used from multiple locations (AiTM & session sharing)",
          grid(formatters=[heat("Countries"), heat("IPs")], sort=("Countries", 2))),
    query(D.RT_DEVICE_CODE, "rt-dc", "Device code and ROPC authentication",
          grid(formatters=[heat("Successes")], sort=("Successes", 2))),
    query(D.RT_KERBEROAST, "rt-enum", "Directory enumeration (pre-Kerberoasting reconnaissance)",
          grid(formatters=[heat("TargetsEnumerated")], sort=("TargetsEnumerated", 2))),
    query(D.RT_LSASS, "rt-lsass", "LSASS access and credential memory reads",
          grid(sort=("TimeGenerated", 2))),
    query(D.RT_CRED_HUNTING, "rt-hunt", "Credential hunting and reuse via command line",
          grid(sort=("TimeGenerated", 2))),
    query(D.RT_SPRAY_VS_STUFFING, "rt-spray", "Password spray vs. brute force vs. credential stuffing",
          grid(formatters=[heat("TargetedAccounts")], sort=("TargetedAccounts", 2))),
    query(D.RT_RDP_SHADOW, "rt-rdp", "RDP session shadowing and concurrent RDP sources",
          grid(sort=("TimeGenerated", 2))),
    query(D.RT_MDI_HONEYTOKEN, "rt-honey", "Honeytoken activity (zero-false-positive signal)",
          grid(sort=("TimeGenerated", 2))),
    query(D.RT_UEBA, "rt-ueba", "UEBA first-time and peer-anomalous identity behaviour",
          grid(formatters=[heat("MaxPriority")], sort=("MaxPriority", 2))),
]

# ======================================================================== DRILL
drill = [
    {"type": 9,
     "content": {"version": "KqlParameterItem/1.0",
                 "parameters": [param("TargetUser", "Account", 2, isRequired=False,
                                      value="",
                                      description="Pick an account to build its evidence pack. "
                                                  "Panels stay empty until one is selected.",
                                      query=D.DRILL_LIST.strip(), queryType=0,
                                      resourceType=WS,
                                      typeSettings={"additionalResourceOptions": [],
                                                    "showDefault": False})],
                 "style": "pills", "queryType": 0, "resourceType": WS},
     "name": "drill-params"},
    tabhelp("drill", HT.DRILL),
    text("**The evidence pack for one identity.** Look for two profiles that *alternate cleanly* "
         "rather than blend — that is two people. A gradual shift is usually one person whose "
         "circumstances changed. Watch for a sudden profile change right after an MFA registration "
         "or password reset.", "dr-txt"),
    query(D.DRILL_IP_SUMMARY, "dr-ip", "Network and device profile for this account",
          grid(formatters=[bar("SignIns"), heat("ManagedPct", "green")], sort=("SignIns", 2))),
    query(D.DRILL_HOURLY, "dr-hour", "Activity by country over time", viz="timechart", size=1),
    query(D.DRILL_ALERTS, "dr-alert", "Alerts naming this account", grid(sort=("TimeGenerated", 2))),
    query(D.DRILL_TIMELINE, "dr-time", "Full authentication timeline", grid(sort=("TimeGenerated", 2))),
]

# ===================================================================== COVERAGE
COVERAGE_MD = """## Coverage, prerequisites and honest limits

### Required data connectors
| Connector / source | Tables used | Panels affected |
|---|---|---|
| Microsoft Entra ID | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` | Overview, Concurrency, Fan-Out, Hygiene, Generic |
| Microsoft Entra ID Protection | `AADUserRiskEvents` | Score risk component, leaked credentials |
| Defender XDR (Defender for Identity) | `IdentityLogonEvents`, `IdentityDirectoryEvents`, `IdentityQueryEvents`, `IdentityInfo` | On-Prem AD, password staleness, dormancy |
| Defender XDR (Defender for Endpoint) | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceEvents` | Local Accounts, parts of Red-Team |
| Microsoft Sentinel UEBA | `BehaviorAnalytics`, `IdentityInfo` | UEBA panel, account attributes |
| Unified alerts | `SecurityAlert` | Alert panels |

Every query uses `union isfuzzy=true` or tolerates missing columns where practical, so panels degrade to empty rather than erroring if a connector is absent. **An empty panel means missing data, not a clean result** — verify the connector before reporting "no findings".

### What this workbook deliberately does not claim
* **It cannot, on its own, list accounts that share the same password.** Password hashes and hash-comparison results are not exposed to Log Analytics by Entra ID or Defender for Identity, and MDI's Password protection page (Password Hygiene / Password Policies / Leaked Credentials / Exposed Passwords) does not compare accounts against each other. **However** — see the **Password Reuse** tab. Real duplicate detection for on-premises AD is achievable by shipping `DSInternals` `Test-PasswordQuality` groupings into `ADPasswordQuality_CL` via the bundled collector, and behavioural proxies cover the rest. For cloud-only identities, the behavioural proxies are the ceiling.
* **It cannot prove sharing.** Every output is an indicator. Concurrency plus geo-velocity plus device fan-out together are strong enough to open an HR or policy case; no single panel is.
* **It cannot enforce anything.** A workbook is a visualisation surface. Containment belongs in Conditional Access, Entra ID Protection risk policies, and Defender XDR automatic attack disruption. Convert the panels you trust into Analytics Rules to get alerting and automation.
* **Non-interactive sign-ins are noisy by design.** Background token refreshes legitimately originate from Microsoft service IPs. Weight interactive evidence more heavily.

### Reading this against a third-party identity protection product
Capability-for-capability, the panels here cover identity inventory and classification, human vs. service vs. shared account typing, stale and dormant account reporting at a tunable threshold, privileged account monitoring, lateral movement and host fan-out, weak and breached credential exposure, and attack-path reconnaissance. Three things a workbook structurally cannot replicate:

1. **Inline enforcement on AD protocols** — stepping up to MFA at the moment of an NTLM or Kerberos authentication. That is a proxy/agent function. The Microsoft equivalent is Conditional Access at the cloud edge plus Defender XDR attack disruption, not a workbook.
2. **A vendor-proprietary risk score.** The score here is deliberately transparent and tunable instead — every weight is visible in the scorecard query and every contribution is named in the `Drivers` column, so you can defend a finding in a review.
3. **Offline password-strength and duplicate-hash analysis** — not from Sentinel data alone, though the **Password Reuse** tab closes most of this gap for on-premises AD via the optional DSInternals feed.

### Turning panels into detections
The highest-value candidates for promotion to Analytics Rules, in order:
1. Geo-velocity violations above 1,500 km/h.
2. Session or refresh token used from more than one country.
3. Any honeytoken authentication.
4. A generic-named account performing an interactive logon from a new host.
5. One MFA factor newly registered against a third distinct account.
6. A local administrator account authenticating over the network to five or more hosts.

### Tuning order
Set **Exclude accounts** first (break-glass, vulnerability scanners, backup and RMM service principals, conference-room and kiosk accounts). Then raise the fan-out thresholds until the Critical band is small enough to work daily. Resist lowering thresholds until exclusions are complete — untuned fan-out panels generate volume, not insight.
"""

coverage = [
    tabhelp("coverage", HT.COVERAGE),
    text("**Start here, not at the Overview.** An empty panel and a clean result look identical and "
         "mean opposite things. Check connector status below before trusting anything else.",
         "cov-intro"),
    query(P.DATA_AVAILABILITY, "cov-avail", "Tables present in this workspace",
          grid(formatters=[bar("Rows")], sort=("Rows", 2))),
    query(P.ABSENT_TABLES, "cov-missing", "Tables NOT present (connector not deployed)"),
    collapsible("Required connectors, honest limits, and what to promote into Analytics Rules",
                "help-coverage-detail", COVERAGE_MD, expanded=False),
]

# ======================================================================== build
items = [HEADER] + HELPBLOCK + [PARAMS, TABSTATE, TABITEM,
         group("overview", "overview", overview),
         group("concurrency", "concurrency", concurrency),
         group("fanout", "fanout", fanout),
         group("hygiene", "hygiene", hygiene),
         group("pwreuse", "pwreuse", pwreuse),
         group("generic", "generic", generic),
         group("onprem", "onprem", onprem),
         group("local", "local", local),
         group("redteam", "redteam", redteam),
         group("drill", "drill", drill),
         group("coverage", "coverage", coverage)]

wb = {"version": "Notebook/1.0",
      "items": items,
      "isLocked": False,
      "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"}

out = os.path.join(HERE, "AccountSharingVisibility.workbook.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(wb, f, indent=2, ensure_ascii=False)

# ------------------------------------------------------------------ validation
raw = open(out, encoding="utf-8").read()
json.loads(raw)

declared = {p["name"] for p in PARAMS["content"]["parameters"]} | {"TargetUser", "SelectedTab"}
used = set()
for m in re.finditer(r"\{([A-Za-z][A-Za-z0-9_]*)\}", raw):
    used.add(m.group(1))
unknown = used - declared
qcount = sum(1 for i in json.dumps(wb) .split('"KqlItem/1.0"')) - 1

print("wrote:", out, os.path.getsize(out), "bytes")
print("tabs:", len(TABS), "| query panels:", qcount)
print("params declared:", sorted(declared))
print("UNKNOWN parameter tokens in KQL:", sorted(unknown) if unknown else "none")
