# -*- coding: utf-8 -*-
"""Long-form help content rendered into collapsible sections."""

# ===========================================================================
# HOW TO USE
# ===========================================================================
QUICKSTART = """
### First run — do these four things in order

**1. Check your data before you trust any panel.** Open **Coverage & Limits → Tables present in this
workspace**. An empty panel and a clean result look identical and mean opposite things. If
`SigninLogs` shows 0 rows, nothing else on this workbook means anything yet.

**2. Set exclusions before you tune anything else.** Put your break-glass accounts, vulnerability
scanners, backup and RMM service accounts, and any sanctioned kiosk accounts into
**Exclude accounts**. It is a substring match, so `svc-backup` catches `svc-backup01@contoso.com`.
Tuning thresholds before excluding known-noisy accounts means you are tuning against noise you
already know about.

**3. Work the Overview scorecard top-down.** Start at Critical, then High. Read the **Drivers**
column before anything else — it tells you *which* indicators fired, and that determines whether the
score means anything.

**4. Pivot to Account Drilldown** for anything you intend to act on. Never escalate from a
scorecard row alone.

### The daily loop, once tuned

Overview → sort by score → open Drivers → for each Critical/High account, ask "could one person
plausibly produce this pattern?" → if no, pivot to Drilldown → build the evidence pack → hand to
the account owner's manager or IAM.

Ten minutes a day once thresholds are set. If it takes longer, your thresholds are too low.
"""

READING_SCORE = """
### What the score is, and what it is not

The Sharing Score is a **weighted sum of independent indicators**, capped at 100. It is deliberately
transparent — every weight is visible in the scorecard query, and the `Drivers` column names each
contribution. There is no machine learning and nothing hidden.

| Component | Max | What it measures |
|---|---|---|
| IP fan-out | 20 | Distinct source IPs, scaled against your threshold |
| Concurrent sessions | 20 | Windows with 3+ IPs, and multi-country windows |
| Device fan-out | 15 | Distinct registered devices |
| Geo fan-out | 15 | Distinct countries |
| Entra risk detections | 15 | Impossible travel, leaked credentials, anomalous token |
| Generic naming | 10 | Account name matches a shared/service pattern |
| Token replay | 10 | One token used from multiple IPs |
| Weak auth surface | 10 | Legacy auth, single-factor, unmanaged devices |
| On-prem host fan-out | 10 | Distinct AD hosts the account authenticates from |

### Reading Drivers — this is the important part

**A score is only as good as its drivers.** Two accounts can both score 55 and mean completely
different things.

* `ip-fanout(24)` **alone** — weak. Mobile carriers rotate IPs constantly; a field engineer on 5G
  produces this every day. Do not escalate.
* `concurrent-sessions(4), geo-fanout(3), device-fanout(6)` — strong. Three *independent* signals
  agreeing. One person cannot be in three countries on six devices at once.
* `generic-name, onprem-host-fanout(22)` — this is a shared service credential, and it is a policy
  and architecture problem rather than an individual one.
* `token-replay(3), entra-risk` — treat as **potential compromise, not sharing**. Route to incident
  response, not to HR.

### Bands

| Band | Score | Meaning |
|---|---|---|
| Critical | 70+ | Multiple strong indicators. Investigate today. |
| High | 50–69 | Credible. Investigate this week. |
| Medium | 30–49 | Worth a look when time permits, or a pattern to watch. |
| Low | 15–29 | Usually explainable. Useful for spotting trends, not cases. |
| Informational | <15 | Noise floor. |

Bands are guidance, not policy. Decide locally what warrants action, then write it down so
investigations stay consistent between analysts.
"""

# ===========================================================================
# PARAMETER REFERENCE
# ===========================================================================
PARAM_REF = """
Every threshold answers the same question: **how much variety is normal for one human?** The right
answer depends entirely on your organisation. A single-site law firm and a global company with
follow-the-sun support have legitimately different baselines.

**General rule: start high, then lower.** A too-high threshold shows you only the extremes, which is
a short, workable list. A too-low threshold buries the extremes in noise and trains people to ignore
the workbook — which is much harder to recover from.

---

### Time range
**What it does:** the observation window for nearly every panel.

**Raise it (30–90 days)** for baselining, provisioning-cohort analysis, and password-rotation
correlation, which needs several rotation cycles to say anything.

**Lower it (24h–7d)** for active investigation and daily triage.

**Watch out:** fan-out counts grow with the window. An account showing 12 IPs over 90 days is
unremarkable; 12 IPs in 24 hours is not. **Always re-tune thresholds after changing the time range**
— this is the single most common reason a tuned workbook suddenly floods.

---

### Concurrency window · default 15 minutes
**What it does:** how close two sign-ins must be to count as simultaneous. The engine counts distinct
IPs per account per window and flags windows with 3 or more.

**Raise it (30m–1h)** if VPN reconnects, split-tunnelling or mobile hand-off produce constant
false hits. A longer window is more forgiving but blurs genuine overlap.

**Lower it (5m)** for high-assurance environments, or when hunting a specific account. Five minutes
is close to "literally at the same moment" and produces very few, very strong hits.

**Watch out:** this is the highest-signal parameter in the workbook. Two people using one account
*must* produce concurrent sessions eventually. If this panel is always empty, suspect your window is
too long or your exclusions too broad — not that sharing is absent.

---

### IP fan-out threshold · default 8
**What it does:** distinct source IP addresses per account over the time range.

**Raise it (12–20)** if your users are heavily mobile, if you use carrier-grade NAT, or if you have
many remote workers on consumer broadband with dynamic addressing. Also raise it whenever you
lengthen the time range.

**Lower it (3–5)** for office-bound populations on static egress, or for privileged and service
accounts, where *any* variety is suspicious.

**Watch out:** **IP count on its own is the weakest signal here.** A single phone moving between
cell towers and Wi-Fi can generate a dozen IPs in a day. Only treat it as meaningful when it appears
alongside device or geographic fan-out. This is exactly why the `Drivers` column exists.

---

### Device fan-out threshold · default 3
**What it does:** distinct registered device IDs per account.

**Raise it (5–8)** if BYOD is widespread, or during a hardware refresh when people legitimately
straddle old and new machines.

**Lower it (2)** in tightly managed estates where everyone has exactly one laptop and one phone.

**Watch out:** stronger than IP count, because device registration is deliberate. **OS diversity is
stronger still** — the Fan-Out tab surfaces it separately. One person signing in from Windows, macOS
*and* Android in the same week is a much better indicator than raw device count, because people
rarely switch platforms mid-task.

---

### Country fan-out threshold · default 2
**What it does:** distinct countries per account.

**Raise it (3–5)** for genuinely global teams, or if VPN egress points land in other countries —
check where your VPN exits before tuning this.

**Lower it (1)** for staff who never travel. With a threshold of 1, any second country is flagged,
which is very aggressive but appropriate for privileged accounts.

**Watch out:** geolocation is inferred from IP and is wrong often enough to matter, particularly for
satellite links, corporate proxies and newly allocated ranges. Prefer the **geo-velocity** panel on
the Concurrent Sessions tab, which uses the implied travel speed between consecutive sign-ins and is
far harder to explain away.

---

### Accounts-per-device threshold · default 4
**What it does:** distinct accounts signing in from one device. This is the **reverse** direction —
it finds machines, not accounts.

**Raise it (8–15)** if you operate genuine shared terminals, kiosks or clinical workstations.

**Lower it (2)** in one-person-one-laptop estates, where a second account on a device is worth
knowing about.

**Watch out:** there are two very different readings. A sanctioned kiosk is fine and should be
excluded. **One person's laptop accumulating other people's credentials is the finding you care
about** — and the two are distinguished by asset inventory, not by telemetry. Check the device name
against your CMDB before dismissing a hit.

---

### On-prem host fan-out threshold · default 5
**What it does:** distinct Active Directory hosts one account authenticates from, via Defender for
Identity sensors.

**Raise it (10–20)** for admin and operations staff who legitimately touch many servers.

**Lower it (3)** for standard user accounts, which should touch very few hosts.

**Watch out:** **this is the cleanest fan-out signal in the workbook.** There is no CGNAT, no mobile
churn and no geolocation guesswork on an internal network — a user account authenticating from 20
workstations is shared, automated, or stolen, with very little room for a benign explanation. Weight
it accordingly.

---

### Dormant / stale threshold · default 90 days
**What it does:** how long an enabled account can sit unused before it is reported.

**Raise it (180)** to surface only the most clearly abandoned accounts.

**Lower it (30–45)** for a tighter hygiene programme, or to satisfy an audit requirement.

**Watch out:** this parameter exists specifically because the platform's built-in inactivity
recommendation is **fixed and not configurable**. Run it at 30, 60 and 90 and compare — the
difference between those three lists is usually where the interesting accounts live.

---

### Minimum sharing score · default 15
**What it does:** filters the Overview scorecard.

**Raise it (50–70)** for daily triage — you want a queue you can actually finish.

**Lower it (0)** when tuning, to see the full distribution and understand where your noise floor
sits.

---

### Exclude accounts · default `none@example.invalid`
**What it does:** substring match against UPN, applied across almost every panel.

**Add:** break-glass accounts, vulnerability scanners, backup and RMM agents, monitoring accounts,
sanctioned kiosk and conference-room accounts.

**Watch out:** exclusions are invisible once set, and an excluded account is a blind spot forever.
**Document every entry and review the list quarterly** — an attacker who learns an exclusion pattern
gets free rein. Never exclude a privileged account to quiet a panel; fix the underlying noise
instead.

---

### Password-rotation correlation window · default 10 minutes
**What it does:** how close two password changes must be to count as synchronised.

**Raise it (1h–1d)** if rotations are done manually and a batch takes a while to work through.

**Lower it (5m)** if rotations are scripted, where genuinely linked accounts change within seconds.

**Watch out:** a long window plus a scheduled expiry policy creates false pairs — if everyone's
password expires on the same day, everyone "rotates together". Cross-check against
**Minimum synchronised rotations** before believing any pair.

---

### Minimum synchronised rotations · default 2
**What it does:** how many *independent* rotation cycles must coincide before a pair is reported.

**Raise it (3–5)** to eliminate coincidence almost entirely. Two accounts changing together three
times in a row is not chance.

**Lower it (2)** when your time range is short and you have only seen a couple of cycles.

**Watch out:** this is the precision dial for the strongest password-reuse proxy available. The
`SyncRatio` column matters as much as the count — 100% across 3+ rotations means the credentials are
maintained as one secret.

---

### Bulk-reset account threshold · default 5
**What it does:** how many accounts one actor must reset inside one window to be flagged.

**Raise it (10–20)** if large helpdesk batches are routine.

**Lower it (3)** to catch smaller batches.

**Watch out:** the concern is not the reset itself but **whether every account got a unique value**.
Check whether your reset tooling generates per-account passwords and enforces change-at-next-logon.
If it does not, every bulk reset creates a cohort sharing one password.

---

### Credential-custody threshold · default 3
**What it does:** distinct identities authenticating from one host.

**Raise it (5–10)** for jump boxes and admin workstations, where this is expected.

**Lower it (2)** for standard endpoints.

**Watch out:** reframes the question usefully — whoever operates the host can authenticate as every
account listed. Whether they share one password or hold ten is irrelevant to blast radius and to the
containment action.

---

### Provisioning-cohort minimum size · default 3
**What it does:** how many accounts sharing a naming stem, with no observed rotation, before the
cohort is reported.

**Raise it (5–10)** in large estates where naming stems are common by coincidence.

**Lower it (2)** for focused hunting.

**Watch out:** "no rotation observed" may mean the change predates log retention rather than that
the password is genuinely unchanged. **Confirm against `pwdLastSet` in AD before acting.**
"""

# ===========================================================================
# GLOSSARY
# ===========================================================================
GLOSSARY = """
### Fan-out
The spread of one thing across many. **Account fan-out** = one account across many
IPs/devices/countries — suggests several people using it. **Device fan-out** = one device used by
many accounts — either a shared terminal or someone collecting credentials. Both directions matter
and they mean different things.

### Concurrent session
The same identity authenticated from multiple distinct sources inside one time window. The strongest
single indicator of sharing, because one person cannot be in two places at once. Legitimate causes
exist — VPN split-tunnelling, mobile hand-off, cloud app proxies — so check the IP and ASN detail
before escalating.

### Geo-velocity
The travel speed implied by two consecutive sign-ins: distance ÷ elapsed time. Above ~900 km/h you
are faster than a commercial flight; above ~5,000 km/h the journey is physically impossible, meaning
concurrent use or a proxy. Computed here from raw coordinates rather than taken from Entra ID
Protection, so it works without P2 licensing and you can audit the arithmetic.

### ASN (Autonomous System Number)
Identifies the network operator behind an IP. More stable than the IP itself — a phone changing
towers keeps its carrier's ASN, so ASN *changes* are far more meaningful than IP changes. Several
distinct ASNs in one window is a much stronger signal than several IPs.

### Interactive vs. non-interactive sign-in
**Interactive** = a human supplied credentials. **Non-interactive** = a client refreshed a token in
the background. Non-interactive volume is high and legitimately originates from Microsoft service
IPs. **Weight interactive evidence more heavily**; a service account with only non-interactive
sign-ins is behaving correctly, and the same account signing in interactively is not.

### Trust type / managed vs. unmanaged
Whether the device is Entra-joined, hybrid-joined or registered. Empty trust type means an unmanaged
or personal device. A high proportion of unmanaged sign-ins raises the odds that credentials are
being entered somewhere you do not control.

### Token replay
The same session or refresh token presented from more than one IP. Either an adversary-in-the-middle
attack (the session was stolen, and MFA was bypassed because the token is post-authentication) or
deliberate session sharing. **Multiple countries makes this near-conclusive.**

### NTLM vs. Kerberos
NTLM authenticates using the password **hash** alone, so a hash lifted from one machine works
anywhere. Kerberos uses tickets with more context. High NTLM usage is both a sharing enabler and the
precondition for pass-the-hash. Reducing NTLM is a structural fix worth more than any detection.

### Pass-the-Hash / Pass-the-Ticket
Reusing stolen credential *material* without ever knowing the password. Relevant here because an
attacker who has your hash is, in effect, sharing your account — the telemetry is very similar.

### Kerberoasting
Requesting service tickets and cracking them offline to recover service-account passwords. Targets
exactly the accounts most likely to already be shared and to have non-expiring passwords.

### Device code flow
An authentication flow where a code shown on one device is approved on another. Both a phishing
technique *and* the simplest consensual way to hand someone else a working session — which is why it
appears on the Red-Team tab rather than being treated as benign.

### Honeytoken
A decoy account no human should ever touch. Any authentication against it is unauthorised by
definition, which makes it the only **zero-false-positive** signal in this workbook. If that panel is
empty, none are configured — that is the cheapest detection win available to you.

### LAPS (Windows Local Administrator Password Solution)
Randomises the local admin password per machine. Its absence is what makes "one local account name
across many hosts" a finding at all. The Local Accounts tab is as much a measure of LAPS coverage as
of user behaviour.

### Generic / service / shared account
An account with no single human owner. These get shared because sharing costs nobody anything. The
workbook classifies on evidence — naming pattern, no manager, no job title, no interactive sign-ins
— rather than on name alone.
"""

# ===========================================================================
# INVESTIGATION
# ===========================================================================
TRIAGE = """
### Before you escalate, ask these five questions

**1. Could one person plausibly produce this?**
A consultant travelling with a laptop and a phone generates real fan-out. A sales engineer on 5G
rotates IPs constantly. Compare against the person's role before assuming sharing.

**2. Do the indicators agree, or is one doing all the work?**
Check `Drivers`. Multiple independent signals pointing the same way is the whole basis for
confidence. A single inflated count is not.

**3. Is there a clean split, or a blend?**
Open the Drilldown IP profile. **Two distinct clusters that alternate** — different devices,
different hours, different locations — is sharing. **One gradually shifting pattern** is usually one
person with changing circumstances. This distinction does more work than any threshold.

**4. Does it continue when the user cannot be working?**
Activity during the account owner's leave, off-hours or a known outage is very hard to explain. Check
the hourly-by-country chart in the Drilldown.

**5. Sharing, or compromise?**
Sharing tends to be *stable and routine* — the same second location, week after week. Compromise
tends to be *new and abrupt*, often with token replay or Entra risk detections. **They need different
responses: one is a policy conversation, the other is an incident.** Getting this wrong wastes an
investigation and can tip off an attacker.

### Building an evidence pack

For anything going to HR, legal or a manager, collect:

1. The scorecard row — score, band and drivers.
2. Concurrent-session windows showing overlapping IPs and countries, with timestamps.
3. Geo-velocity violations with the computed speed and both locations.
4. The device/OS profile showing distinct clusters.
5. The full authentication timeline from the Drilldown.
6. Any on-prem host fan-out from MDI.

State plainly what the evidence **does** and **does not** show. It demonstrates that one credential
was used from places and devices a single person could not plausibly occupy. It does not identify
*who* the second person is — telemetry cannot do that, and claiming otherwise will not survive
scrutiny.

### When it is a service account

Do not route it to HR. Generic-named accounts used interactively from many hosts are an architecture
problem: the fix is a managed identity or gMSA, credential vaulting, and removing interactive logon
rights. The people using it are usually doing their jobs with the tools they were given.
"""

FALSE_POSITIVES = """
### Known benign causes — check these before escalating

| Pattern | Usually caused by | How to confirm |
|---|---|---|
| High IP count, one country, one device | Mobile carrier / CGNAT | ASN is stable across IPs |
| Two countries, impossible travel | VPN egress or cloud proxy | Egress IP belongs to your VPN provider's ASN |
| Concurrent sessions, same city | Split-tunnelling — some traffic via VPN, some direct | Two consistent IPs alternating all day |
| Many devices, one OS | Hardware refresh, VDI, or device re-registration | Device names follow a build/pool naming scheme |
| Non-interactive from Microsoft IPs | Background token refresh | `SignInClass` is NonInteractive; IP belongs to Microsoft |
| Device shared by many accounts | Sanctioned kiosk or clinical workstation | Device name matches a known shared asset in the CMDB |
| Whole cohort rotates together | Organisation-wide password expiry | Check `SyncRatio` and whether it recurs across cycles |
| Service account from many hosts | Legitimate automation | Non-interactive only, and the hosts are servers |

### Things that are *not* false positives, however tempting

* **"They're an admin, they touch everything."** Privileged accounts are the highest-value target.
  Admin status raises the stakes; it does not explain the pattern away.
* **"That's just how the team works."** Shared team credentials are the finding, not an exemption.
  Route it to IAM as an access-model problem.
* **"It's an old account nobody uses."** A dormant enabled account with a non-expiring password is
  a standing invitation. Dormancy is the risk, not a mitigation.
* **"The vendor needs it."** Third-party access should be a named identity with Conditional Access
  scope and an expiry date, not a shared credential.
"""
