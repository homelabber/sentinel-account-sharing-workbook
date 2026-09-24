# -*- coding: utf-8 -*-
"""Per-tab collapsible help: how to read the tab, and how to tune it."""

OVERVIEW = """
**What this tab answers:** which accounts should I look at first, and why?

The scorecard is a triage queue. It does not decide anything — it ranks accounts by how many
independent indicators point at shared use, and shows you exactly which ones fired.

**Read it in this order:** Band → Drivers → the specific counts. Jumping straight to the counts
loses the context that makes them meaningful.

**Estate summary tiles** give the shape of the problem. If "Accounts observed" is 0, stop and check
the Coverage tab — you have a data problem, not a clean estate. If "Generic/service-named accounts"
is large relative to your headcount, you have an account-hygiene problem that will dominate
everything else until it is addressed.

**The trend chart** matters more than any single day. A steady line is your normal. A step change
means something happened — a policy change, a new VPN egress, an onboarding wave, or a genuine
incident. Investigate the step, not the level.
"""

CONCURRENCY = """
**What this tab answers:** was this account used in two places at once?

This is the strongest evidence available. Everything else on the workbook suggests; this comes close
to demonstrating.

**Two independent methods, deliberately:**

*Session overlap* counts distinct IPs per account per window. Tunable, fast, and good for finding
patterns across the estate.

*Geo-velocity* computes the implied travel speed between consecutive sign-ins. Harder to argue with,
because the arithmetic is visible — 4,000 km in 20 minutes is not a threshold judgement, it is a
physical impossibility. Computed here from raw coordinates rather than read from Entra ID
Protection, so it needs no P2 licence.

**Persistence is what separates sharing from anomaly.** One overlapping window is an event. The same
account overlapping every working day for three weeks is an arrangement. The roll-up panel's
`Persistence` column captures this.

**Tune here first.** If the overlap panel is overwhelming, your window is too long or your VPN
egress is producing artefacts — check the IP/ASN detail in the evidence panel before lowering
anything.
"""

FANOUT = """
**What this tab answers:** how widely is this credential spread, and in which direction?

**One account → many devices** means several people are probably using it.
**One device → many accounts** is either a sanctioned kiosk or one person collecting credentials —
and telemetry cannot tell those apart. Check the device against your asset inventory.

**OS diversity is the signal to trust here.** Raw device or IP counts inflate easily. A single user
signing in from Windows, macOS *and* Android inside a short window is genuinely unusual, because
people do not casually switch platforms mid-task.

**Unmanaged device share matters too.** A high proportion of sign-ins with no trust type means
credentials are being entered on machines you do not control — which is both a sharing indicator and
an independent risk worth fixing.

**Network dispersion is the weakest panel on this tab** and is included for completeness. Treat many
ASNs as corroboration, never as a case on its own.
"""

HYGIENE = """
**What this tab answers:** which credentials are structurally easy to share?

Sharing needs a password that stays valid and is easy to hand over. These panels find the conditions
that make that possible.

**The shared-MFA panel is the highest-value item here.** One phone number or authenticator device
registered against several accounts is about the closest thing to a hard shared-credential *fact*
the platform exposes — and it is frequently the actual mechanism behind sharing, because whoever
holds the second factor controls every account it covers.

**Third-party MFA registration** has two readings: sanctioned helpdesk enrolment, or credential
hand-off and attacker persistence. Confirm against your enrolment process.

**Legacy authentication is the single biggest enabler of silent sharing.** It bypasses MFA entirely,
so a shared password just works, indefinitely, with nothing to detect. If anything on this tab
justifies a project, it is this.

**Non-expiring and not-required passwords** are the structural precondition for a password to be
shared and stay shared. `PASSWD_NOTREQD` in particular means the account may have no password at all.
"""

PWREUSE = """
**What this tab answers:** are these accounts actually using the same password?

Read the tier explanation at the top of the tab — it matters. Tier 2 panels do **not** prove two
passwords are identical. They prove the credentials are *managed as one secret* or *held by one
operator*, which for containment purposes is the same finding and should be reported that way.

**Synchronised rotation is the strongest proxy.** Look at `SyncRatio`, not just the count. Two
accounts that rotate together on 100% of cycles across three or more independent rotations are being
maintained as a single credential. Coincidence does not survive three cycles.

**Correlated lockouts are widely misread.** A *small, stable* set of accounts locking together is a
shared credential cached in a script or mapped drive. A *large, shifting* set is a password spray.
Same panel, opposite conclusions — the `Discriminator` column tells you which.

**Bulk resets** are only a problem if the tooling issued one shared temporary value. Check that
before raising anything.

**Tier 1 is real ground truth** but needs the DSInternals collector deployed, covers on-premises AD
only, and must be run against an offline `ntds.dit` snapshot — replication mode looks exactly like
DCSync to Defender for Identity.
"""

GENERIC = """
**What this tab answers:** which accounts have no real owner?

Accounts nobody owns personally are the ones that get shared, because sharing them costs nobody
anything and embarrasses nobody.

**Classification is evidence-based, not name-based.** An account is flagged when at least two signals
agree: generic naming, no manager, no job title, or zero interactive sign-ins. Name matching alone
produces too many false hits — plenty of real people have "admin" in their UPN.

**The row type that matters most: a generic-named account logging on interactively.** A genuine
service account authenticates non-interactively only. The moment a human signs in to `svc-backup` at
a keyboard, it is a shared human credential regardless of what it is called — and it almost certainly
has a non-expiring password that several people know.

**The dormancy panel uses your threshold**, unlike the platform's built-in inactivity recommendation
which is fixed. Run it at 30, 60 and 90 and compare the three lists — the accounts that appear only
at 30 days are the ones drifting out of use right now, which is the cheapest moment to reclaim them.
"""

ONPREM = """
**What this tab answers:** how is this credential actually used inside the network?

Entra sign-in logs stop at the cloud edge. This tab comes from Defender for Identity sensors on your
domain controllers and shows what the credential does once it is inside — which is where a shared or
stolen credential does its damage.

**Host fan-out is the cleanest signal in the whole workbook.** No CGNAT, no mobile churn, no
geolocation guesswork. A user account authenticating from twenty workstations is shared, automated,
or stolen — there is very little benign explanation available.

**NTLM share deserves specific attention.** NTLM authenticates with the password hash alone, so a
hash copied to another machine is indistinguishable from the real user everywhere it is used. High
NTLM usage combined with host fan-out is simultaneously a sharing indicator and the precondition for
pass-the-hash. Reducing NTLM is worth more than any detection you could build on top of it.

**Group membership changes** are included because privilege sharing is a form of account sharing —
granting someone else's account your access is the same outcome by a different route.
"""

LOCAL = """
**What this tab answers:** are local, non-domain accounts being reused across machines?

This is a genuinely different problem from domain-account sharing, and it is **invisible to both
Defender for Identity and Entra ID** — a local SAM account never touches a domain controller or the
cloud. It is covered here from Defender for Endpoint logon telemetry.

**The classic finding is one local account name across many machines** — the signature of a
golden-image or helpdesk password identical estate-wide. When that account also authenticates *over
the network*, the shared password is being actively used for lateral movement, and it is the most
reliable path an attacker has to move without ever touching a domain credential.

**The fix is structural, not detective.** Windows LAPS randomises the local administrator password
per machine and makes this entire class of finding disappear. Treat these panels as a LAPS coverage
report as much as a behavioural one — chasing individual hits without deploying LAPS is effort spent
on a symptom.
"""

REDTEAM = """
**What this tab answers:** is someone *taking* credentials rather than being given them?

Account sharing and credential theft are the same telemetry viewed with different intent. An
adversary holding your credential is, functionally, sharing your account with you — and every
technique here exists to make one credential usable by a second party.

**Honeytokens are the highest-fidelity control available to you.** A decoy account no human should
touch produces zero false positives; any authentication against it is unauthorised by definition. If
that panel is empty, none are configured — that is the cheapest detection win on this page and worth
doing before tuning anything else.

**Token replay across countries is near-conclusive** and means MFA was bypassed, because the token is
post-authentication. Route it to incident response immediately, not to a policy conversation.

**Device code flow** is the one people miss. It is both a phishing technique and the easiest
*consensual* way to hand a working session to a colleague — which is precisely why it belongs here
and not filed under benign authentication.

**Spray vs. brute force vs. stuffing** are distinguished by shape: few attempts against many accounts
is a spray, many attempts against few is brute force, and a broad reused-credential list is stuffing.
The `Pattern` column does this classification for you.
"""

DRILL = """
**What this tab answers:** what is the full story for one account?

Everything the workbook knows about a single identity: Entra interactive, Entra non-interactive,
on-premises AD and the Entra audit log on one timeline, plus the network and device profile and any
alerts naming the account.

**The clearest tell is two profiles that alternate cleanly rather than blend.** Two device names,
two IP clusters, two working-hour patterns, switching back and forth — that is two people. One
gradually shifting pattern is usually one person whose circumstances changed.

**Check activity against what you know about the person.** Sign-ins during their leave, during a
known outage, or at hours that do not match their role are very difficult to explain away.

**Watch for a sudden profile change immediately after an MFA registration or password reset** — that
sequence is the signature of a credential being handed over or taken.

**Panels stay empty until you pick an account.** That is intentional, not an error.
"""

COVERAGE = """
**What this tab answers:** can I trust what the other tabs are telling me?

**Start here, not at the Overview.** An empty panel and a clean result look identical and mean
opposite things. The live connector status shows which tables exist in this workspace, how many rows
each has in your selected range, and which panels depend on them.

The written section covers what this workbook **cannot** do — including the precise reason
identical-password detection is not directly queryable, and the three capabilities a workbook
structurally cannot replicate from an inline identity-protection agent. Read it before presenting
results to anyone who will ask "are we sure?".

It also lists the highest-value panels to promote into **Analytics Rules**. A workbook is a
visualisation surface; it cannot alert or contain. Converting the panels you trust into rules is how
this becomes operational rather than something someone remembers to open.
"""
