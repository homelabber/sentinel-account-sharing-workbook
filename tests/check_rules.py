# -*- coding: utf-8 -*-
"""Portal-contract validation for the analytics rules.

Valid YAML containing valid KQL can still produce a rule that Sentinel rejects on
save, or — worse — accepts and then silently drops half of. These are the checks
that catch that class of failure:

  * an entity mapping, custom detail or alert-override placeholder that names a
    column the query never projects. Sentinel does not fail the save; the alert
    is simply created with no entities, which is the single most common way a
    working detection produces useless incidents.
  * queryPeriod shorter than queryFrequency, so the rule misses events between runs.
  * queryPeriod longer than the 14 days the scheduled engine allows.
  * a baseline window inside the query that exceeds queryPeriod, so the baseline
    is silently truncated and every result looks new.
  * severity, tactic, entity-type and identifier values outside the accepted sets.
  * duplicate rule ids, which overwrite each other on deployment.

Run:  python tests/check_rules.py
"""
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("pyyaml is required:  pip install pyyaml")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(HERE, "rules")

SEVERITIES = {"Informational", "Low", "Medium", "High"}

TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact", "ImpairProcessControl", "InhibitResponseFunction",
}

# entity type -> identifiers Sentinel accepts for it
ENTITY_IDENTIFIERS = {
    "Account": {"Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid",
                "AadUserId", "AadTenantId", "PUID", "ObjectGuid", "CloudAppAccountId"},
    "Host": {"HostName", "FullName", "NetBiosName", "AzureID", "OMSAgentID", "DnsDomain"},
    "IP": {"Address"},
    "URL": {"Url"},
    "FileHash": {"Algorithm", "Value"},
    "File": {"Name", "Directory"},
    "Process": {"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "DNS": {"DomainName"},
    "AzureResource": {"ResourceId"},
    "Mailbox": {"MailboxPrimaryAddress", "DisplayName", "Upn"},
    "MailMessage": {"Recipient", "Sender", "SenderIP", "Subject", "NetworkMessageId"},
    "SecurityGroup": {"DistinguishedName", "SID", "ObjectGuid"},
    "RegistryKey": {"Hive", "Key"},
    "RegistryValue": {"Name", "Value"},
    "Malware": {"Name", "Category"},
    "IoTDevice": {"IoTHub", "DeviceId"},
    "SubmissionMail": {"NetworkMessageId", "SubmissionId", "Submitter", "Recipient"},
}

MAX_PERIOD_MINUTES = 14 * 24 * 60
MIN_FREQUENCY_MINUTES = 5
MAX_ENTITY_MAPPINGS = 10
MAX_IDENTIFIERS_PER_ENTITY = 3

ISO_RE = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")
# 'let Name = 14d;' style declarations inside the query
LET_DURATION_RE = re.compile(r"^\s*let\s+(\w+)\s*=\s*(\d+)\s*([mhd])\s*;", re.MULTILINE)
PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")

problems = []
checked = 0


def fail(rule_file, msg):
    problems.append("%s: %s" % (rule_file, msg))


def iso_to_minutes(value):
    """Parse the ISO-8601 subset Sentinel accepts. Returns None if unparseable."""
    if not isinstance(value, str):
        return None
    m = ISO_RE.match(value)
    if not m or value in ("P", "PT"):
        return None
    days, hours, minutes = (int(g) if g else 0 for g in m.groups())
    total = days * 24 * 60 + hours * 60 + minutes
    return total or None


def duration_token_to_minutes(amount, unit):
    return int(amount) * {"m": 1, "h": 60, "d": 24 * 60}[unit]


def final_projected_columns(query):
    """Column names produced by the query's last projection.

    Returns None when no projection can be located, which is treated as a failure
    rather than a pass. A checker that quietly finds nothing to check is worse
    than no checker, because it reads like evidence.
    """
    # strip comments so a '| project' inside one is not mistaken for the real thing
    body = "\n".join(re.sub(r"//.*$", "", line) for line in query.splitlines())

    matches = list(re.finditer(r"\|\s*project(?:-rename)?\s", body))
    if not matches:
        return None

    start = matches[-1].end()
    rest = body[start:]
    # the projection runs until the next pipe that starts a new operator
    end = rest.find("|")
    clause = rest if end == -1 else rest[:end]

    columns = []
    depth = 0
    current = ""
    for ch in clause:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            columns.append(current)
            current = ""
        else:
            current += ch
    columns.append(current)

    names = []
    for col in columns:
        col = col.strip()
        if not col:
            continue
        if "=" in col:
            name = col.split("=", 1)[0].strip()
        else:
            name = col.split(".")[-1].strip()
        if re.fullmatch(r"\w+", name):
            names.append(name)
    return names or None


def check_rule(doc, fname):
    global checked
    checked += 1

    for field in ("id", "name", "description", "severity", "query",
                  "queryFrequency", "queryPeriod", "kind"):
        if not doc.get(field):
            fail(fname, "missing required field '%s'" % field)
            return

    if doc["severity"] not in SEVERITIES:
        fail(fname, "severity '%s' is not one of %s" % (doc["severity"], sorted(SEVERITIES)))

    for tactic in doc.get("tactics", []):
        if tactic not in TACTICS:
            fail(fname, "unknown tactic '%s'" % tactic)

    for technique in doc.get("relevantTechniques", []):
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
            fail(fname, "technique '%s' is not a valid ATT&CK id" % technique)

    freq = iso_to_minutes(doc["queryFrequency"])
    period = iso_to_minutes(doc["queryPeriod"])

    if freq is None:
        fail(fname, "queryFrequency '%s' is not a valid ISO-8601 duration" % doc["queryFrequency"])
    if period is None:
        fail(fname, "queryPeriod '%s' is not a valid ISO-8601 duration" % doc["queryPeriod"])

    if freq and period:
        if period < freq:
            fail(fname, "queryPeriod (%s) is shorter than queryFrequency (%s) - "
                        "events between runs are never evaluated"
                 % (doc["queryPeriod"], doc["queryFrequency"]))
        if period > MAX_PERIOD_MINUTES:
            fail(fname, "queryPeriod (%s) exceeds the 14-day scheduled-rule maximum" % doc["queryPeriod"])
        if freq < MIN_FREQUENCY_MINUTES:
            fail(fname, "queryFrequency (%s) is below the 5-minute minimum" % doc["queryFrequency"])

    query = doc["query"]

    # a lookback declared inside the query cannot exceed the data the engine hands it
    if period:
        for name, amount, unit in LET_DURATION_RE.findall(query):
            minutes = duration_token_to_minutes(amount, unit)
            if minutes > period:
                fail(fname, "query declares '%s = %s%s' (%d min) but queryPeriod is %s (%d min) - "
                            "the lookback is silently truncated"
                     % (name, amount, unit, minutes, doc["queryPeriod"], period))

    columns = final_projected_columns(query)
    if columns is None:
        fail(fname, "could not locate a final 'project' in the query - "
                    "entity and custom-detail columns cannot be verified")
        return
    known = set(columns)

    mappings = doc.get("entityMappings", [])
    if len(mappings) > MAX_ENTITY_MAPPINGS:
        fail(fname, "%d entity mappings exceeds the limit of %d"
             % (len(mappings), MAX_ENTITY_MAPPINGS))

    for mapping in mappings:
        etype = mapping.get("entityType")
        if etype not in ENTITY_IDENTIFIERS:
            fail(fname, "unknown entityType '%s'" % etype)
            continue
        fields = mapping.get("fieldMappings", [])
        if not fields:
            fail(fname, "entityType '%s' has no fieldMappings" % etype)
        if len(fields) > MAX_IDENTIFIERS_PER_ENTITY:
            fail(fname, "entityType '%s' has %d identifiers, the limit is %d"
                 % (etype, len(fields), MAX_IDENTIFIERS_PER_ENTITY))
        for fm in fields:
            ident = fm.get("identifier")
            column = fm.get("columnName")
            if ident not in ENTITY_IDENTIFIERS[etype]:
                fail(fname, "'%s' is not a valid identifier for entityType '%s'" % (ident, etype))
            if column not in known:
                fail(fname, "entity mapping %s.%s references column '%s', which the query "
                            "does not project - the alert would be created with no entity"
                     % (etype, ident, column))

    for label, column in (doc.get("customDetails") or {}).items():
        if not re.fullmatch(r"\w+", label):
            fail(fname, "custom detail key '%s' must be alphanumeric" % label)
        if column not in known:
            fail(fname, "custom detail '%s' references column '%s', which the query does not project"
                 % (label, column))

    override = doc.get("alertDetailsOverride") or {}
    for key, template in override.items():
        if not isinstance(template, str):
            continue
        for placeholder in PLACEHOLDER_RE.findall(template):
            if placeholder not in known:
                fail(fname, "alertDetailsOverride.%s uses {{%s}}, which the query does not project "
                            "- the placeholder renders literally in the incident"
                     % (key, placeholder))

    grouping = (doc.get("incidentConfiguration") or {}).get("groupingConfiguration") or {}
    if grouping.get("matchingMethod") == "Selected" and not grouping.get("groupByEntities"):
        fail(fname, "groupingConfiguration uses matchingMethod 'Selected' but names no groupByEntities")
    if grouping.get("groupByEntities"):
        mapped_types = {m.get("entityType") for m in mappings}
        for entity in grouping["groupByEntities"]:
            if entity not in mapped_types:
                fail(fname, "groupByEntities names '%s' but the rule maps no such entity" % entity)


def main():
    if not os.path.isdir(RULES_DIR):
        sys.exit("rules/ directory not found at %s" % RULES_DIR)

    files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith((".yaml", ".yml")))
    if not files:
        sys.exit("no rule files found in %s" % RULES_DIR)

    ids = {}
    for fname in files:
        with open(os.path.join(RULES_DIR, fname), "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            fail(fname, "did not parse as a YAML mapping")
            continue
        rid = doc.get("id")
        if rid in ids:
            fail(fname, "duplicate rule id %s, already used by %s" % (rid, ids[rid]))
        ids[rid] = fname
        check_rule(doc, fname)

    print("Checked %d analytics rules" % checked)
    if problems:
        print("\n%d problem(s):\n" % len(problems))
        for p in problems:
            print("  FAIL  %s" % p)
        return 1
    print("All rule structure checks PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
