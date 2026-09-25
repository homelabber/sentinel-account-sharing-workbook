# -*- coding: utf-8 -*-
"""Confirms check_rules catches the bugs it claims to, by reintroducing them.

Every case below is a mistake that produces a rule Sentinel accepts. None of them
raise a KQL error, and several produce a detection that appears to work while
quietly emitting incidents with no entities attached.

A green check from an untested checker is worse than no checker, because it reads
like evidence.
"""
import copy
import os
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("pyyaml is required:  pip install pyyaml")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
RULES = os.path.join(HERE, "rules")
CHECKER = os.path.join(HERE, "tests", "check_rules.py")

# The pristine copy lives outside the repo. Keeping it in-tree means a sync
# client or editor can hold the directory open, and the cleanup then fails
# partway through leaving a deliberately-broken rule on disk.
BAK = tempfile.mkdtemp(prefix="acctshare-rules-")

SUBJECT = "01-geo-velocity.yaml"
SECOND = "02-token-multi-country.yaml"


def load(fname):
    with open(os.path.join(RULES, fname), "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def write(fname, doc):
    with open(os.path.join(RULES, fname), "w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, width=10000, allow_unicode=True)


def run():
    r = subprocess.run([sys.executable, CHECKER], capture_output=True, text=True)
    return r.returncode, r.stdout


def restore():
    """Copy the pristine files back over the mutated ones."""
    backed_up = os.listdir(BAK)
    for fname in backed_up:
        shutil.copyfile(os.path.join(BAK, fname), os.path.join(RULES, fname))
    for fname in os.listdir(RULES):
        if fname not in backed_up:
            os.remove(os.path.join(RULES, fname))


def mutate_and_test(label, fname, fn):
    doc = copy.deepcopy(load(fname))
    fn(doc)
    write(fname, doc)
    rc, out = run()
    caught = rc != 0
    print("  [%s] %s" % ("CAUGHT" if caught else "MISSED", label))
    if caught:
        for line in out.splitlines():
            if "FAIL" in line:
                print("           %s" % line.strip()[:120])
    restore()
    return caught


def main():
    for fname in os.listdir(RULES):
        if fname.endswith((".yaml", ".yml")):
            shutil.copyfile(os.path.join(RULES, fname), os.path.join(BAK, fname))

    try:
        # the suite is meaningless unless the unmodified rules pass
        rc, _ = run()
        if rc != 0:
            print("Baseline rules do not pass check_rules - fix them before testing the checker.")
            return 1
        return run_cases()
    finally:
        restore()
        shutil.rmtree(BAK, ignore_errors=True)


def run_cases():
    print("Regression tests - each reintroduces a rule bug Sentinel would accept:\n")
    results = []

    # Bug 1: entity mapping points at a column the query never projects.
    # Sentinel saves the rule happily and creates incidents with no entities.
    def b1(d):
        d["entityMappings"][0]["fieldMappings"][0]["columnName"] = "UserPrincipalNam"
    results.append(mutate_and_test(
        "entity mapping references a non-existent column", SUBJECT, b1))

    # Bug 2: custom detail bound to a column that does not exist.
    def b2(d):
        d["customDetails"]["DistanceKm"] = "DistanceKilometres"
    results.append(mutate_and_test(
        "custom detail references a non-existent column", SUBJECT, b2))

    # Bug 3: alert override placeholder with no matching column - renders as
    # the literal text {{Speed}} in the incident title.
    def b3(d):
        d["alertDetailsOverride"]["alertDisplayNameFormat"] = "Geo-velocity {{Speed}} km/h"
    results.append(mutate_and_test(
        "alertDetailsOverride placeholder with no column", SUBJECT, b3))

    # Bug 4: queryPeriod shorter than queryFrequency - events that arrive between
    # runs are never evaluated by any run.
    def b4(d):
        d["queryFrequency"] = "PT6H"
        d["queryPeriod"] = "PT1H"
    results.append(mutate_and_test(
        "queryPeriod shorter than queryFrequency", SUBJECT, b4))

    # Bug 5: queryPeriod beyond the 14-day engine maximum.
    def b5(d):
        d["queryPeriod"] = "P30D"
    results.append(mutate_and_test(
        "queryPeriod exceeds the 14-day maximum", SUBJECT, b5))

    # Bug 6: the query looks back further than the engine hands it, so the
    # baseline is truncated and every result looks new.
    def b6(d):
        d["query"] = d["query"].replace("let LookbackWindow  = 6h;",
                                        "let LookbackWindow  = 30d;")
    results.append(mutate_and_test(
        "in-query lookback longer than queryPeriod", SUBJECT, b6))

    # Bug 7: identifier that does not belong to the entity type.
    def b7(d):
        d["entityMappings"][1]["fieldMappings"][0]["identifier"] = "IpAddress"
    results.append(mutate_and_test(
        "invalid identifier for the entity type", SUBJECT, b7))

    # Bug 8: tactic outside the ATT&CK enum - rejected on deployment.
    def b8(d):
        d["tactics"] = ["InitialAccess", "CredentialTheft"]
    results.append(mutate_and_test(
        "tactic outside the accepted enum", SUBJECT, b8))

    # Bug 9: malformed technique id.
    def b9(d):
        d["relevantTechniques"] = ["T1078", "1550.001"]
    results.append(mutate_and_test(
        "malformed ATT&CK technique id", SUBJECT, b9))

    # Bug 10: severity outside the accepted set.
    def b10(d):
        d["severity"] = "Critical"
    results.append(mutate_and_test(
        "severity outside the accepted set", SUBJECT, b10))

    # Bug 11: two rules sharing an id - the second overwrites the first silently
    # on deployment, so one detection simply never exists.
    def b11(d):
        d["id"] = load(SUBJECT)["id"]
    results.append(mutate_and_test(
        "duplicate rule id across two files", SECOND, b11))

    # Bug 12: grouping by an entity the rule never maps - grouping silently
    # does nothing and every alert becomes its own incident.
    def b12(d):
        d["incidentConfiguration"]["groupingConfiguration"]["groupByEntities"] = ["Host"]
    results.append(mutate_and_test(
        "groupByEntities names an unmapped entity", SUBJECT, b12))

    # Bug 13: a query with no final project. The checker must FAIL here rather
    # than pass, because it can no longer verify any column reference. This is
    # the specific way check_dynamic.py once passed while catching nothing.
    def b13(d):
        d["query"] = "SigninLogs\n| where TimeGenerated > ago(1h)\n| take 10\n"
    results.append(mutate_and_test(
        "query with no projection is unverifiable, not clean", SUBJECT, b13))

    caught = sum(results)
    total = len(results)
    print("\n%d/%d bugs caught" % (caught, total))
    if caught != total:
        print("check_rules.py has gaps - it reports clean on a broken rule.")
        return 1
    print("check_rules.py catches every bug it claims to.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
