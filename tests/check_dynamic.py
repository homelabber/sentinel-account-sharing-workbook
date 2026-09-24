# -*- coding: utf-8 -*-
"""Detects dot/index access to a dynamic column that happens AFTER a union.

Kusto's semantic analyser accepts this (the column is dynamic in every leg), but
the Log Analytics service rejects it at runtime with:

    Failed to resolve expression 'DeviceDetail.deviceId'

because the unioned column is no longer statically typed as dynamic. Fix by
unpacking the field inside each union leg before the legs are combined.

Detection is character-accurate: it tracks parenthesis depth from the union
keyword onward, so access inside a multi-line leg (depth > 0) is not flagged.
Comments and string literals are blanked first so they never match.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
wb = json.load(open(os.path.join(HERE, "AccountSharingVisibility.workbook.json"), encoding="utf-8"))

DYNAMIC = ["DeviceDetail", "LocationDetails", "TargetResources", "InitiatedBy",
           "AdditionalFields", "MfaDetail", "AuthenticationDetails",
           "ActivityInsights", "DevicesInsights", "UsersInsights",
           "AuthenticationProcessingDetails"]

DOT = re.compile(r"\b(" + "|".join(DYNAMIC) + r")\s*(?:\.|\[)")
UNION = re.compile(r"\bunion\b", re.I)


def strip_noise(q):
    out = []
    for line in q.split("\n"):
        line = re.sub(r"//.*$", lambda m: " " * len(m.group(0)), line)
        line = re.sub(r'"[^"]*"', lambda m: " " * len(m.group(0)), line)
        line = re.sub(r"'[^']*'", lambda m: " " * len(m.group(0)), line)
        out.append(line)
    return "\n".join(out)


def collect(node, out):
    if isinstance(node, dict):
        if node.get("type") == 3:
            out.append((node.get("name"), node["content"].get("query", "")))
        if node.get("type") == 9:
            for p in node["content"].get("parameters", []):
                if p.get("queryType") == 0 and p.get("query"):
                    out.append((f"param:{p['name']}", p["query"]))
        for v in node.values():
            collect(v, out)
    elif isinstance(node, list):
        for v in node:
            collect(v, out)


qs = []
collect(wb, qs)

findings = []
for name, raw in qs:
    clean = strip_noise(raw)
    um = UNION.search(clean)
    if not um:
        continue

    # The union's legs are everything up to the first pipe at paren-depth 0.
    # Function-call parens (tostring(...)) must not be mistaken for leg parens,
    # so the boundary is located first and the whole remainder is then unsafe.
    depth = 0
    boundary = None
    for i in range(um.end(), len(clean)):
        ch = clean[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth <= 0:
            boundary = i
            break
    if boundary is None:
        continue

    for m in DOT.finditer(clean, boundary):
        line = clean.count("\n", 0, m.start()) + 1
        snippet = raw.split("\n")[line - 1].strip()[:95]
        findings.append((name, line, m.group(1), snippet))

print(f"scanned {len(qs)} queries for post-union dynamic access\n")
if findings:
    for name, line, col, snippet in findings:
        print(f"UNSAFE  {name}  line {line}  column '{col}'")
        print(f"        {snippet}")
        print(f"        fix: unpack '{col}' inside each union leg")
        print()
    print(f"FAILED - {len(findings)} post-union dynamic access(es)")
    sys.exit(1)

print("OK - no dynamic column is dot-accessed after a union")
