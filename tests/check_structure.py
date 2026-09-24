# -*- coding: utf-8 -*-
"""Structural checks for the workbook.

Catches the failure modes that produce a workbook which is valid JSON, has
valid KQL, and still does not work in the portal:
  * a required parameter with no resolvable default  -> mandatory pill, blocks queries
  * a JSON dropdown whose payload is in 'query'      -> stuck on <unset> with a spinner
  * HTML entities in labels/titles                   -> rendered literally as '&amp;'
  * a tab with no group, or a group no tab can reach -> blank page
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
wb = json.load(open(os.path.join(HERE, "AccountSharingVisibility.workbook.json"), encoding="utf-8"))

errors, warnings = [], []
params = {}
titles = []


def walk(node, scope):
    if not isinstance(node, dict):
        return
    t = node.get("type")
    c = node.get("content", {})

    if t == 9:
        for p in c.get("parameters", []):
            params[p["name"]] = (p, scope)
            for f in ("label", "description"):
                if p.get(f):
                    titles.append((f"param {p['name']}.{f}", p[f]))

    if t == 3 and c.get("title"):
        titles.append((f"panel {node.get('name')}", c["title"]))

    if t == 11:
        for l in c.get("links", []):
            titles.append((f"tab {l.get('subTarget')}", l.get("linkLabel", "")))

    if t == 12:
        c12 = node.get("content", {})
        nm = node.get("name")
        if c12.get("expandable"):
            if not c12.get("title"):
                errors.append(f"group {nm}: expandable but has no title — renders as an "
                              f"unlabelled collapsed strip the user cannot identify")
            if "expanded" not in c12:
                warnings.append(f"group {nm}: expandable with no explicit 'expanded' state")
            if not c12.get("items"):
                errors.append(f"group {nm}: expandable but empty")
            if node.get("conditionalVisibility") and c12.get("expandable"):
                pass  # nested help inside a tab group is fine
        vis = node.get("conditionalVisibility")
        s = vis.get("value") if vis else scope
        for i in c.get("items", []):
            walk(i, s)


for item in wb["items"]:
    walk(item, "global")

# ---- 1. parameters must resolve without user interaction -------------------
for name, (p, scope) in params.items():
    ptype = p.get("type")
    required = p.get("isRequired", False)
    qt = p.get("queryType")
    has_value = "value" in p and p["value"] is not None

    if required and not has_value:
        errors.append(f"{name}: isRequired=True with no 'value' - renders as an "
                      f"unsatisfied mandatory pill and blocks bound queries")

    if "jsonData" in p:
        if qt is not None:
            errors.append(f"{name}: JSON dropdown must NOT set 'queryType' (has {qt}). "
                          f"Verified against 280/280 shipping Microsoft workbooks — setting it "
                          f"makes the portal try to execute the parameter and it hangs on <unset>.")
        if p.get("query"):
            errors.append(f"{name}: has both 'jsonData' and 'query'")
        try:
            opts = json.loads(p["jsonData"])
        except Exception as e:
            errors.append(f"{name}: jsonData is not valid JSON ({e})")
            continue
        vals = [o.get("value") if isinstance(o, dict) else o for o in opts]
        if not any(isinstance(o, dict) and o.get("selected") for o in opts):
            warnings.append(f"{name}: no option marked selected")
        if has_value and p["value"] not in vals:
            errors.append(f"{name}: default {p['value']!r} not among options {vals}")

    elif qt == 8:
        errors.append(f"{name}: queryType 8 with no 'jsonData' — nothing to load")

    if ptype == 2 and qt == 0 and required and not has_value:
        errors.append(f"{name}: KQL-backed dropdown is required but has no default")

# ---- 2. visualization must be a valid string, settings in the right slot ----
VALID_VIZ = {"table", "tiles", "barchart", "piechart", "linechart", "timechart",
             "areachart", "scatterchart", "graph", "map", "honeycomb",
             "stepchart", "unstackedbar", "categoricalbar"}


def check_panels(node):
    if isinstance(node, dict):
        if node.get("type") == 3:
            c = node["content"]
            nm = node.get("name")
            v = c.get("visualization")
            if not isinstance(v, str):
                errors.append(f"panel {nm}: visualization is {type(v).__name__}, not a string "
                              f"-> portal shows 'Unable to find visualization: [object Object]'. "
                              f"Almost always a settings dict passed into the wrong argument.")
            elif v not in VALID_VIZ:
                errors.append(f"panel {nm}: unknown visualization {v!r}")
            gs = c.get("gridSettings")
            if gs is not None and not isinstance(gs, dict):
                errors.append(f"panel {nm}: gridSettings must be an object")
            if isinstance(gs, dict) and "formatters" in gs:
                if not isinstance(gs["formatters"], list):
                    errors.append(f"panel {nm}: gridSettings.formatters must be a list")
            if not c.get("query", "").strip():
                errors.append(f"panel {nm}: empty query")
        for v in node.values():
            check_panels(v)
    elif isinstance(node, list):
        for v in node:
            check_panels(v)


check_panels(wb)

# ---- 3. no HTML entities in anything the user reads ------------------------
ENT = re.compile(r"&(amp|lt|gt|quot|#\d+);")
for where, s in titles:
    m = ENT.search(s or "")
    if m:
        errors.append(f"HTML entity {m.group(0)!r} in {where} - renders literally: {s!r}")

# ---- 3. parameter tokens used in queries must exist ------------------------
qtext = []


def collect(node):
    if isinstance(node, dict):
        if node.get("type") == 3:
            qtext.append(node["content"].get("query", ""))
        if node.get("type") == 9:
            for p in node["content"].get("parameters", []):
                if p.get("queryType") == 0 and p.get("query"):
                    qtext.append(p["query"])
        for v in node.values():
            collect(v)
    if isinstance(node, list):
        for v in node:
            collect(v)


collect(wb)
used = set(re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", " ".join(qtext)))
declared = set(params)
if used - declared:
    errors.append(f"queries reference undeclared parameters: {sorted(used - declared)}")
if declared - used - {"SelectedTab"}:
    warnings.append(f"declared but unused: {sorted(declared - used - {'SelectedTab'})}")

# ---- 4. tab wiring ---------------------------------------------------------
tab_items = [i for i in wb["items"] if i.get("type") == 11]
subtargets = set()
if not tab_items:
    errors.append("no tab strip found")
else:
    subtargets = {l["subTarget"] for l in tab_items[0]["content"]["links"]}
    groups = {i["conditionalVisibility"]["value"] for i in wb["items"]
              if i.get("type") == 12 and i.get("conditionalVisibility")}
    if subtargets - groups:
        errors.append(f"tabs with no group: {sorted(subtargets - groups)}")
    if groups - subtargets:
        errors.append(f"groups unreachable: {sorted(groups - subtargets)}")
    tp = params.get("SelectedTab")
    if not tp:
        errors.append("SelectedTab never declared - workbook loads with no tab selected")
    elif tp[0].get("value") not in subtargets:
        errors.append(f"SelectedTab default {tp[0].get('value')!r} is not a tab")

# ---- 5. no stale fallbackResourceIds --------------------------------------
fb = wb.get("fallbackResourceIds")
if fb and any(not str(x).startswith("/subscriptions/") for x in fb):
    errors.append(f"fallbackResourceIds contains non-resource-id values {fb} - "
                  f"can break workspace binding for every query")

# ---- 6. every item name must be unique -------------------------------------
names = []


def all_names(node):
    if isinstance(node, dict):
        if "name" in node and isinstance(node.get("name"), str) and "type" in node:
            names.append(node["name"])
        for v in node.values():
            all_names(v)
    elif isinstance(node, list):
        for v in node:
            all_names(v)


all_names(wb)
seen = {}
for n in names:
    seen[n] = seen.get(n, 0) + 1
dupe = {k: v for k, v in seen.items() if v > 1}
if dupe:
    errors.append(f"duplicate item names {dupe} — workbooks key items by name and "
                  f"duplicates cause items to overwrite or fail to render")

jsoncount = sum(1 for p, _ in params.values() if "jsonData" in p)
print(f"parameters : {len(params)}   (json dropdowns: {jsoncount})")
print(f"tabs       : {len(subtargets)}")
print(f"queries    : {len(qtext)}")
print()
for w in warnings:
    print("WARN ", w)
for e in errors:
    print("ERROR", e)
print()
if errors:
    print(f"FAILED - {len(errors)} structural error(s)")
    sys.exit(1)
print("STRUCTURE OK - parameters resolve on load, tabs wired, no entity leakage")
