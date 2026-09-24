"""Diffs our dropdown parameters against the schema Microsoft actually ships."""
import json, os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
ref = json.load(open(os.path.join(HERE, "reference_schema.json")))
wb = json.load(open(os.path.join(HERE, "AccountSharingVisibility.workbook.json"), encoding="utf-8"))

print("Microsoft's shipping schema (representative, from 280 real examples):")
print(json.dumps(ref["sample"], indent=2))
print(f"\n  queryType absent in {ref['queryType_absent']}/{ref['total']} real examples")

p = [i for i in wb["items"] if i.get("type") == 9 and i.get("name") == "parameters"][0]
ours = [x for x in p["content"]["parameters"] if "jsonData" in x]

print(f"\n{'=' * 74}")
print(f"OUR {len(ours)} DROPDOWNS")
print("=" * 74)
print(json.dumps(ours[0], indent=2))

print(f"\n{'=' * 74}")
print("CONFORMANCE")
print("=" * 74)
bad = 0
for x in ours:
    issues = []
    if "queryType" in x:
        issues.append(f"has queryType={x['queryType']} (must be absent)")
    if "jsonData" not in x:
        issues.append("no jsonData")
    if "value" not in x:
        issues.append("no value")
    if "query" in x:
        issues.append("has stray query")
    try:
        opts = json.loads(x["jsonData"])
        vals = [o.get("value") if isinstance(o, dict) else o for o in opts]
        if x.get("value") not in vals:
            issues.append(f"value {x.get('value')!r} not in options")
    except Exception as e:
        issues.append(f"bad jsonData: {e}")
    status = "OK  " if not issues else "BAD "
    if issues:
        bad += 1
    print(f"  {status}{x['name']:22} {'; '.join(issues) if issues else 'conforms'}")

print(f"\n{len(ours) - bad}/{len(ours)} conform to the verified Microsoft schema")
