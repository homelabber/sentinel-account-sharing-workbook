"""Confirms check_dynamic.py catches the real runtime failure it targets."""
import json, copy, subprocess, sys, os, shutil

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
SRC = os.path.join(HERE, "AccountSharingVisibility.workbook.json")
BAK = SRC + ".bak"

good = json.load(open(SRC, encoding="utf-8"))
shutil.copy(SRC, BAK)


def run():
    r = subprocess.run([sys.executable, os.path.join(HERE, "check_dynamic.py")],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def find_q(wb, name):
    def w(n):
        if isinstance(n, dict):
            if n.get("type") == 3 and n.get("name") == name:
                return n
            for v in n.values():
                r = w(v)
                if r:
                    return r
        if isinstance(n, list):
            for v in n:
                r = w(v)
                if r:
                    return r
    return w(wb)


def test(label, name, old, new):
    wb = copy.deepcopy(good)
    q = find_q(wb, name)
    assert q, f"panel {name} not found"
    assert old in q["content"]["query"], f"pattern not present in {name}"
    q["content"]["query"] = q["content"]["query"].replace(old, new, 1)
    json.dump(wb, open(SRC, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    rc, out = run()
    caught = rc != 0
    print(f"  [{'CAUGHT' if caught else 'MISSED'}] {label}")
    if caught:
        for l in out.splitlines():
            if l.startswith("UNSAFE"):
                print(f"           {l}")
    return caught


print("Reintroducing the runtime failure the portal reported:\n")
res = []

# The exact bug: move the dynamic unpack to AFTER the union legs close.
res.append(test(
    "DeviceDetail.deviceId unpacked after union (ov-score)",
    "ov-score",
    "| extend DeviceId = iff(DeviceId ==",
    "| extend DeviceId = tostring(DeviceDetail.deviceId)\n| extend DeviceId = iff(DeviceId =="))

res.append(test(
    "LocationDetails.city unpacked after union (cc-win)",
    "cc-win",
    "| extend DeviceId = iff(DeviceId ==",
    "| extend City2 = tostring(LocationDetails.city)\n| extend DeviceId = iff(DeviceId =="))

res.append(test(
    "TargetResources[0] indexed after union (dr-time)",
    "dr-time",
    "| sort by TimeGenerated desc",
    "| extend X = tostring(TargetResources[0].userPrincipalName)\n| sort by TimeGenerated desc"))

shutil.move(BAK, SRC)
rc, _ = run()
print(f"\nrestored original -> {'clean' if rc == 0 else 'DIRTY'}")
print(f"\n{sum(res)}/{len(res)} caught")
sys.exit(0 if all(res) and rc == 0 else 1)
