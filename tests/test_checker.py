"""Confirms check_structure catches the bugs it claims to, by reintroducing them."""
import json, copy, subprocess, sys, os, shutil

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
SRC = os.path.join(HERE, "AccountSharingVisibility.workbook.json")
BAK = SRC + ".bak"

good = json.load(open(SRC, encoding="utf-8"))
shutil.copy(SRC, BAK)


def run():
    r = subprocess.run([sys.executable, os.path.join(HERE, "check_structure.py")],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def mutate_and_test(label, fn):
    wb = copy.deepcopy(good)
    fn(wb)
    json.dump(wb, open(SRC, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    rc, out = run()
    caught = rc != 0
    print(f"  [{'CAUGHT' if caught else 'MISSED'}] {label}")
    if caught:
        for line in out.splitlines():
            if line.startswith("ERROR"):
                print(f"           {line[6:][:110]}")
    return caught


def params_of(wb):
    return [i for i in wb["items"] if i.get("type") == 9 and i.get("name") == "parameters"][0]["content"]["parameters"]


print("Regression tests - each reintroduces a bug that broke the portal:\n")
results = []

# Bug 1: queryType set on a jsonData dropdown  (the <unset> spinner)
def b1(wb):
    p = [x for x in params_of(wb) if x["name"] == "MaxIPs"][0]
    p["queryType"] = 8
results.append(mutate_and_test("queryType set on a jsonData dropdown", b1))

# Bug 1b: payload in 'query' instead of 'jsonData'
def b1b(wb):
    p = [x for x in params_of(wb) if x["name"] == "MaxCountries"][0]
    p["query"] = p.pop("jsonData")
    p["queryType"] = 8
results.append(mutate_and_test("JSON payload in 'query' not 'jsonData'", b1b))

# Bug 2: required param with no default  (mandatory pill)
def b2(wb):
    p = [x for x in params_of(wb) if x["name"] == "MaxDevices"][0]
    p.pop("value")
results.append(mutate_and_test("required parameter with no default value", b2))

# Bug 3: HTML entity in a tab label
def b3(wb):
    t = [i for i in wb["items"] if i.get("type") == 11][0]
    t["content"]["links"][0]["linkLabel"] = "Overview &amp; Score"
results.append(mutate_and_test("HTML entity in tab label", b3))

# Bug 4: SelectedTab undeclared  (blank page)
def b4(wb):
    wb["items"] = [i for i in wb["items"] if i.get("name") != "tabstate"]
results.append(mutate_and_test("SelectedTab never declared", b4))

# Bug 5: bogus fallbackResourceIds
def b5(wb):
    wb["fallbackResourceIds"] = ["Azure Monitor"]
results.append(mutate_and_test("bogus fallbackResourceIds", b5))

# Bug 6: default not among dropdown options
def b6(wb):
    p = [x for x in params_of(wb) if x["name"] == "DormantDays"][0]
    p["value"] = "999"
results.append(mutate_and_test("default value not among dropdown options", b6))

# Bug 7: grid dict landing in the visualization slot
def b7(wb):
    def find(n):
        if isinstance(n, dict):
            if n.get("type") == 3 and n.get("name") == "ov-score":
                return n
            for v in n.values():
                r = find(v)
                if r:
                    return r
        if isinstance(n, list):
            for v in n:
                r = find(v)
                if r:
                    return r
    q = find(wb)
    q["content"]["visualization"] = q["content"].get("gridSettings", {"formatters": []})
results.append(mutate_and_test("grid dict passed into the visualization slot", b7))

# Bug 8: unknown visualization name
def b8(wb):
    def find(n):
        if isinstance(n, dict):
            if n.get("type") == 3 and n.get("name") == "ov-band":
                return n
            for v in n.values():
                r = find(v)
                if r:
                    return r
        if isinstance(n, list):
            for v in n:
                r = find(v)
                if r:
                    return r
    find(wb)["content"]["visualization"] = "bargraph"
results.append(mutate_and_test("unknown visualization name", b8))

# Bug 9: duplicate item names
def b9(wb):
    def find(n, want):
        if isinstance(n, dict):
            if n.get("name") == want:
                return n
            for v in n.values():
                r = find(v, want)
                if r:
                    return r
        if isinstance(n, list):
            for v in n:
                r = find(v, want)
                if r:
                    return r
    find(wb, "help-glossary")["name"] = "help-quickstart"
results.append(mutate_and_test("duplicate item names", b9))

# Bug 10: expandable group with no title
def b10(wb):
    def find(n, want):
        if isinstance(n, dict):
            if n.get("name") == want:
                return n
            for v in n.values():
                r = find(v, want)
                if r:
                    return r
        if isinstance(n, list):
            for v in n:
                r = find(v, want)
                if r:
                    return r
    del find(wb, "help-params")["content"]["title"]
results.append(mutate_and_test("expandable group with no title", b10))

shutil.move(BAK, SRC)
rc, out = run()
print(f"\nrestored original -> {'clean' if rc == 0 else 'DIRTY'}")
print(f"\n{sum(results)}/{len(results)} regressions caught")
sys.exit(0 if all(results) and rc == 0 else 1)
