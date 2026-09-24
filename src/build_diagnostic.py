# -*- coding: utf-8 -*-
"""Emits a tiny diagnostic workbook that isolates which layer is failing:
plain text -> bare query -> parameter -> parameterised query -> tabs."""
import json, os, uuid

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
WS = "microsoft.operationalinsights/workspaces"


def gid(s):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "diag/" + s))


def text(md, name):
    return {"type": 1, "content": {"json": md}, "name": name}


def q(query, name, title):
    return {"type": 3,
            "content": {"version": "KqlItem/1.0", "query": query.strip(), "size": 0,
                        "title": title, "timeContext": {"durationMs": 0},
                        "queryType": 0, "resourceType": WS, "visualization": "table"},
            "name": name}


items = [
    text("# Workbook diagnostic\n"
         "Work down the numbered steps. **The first one that fails identifies the layer at fault.**\n\n"
         "Report back which step number breaks and what it shows.", "d0"),

    text("---\n### Step 1 — Text rendering\n"
         "If you can read this, text items and the outer JSON envelope are fine.", "d1"),

    q("print Result = 'Step 2 OK - the workbook can run a query against this workspace'",
      "d2", "Step 2 — bare query, no parameters, no tables"),

    text("---\n### Step 3 — Parameters\n"
         "Below should show **two filled-in pills**: a time range showing 'Last 7 days' and a "
         "dropdown showing **15m**. If either is blank, empty, or says 'mandatory', parameter "
         "defaults are the problem.", "d3"),

    {"type": 9,
     "content": {"version": "KqlParameterItem/1.0",
                 "parameters": [
                     {"id": gid("p-tr"), "version": "KqlParameterItem/1.0",
                      "name": "TimeRange", "label": "Time range", "type": 4,
                      "isRequired": True,
                      "value": {"durationMs": 604800000},
                      "typeSettings": {"selectableValues": [
                          {"durationMs": 86400000}, {"durationMs": 604800000},
                          {"durationMs": 2592000000}], "allowCustom": True}},
                     {"id": gid("p-w"), "version": "KqlParameterItem/1.0",
                      "name": "TestWindow", "label": "Test dropdown", "type": 2,
                      "isRequired": True,
                      "value": "15m",
                      "queryType": 8,
                      "typeSettings": {"additionalResourceOptions": []},
                      "query": json.dumps([
                          {"value": "5m", "label": "5 minutes"},
                          {"value": "15m", "label": "15 minutes", "selected": True},
                          {"value": "1h", "label": "1 hour"}])}],
                 "style": "pills", "queryType": 0, "resourceType": WS},
     "name": "d3params"},

    q("print Step = 'Step 4', Window = '{TestWindow}', "
      "Note = 'If Window shows 15m, parameter substitution works'",
      "d4", "Step 4 — parameter substitution into a query"),

    q("union isfuzzy=true (SigninLogs | take 1 | extend T='SigninLogs')\n"
      "| where TimeGenerated {TimeRange}\n"
      "| summarize Rows = count()\n"
      "| extend Note = iff(Rows > 0, 'SigninLogs has data in range', "
      "'SigninLogs EMPTY or not connected - this is a data problem, not a workbook problem')",
      "d5", "Step 5 — time range parameter against a real table"),

    text("---\n### Step 6 — Tabs\n"
         "Click the two tabs below. Each should reveal a line of text.\n"
         "If clicking does nothing, or neither section ever appears, the tab/group "
         "mechanism is the problem.", "d6"),

    {"type": 9,
     "content": {"version": "KqlParameterItem/1.0",
                 "parameters": [{"id": gid("p-tab"), "version": "KqlParameterItem/1.0",
                                 "name": "DiagTab", "label": "Selected tab", "type": 1,
                                 "isRequired": False, "value": "a",
                                 "isHiddenWhenLocked": True}],
                 "style": "pills", "queryType": 0, "resourceType": WS},
     "name": "d6state"},

    {"type": 11,
     "content": {"version": "LinkItem/1.0", "style": "tabs",
                 "links": [
                     {"id": gid("t-a"), "cellValue": "DiagTab", "linkTarget": "parameter",
                      "linkLabel": "Tab A", "subTarget": "a", "style": "link"},
                     {"id": gid("t-b"), "cellValue": "DiagTab", "linkTarget": "parameter",
                      "linkLabel": "Tab B", "subTarget": "b", "style": "link"}]},
     "name": "d6tabs"},

    {"type": 12,
     "content": {"version": "NotebookGroup/1.0", "groupType": "editable",
                 "items": [text("**Tab A content visible — tabs work.** "
                                "Tab A is also the default, so this should be showing "
                                "the moment the workbook loads.", "d6a-t")]},
     "conditionalVisibility": {"parameterName": "DiagTab", "comparison": "isEqualTo", "value": "a"},
     "name": "d6a"},

    {"type": 12,
     "content": {"version": "NotebookGroup/1.0", "groupType": "editable",
                 "items": [text("**Tab B content visible — tab switching works.**", "d6b-t")]},
     "conditionalVisibility": {"parameterName": "DiagTab", "comparison": "isEqualTo", "value": "b"},
     "name": "d6b"},
]

wb = {"version": "Notebook/1.0", "items": items, "isLocked": False,
      "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"}

out = os.path.join(HERE, "Diagnostic.workbook.json")
json.dump(wb, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
json.loads(open(out, encoding="utf-8").read())
print("wrote:", out, os.path.getsize(out), "bytes")
