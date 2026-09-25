# -*- coding: utf-8 -*-
"""Generate the deployable ARM template from rules/*.yaml.

The YAML files are the source of truth. This emits
AccountSharingAnalyticsRules.json, an ARM template that creates every rule as a
Microsoft.SecurityInsights scheduled alert rule in a chosen workspace.

Rebuild with:  python src/build_rules.py
"""
import json
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("pyyaml is required:  pip install pyyaml")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
RULES_DIR = os.path.join(HERE, "rules")
OUT = os.path.join(HERE, "AccountSharingAnalyticsRules.json")

API_VERSION = "2023-02-01"

# Properties that belong on the ARM resource, in the order the portal writes them.
# Anything else in the YAML (id, name, kind, version, requiredDataConnectors) is
# either promoted to the resource envelope or is documentation only.
PASSTHROUGH = [
    "displayName",
    "description",
    "severity",
    "enabled",
    "query",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "suppressionDuration",
    "suppressionEnabled",
    "tactics",
    "techniques",
    "alertRuleTemplateName",
    "incidentConfiguration",
    "eventGroupingSettings",
    "alertDetailsOverride",
    "customDetails",
    "entityMappings",
]


def load_rules():
    """Read every rule YAML in filename order."""
    if not os.path.isdir(RULES_DIR):
        sys.exit("rules/ directory not found at %s" % RULES_DIR)

    files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith((".yaml", ".yml")))
    if not files:
        sys.exit("no rule files found in %s" % RULES_DIR)

    rules = []
    for fname in files:
        path = os.path.join(RULES_DIR, fname)
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            sys.exit("%s did not parse as a YAML mapping" % fname)
        doc["_file"] = fname
        rules.append(doc)
    return rules


def to_properties(rule):
    """Map the community rule schema onto alertRules properties."""
    props = {
        "displayName": rule["name"],
        "description": rule.get("description", "").strip(),
        "severity": rule["severity"],
        "enabled": rule.get("enabled", True),
        "query": rule["query"].rstrip("\n"),
        "queryFrequency": rule["queryFrequency"],
        "queryPeriod": rule["queryPeriod"],
        "triggerOperator": rule.get("triggerOperator", "gt"),
        "triggerThreshold": rule.get("triggerThreshold", 0),
        "suppressionDuration": rule.get("suppressionDuration", "PT1H"),
        "suppressionEnabled": rule.get("suppressionEnabled", False),
        "tactics": rule.get("tactics", []),
        # The YAML field is relevantTechniques to match the community schema;
        # the ARM property is techniques.
        "techniques": rule.get("relevantTechniques", []),
    }

    for key in ("incidentConfiguration", "eventGroupingSettings",
                "alertDetailsOverride", "customDetails", "entityMappings"):
        if key in rule:
            props[key] = rule[key]

    return {k: props[k] for k in PASSTHROUGH if k in props}


def to_resource(rule):
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": API_VERSION,
        "name": "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/%s')]" % rule["id"],
        "kind": rule.get("kind", "Scheduled"),
        "location": "[parameters('location')]",
        "properties": to_properties(rule),
    }


def build(rules):
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": (
                "Analytics rules accompanying the Account & Credential Sharing "
                "Sentinel workbook. Generated from rules/*.yaml by "
                "src/build_rules.py - edit the YAML, not this file."
            ),
        },
        "parameters": {
            "workspaceName": {
                "type": "string",
                "metadata": {
                    "description": "Name of the Log Analytics workspace that Microsoft Sentinel is enabled on."
                },
            },
            "location": {
                "type": "string",
                "defaultValue": "[resourceGroup().location]",
                "metadata": {"description": "Region of the workspace."},
            },
        },
        "resources": [to_resource(r) for r in rules],
        "outputs": {
            "rulesDeployed": {
                "type": "int",
                "value": len(rules),
            }
        },
    }


def main():
    rules = load_rules()

    seen = {}
    for r in rules:
        for field in ("id", "name", "severity", "query", "queryFrequency", "queryPeriod"):
            if field not in r:
                sys.exit("%s is missing required field '%s'" % (r["_file"], field))
        if r["id"] in seen:
            sys.exit("duplicate rule id %s in %s and %s" % (r["id"], seen[r["id"]], r["_file"]))
        seen[r["id"]] = r["_file"]

    template = build(rules)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(template, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print("wrote %s" % os.path.relpath(OUT, HERE))
    for r in rules:
        print("  %-38s %s  [%s]" % (r["_file"], r["severity"].ljust(8), r["id"]))
    print("%d rules" % len(rules))


if __name__ == "__main__":
    main()
