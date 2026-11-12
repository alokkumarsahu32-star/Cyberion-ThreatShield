import yaml
from pathlib import Path
from sigma.collection import SigmaCollection

files = [
    "WIN-SYSMON-7-PowerShell-Credential-DLL-Load.yml",
    "WIN-SYSMON-10-PowerShell-LSASS-Access.yml",
    "WIN-SYSMON-CORR-001-PowerShell-LSASS-DLL-Sequence.yml",
]

rules = []

for filename in files:
    path = Path("detection_rules") / filename
    with path.open("r", encoding="utf-8-sig") as f:
        rules.append(yaml.safe_load(f))

print("Loaded YAML documents:", len(rules))

collection = SigmaCollection.from_dicts(rules)

print("PySigma parsed rules:", len(collection.rules))

for rule in collection.rules:
    print("Parsed:", type(rule).__name__, "|", getattr(rule, "name", None))

collection.resolve_rule_references()

print("\nSUCCESS: PySigma parsing and rule-reference resolution passed.")
