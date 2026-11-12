import yaml
from pathlib import Path
from sigma.collection import SigmaCollection

files = [
    "WIN-SYSMON-7-PowerShell-Credential-DLL-Load.yml",
    "WIN-SYSMON-10-PowerShell-LSASS-Access.yml",
    "WIN-SYSMON-CORR-001-PowerShell-LSASS-DLL-Sequence.yml",
]

documents = [
    yaml.safe_load((Path("detection_rules") / f).read_text(encoding="utf-8-sig"))
    for f in files
]

collection = SigmaCollection.from_dicts(documents)
collection.resolve_rule_references()

corr = next(r for r in collection.rules if type(r).__name__ == "SigmaCorrelationRule")

print("Correlation name:", corr.name)
print("Correlation type:", corr.type)
print("Timespan:", corr.timespan)
print("Group by:", corr.group_by)
print("Aliases:", corr.aliases.to_dict())
print("Condition:", corr.condition.to_dict())

print("\nReferenced rules:")
for ref in corr.rules:
    print("-", ref.reference, "=>", ref.rule.name)

print("\nCORRELATION CONFIGURATION VERIFIED")
