import yaml
from sigma.collection import SigmaCollection

path = "detection_rules/WIN-SEC-1102-Security-Log-Cleared.yml"

with open(path, encoding="utf-8-sig") as f:
    rule_data = yaml.safe_load(f)

assert rule_data["detection"]["selection"]["EventID"] == 1102
assert rule_data["logsource"]["service"] == "security"

collection = SigmaCollection.from_dicts([rule_data])

print("YAML validation: PASSED")
print("PySigma parsing: PASSED")
print("Rule title:", rule_data["title"])
print("Rule name:", rule_data["name"])
