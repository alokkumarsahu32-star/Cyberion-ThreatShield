import yaml
from sigma.collection import SigmaCollection

path = "detection_rules/WIN-5156-Plink-Loopback-RDP-Connection.yml"

with open(path, "r", encoding="utf-8-sig") as f:
    rule_data = yaml.safe_load(f)

print("YAML parsing: PASSED")
print("Title:", rule_data["title"])
print("Rule ID:", rule_data["id"])
print("Detection condition:", rule_data["detection"]["condition"])

try:
    collection = SigmaCollection.from_yaml(
        open(path, "r", encoding="utf-8-sig").read()
    )
    print("\nPySigma parsing: PASSED")
    print("Parsed rules:", len(collection.rules))
except Exception as e:
    print("\nPySigma parsing: FAILED")
    print(type(e).__name__ + ":", e)
    raise
