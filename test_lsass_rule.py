import pandas as pd
import yaml
from pathlib import Path
from sigma.rule import SigmaRule

rule_path = Path("detection_rules/WIN-SYSMON-10-Suspicious-LSASS-Access.yml")
data_path = Path("datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv")
report_path = Path("docs/rule_test_reports/WIN-SYSMON-10-LSASS-Access-Test-Report.md")

# 1. Validate Sigma rule
rule_text = rule_path.read_text(encoding="utf-8")
rule = yaml.safe_load(rule_text)
SigmaRule.from_yaml(rule_text)

print("YAML validation: PASS")
print("pySigma validation: PASS")

# 2. Load dataset
df = pd.read_csv(data_path, low_memory=False)

# 3. Select Sysmon Event ID 10
events = df[df["EventID"].astype(str).eq("10")].copy()

# 4. Match LSASS target
target_match = (
    events["TargetImage"]
    .fillna("")
    .astype(str)
    .str.lower()
    .str.endswith("\\lsass.exe")
)

# 5. Match known tool names
names = [
    "mimikatz",
    "procdump",
    "ppldump",
    "dumpert",
    "andrewspecial"
]

source = (
    events["SourceImage"]
    .fillna("")
    .astype(str)
    .str.lower()
)

source_match = source.str.contains(
    "|".join(names),
    regex=True,
    na=False
)

# 6. Apply both conditions
matched = events[target_match & source_match]

# 7. Calculate results
scenario_counts = matched.groupby("EVTX_FileName").size()
source_counts = matched["SourceImage"].value_counts()

print("\nDATASET TEST RESULTS")
print("--------------------")
print("Total dataset records:", len(df))
print("Event ID 10 records:", len(events))
print("LSASS Event ID 10:", int(target_match.sum()))
print("Rule matches:", len(matched))
print("Unique source processes:", matched["SourceImage"].nunique())
print("Matched scenarios:", len(scenario_counts))

# 8. Create report
report = f"""# Rule Test Report: Known Credential Dumping Tool Accessing LSASS

## Rule Information

- Rule file: `{rule_path.as_posix()}`
- Rule title: {rule['title']}
- Rule ID: `{rule['id']}`
- Status: {rule['status']}
- ATT&CK mapping: T1003 – OS Credential Dumping
- Log source: Windows Sysmon Process Access (Event ID 10)

## Dataset

- Source: EVTX-ATTACK-SAMPLES
- Dataset file: evtx_data.csv
- Total records: {len(df):,}
- Event ID 10 records: {len(events):,}
- Event ID 10 records targeting LSASS: {int(target_match.sum())}

## Detection Logic Tested

The Python test evaluated the equivalent of these Sigma conditions:

1. TargetImage ends with `\\lsass.exe`.
2. SourceImage contains one of the following:
   - mimikatz
   - procdump
   - ppldump
   - dumpert
   - andrewspecial

Both conditions must match.

## Results

- Candidate matches: **{len(matched)}**
- Unique source process paths: {matched['SourceImage'].nunique()}
- Dataset scenarios with matches: {len(scenario_counts)}

### Matches by Scenario

| Scenario | Matches |
|---|---:|
""" + "\n".join(
    f"| `{name}` | {count} |"
    for name, count in scenario_counts.items()
) + """

### Matches by Source Process

| Source Process | Matches |
|---|---:|
""" + "\n".join(
    f"| `{name}` | {count} |"
    for name, count in source_counts.items()
) + """

## Interpretation

The rule identified LSASS access events associated with known
credential-dumping tool-name indicators in the selected dataset.

These are candidate detections, not independently confirmed incidents.
The dataset contains attack-labelled scenarios, but the rule has not
been tested against a separate benign enterprise dataset.

## False Positive Considerations

- Authorized incident response and forensic investigations.
- Approved penetration testing and security validation.
- Legitimate administrative use of Sysinternals ProcDump.

## Limitations

- Renamed or unknown tools may evade filename-based matching.
- PowerShell-based LSASS access is not covered by this rule.
- A process name alone does not establish malicious intent.
- The Python test evaluates equivalent selection logic; it is not a
  full SIEM/backend execution of the Sigma rule.
- False-positive rate has not been measured against benign enterprise logs.

## Validation

- YAML parsing: PASS
- UUID validation: PASS (validated separately)
- pySigma parsing: PASS
- Dataset-based equivalent-condition test: PASS

## Conclusion

The rule produced candidate matches in the selected EVTX-ATTACK-SAMPLES
dataset. Further validation with benign telemetry and additional LSASS
access scenarios is required before production deployment.
"""

# 9. Save report
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(report, encoding="utf-8")

print("\nReport created:", report_path)
print("Report size:", report_path.stat().st_size, "bytes")