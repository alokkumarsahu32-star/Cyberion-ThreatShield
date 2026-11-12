# WIN-SYSMON-10 LSASS Path Fix Validation Report

## 1. Rule Information

- Rule: WIN-SYSMON-10-Suspicious-LSASS-Access
- Rule ID: 6b3a9c42-8d71-4e25-a6f0-2b9d7c51e843
- Validation date: 2026-11-10
- Validation type: YAML validation, Sigma conversion, offline dataset validation
- Change type: Detection path bug fix
- False-positive reduction: Not demonstrated

## 2. Original Issue

The original TargetImage condition used a double-backslash suffix:

`TargetImage|endswith: '\\lsass.exe'`

This caused the condition to fail against the observed dataset paths.

## 3. Corrective Change

The suffix was corrected to:

`TargetImage|endswith: '\lsass.exe'`

No access-mask filter was added because the observed access-mask distribution did not provide a reliable selector for known credential-dumping tools.

## 4. YAML Validation

Result: PASSED

The YAML file parsed successfully after the path correction.

## 5. Sigma Conversion

Command:

` sigma convert -t splunk -p splunk_windows detection_rules/WIN-SYSMON-10-Suspicious-LSASS-Access.yml `

Result: PASSED

Generated query:

`TargetImage="*\\lsass.exe" (SourceImage IN ("*mimikatz*", "*procdump*", "*ppldump*", "*dumpert*", "*andrewspecial*"))`

This confirms conversion by the installed Splunk backend. It does not establish execution in a live Splunk environment.

## 6. Offline Dataset Validation

Dataset:

`datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`

| Metric | Result |
|---|---:|
| Total Event ID 10 records | 140 |
| LSASS target records | 26 |
| Known-tool source records | 15 |
| Corrected rule matches | 12 |
| Unique EventRecordIDs | 12 |

### Matched source processes

| Source process | Matches |
|---|---:|
| PPLdump.exe | 2 |
| Outflank-Dumpert.exe | 2 |
| AndrewSpecial.exe | 2 |
| procdump64.exe | 2 |
| procdump.exe | 2 |
| mimikatz.exe | 1 |
| ppldump.exe | 1 |
| **Total** | **12** |

## 7. Access-Mask Review

An access-mask filter was evaluated but rejected.

The observed `0x001fffff` mask occurred in both known-tool and non-tool process records. Other masks were also shared across different process types. Therefore, adding a mask condition could exclude relevant detections or retain unrelated activity.

## 8. Before/After Interpretation

- Original YAML path condition: 0 matches.
- Corrected path condition with known-tool selection: 12 matches.
- The result confirms a path-matching bug fix.
- This is not evidence of a 12-record false-positive reduction.
- No benign baseline was available to establish false-positive reduction.

## 9. Limitations

- Validation used an offline attack-sample dataset.
- Sigma conversion was successful, but no live Splunk execution was performed.
- Detection of a known process accessing LSASS does not independently prove credential extraction.
- Production effectiveness and false-positive rate remain unverified.

## 10. Final Status

**Path bug fix: VALIDATED**

**YAML parsing: PASSED**

**Sigma conversion: PASSED**

**Offline dataset validation: PASSED**

**Genuine false-positive reduction: NOT DEMONSTRATED**
