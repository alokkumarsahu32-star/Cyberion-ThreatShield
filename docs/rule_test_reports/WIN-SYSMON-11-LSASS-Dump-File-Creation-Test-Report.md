# Rule Test Report: LSASS Dump File Creation

**Project:** Cyberion ThreatShield  
**Rule File:** `detection_rules/WIN-SYSMON-11-LSASS-Dump-File-Creation.yml`  
**Rule Name:** LSASS Dump File Creation  
**Rule ID:** `8d2b6f41-3c97-4a50-b1e6-9f7c2d5a8043`  
**Test Date:** 2026-11-08  
**Severity:** Medium  
**Status:** Experimental

## 1. Detection Objective

Detect Sysmon Event ID 11 file creation events where the target filename ends with `.dmp`.

This rule identifies potential dump-file creation activity. A `.dmp` extension alone does not prove that the file contains LSASS memory.

## 2. Detection Logic

- Log source: Windows
- Category: File Event
- Event ID: 11
- Field: TargetFilename
- Condition: Filename ends with `.dmp`

## 3. Dataset Used

**Dataset:** `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`

| Metric | Result |
|---|---:|
| Total dataset records | 4,633 |
| Event ID 11 records | 185 |
| Matching dump-file events | 8 |
| Unique EVTX scenarios | 4 |

## 4. Process Distribution

| Process | Matching Events |
|---|---:|
| rundll32.exe | 2 |
| services.exe | 1 |
| procdump.exe | 1 |
| taskmgr.exe | 1 |
| Outflank-Dumpert.exe | 1 |
| AndrewSpecial.exe | 1 |
| rdrleakdiag.exe | 1 |

## 5. Scenario Distribution

| EVTX Scenario | Matching Events |
|---|---:|
| sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx | 4 |
| sysmon_10_11_lsass_memdump.evtx | 2 |
| ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx | 1 |
| sysmon_rdrleakdiag_lsass_dump.evtx | 1 |

All 8 matching records had the dataset tactic label `Credential Access`.

## 6. Evidence Examples

| Process | Target Filename |
|---|---|
| services.exe | C:\Users\IEUser\Desktop\lsass.dmp |
| procdump.exe | C:\Users\IEUser\Desktop\lsass.exe_190317_120941.dmp |
| taskmgr.exe | C:\Users\IEUser\AppData\Local\Temp\lsass (2).DMP |
| Outflank-Dumpert.exe | C:\Windows\Temp\dumpert.dmp |
| rundll32.exe | C:\Windows\Temp\dumpert.dmp |
| AndrewSpecial.exe | C:\Users\administrator\Desktop\Andrew.dmp |
| rdrleakdiag.exe | C:\Users\wanwan\Desktop\minidump_668.dmp |

Note: The matching analysis normalized filename case before checking the `.dmp` extension. Case sensitivity in an actual Sigma backend has not yet been verified.

## 7. Validation Results

| Validation | Result |
|---|---|
| YAML syntax parsing | PASS |
| pySigma rule loading | PASS |
| Rule title and ID loading | PASS |
| Dataset matching analysis | PASS |
| Sigma CLI check | NOT VERIFIED - check command is not implemented |
| Sigma backend query conversion | NOT TESTED - no backend installed |
| Live Windows endpoint testing | NOT TESTED |

### Validation Details

- YAML parsing completed successfully.
- pySigma 2.0.1 successfully loaded one rule.
- Dataset analysis identified 8 matching events across 4 scenarios.
- The Sigma CLI check command reports that its validation functionality is not yet implemented.
- No Sigma backend was installed for query conversion testing.

## 8. False Positive Considerations

Potential legitimate matches include:

- Authorized troubleshooting and forensic activity.
- Application-generated crash dumps.
- Approved system or application diagnostic dumps.

Analysts should investigate the process, file path, user context, and surrounding events before classifying an alert as malicious.

## 9. Limitations

- The `.dmp` extension does not independently confirm LSASS memory access.
- Dataset matching is not equivalent to executing the Sigma rule against a live SIEM backend.
- Backend-specific case handling remains unverified.
- Live Windows endpoint testing remains pending.

## 10. Conclusion

The rule successfully passed YAML syntax parsing and pySigma structural loading. Dataset analysis identified 8 matching dump-file events across 4 EVTX scenarios.

The rule is suitable as a detection building block for further investigation and correlation. Backend conversion and live endpoint validation are still pending.

**Final Status: PARTIALLY VALIDATED - Dataset and structural validation passed; backend and live testing pending.**
