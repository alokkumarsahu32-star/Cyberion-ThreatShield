# Rule 2 Test Report: Known Credential Dumping Tool Accessing LSASS

## Rule Information

- Rule file: `detection_rules/WIN-SYSMON-10-Suspicious-LSASS-Access.yml`
- Rule title: Known Credential Dumping Tool Accessing LSASS
- Rule ID: `6b3a9c42-8d71-4e25-a6f0-2b9d7c51e843`
- Status: experimental
- ATT&CK mapping: T1003 – OS Credential Dumping
- Log source: Windows Sysmon Process Access (Event ID 10)

## Dataset

- Source: EVTX-ATTACK-SAMPLES
- Dataset file: evtx_data.csv
- Total records: 4,633
- Event ID 10 records: 140
- Event ID 10 records targeting LSASS: 26

## Detection Logic Tested

The Python test evaluated the equivalent of these Sigma conditions:

1. TargetImage ends with `\lsass.exe`.
2. SourceImage contains one of the following:
   - mimikatz
   - procdump
   - ppldump
   - dumpert
   - andrewspecial

Both conditions must match.

## Results

- Candidate matches: **12**
- Unique source process paths: 8
- Dataset scenarios with matches: 6

### Matches by Scenario

| Scenario | Matches |
|---|---:|
| `DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` | 1 |
| `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx` | 2 |
| `sysmon_10_11_lsass_memdump.evtx` | 1 |
| `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` | 4 |
| `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | 1 |
| `sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx` | 3 |

### Matches by Source Process

| Source Process | Matches |
|---|---:|
| `c:\Users\IEUser\Desktop\PPLdump.exe` | 2 |
| `C:\Users\administrator\Desktop\x64\Outflank-Dumpert.exe` | 2 |
| `C:\Users\administrator\Desktop\AndrewSpecial.exe` | 2 |
| `C:\Users\Public\tools\SysinternalsSuite\procdump64.exe` | 2 |
| `C:\Users\IEUser\Desktop\procdump.exe` | 1 |
| `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe` | 1 |
| `C:\Users\Public\tools\SysinternalsSuite\procdump.exe` | 1 |
| `c:\Users\Public\BYOV\ZAM64\ppldump.exe` | 1 |

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
