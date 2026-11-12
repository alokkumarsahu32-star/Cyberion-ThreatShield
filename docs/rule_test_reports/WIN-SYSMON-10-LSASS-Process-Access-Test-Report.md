# Rule Test Report: Process Access to LSASS

## Rule Information

- Rule file: `detection_rules/WIN-SYSMON-10-LSASS-Process-Access.yml`
- Rule title: Process Access to LSASS
- Rule ID: `4c7a1e92-8b35-4d61-a9f2-7e3c5b0d8146`
- Status: experimental
- ATT&CK mapping: T1003.001 – LSASS Memory
- Log source: Windows Sysmon Process Access (Event ID 10)
- Severity: medium

## Dataset

- Source: EVTX-ATTACK-SAMPLES
- Dataset file: `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`
- Total records: 4633
- Event ID 10 records: 140
- Records targeting LSASS: 26
- Unique source process paths: 15
- Unique scenarios: 12

## Detection Logic Tested

The dataset test evaluated the equivalent of the Sigma selection:

1. `EventID` equals `10`.
2. `TargetImage` ends with `\lsass.exe`.

The filename comparison was performed after converting the target path to lowercase. Backend-specific case handling remains unverified.

## Results

### Matches by Source Process

| Source Process | Matches |
|---|---:|
| `C:\Windows\system32\rundll32.exe` | 4 |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 3 |
| `c:\Users\IEUser\Desktop\PPLdump.exe` | 2 |
| `C:\Windows\system32\services.exe` | 2 |
| `C:\Users\administrator\Desktop\x64\Outflank-Dumpert.exe` | 2 |
| `C:\Users\administrator\Desktop\AndrewSpecial.exe` | 2 |
| `C:\Users\Public\tools\SysinternalsSuite\procdump64.exe` | 2 |
| `c:\python27\python.exe` | 2 |
| `\\VBOXSVR\HTools\voice_mail.msg.exe` | 1 |
| `C:\Users\IEUser\Desktop\procdump.exe` | 1 |
| `C:\Windows\system32\taskmgr.exe` | 1 |
| `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe` | 1 |
| `C:\Users\Public\tools\SysinternalsSuite\procdump.exe` | 1 |
| `c:\Users\Public\BYOV\ZAM64\ppldump.exe` | 1 |
| `D:\m.exe` | 1 |

### Matches by Scenario

| EVTX Scenario | Matches |
|---|---:|
| `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` | 8 |
| `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx` | 4 |
| `sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx` | 3 |
| `babyshark_mimikatz_powershell.evtx` | 2 |
| `sysmon_10_11_lsass_memdump.evtx` | 2 |
| `CA_sysmon_hashdump_cmd_meterpreter.evtx` | 1 |
| `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | 1 |
| `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | 1 |
| `DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` | 1 |
| `discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx` | 1 |
| `sysmon_20_21_1_CommandLineEventConsumer.evtx` | 1 |
| `sysmon_privesc_from_admin_to_system_handle_inheritance.evtx` | 1 |

### Dataset Tactic Distribution

| Dataset Tactic | Matches |
|---|---:|
| `Credential Access` | 22 |
| `Defense Evasion` | 1 |
| `Discovery` | 1 |
| `Persistence` | 1 |
| `Privilege Escalation` | 1 |

## Sample Evidence

| SourceImage | TargetImage | GrantedAccess | EVTX_FileName |
|---|---|---|---|
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\system32\lsass.exe | 0x00001010 | babyshark_mimikatz_powershell.evtx |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\system32\lsass.exe | 0x00001010 | babyshark_mimikatz_powershell.evtx |
| \\VBOXSVR\HTools\voice_mail.msg.exe | C:\Windows\system32\lsass.exe | 0x001f1fff | CA_sysmon_hashdump_cmd_meterpreter.evtx |
| c:\Users\IEUser\Desktop\PPLdump.exe | C:\Windows\system32\lsass.exe | 0x00001000 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| c:\Users\IEUser\Desktop\PPLdump.exe | C:\Windows\system32\lsass.exe | 0x00001000 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| C:\Windows\system32\services.exe | C:\Windows\system32\lsass.exe | 0x00001410 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| C:\Windows\system32\services.exe | C:\Windows\system32\lsass.exe | 0x001fffff | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| C:\Users\IEUser\Desktop\procdump.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_lsass_memdump.evtx |
| C:\Windows\system32\taskmgr.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_lsass_memdump.evtx |
| C:\Users\administrator\Desktop\x64\Outflank-Dumpert.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Users\administrator\Desktop\x64\Outflank-Dumpert.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Windows\system32\rundll32.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Windows\system32\rundll32.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Windows\system32\rundll32.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Windows\system32\rundll32.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Users\administrator\Desktop\AndrewSpecial.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Users\administrator\Desktop\AndrewSpecial.exe | C:\Windows\system32\lsass.exe | 0x001fffff | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe | C:\Windows\system32\lsass.exe | 0x00001010 | sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx |
| C:\Users\Public\tools\SysinternalsSuite\procdump.exe | C:\windows\system32\lsass.exe | 0x001fffff | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx |
| C:\Users\Public\tools\SysinternalsSuite\procdump64.exe | C:\windows\system32\lsass.exe | 0x001fffff | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx |
| C:\Users\Public\tools\SysinternalsSuite\procdump64.exe | C:\windows\system32\lsass.exe | 0x001fffff | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\system32\lsass.exe | 0x0000143a | sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx |
| c:\Users\Public\BYOV\ZAM64\ppldump.exe | C:\Windows\system32\lsass.exe | 0x001fffff | DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx |
| D:\m.exe | C:\Windows\system32\lsass.exe | 0x00001410 | discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx |
| c:\python27\python.exe | C:\Windows\system32\lsass.exe | 0x00001410 | sysmon_20_21_1_CommandLineEventConsumer.evtx |
| c:\python27\python.exe | C:\Windows\system32\lsass.exe | 0x00101ffb | sysmon_privesc_from_admin_to_system_handle_inheritance.evtx |

## Interpretation

The rule identified 26 Sysmon Event ID 10 records targeting LSASS in the selected dataset. These are candidate LSASS access detections, not independently confirmed credential-dumping incidents.

The dataset includes multiple attack-labelled scenarios. The presence of LSASS access alone does not establish malicious intent.

## False Positive Considerations

- Legitimate endpoint security software accessing LSASS.
- Authorized debugging and forensic activity.
- Approved credential auditing tools.

## Limitations

- The rule detects access to LSASS without restricting the source process.
- Legitimate security and administrative tools may generate matches.
- Dataset matching evaluates equivalent selection logic, not full SIEM/backend execution.
- False-positive rate has not been measured against a separate benign enterprise dataset.
- Live Windows endpoint testing has not been performed.
- Backend-specific case handling has not been verified.

## Validation

| Validation | Result |
|---|---|
| YAML syntax parsing | PASS |
| UUID validation | PASS |
| pySigma structural loading | PASS (1 rule loaded) |
| Dataset equivalent-condition test | PASS (26 matches) |
| Sigma backend query conversion | NOT TESTED |
| Live Windows endpoint testing | NOT TESTED |

## Conclusion

The rule passed YAML parsing, UUID validation, and pySigma structural loading. Dataset analysis identified 26 LSASS access events across 12 scenarios.

The rule is suitable as a building block for LSASS access detection and correlation. Benign telemetry testing, backend conversion, and live endpoint validation remain pending.

**Final Status: PARTIALLY VALIDATED – Structural and dataset validation passed; backend and live testing pending.**
