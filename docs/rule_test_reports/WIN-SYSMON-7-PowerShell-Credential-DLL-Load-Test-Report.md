# PowerShell Loading Credential Access Related DLLs — Test Report

## Rule Details
- **Title:** PowerShell Loading Credential Access Related DLLs
- **Rule ID:** 8d2f6a91-4c73-4b10-9e25-6a1d8f3c7b42
- **Rule name:** powershell_credential_dll_load
- **Severity:** low
- **Status:** experimental
- **Log source:** Windows / Image Load (Sysmon Event ID 7)
- **Detection:** PowerShell loading one of the four specified DLLs.
- **DLLs:** cryptdll.dll, samlib.dll, hid.dll, WinSCard.dll

## Validation Results
| Validation | Result |
|---|---|
| YAML parsing | PASS |
| UUID validation | PASS |
| pySigma structural loading | PASS |
| Rules loaded | 1 |

## Dataset Test Results
- **Dataset:** `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`
- **Total records:** 4633
- **Event ID 7 records:** 613
- **PowerShell + selected DLL matches:** 8
- **Unique PowerShell image paths:** 1
- **Unique DLL paths:** 4

## DLL Distribution
| ImageLoaded | Count |
| --- | --- |
| C:\Windows\System32\cryptdll.dll | 2 |
| C:\Windows\System32\samlib.dll | 2 |
| C:\Windows\System32\hid.dll | 2 |
| C:\Windows\System32\WinSCard.dll | 2 |

## Source Process Distribution
| Image | Count |
| --- | --- |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | 8 |

## EVTX Scenario Distribution
| EVTX_FileName | Count |
| --- | --- |
| babyshark_mimikatz_powershell.evtx | 8 |

## Tactic Distribution
| EVTX_Tactic | Count |
| --- | --- |
| Credential Access | 8 |

## Sample Evidence
| Image | ImageLoaded | EVTX_FileName | EVTX_Tactic | processId | ProcessGuid |
| --- | --- | --- | --- | --- | --- |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\cryptdll.dll | babyshark_mimikatz_powershell.evtx | Credential Access |  | {365abb72-ac28-5cb8-0000-0010f3f70700} |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\samlib.dll | babyshark_mimikatz_powershell.evtx | Credential Access |  | {365abb72-ac28-5cb8-0000-0010f3f70700} |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\hid.dll | babyshark_mimikatz_powershell.evtx | Credential Access |  | {365abb72-ac28-5cb8-0000-0010f3f70700} |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\System32\WinSCard.dll | babyshark_mimikatz_powershell.evtx | Credential Access |  | {365abb72-ac28-5cb8-0000-0010f3f70700} |

## Analysis
The offline dataset test matches Event ID 7 records where the source Image ends with `\\powershell.exe` and ImageLoaded ends with one of the four DLL paths defined in the rule.

These matches demonstrate that the rule condition occurs in the selected dataset. They do not independently establish malicious activity.

This rule is intended as a building block for temporal correlation with subsequent PowerShell-to-LSASS process access.

## False Positive Considerations
- Legitimate PowerShell scripts using Windows authentication or smart-card libraries.
- Authorized administrative and security tools.

## Limitations
- Matching was performed offline against the supplied CSV dataset.
- Case-insensitive path matching was used by the Python test; Sigma backend case-handling remains unverified.
- Backend query conversion and execution were not tested.
- Live Windows endpoint testing was not performed.
- Temporal correlation with LSASS access was not tested by this standalone rule.
- No benign enterprise dataset was used to calculate a false-positive rate.

## Final Status
**PARTIALLY VALIDATED**

YAML, UUID, pySigma structural loading and offline dataset matching were tested. Backend conversion, live endpoint testing, temporal correlation and benign-data false-positive testing remain outstanding.
