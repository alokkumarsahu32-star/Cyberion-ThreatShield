# Rule Test Report: PowerShell DLL Load Followed by LSASS Access

## 1. Rule Information

- Rule ID: 7c4e2a91-5d63-4f80-a219-3b6e8d0c7425
- Rule Name: powershell_dll_then_lsass
- Rule Title: PowerShell DLL Load Followed by LSASS Access
- Rule Type: Sigma temporal_ordered correlation
- Severity: High
- Correlation Window: 30 seconds
- ATT&CK Mapping: T1003 (Credential Dumping) - provisional

## 2. Objective

Identify a sequence in which a PowerShell process loads selected credential-access-related DLLs and subsequently accesses the LSASS process within 30 seconds.

Both events must belong to the same process, identified through the Process GUID.

## 3. Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Analysis file: evtx_data.csv
- Total dataset records: 4,633

## 4. Detection Components

### Base Rule A: PowerShell Credential DLL Load

- Rule name: powershell_credential_dll_load
- Event ID: 7
- Channel: Sysmon
- Field conditions:
  - Image ends with powershell.exe
  - ImageLoaded ends with one of the selected DLL names:
    cryptdll.dll, samlib.dll, hid.dll, WinSCard.dll

### Base Rule B: PowerShell LSASS Access

- Rule name: powershell_lsass_access
- Event ID: 10
- Channel: Sysmon
- Field conditions:
  - SourceImage ends with powershell.exe
  - TargetImage ends with lsass.exe

### Correlation Logic

- Type: temporal_ordered
- Required sequence: DLL load followed by LSASS access
- Time window: 30 seconds
- Grouping field: process_guid
- Event 7 field: ProcessGuid
- Event 10 field: SourceProcessGUID

## 5. Dataset Investigation Results

The selected dataset investigation identified:

- Sysmon Event ID 7 records: 613
- Matching PowerShell DLL-load events: 8
- Matching DLL-load events were found in:
  babyshark_mimikatz_powershell.evtx
- DLL distribution:
  - cryptdll.dll: 2
  - samlib.dll: 2
  - hid.dll: 2
  - WinSCard.dll: 2
- PowerShell-to-LSASS Event ID 10 records: 3
- Same-process ordered sequences identified within 30 seconds: 2

## 6. Correlation Evidence

Both matching sequences used the same process GUID:

`{365abb72-ac28-5cb8-0000-0010f3f70700}`

### Sequence 1

- LSASS access: 2019-04-18 16:58:14.811880
- cryptdll.dll: 1.832634 seconds before
- samlib.dll: 1.422045 seconds before
- hid.dll: 1.161669 seconds before
- WinSCard.dll: 1.071541 seconds before

### Sequence 2

- LSASS access: 2019-04-18 17:01:35.720774
- cryptdll.dll: 1.552233 seconds before
- samlib.dll: 1.271830 seconds before
- hid.dll: 1.061526 seconds before
- WinSCard.dll: 1.031483 seconds before

## 7. Validation Results

- YAML parsing: Passed
- PySigma parsing: Passed
- Correlation rule reference resolution: Passed
- Correlation configuration inspection: Passed
- Dataset-based equivalent-condition investigation: 2 matching sequences identified
- Live SIEM/backend execution: Not performed

## 8. False Positive Considerations

Potential legitimate activity includes:

- Authorized PowerShell-based incident response.
- Digital forensics and credential auditing.
- Approved security testing.
- Administrative scripts that use authentication or smart-card libraries.

A benign comparison dataset was not available during this investigation. Therefore, the false-positive rate has not been measured.

## 9. Limitations

- DLL loading alone does not establish malicious activity.
- LSASS access alone does not prove credential theft.
- Only two matching sequences were identified in the inspected scenario.
- One additional PowerShell-to-LSASS event did not have a corresponding DLL-load event in the inspected records.
- Dataset-based equivalent-condition testing is not the same as execution in a production SIEM.
- ATT&CK T1003 mapping remains provisional pending further technique-level verification.

## 10. Conclusion

The correlation configuration successfully parsed with PySigma, and two ordered same-process sequences were identified in the selected dataset within the configured 30-second window.

The evidence supports retaining this rule as an experimental detection candidate. It should not be treated as a confirmed incident or production-validated detection until further testing and false-positive review are completed.
