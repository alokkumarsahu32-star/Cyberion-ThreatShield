
# RULE 03 Investigation Report: PowerShell DLL Loading Followed by LSASS Access

## 1. Objective

Investigate whether PowerShell image-loading activity followed by LSASS process access can provide evidence for a correlation-based credential-dumping detection.

## 2. Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- Scenario: babyshark_mimikatz_powershell.evtx
- Relevant telemetry: Sysmon Event ID 7 and Event ID 10

## 3. Correlation Conditions

1. Event ID 7 records DLL image loading by PowerShell.
2. Event ID 10 records PowerShell accessing lsass.exe.
3. Both events share the same Process GUID.
4. DLL loading occurs within 30 seconds before LSASS access.

## 4. Observed Evidence

PowerShell Process GUID:

`{365abb72-ac28-5cb8-0000-0010f3f70700}`

### Sequence 1

- LSASS access: 2019-04-18 16:58:14.811880
- Matching DLL events: 4
- cryptdll.dll: 1.832634 seconds before access
- samlib.dll: 1.422045 seconds before access
- hid.dll: 1.161669 seconds before access
- WinSCard.dll: 1.071541 seconds before access

### Sequence 2

- LSASS access: 2019-04-18 17:01:35.720774
- Matching DLL events: 5
- cryptdll.dll: 1.552233 seconds before access
- samlib.dll: 1.271830 seconds before access
- hid.dll: 1.061526 seconds before access
- WinSCard.dll: 1.031483 seconds before access
- vaultcli.dll: 0.040058 seconds before access

## 5. Findings

Two LSASS access events were preceded by selected DLL loading events from the same PowerShell process.

Both Event ID 10 records carried the dataset RuleName metadata:

`technique_id=T1003,technique_name=Credential Dumping`

This supports a correlation-based detection hypothesis.

## 6. Limitations

- Both sequences come from one dataset scenario.
- The rule has not been evaluated against a separate benign enterprise dataset.
- DLL loading alone does not prove credential theft.
- The selected DLL list may not cover all credential-dumping methods.
- The third PowerShell-to-LSASS event in another scenario did not have matching Event ID 7 evidence in the inspected records.
- No production SIEM correlation execution has been performed.

## 7. Proposed Detection

Detect PowerShell processes that load one or more selected DLLs and subsequently access LSASS within 30 seconds, correlating on Process GUID.

## 8. ATT&CK Mapping

Provisional mapping: T1003 – OS Credential Dumping.

## 9. Conclusion

The two observed sequences support further development of a PowerShell DLL-loading and LSASS-access correlation detection. Additional benign and attack telemetry is required before production deployment.
