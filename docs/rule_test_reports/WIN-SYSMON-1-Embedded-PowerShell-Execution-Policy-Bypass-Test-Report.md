# Rule 8 Test Report — Embedded PowerShell Execution Policy Bypass

## 1. Rule information

- Rule file: `WIN-SYSMON-1-Embedded-PowerShell-Execution-Policy-Bypass.yml`
- Rule ID: `6a2f9c41-8d73-4e50-b192-5c7a3f6d8014`
- Rule name: `win_sysmon_embedded_powershell_execution_policy_bypass`
- Status: Experimental
- Severity: Medium
- Log source: Windows Sysmon process creation (Event ID 1)
- ATT&CK mappings:
  - T1059.001 — PowerShell
  - T1562.001 — Disable or Modify Tools

## 2. Detection objective

Identify Windows Script Host (`wscript.exe`) process creation events whose command line embeds PowerShell with an execution policy bypass argument.

The rule checks for:
- Image ending with `\\wscript.exe`
- CommandLine containing `powershell`
- One of the observed bypass argument forms:
  - `-exec bypass`
  - `-executionpolicy bypass`
  - `-ep bypass`

This is a targeted detection for script-host-mediated PowerShell execution. It is not a general detection for every PowerShell execution policy bypass.

## 3. Validation results

| Validation | Result |
|---|---|
| YAML parsing | PASS |
| PySigma structural parsing | PASS |
| Dataset Event ID 1 records | 843 |
| Rule matches | 2 |
| Unique source EVTX files | 2 |

Dataset testing used a Python implementation equivalent to the rule conditions. It was offline dataset validation, not production SIEM execution.

## 4. Match details

### Match 1

- Source: `susp_explorer_exec.evtx`
- Time: `2019-08-14 11:53:29.768`
- Image: `C:\\Windows\\System32\\wscript.exe`
- Parent image: `C:\\Windows\\explorer.exe`
- Process ID: 8180
- User: `MSEDGEWIN10\\IEUser`
- Process GUID: `{747f3d96-f639-5d53-0000-0010b0fc2600}`

The command line embeds `powershell -exec bypass -c`, followed by Base64 decoding and `IEX` execution syntax.

### Match 2

- Source: `sysmon_lolbas_rundll32_zipfldr_routethecall_shell.evtx`
- Time: `2019-08-14 12:17:14.661`
- Image: `C:\\Windows\\System32\\wscript.exe`
- Parent image: `C:\\Windows\\System32\\rundll32.exe`
- Process ID: 2876
- User: `MSEDGEWIN10\\IEUser`
- Process GUID: `{747f3d96-fbca-5d53-0000-001036784100}`

The command line also embeds `powershell -exec bypass -c`, followed by Base64 decoding and `IEX` execution syntax.

The two events have different process GUIDs and different parent processes. They should not be treated as one process execution.

## 5. Interpretation

Both records meet the rule's conditions and contain an embedded PowerShell execution policy bypass argument.

The command lines also contain encoded content and `IEX` syntax. This supports investigation of suspicious script execution.

The available records alone do not establish the initial compromise method, successful payload outcome, or impact on the host. The two matches are candidate detections, not independently confirmed incidents.

## 6. False-positive considerations

Potential legitimate matches include:
- Authorized administration scripts using Windows Script Host to launch PowerShell.
- Software deployment or troubleshooting scripts that intentionally bypass execution policy.
- Legacy automation that embeds PowerShell commands in VBScript.

No representative benign baseline was available in this dataset to measure the false-positive rate.

## 7. Coverage limitations

- Detects `wscript.exe` only; other script hosts are not covered.
- Detects the three explicit bypass argument strings listed above.
- Does not cover every possible abbreviation, spacing variation, quoting pattern, or argument ordering.
- Does not directly detect `powershell.exe` or `pwsh.exe` launched without `wscript.exe`.
- A command-line match does not prove that the embedded PowerShell command completed successfully.

## 8. Conclusion

Rule 8 passed YAML and PySigma structural validation. Its equivalent offline dataset test identified two matching Sysmon Event ID 1 records across two source EVTX files.

The evidence supports retaining the rule as experimental and medium severity, with further tuning and validation against representative benign activity required before operational deployment.

No production SIEM execution or production detection effectiveness is claimed.
