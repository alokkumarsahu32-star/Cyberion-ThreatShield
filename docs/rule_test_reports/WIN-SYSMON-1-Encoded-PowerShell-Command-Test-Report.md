# Rule 7 Test Report — Encoded PowerShell Command

## Rule Information

- Rule file: `WIN-SYSMON-1-Encoded-PowerShell-Command.yml`
- Rule ID: `4f7c2a91-8e35-4d60-b192-6a3e5f8c7041`
- Rule name: `win_sysmon_encoded_powershell_command`
- Severity: Medium
- Status: Experimental
- ATT&CK:
  - T1059.001 — PowerShell
  - T1027.010 — Command Obfuscation

## Detection Logic

The rule detects Sysmon Process Creation (Event ID 1) when:

1. `Image` ends with `\powershell.exe`.
2. `CommandLine` contains `-enc` or `-encodedcommand`.

## Dataset and Methodology

- Dataset: EVTX-ATTACK-SAMPLES
- Source file: `evtx_data.csv`
- Validation method: Python pandas evaluation of the rule's equivalent conditions.
- This is offline dataset validation, not execution in a production SIEM backend.

## Test Results

| Metric | Result |
|---|---:|
| Total Event ID 1 records | 843 |
| Direct PowerShell process records | 11 |
| Exact encoded PowerShell matches | 1 |
| Unique matching source files | 1 |

## Matching Event Evidence

- Source: `discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx`
- Timestamp: `2019-05-27 01:28:42.700`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Parent image: `C:\Windows\System32\inetsrv\w3wp.exe`
- Process GUID: `{365abb72-3d4a-5ceb-0000-0010fa93fd00}`
- Command indicators: `-nop -noni -enc`

## Investigation Context

The Base64 payload was decoded as UTF-16LE for offline inspection only. It contained:

- Temporary file reads.
- XOR-based byte decryption.
- Execution of decrypted content through `IEX`.
- Deletion of a temporary application-code file.

Subsequent process creation events in the same source file recorded `appcmd.exe` commands querying IIS virtual directories, application pools, usernames and password-related configuration fields.

The PowerShell event occurred at 01:28:42.700. The first listed `appcmd.exe` event occurred at 01:29:16.960.

This activity is consistent with encoded PowerShell execution followed by IIS configuration discovery. The available events do not establish the initial compromise method or prove that credentials were successfully obtained.

## False Positive Assessment

Potential legitimate matches include:

- Authorized administration using encoded PowerShell.
- Software deployment and configuration-management tools.
- Security testing and automation frameworks.

No independent benign baseline was available in this dataset. Therefore, false-positive frequency cannot be quantified.

## Scope and Limitations

- The rule covers direct `powershell.exe` process creation.
- It does not cover `pwsh.exe` or PowerShell embedded in another process's command line.
- Three embedded PowerShell candidates identified during preliminary inspection are outside this rule's scope.
- Renamed executables and alternative encoding or obfuscation methods may evade this condition.
- The dataset contains one exact match; one match does not establish detection recall.
- No production SIEM execution or live alert validation was performed.

## Conclusion

The rule passed YAML and PySigma parsing and matched one event in the selected dataset using equivalent Python conditions.

The matching event provides a useful investigation lead because its decoded payload and subsequent IIS configuration discovery activity supply additional context.

The rule remains experimental and requires benign-baseline testing and backend-specific validation before production use.
