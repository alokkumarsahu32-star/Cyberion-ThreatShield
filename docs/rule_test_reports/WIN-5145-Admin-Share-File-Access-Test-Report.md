# Rule 1 Test Report — Windows Admin Share File Access

## Rule Information

- Rule file: `detection_rules/WIN-5145-Suspicious-Admin-Share-File-Access.yml`
- Rule title: Suspicious Executable or Script Access Through Windows Admin Share
- Rule ID: `20f856b8-11da-4247-b9fb-62b6bd60af30`
- Status: Experimental
- Severity: Medium
- Proposed ATT&CK mapping: T1021.002 — SMB/Windows Admin Shares
- Mapping status: Provisional; scenario context supports investigation, but full technique validation remains pending.

## Dataset

- Source: EVTX-ATTACK-SAMPLES
- CSV: `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`
- Total records: 4,633
- Selected scenario: `LM_5145_Remote_FileCopy.evtx`
- Selected scenario records: 869

## Detection Logic

The candidate condition matches:
1. Event ID 5145.
2. Share name ending in `\C$`.
3. Object type `File`.
4. Relative target path ending in `.exe`, `.bat`, `.cmd`, `.ps1`, `.dll`, `.scr`, or `.com`.

## Validation Results

- YAML syntax: Passed
- UUID format: Passed
- Required Sigma sections: Present
- pySigma parser: Passed

## Full Dataset Test Results

- Total records: 4,633
- Matching records: 18
- Unique matching records: 18
- Matches in `LM_5145_Remote_FileCopy.evtx`: 12
- Matches in `LM_REMCOM_5145_TargetHost.evtx`: 6

### Remote File Copy Scenario

All 12 matches were associated with:
- Computer: `PC01.example.corp`
- Account: `EXAMPLE\Administrator`
- Source IP: `10.0.2.15`
- Share: `\*\C$`

Observed paths:
- `malwr.exe` — 5 records
- `Windows\Temp\wodCmdTerm.exe` — 3 records
- `Windows\Temp\setup.bat` — 2 records
- `ui\SwDRM.dll` — 1 record
- `Windows\Temp\ui\SwDRM.dll` — 1 record

### RemCom Target-Host Scenario

Six matches involved:
- Computer: `PC01.example.corp`
- Account: `IEUser`
- Domain: `PC01`
- Source IP: `::1` (IPv6 loopback)
- Target: `Windows\System32\RemComSvc.exe`
- Event ID: `5145`
- Dataset tactic label: Lateral Movement

The scenario contained 30 Security Event ID 5145 records. No process creation or service installation events (Event IDs 1, 6, 7, 11, 12, 13, 4688, 4697, or 7045) were present in this scenario file. Therefore, execution of RemComSvc.exe cannot be confirmed from this file alone.

## Interpretation

The rule identified file-access checks involving executable or script-like paths through the C$ administrative share in two dataset scenarios.

Event ID 5145 records detailed file-share access checks. These records alone do not prove that a file transfer completed, that a file executed, or that the activity was malicious.

The six RemComSvc matches have a loopback source address and lack corroborating process/service events in the selected scenario file.

## False Positive Considerations

Potential legitimate matches include:
- Approved remote software deployment.
- IT administration and maintenance scripts.
- Endpoint-management tools.
- Backup and inventory software using administrative shares.

No benign comparison dataset has been tested yet. False-positive rate and production detection accuracy are therefore not established.

## Limitations and Follow-up

1. Validate the ATT&CK mapping against the complete scenario context.
2. Test against benign Windows administrative-share activity.
3. Correlate Event ID 5145 with logon, process creation, and service events where available.
4. Review access-mask semantics before adding access-specific filters.
5. Tune the rule using additional datasets and document observed false positives.

## Test Conclusion

Result: Candidate detection condition matched 18 unique records in the supplied dataset.

Validation: YAML and pySigma parsing passed.

Classification: Dataset matches observed; maliciousness and successful file transfer are not independently confirmed.
