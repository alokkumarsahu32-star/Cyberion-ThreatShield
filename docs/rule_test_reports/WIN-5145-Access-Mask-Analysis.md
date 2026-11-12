# Windows Event ID 5145 — Access Mask Analysis

## Dataset Evidence

Analyzed scenarios:
- `LM_5145_Remote_FileCopy.evtx`
- `LM_REMCOM_5145_TargetHost.evtx`

Total Event ID 5145 records analyzed: 899

## Observed Access Masks

| Access mask | Remote File Copy | RemCom |
|---|---:|---:|
| `0x00100081` | 702 | 1 |
| `0x00120089` | 157 | 0 |
| `0x00100080` | 2 | 15 |
| `0x00120196` | 0 | 6 |
| `0x0017019f` | 4 | 0 |
| `0x00000080` | 2 | 2 |
| `0x00100088` | 0 | 3 |
| `0x0012019f` | 0 | 3 |
| `0x001200a9` | 2 | 0 |

## Verified Access Rights

Microsoft's Event ID 5145 documentation defines the access codes and explains that AccessMask is the sum of requested access rights.

Examples observed in this dataset:

- `0x00100081`: ReadData, ReadAttributes, Synchronize.
- `0x00120089`: ReadData, ReadEA, ReadAttributes, ReadControl, Synchronize.
- `0x0017019f`: includes ReadData, WriteData, AppendData, ReadEA, WriteEA, ReadAttributes, WriteAttributes, Delete, ReadControl, WriteDac and Synchronize.

The `AccessList` field contains resource identifiers such as `%%4416`, `%%4417`, `%%1537`, and `%%1539`. These correspond to the documented access-right labels.

## Important Detection Interpretation

The observed masks do not establish that the executable or script was executed.

The rule detects access checks involving executable/script-like file paths on the C$ administrative share. It does not detect process execution.

The observed AccessList values do not show the Execute/Traverse right (`0x20`) in these records.

## Tuning Decision

Do not add an AccessMask filter to Rule 1 at this stage.

Reasons:
1. The two scenarios show different access-mask distributions.
2. Restricting the rule to one mask could exclude relevant scenario matches.
3. The current candidate condition has 18 matches across the full dataset.
4. Benign comparison data is not yet available.
5. Access-mask filtering should be considered only after broader testing and false-positive review.

## Source

Microsoft Learn — Event 5145:
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145

## Conclusion

Access-mask analysis supports retaining the current broad candidate condition for now. No access-mask-based tuning is justified by the available evidence.
