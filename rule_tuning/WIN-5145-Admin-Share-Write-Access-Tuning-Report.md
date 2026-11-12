# WIN-5145 Admin Share Write Access – Tuning Report

## 1. Objective

Create a focused companion analytic for Windows Security Event ID 5145
records that request write-capable access to executable, script, or DLL
paths through the C$ administrative share.

The original broad detection remains unchanged.

## 2. Dataset

- Dataset: datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv
- Total dataset records: 4,633
- Event ID 5145 records: 950
- Validation type: Offline dataset matching

## 3. Baseline

The original broad rule matched 18 records.

Conditions:
- Event ID 5145
- C$ administrative share
- ObjectType File
- Executable, script, or DLL-related file extensions

## 4. Evidence analysis

AccessMask 0x0017019f appeared in 4 of the 950 Event ID 5145 records.

The mask contains these write-related rights:
- FILE_WRITE_DATA
- FILE_APPEND_DATA
- FILE_WRITE_EA
- FILE_WRITE_ATTRIBUTES

The same mask also contains read-related rights.

All four records belonged to:
- Computer: PC01.example.corp
- Subject: Administrator
- Source IP: 10.0.2.15
- Source file: LM_5145_Remote_FileCopy.evtx

Matched paths:
- malwr.exe (2 records)
- Windows/Temp/setup.bat (2 records)

The dataset does not establish that the requested writes completed successfully.
Status was unavailable, and AccessReason was '-' for these four records.

## 5. Focused companion analytic

Rule:
detection_rules/WIN-5145-Admin-Share-Write-Access.yml

Additional condition:
AccessMask = 0x0017019f

The original broad rule was not modified.

## 6. Before/after results

| Measurement | Result |
|---|---:|
| Event ID 5145 dataset records | 950 |
| Original broad rule matches | 18 |
| Focused companion matches | 4 |
| Focused matches also in broad rule | 4 |
| Unique focused EventRecordIDs | 4 |
| Broad matches outside focused subset | 14 |

The focused analytic identifies a narrower subset. It does not replace
the original broad rule or establish that the other 14 records are benign.

## 7. Validation

- YAML parsing: PASSED
- Sigma to Splunk conversion: PASSED
- Offline dataset matching: PASSED
- Focused result count: 4
- Unique EventRecordID check: PASSED

No live Splunk execution was performed.

## 8. Limitations

- Exact access mask is dataset-specific and may not generalize to all
  Windows 5145 write-capable access requests.
- AccessMask represents requested access rights, not proof of completed writes.
- No labelled benign baseline was available.
- No false-positive reduction percentage is claimed.
- Live SIEM execution remains unverified.

## 9. Conclusion

An evidence-supported focused companion analytic was created and tested.
The original broad detection remains intact to preserve its wider coverage.
This is a focused analytic refinement, not a demonstrated reduction in
false positives for the original rule.
