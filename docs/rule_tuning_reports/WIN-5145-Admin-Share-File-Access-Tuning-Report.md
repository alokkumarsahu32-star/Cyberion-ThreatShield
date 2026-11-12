# Rule Tuning Report 1 — Windows Admin Share File Access

## Rule Information
- Rule file: WIN-5145-Suspicious-Admin-Share-File-Access.yml
- Rule ID: 20f856b8-11da-4247-b9fb-62b6bd60af30
- Rule name: suspicious_admin_share_file_access
- Review type: AccessMask analysis and false-positive review
- Review status: Completed

## Baseline Test Evidence
- Dataset: EVTX-ATTACK-SAMPLES
- Total records: 4,633
- Candidate matches: 18 unique records
- Remote file-copy scenario: 12 matches
- RemCom target-host scenario: 6 matches

## Review Findings
The rule detects Event ID 5145 file-share access checks involving executable or script-like paths through the C$ administrative share.

The two observed scenarios have different AccessMask distributions. The observed records do not independently establish successful file transfer or execution.

Potential legitimate activity includes approved software deployment, IT administration, endpoint management, and backup operations.

## Tuning Decision
**Decision: Retain the existing detection logic. No AccessMask filter added.**

Reasons:
1. AccessMask distributions differ between the two scenarios.
2. Restricting the rule to one observed mask could exclude relevant candidate events.
3. No representative benign baseline is available.
4. Current evidence does not justify a narrower access-mask condition.

## Validation Status
- Existing YAML parsing: PASS
- Existing pySigma structural load: PASS
- Existing offline dataset test: PASS
- Post-tuning logic change: NOT APPLICABLE — no logic change made
- Benign false-positive rate: NOT MEASURED

## Limitations
The dataset contains attack samples and is not a representative benign baseline. Event ID 5145 records access checks; they do not prove completed file transfer, execution, or malicious intent.

## Conclusion
Rule 1 was reviewed using dataset evidence and AccessMask semantics. The existing candidate condition is retained because the available evidence does not justify a narrower filter. This is a documented no-change tuning decision, not a measured false-positive reduction.
