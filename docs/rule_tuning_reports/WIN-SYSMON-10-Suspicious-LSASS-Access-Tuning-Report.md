# Rule Tuning Report 3 — Known Credential Dumping Tool Accessing LSASS

## Rule Information
- Rule file: WIN-SYSMON-10-Suspicious-LSASS-Access.yml
- Rule ID: 6b3a9c42-8d71-4e25-a6f0-2b9d7c51e843
- Rule name: suspicious_lsass_access
- Review type: Tool-name detection coverage and false-positive review
- Review status: Completed

## Dataset Evidence
- Dataset: EVTX-ATTACK-SAMPLES
- Total records: 4,633
- Event ID 10 records: 140
- Event ID 10 records targeting LSASS: 26
- Candidate matches: 12
- Unique source process paths: 8
- Scenarios with matches: 6

## Review Findings
The rule identified LSASS process-access events where the source process path contained a known tool-name indicator:
- mimikatz
- procdump
- ppldump
- dumpert
- andrewspecial

These matches are candidate detections from attack-labelled scenarios. They do not independently establish malicious intent.

## Tuning Decision
**Decision: Retain existing tool-name conditions. No logic change justified by current evidence.**

Reasons:
1. The existing conditions identified 12 candidate records across six scenarios.
2. No benign enterprise baseline is available to evaluate additional exclusions or restrictions.
3. Filename-based detection has an inherent limitation: renamed tools and unknown tool names may not match.
4. Adding broader conditions without additional evidence could increase noise.

## Coverage Limitations
- Renamed or unknown credential-dumping tools may evade filename-based matching.
- PowerShell-based LSASS access is covered by a separate detection rule.
- Authorized forensic and incident-response tools may produce similar activity.
- A process name alone does not establish malicious intent.

## Validation Status
- Existing YAML parsing: PASS
- Existing UUID validation: PASS
- Existing pySigma structural parsing: PASS
- Existing offline dataset condition test: PASS
- Post-tuning logic change: NOT APPLICABLE — no logic change made
- Benign false-positive rate: NOT MEASURED

## Recommended Future Improvement
Evaluate additional source-process indicators and process context against a broader dataset containing both benign and malicious LSASS access events before expanding the detection logic.

## Conclusion
Rule 10 was reviewed using observed LSASS process-access evidence. The current detection logic is retained because the available evidence does not justify additional filters or exclusions. The filename-based coverage limitation is documented. This is a no-change tuning decision, not a measured false-positive reduction.
