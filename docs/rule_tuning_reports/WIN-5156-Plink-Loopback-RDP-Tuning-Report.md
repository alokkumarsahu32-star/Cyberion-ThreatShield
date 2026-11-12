# Rule Tuning Report 2 — Plink Loopback RDP Connection

## Rule Information
- Rule file: WIN-5156-Plink-Loopback-RDP-Connection.yml
- Rule ID: 5e8c2a41-7b93-4d16-a0f5-2c9e61b73842
- Rule name: windows_plink_loopback_rdp_connection
- Review type: Detection scope and false-positive review
- Review status: Completed

## Dataset Evidence
- Dataset: EVTX-ATTACK-SAMPLES
- Total Event ID 5156 records: 92
- Candidate matches: 2
- Matching scenario: DE_RDP_Tunnel_5156.evtx
- Application: plink.exe
- Destination: 127.0.0.2:3389
- Related Event ID 4688: Plink process creation observed

## Review Findings
Both matching records involve Plink connecting to a loopback destination on TCP port 3389. A related process creation event supports the association with Plink.

The available Event ID 4688 record does not contain command-line arguments. SSH session details and server-side logs are unavailable.

## Tuning Decision
**Decision: Retain the existing detection logic. No logic change justified by current evidence.**

Reasons:
1. The rule already requires Plink, destination port 3389 and a loopback destination.
2. The two observed records satisfy all existing conditions.
3. Adding a command-line condition is not possible to validate with the available evidence.
4. Restricting source addresses could exclude relevant tunneling activity.
5. No representative benign baseline is available.

## Validation Status
- Existing YAML parsing: PASS
- Existing pySigma structural parsing: PASS
- Existing offline dataset condition test: PASS
- Post-tuning logic change: NOT APPLICABLE — no logic change made
- Benign false-positive rate: NOT MEASURED

## Limitations
The observed connections do not independently prove successful SSH tunneling or unauthorized RDP access. The dataset is not a representative benign baseline, and no live SIEM validation was performed.

## Conclusion
Rule 5156 was reviewed using process and network telemetry evidence. The current narrow detection condition is retained because the available data does not justify additional restrictions. This is a documented no-change tuning decision, not a measured false-positive reduction.
