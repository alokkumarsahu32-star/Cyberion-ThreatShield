# Cyberion ThreatShield
## Final Project Presentation

---

## Slide 1 — Title
**Cyberion ThreatShield**

Detection Engineering and Threat Hunting Platform

Project Focus:
- Windows Security Log Analysis
- Detection Engineering
- Threat Hunting
- MITRE ATT&CK Mapping

---

## Slide 2 — Problem Statement
Organizations generate large volumes of Windows security events.

Security analysts need ways to:
- Identify suspicious activities.
- Detect potential attack behavior.
- Correlate related security events.
- Investigate alerts.
- Document findings and response recommendations.

Cyberion ThreatShield demonstrates an offline workflow for these activities.

---

## Slide 3 — Project Objectives
- Develop Windows-focused Sigma detection rules.
- Analyze Windows event telemetry.
- Map detections to MITRE ATT&CK.
- Perform structured threat hunts.
- Document incident investigation case studies.
- Review detection scope and potential false positives.
- Provide a web-based log analysis demonstration.

---

## Slide 4 — Dataset and Telemetry
**Dataset:** EVTX-ATTACK-SAMPLES

- Total records: 4,633
- Total columns: 326
- Windows security and Sysmon event telemetry.
- Analysis performed offline.

Examples of analyzed event IDs:
- Sysmon: 1, 3, 8, 10, 11 and 13.
- Windows Security: 1102, 5145 and 5156.

The dataset is attack-sample oriented and is not a representative benign enterprise baseline.

---

## Slide 5 — Detection Engineering
**17 Sigma YAML files**

- 14 individual detection rules.
- 3 correlation detection rules.

Detection topics include:
- Suspicious PowerShell activity.
- LSASS process access.
- Credential dumping indicators.
- Admin share access.
- Plink loopback RDP connections.
- Windows audit log clearing.
- Suspicious persistence activity.

YAML parsing and pySigma structural validation were performed.

---

## Slide 6 — MITRE ATT&CK Coverage
**Current documented coverage: 13 / 20 techniques**

- 10 techniques explicitly represented in Sigma rule tags.
- 3 additional techniques implemented and tested in the Log Analyzer.
- Coverage spans 6 documented tactics.

Seven additional techniques remain pending verification.

---

## Slide 7 — Log Analyzer Demonstration
The web application provides:
1. Admin login.
2. Log Analyzer page.
3. CSV file upload.
4. File validation and data preview.
5. Detection analysis.
6. Alert results.

Selected synthetic detection tests cover:
- WMI permanent event subscriptions.
- Suspicious scheduled task creation.
- Suspicious Windows service installation.

These tests validate selected detection logic using synthetic data.

---

## Slide 8 — Threat Hunting Results
**Two documented threat hunts**

HUNT-01:
- Investigated LSASS remote-thread and process-access activity.
- Identified 1 correlated event pair.
- Used a 60-second correlation window.

HUNT-02:
- Investigated LSASS process access and dump-file creation.
- Identified 16 correlated event pairs.
- Identified 5 unique process GUIDs.
- Used a 60-second correlation window.

Correlated event pairs are analytical findings, not automatically independent incidents.

---

## Slide 9 — Incident Investigation
**Two offline investigation case studies**

CASE-01:
- LSASS credential-dumping activity.
- 16 correlated event pairs.
- 6 unique process-level correlations.

CASE-02:
- Windows Security audit log clearing.
- 21 Event ID 1102 records.
- 21 EVTX source files.

Both cases document evidence, findings, limitations, and recommended response actions. Neither is presented as a confirmed live incident.

---

## Slide 10 — False-Positive Review
Four tuning review documents are available.

Three completed reviews verified:
- Windows Admin Share File Access.
- Plink Loopback RDP Connection.
- Suspicious LSASS Access.

The reviews document candidate matches, detection scope, limitations, and tuning decisions.

No measured false-positive reduction is claimed because representative benign baseline data is unavailable.

---

## Slide 11 — Incident Response and Platform
**Response preparation**
- Three incident response playbooks.
- Investigation and response recommendations.
- Analyst-focused guidance.

**Web application modules**
- Dashboard.
- CSV Log Analyzer.
- Detection Engineering.
- MITRE ATT&CK Coverage.
- Threat Hunting.
- Incident Cases.

The application is a demonstration platform, not a production SIEM or automated response system.

---

## Slide 12 — Testing and Validation
Validation evidence includes:
- YAML parsing.
- pySigma structural loading.
- Offline dataset condition tests.
- Synthetic detection tests.
- Python syntax compilation.
- Browser testing of application pages.

Different validation activities are documented separately. A successful offline test does not establish production detection effectiveness.

---

## Slide 13 — Project Limitations
- Offline attack-sample dataset.
- No representative benign enterprise baseline.
- Benign false-positive rate not measured.
- Live endpoint monitoring not validated.
- Production SIEM integration not validated.
- ATT&CK target of 20 techniques not yet completed.
- Dataset correlations do not independently prove compromise.

---

## Slide 14 — Future Scope
- Complete and verify 20 ATT&CK techniques.
- Test detections against benign and malicious telemetry.
- Improve detection coverage and context.
- Validate correlation rules in a supported SIEM.
- Evaluate detections in a controlled environment.
- Explore live telemetry integration.

---

## Slide 15 — Conclusion
Cyberion ThreatShield demonstrates a structured approach to Windows detection engineering and threat hunting.

The project combines:
- Sigma detection rules.
- Offline log analysis.
- MITRE ATT&CK mapping.
- Threat hunting.
- Incident investigation.
- False-positive review.
- Incident response preparation.
- A web-based demonstration interface.

**Thank You**

Questions and Discussion
