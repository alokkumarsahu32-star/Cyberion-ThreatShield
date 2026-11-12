# Cyberion ThreatShield
## Executive Summary

### 1. Project Overview
Cyberion ThreatShield is a detection engineering and threat hunting project focused on identifying suspicious Windows activity through log analysis, Sigma detection rules, correlation logic, and structured investigation reports.

The project uses an offline Windows event dataset and a web-based demonstration platform to support detection analysis and review.

### 2. Project Objectives
- Develop and validate Windows-focused detection rules.
- Map detection coverage to MITRE ATT&CK techniques.
- Perform structured threat hunting using event correlation.
- Document investigation findings and response recommendations.
- Review detection logic for potential false positives.
- Provide a simple interface for CSV log analysis.

### 3. Detection Engineering
The project contains 17 Sigma YAML rule files:
- 14 individual detection rules.
- 3 correlation detection rules.

The rules cover suspicious process activity, credential access, lateral movement, persistence, defense evasion, and other Windows security events.

YAML parsing and structural validation were performed. Correlation backend compatibility has limitations and is documented in the project evidence.

### 4. Dataset and Telemetry
The offline EVTX-ATTACK-SAMPLES dataset contains:
- 4,633 event records.
- 326 columns.
- Multiple Windows event sources, including Sysmon and Windows Security events.

The dataset supports offline detection testing and investigation. It is not a representative benign enterprise baseline.

### 5. MITRE ATT&CK Coverage
The project currently documents 13 distinct ATT&CK techniques:
- 10 techniques explicitly represented in Sigma rule tags.
- 3 additional techniques implemented and tested in the Log Analyzer.

The project target is 20 techniques. Seven additional techniques remain to be documented and verified.

### 6. Threat Hunting
Two dataset-based threat hunts were completed:
- HUNT-01: LSASS remote-thread and process-access correlation.
- HUNT-02: LSASS process-access and dump-file creation correlation.

HUNT-01 identified one correlated event pair. HUNT-02 identified 16 correlated event pairs across five unique process GUIDs.

These findings are analytical observations, not confirmation of successful credential theft.

### 7. Incident Investigation
Two offline investigation case studies were documented:
- CASE-01: LSASS credential-dumping activity.
- CASE-02: Windows Security audit log clearing.

Both reports include evidence, analytical findings, limitations, and recommended investigation or response actions. They do not represent confirmed live incidents.

### 8. False-Positive Review
Four rule-tuning review documents are available. Three completed reviews have been verified:
- Windows Admin Share File Access.
- Plink Loopback RDP Connection.
- Suspicious LSASS Access.

The reviews document detection scope, candidate matches, limitations, and tuning decisions. No measured benign false-positive reduction is claimed because a representative benign baseline is unavailable.

### 9. Incident Response Preparation
The project includes three incident response playbooks covering documented response scenarios. These provide recommended investigation and response procedures; automated containment has not been implemented or claimed.

### 10. Demonstration Platform
The web application provides:
- Admin-protected dashboard.
- CSV Log Analyzer with upload validation and preview.
- Detection Engineering rule viewer.
- MITRE ATT&CK coverage page.
- Threat Hunting reports.
- Incident Case reports.

The application is a project demonstration interface, not a production SIEM or automated incident response platform.

### 11. Limitations
- Analysis is based primarily on an offline attack-sample dataset.
- Benign enterprise false-positive rates have not been measured.
- Live endpoint monitoring and production SIEM integration have not been validated.
- Detection results are candidate findings and require analyst investigation.
- ATT&CK coverage target of 20 techniques is not yet complete.

### 12. Conclusion
Cyberion ThreatShield demonstrates a practical workflow for Windows detection engineering, offline log analysis, threat hunting, ATT&CK mapping, investigation documentation, and false-positive review.

The project establishes a documented and testable foundation for further detection development. Future work should focus on completing the 20-technique ATT&CK target, evaluating detections against benign telemetry, and validating integrations in a controlled SIEM environment.
