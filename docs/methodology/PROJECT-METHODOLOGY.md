# Cyberion ThreatShield
## Project Methodology

### 1. Methodology Overview
This project follows a structured detection engineering and threat hunting workflow. The workflow uses offline Windows event data, Sigma rules, correlation analysis, validation scripts, and documented investigation reports.

### 2. Data Collection and Preparation
- Used the EVTX-ATTACK-SAMPLES dataset for offline analysis.
- Loaded the dataset from `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`.
- Identified 4,633 records and 326 columns.
- Reviewed available Windows event IDs, host information, timestamps, process details, and scenario labels.
- Used available telemetry fields to select suitable detection opportunities.

The dataset is attack-sample oriented and does not provide a representative benign enterprise baseline.

### 3. Telemetry Analysis
Relevant Windows telemetry was selected according to detection objectives.

Examples include:
- Sysmon Event ID 1: Process creation.
- Sysmon Event ID 3: Network connection.
- Sysmon Event ID 8: CreateRemoteThread.
- Sysmon Event ID 10: Process access.
- Sysmon Event ID 11: File creation.
- Sysmon Event ID 13: Registry value modification.
- Windows Security Event ID 1102: Audit log cleared.
- Windows Security Event IDs 5145 and 5156: File-share access and network filtering events.

Additional event sources were reviewed where available. Event interpretation depends on the fields actually present in the dataset.

### 4. Detection Rule Development
- Developed Windows-focused Sigma YAML detection rules.
- Organized rules in the `detection_rules` directory.
- Used rule identifiers, titles, log sources, detection conditions, severity, references, and ATT&CK tags.
- Included individual and correlation detection rules.
- Used YAML parsing and pySigma structural loading to validate rule structure.

The project contains 17 Sigma YAML files: 14 individual rules and 3 correlation rules.

### 5. Detection Validation
Detection validation used available dataset records and focused test scripts.

The validation process included:
1. Inspecting the rule definition.
2. Identifying the relevant event IDs and fields.
3. Applying equivalent offline conditions to the dataset.
4. Reviewing candidate matches.
5. Checking related process, host, and timestamp context where available.
6. Recording results and limitations in test reports.

Synthetic test datasets were also used to validate selected Log Analyzer detection logic, including WMI permanent event subscriptions, scheduled tasks, and Windows service installation.

A successful offline test does not establish production detection effectiveness.

### 6. MITRE ATT&CK Mapping
- Reviewed detection behavior and associated ATT&CK techniques.
- Recorded technique identifiers and tactic information.
- Maintained the coverage matrix in `attack_mapping/MITRE-ATTACK-COVERAGE-MATRIX.md`.
- Distinguished Sigma rule tags from additional Log Analyzer detection mappings.

The currently documented coverage is 13 distinct techniques against a target of 20. Seven additional techniques remain pending verification.

### 7. Correlation Analysis
Correlation analysis used available host, process GUID, event type, and timestamp fields.

For the LSASS investigations:
- HUNT-01 correlated Event ID 8 and Event ID 10 activity.
- HUNT-02 correlated Event ID 10 process access and Event ID 11 dump-file creation.
- A 60-second correlation window was used.
- Host and process identifiers were used to associate records.

Correlated event pairs are analytical findings and are not automatically equivalent to independent incidents.

### 8. Threat Hunting
Two structured hunts were documented:
- HUNT-01: LSASS remote-thread and process-access activity.
- HUNT-02: LSASS process-access and dump-file creation activity.

Each hunt records its hypothesis, data source, analysis method, findings, evidence, assessment, and limitations.

### 9. Incident Investigation
Two dataset-based investigation case studies were prepared:
- CASE-01: LSASS credential-dumping activity.
- CASE-02: Windows Security audit log clearing.

The investigations document observed evidence, analytical priority, possible explanations, recommended actions, and limitations.

Neither case is presented as a confirmed live security incident.

### 10. False-Positive Review and Tuning
Detection reviews considered:
- Detection scope and candidate matches.
- AccessMask and process-name indicators where applicable.
- Potential legitimate administrative or forensic activity.
- Risk of excluding relevant activity through overly restrictive conditions.
- Availability of benign baseline telemetry.

Four tuning review documents are available. Three completed reviews have been verified.

Where evidence did not justify a logic change, the existing rule was retained and the no-change decision was documented. No measured false-positive reduction is claimed.

### 11. Incident Response Preparation
Three response playbooks were prepared to document recommended investigation and response procedures for relevant detection scenarios.

The playbooks provide analyst guidance. Automated containment and remediation execution are outside the implemented project scope.

### 12. Demonstration Application
A FastAPI-based web application provides a demonstration interface for:
- Admin authentication.
- CSV upload validation and preview.
- Log Analyzer detection.
- Sigma rule browsing.
- MITRE ATT&CK coverage.
- Threat hunting reports.
- Incident investigation case studies.

The application is a demonstration platform and is not a production SIEM.

### 13. Validation and Evidence Management
Project evidence is maintained in structured directories, including:
- `docs/rule_test_reports`
- `docs/rule_tuning_reports`
- `docs/threat_hunting`
- `docs/incident_cases`
- `attack_mapping`
- `tests`

Validation claims are limited to checks and tests actually performed. Syntax compilation, YAML parsing, structural loading, offline dataset tests, synthetic tests, and browser checks are treated as separate forms of evidence.

### 14. Limitations
- The primary dataset is an offline attack-sample dataset.
- Representative benign enterprise telemetry is unavailable.
- Benign false-positive rates have not been measured.
- Live endpoint monitoring has not been validated.
- Production SIEM integration has not been validated.
- ATT&CK coverage remains below the 20-technique target.
- Dataset correlations do not independently prove malicious intent or successful compromise.

### 15. Conclusion
The methodology provides a repeatable workflow for offline Windows telemetry analysis, detection development, rule validation, ATT&CK mapping, threat hunting, investigation documentation, and false-positive review.

Further validation against representative benign and malicious telemetry, completion of the ATT&CK target, and controlled SIEM integration are recommended future activities.
