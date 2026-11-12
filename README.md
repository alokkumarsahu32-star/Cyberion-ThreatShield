# Cyberion ThreatShield
## Detection Engineering and Threat Hunting Platform

**Internship Project | 4-Week Individual Engagement**

---

## 1. Project Overview

Cyberion ThreatShield is a Detection Engineering and Threat
Hunting project focused on identifying, analyzing, and
documenting real-world attacker behaviors using security
telemetry and publicly available datasets.

The project follows a structured security analysis approach
based on Sigma detection rules, MITRE ATT&CK mapping,
hypothesis-driven threat hunting, IOC research, incident
investigation, and incident response playbooks.

The primary objective is to develop practical detection
engineering and threat hunting capabilities.

## 2. Project Objectives

- Understand different security log and telemetry sources.
- Develop and test at least 15 Sigma detection rules.
- Map detection coverage to MITRE ATT&CK.
- Perform at least 2 hypothesis-driven threat hunts.
- Conduct at least 2 incident investigations.
- Research and correlate Indicators of Compromise (IOCs).
- Prepare at least 3 incident response playbooks.
- Review and tune detection rules to reduce false positives.
- Prepare an executive summary and final presentation.

## 3. Project Scope

This project focuses on analytical security deliverables
and detection content.

The engagement does not require developing a custom
application, backend, database, or hosted SIEM platform.

## 4. Core Deliverables

| Deliverable | PRD Requirement |
|---|---|
| Log & Telemetry Data Dictionary | At least 3 source types |
| Sigma Detection Rules | 15 or more |
| Correlation-style Rules | At least 3 |
| MITRE ATT&CK Coverage Matrix | At least 20 techniques assessed |
| Threat Hunting Reports | At least 2 |
| Incident Investigation Reports | At least 2 |
| IOC Research Notes | Required |
| Incident Response Playbooks | At least 3 |
| Rule Tuning Documentation | At least 3 tuned rules |
| Executive Summary | Required |
| Methodology Document | Required |
| Final Presentation | Required |

## 5. Technologies and Tools

- Python 3.11+
- pandas
- Jupyter Notebook
- Sigma Rules
- Sigma CLI / pySigma
- MITRE ATT&CK
- MITRE ATT&CK Navigator
- Atomic Red Team (optional)
- Git and GitHub
- Markdown and Spreadsheet Documentation

## 6. Dataset Sources

The project will use real security telemetry and publicly
available datasets.

Potential sources identified in the PRD:

- Mordor / Open Threat Research Forge
- Splunk Boss of the SOC (BOTS)
- EVTX-ATTACK-SAMPLES
- Locally generated telemetry using Atomic Red Team,
  Sysmon, or Linux auditd

Selected datasets and their sources will be documented
in the methodology report.

## 7. Four-Week Project Plan

### Week 1 — Log & Telemetry Familiarization
- Select security datasets.
- Identify at least 3 telemetry source types.
- Prepare the Data Dictionary.
- Select and justify initial MITRE ATT&CK techniques.
- Establish a version-controlled detection repository.

### Week 2 — Detection Rule Engineering
- Develop the first 10 or more Sigma rules.
- Test rules against actual log datasets.
- Begin MITRE ATT&CK coverage mapping.

### Week 3 — Threat Hunting & Investigation
- Conduct at least 2 hypothesis-driven threat hunts.
- Investigate detection findings.
- Prepare at least one incident case report.

### Week 4 — Finalization & Reporting
- Complete 15 or more Sigma rules.
- Complete incident case reports.
- Prepare response playbooks.
- Complete IOC research and rule tuning.
- Finalize ATT&CK coverage matrix.
- Prepare executive summary and presentation.

## 8. Detection Rule Quality

Each Sigma rule will document:

- Rule title and unique ID
- Description and references
- MITRE ATT&CK technique ID
- Log source
- Detection logic
- Severity level and justification
- False-positive scenarios

Every rule must be tested against actual log data and
reviewed for false positives.

## 9. Project Status

**Current status: In Progress**

Deliverables will be marked complete only after
implementation, testing, and documentation.

## 10. Repository Structure

The repository will contain the following project
deliverables as they are developed:

- `datasets/` — Selected security datasets and references
- `data_dictionary/` — Log source and field documentation
- `sigma_rules/` — Sigma detection rule library
- `attack_mapping/` — MITRE ATT&CK coverage matrix
- `threat_hunting/` — Threat hunting reports
- `incident_reports/` — Incident investigation reports
- `ioc_research/` — IOC research and correlation notes
- `playbooks/` — Incident response playbooks
- `rule_tuning/` — Detection tuning documentation
- `methodology/` — Project methodology
- `executive_summary/` — Executive report
- `presentation/` — Final internship presentation
- `tests/` — Detection testing resources

## 11. Evaluation Approach

Project completion will be evaluated against the original
PRD deliverables and success metrics, including:

- 15 or more Sigma detection rules.
- At least 20 ATT&CK techniques assessed.
- At least 2 threat hunts and 2 incident investigations.
- At least 3 incident response playbooks.
- Testing of every detection rule against actual log data.
- False-positive review for every rule.

---

**Project:** Cyberion ThreatShield  
**Focus:** Detection Engineering & Threat Hunting  
**Engagement:** Individual Internship Project