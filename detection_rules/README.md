# Cyberion ThreatShield – Detection Rules

## 1. Overview

This directory contains Sigma-based detection rules developed for the Cyberion ThreatShield Detection Engineering and Threat Hunting project.

The rules are designed to identify suspicious activities in Windows security telemetry, including Windows Security Event Logs and Sysmon events.

The detection content focuses on suspicious process execution, PowerShell abuse, credential access, lateral movement, log clearing, persistence, and other security-relevant behaviours.

## 2. Rule Inventory

The directory currently contains **17 YAML rule files**:

- 14 individual detection rules
- 3 correlation detection rules

Each rule is maintained as an individual YAML file.

## 3. Detection Rule Categories

The detection rules cover the following activity areas:

- PowerShell encoded command execution
- Embedded PowerShell execution policy bypass
- LSASS process access and credential dumping indicators
- LSASS dump file creation
- Suspicious DLL loading
- Remote thread creation
- Winlogon shell modification
- MSHTA outbound network connections
- Windows Security log clearing
- Administrative share access
- Plink-based loopback RDP connections

## 4. Correlation Rules

Three correlation rule files are maintained:

| Rule ID | Detection focus |
|---|---|
| CORR-001 | PowerShell and LSASS DLL activity sequence |
| CORR-002 | LSASS access followed by dump file creation |
| CORR-003 | LSASS remote thread and process access correlation |

Correlation rules are intended to identify related activities across multiple events rather than relying on a single event in isolation.

## 5. Rule Structure

Individual Sigma rules may contain the following fields:

- `title` – Human-readable detection name
- `id` – Unique rule identifier
- `status` – Development or production readiness status
- `description` – Explanation of the detected behaviour
- `logsource` – Required telemetry source
- `detection` – Selection logic and matching conditions
- `falsepositives` – Known legitimate activity that may trigger the rule
- `level` – Detection severity
- `tags` – MITRE ATT&CK tactic and technique references

## 6. MITRE ATT&CK Mapping

Rules include MITRE ATT&CK tags where applicable. These mappings help associate detection logic with adversary behaviours and support ATT&CK coverage analysis.

Refer to the project's `attack_mapping/` directory for the broader technique coverage documentation.

## 7. Validation and Testing

Detection rules must be evaluated against relevant telemetry and test scenarios.

Validation should consider:

- Positive test cases
- Negative or benign test cases
- False-positive behaviour
- Correlation and event-sequence requirements
- Detection logic consistency

A rule should only be considered validated after its test evidence has been reviewed.

## 8. Severity Levels

Sigma severity levels are used to communicate the relative priority of detected activity:

- `low`
- `medium`
- `high`
- `critical`

Severity does not independently establish that an event represents a confirmed compromise.

## 9. Project Status

This directory currently contains 17 YAML detection rule files, including 3 correlation rules.

The presence of a rule file does not by itself establish successful validation. Rule quality, ATT&CK mapping, and test evidence are tracked separately as part of the project audit.

---

**Project:** Cyberion ThreatShield  
**Workstream:** Detection Engineering  
**Format:** Sigma YAML  
**Repository Area:** `detection_rules/`
