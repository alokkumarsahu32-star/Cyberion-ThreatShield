# Rule 14 Test Report: MSHTA Outbound Network Connection

## Rule Information
- Rule file: WIN-SYSMON-3-MSHTA-Outbound-Network-Connection.yml
- Rule name: mshta_outbound_network_connection
- Log source: Windows Sysmon Network Connection (Event ID 3)
- Status: Experimental
- Severity: High
- ATT&CK: T1218.005 - Mshta

## Validation Results
- YAML parsing: PASS
- UUID validation: PASS
- pySigma structural loading: PASS
- Offline dataset matching: PASS

## Dataset Results
- Total dataset events: 4,633
- Event ID 3 events: 153
- Rule matches: 4
- Unique process GUIDs: 2
- Matching scenarios: 2

## Match Analysis

### Scenario 1
- Scenario: exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx
- Matching events: 3
- Process GUID: {365abb72-1a29-5ce4-0000-001079f92101}
- Destinations:
  - 108.179.232.58:443
  - 105.73.6.112:80
  - 105.73.6.105:80

### Scenario 2
- Scenario: sysmon_mshta_sharpshooter_stageless_meterpreter.evtx
- Matching events: 1
- Process GUID: {365abb72-9aa6-5d04-0000-00109c850f00}
- Destination: 10.0.2.18:4443

## Excluded Event
One MSHTA Event ID 3 record had Initiated=False and was excluded by the rule condition.

## Limitations
- The dataset contains attack-oriented scenarios and is not a representative benign baseline.
- Outbound MSHTA activity alone does not prove malicious execution or successful command-and-control.
- Three connections belong to one process instance and should not be treated as three independent executions.
- No live Windows endpoint or SIEM validation was performed.
- No backend-specific Sigma conversion was performed.

## Assessment
PARTIALLY VALIDATED - EXPERIMENTAL

The rule passed YAML, UUID, pySigma structural loading, and offline dataset matching checks. Its four matching events across two process instances are consistent with suspicious MSHTA network activity in the supplied attack scenarios. Benign baseline testing and live telemetry validation remain outstanding.
