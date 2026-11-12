# PB-03 - Malicious Process and Network Activity Response

## 1. Purpose
Provide a response procedure for suspicious process execution and network communication.

## 2. Trigger conditions
- Suspicious process execution or parent-child relationships.
- Unexpected outbound network connections.
- Execution of tools from unusual directories.
- Correlation between suspicious processes and network activity.

## 3. Initial triage
1. Record hostname, timestamp, username and process GUID.
2. Identify process image, command line and parent process.
3. Review Sysmon Event IDs 1, 3 and 7.
4. Identify remote IP, port and destination domain, if available.
5. Check whether the process and connection are authorized.

## 4. Containment
1. Escalate confirmed suspicious activity.
2. Block verified malicious destinations using approved security controls.
3. Isolate affected endpoints when authorized.
4. Preserve logs and relevant files before remediation.

## 5. Investigation
1. Examine process ancestry and executable metadata.
2. Collect file hashes and digital signatures.
3. Review DNS, firewall, proxy and endpoint network logs.
4. Identify related hosts communicating with the same destination.
5. Establish the activity timeline and potential impact.

## 6. Eradication and recovery
1. Remove confirmed malicious files and persistence.
2. Block confirmed malicious network indicators.
3. Reset affected credentials if compromise is suspected.
4. Restore endpoint security controls.
5. Validate normal business operations.

## 7. Validation
- Confirm suspicious processes have stopped.
- Confirm unauthorized network connections have ceased.
- Verify security monitoring is operational.
- Monitor for recurrence and related indicators.

## 8. Evidence to retain
- Sysmon process and network events
- Process command lines and ancestry
- IP addresses, domains and ports
- File hashes and signatures
- Incident timeline and response actions

## 9. Closure criteria
Close after investigation, containment, eradication and recovery are documented and approved.

## 10. References
MITRE ATT&CK:
- T1059 - Command and Scripting Interpreter
- T1071 - Application Layer Protocol
- T1105 - Ingress Tool Transfer

Note: Network indicators must be validated before blocking. Perform response actions only through authorized procedures.
