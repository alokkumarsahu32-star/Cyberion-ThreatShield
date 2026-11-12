# Rule Test Report: WIN-5156 Plink Loopback RDP Connection

## 1. Rule Information

- Rule title: Plink Process Connecting to Loopback RDP Port
- Rule ID: 5e8c2a41-7b93-4d16-a0f5-2c9e61b73842
- Rule name: windows_plink_loopback_rdp_connection
- Log source: Windows Security / Windows Filtering Platform
- Event ID: 5156
- Severity: Medium
- Status: Experimental
- ATT&CK mapping: T1572 - Protocol Tunneling (provisional)

## 2. Detection Objective

Identify network connection events where Plink is the initiating
application and the destination is a loopback address using TCP port 3389.

This pattern may be consistent with SSH-based RDP port forwarding.
It is not, by itself, proof of a malicious SSH session or unauthorized
remote access.

## 3. Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- Source file containing matches: DE_RDP_Tunnel_5156.evtx
- Total CSV records: 4,633
- Total Event ID 5156 records: 92

## 4. Detection Logic

The rule requires all of the following:

1. Event ID equals 5156.
2. Application path ends with \plink.exe.
3. Destination port equals 3389.
4. Destination address starts with 127.

The rule was parsed using YAML and PySigma.
Dataset matching was performed using an equivalent Python condition.

## 5. Test Results

- YAML parsing: PASSED
- PySigma parsing: PASSED
- Dataset condition test: PASSED
- Total matching records: 2
- Distinct source files containing matches: 1

Both matching records were found in DE_RDP_Tunnel_5156.evtx.

## 6. Observed Evidence

Host: PC01.example.corp
Application: \device\harddiskvolume1\users\user01\desktop\plink.exe
Process ID: 3324
Protocol: 6 (TCP)

Connection 1:
- Time: 2019-02-13 18:04:01.632120
- Source: 127.0.0.1:49271
- Destination: 127.0.0.2:3389

Connection 2:
- Time: 2019-02-13 18:04:45.905783
- Source: 127.0.0.1:49274
- Destination: 127.0.0.2:3389

A related Event ID 4688 process creation record showed Plink launched
from C:\Users\user01\Desktop\plink.exe at 18:03:28.318441.

An additional Event ID 5156 record associated with the same process
showed a connection from 10.0.2.17:49269 to 10.0.2.18:80.

## 7. False-Positive Considerations

Potential legitimate explanations include:

- Authorized SSH tunneling by system administrators.
- Approved RDP port forwarding for remote administration.
- Controlled penetration testing or security validation.
- Troubleshooting involving local port forwarding.

The selected scenario contained two matching port-3389 records,
both associated with Plink. However, this is not an independent
benign-system baseline and cannot establish a production false-positive rate.

## 8. Limitations

- The Event ID 4688 records did not contain command-line arguments.
- SSH session details and server-side logs were not available.
- The observed connections do not independently prove that an SSH tunnel
  was successfully established.
- The dataset scenario label is not independent proof of malicious activity.
- The test was performed against the selected CSV dataset, not a live SIEM.
- PySigma parsing does not execute the detection rule against an event stream.

## 9. Conclusion

The experimental rule matched two Event ID 5156 records in the selected
dataset. Both records involved Plink connecting to loopback destination
127.0.0.2 on TCP port 3389.

The observed process and network activity is consistent with a possible
RDP port-forwarding pattern. Further investigation would be required to
confirm the SSH tunnel configuration, authorization status and security impact.

The rule is suitable for further testing and tuning, but should not be
treated as a confirmed malicious-activity detector based on this dataset alone.
