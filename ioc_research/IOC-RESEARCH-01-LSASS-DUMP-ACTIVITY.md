# IOC Research - LSASS Credential Dumping Activity

## Objective
Record and assess observable artifacts identified during HUNT-01 and HUNT-02.

## Evidence sources
- HUNT-01: LSASS Remote Thread and Process Access
- HUNT-02: LSASS Access Correlated with Dump File Creation
- Dataset: EVTX-ATTACK-SAMPLES/evtx_data.csv

## Observed artifacts

| Artifact | Observation | Assessment |
|---|---|---|
| procdump.exe | LSASS access and dump creation correlation | Investigate; legitimate administrative use is possible |
| Outflank-Dumpert.exe | LSASS access and dump creation correlation | Suspicious credential-dumping tooling |
| rundll32.exe | LSASS access and dump creation correlation | Context-dependent; investigate execution chain |
| AndrewSpecial.exe | LSASS access and dump creation correlation | Suspicious; requires binary verification |
| services.exe | Associated with lsass.dmp creation | Investigate process behavior and context |
| taskmgr.exe | Associated with LSASS-named dump creation | May be legitimate diagnostic activity |

## Observed file paths

- C:\Users\IEUser\Desktop\lsass.dmp
- C:\Users\IEUser\Desktop\lsass.exe_190317_120941.dmp
- C:\Users\IEUser\AppData\Local\Temp\lsass (2).DMP
- C:\Windows\Temp\dumpert.dmp
- C:\Users\administrator\Desktop\Andrew.dmp

## Observed hosts
- MSEDGEWIN10
- PC04.example.corp
- alice.insecurebank.local

These are dataset host identifiers, not independently verified malicious infrastructure.

## MITRE ATT&CK mapping
- T1003.001 - OS Credential Dumping: LSASS Memory

## IOC confidence and limitations
- Process names and file paths are observed artifacts, not automatically confirmed malicious IOCs.
- Process GUIDs are event-correlation identifiers, not reusable threat indicators.
- No verified file hashes, external IP addresses, or malicious domains were established by the two hunts.
- Binary hashes and signatures must be collected before making file-level IOC claims.
- Legitimate tools such as ProcDump and Task Manager can generate false positives.

## Conclusion
The hunts identified suspicious LSASS access and dump-file creation activity. Outflank-Dumpert.exe and the associated dump artifacts deserve priority investigation. Further enrichment is required before classifying individual artifacts as confirmed malicious IOCs.
