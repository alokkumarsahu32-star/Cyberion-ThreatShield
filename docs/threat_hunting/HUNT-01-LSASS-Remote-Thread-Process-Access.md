# Threat Hunt 01 - LSASS Remote Thread Creation Followed by Process Access

## Hypothesis
An attacker attempting credential dumping may create a remote thread targeting LSASS and access LSASS from the same source process within 60 seconds.

## Data Source
- Dataset: EVTX-ATTACK-SAMPLES
- File: datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv
- Events: Sysmon Event ID 8 and Event ID 10

## Hunting Method
Filtered Event ID 8 and Event ID 10 records targeting lsass.exe. Correlated events using the source Process GUID and Computer, requiring Event ID 10 to occur within 0-60 seconds after Event ID 8.

## Results
- Unique Event ID 8 LSASS records: 2
- Event ID 10 LSASS records: 26
- GUID-matched pairs: 1
- Correlated pairs within 60 seconds: 1

## Confirmed Evidence
- Host: IEWIN7
- Source process: \\VBOXSVR\HTools\voice_mail.msg.exe
- Source Process GUID: {365abb72-4055-5cc8-0000-0010769d0b00}
- Event ID 8 timestamp: 2019-04-30 12:43:43.784
- Event ID 10 timestamp: 2019-04-30 12:43:43.784
- Time difference: 0 seconds
- Source EVTX: CA_sysmon_hashdump_cmd_meterpreter.evtx

## Assessment
The correlated events support the hypothesis of suspicious LSASS interaction and warrant investigation for possible credential-dumping activity.

This evidence does not independently prove that credentials were successfully extracted.

## Conclusion
Hunt 01 identified one confirmed same-host, same-source-process correlation between remote thread creation targeting LSASS and subsequent LSASS process access.
