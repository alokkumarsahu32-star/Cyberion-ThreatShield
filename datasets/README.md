# Dataset Documentation — Cyberion ThreatShield

## 1. Dataset Source

- **Dataset name:** EVTX-ATTACK-SAMPLES
- **Original repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **Original author/repository owner:** sbousseaden
- **Primary format:** Windows Event Viewer (EVTX)
- **Parsed data:** `evtx_data.csv`
- **License file included with source:** `LICENSE.GPL` (GNU General Public License, Version 3)

The original repository describes these as Windows event samples associated with specific attack and post-exploitation techniques. It identifies their use for detection testing, DFIR training, threat hunting and Windows/Sysmon detection use-case development.

## 2. Local Dataset Inventory

The following inventory was verified in the downloaded local copy:

| Item | Verified count / value |
|---|---:|
| Total files (excluding nested Git metadata) | 316 |
| EVTX files | 278 |
| Parsed CSV records | 4,633 |
| Parsed CSV columns | 326 |
| Total dataset size | Approximately 59.93 MB |

The original source README describes the collection as approximately 200 EVTX examples. The local file inventory contains 278 EVTX files. These are recorded separately because the source description and local file count are not identical.

## 3. Main Contents

- `evtx_data.csv` — parsed Windows event records.
- `*.evtx` — original Windows event log samples.
- `EVTX_ATT&CK_Metadata/` — source-provided ATT&CK-related metadata.
- Attack-category folders — source-organized event samples.
- `LICENSE.GPL` — license text included with the source repository.
- `README.md` — original dataset documentation.
- PowerShell scripts and example configuration — source-provided parsing/replay utilities.

## 4. Telemetry Sources Observed

The parsed CSV contains records from multiple Windows event channels, including:

- Microsoft-Windows-Sysmon/Operational
- Security
- Application
- Other Windows operational channels

See `data_dictionary/telemetry_data_dictionary.md` for the inspected channel counts, event IDs, field descriptions and detection significance.

## 5. License and Attribution

This repository retains the original dataset's `LICENSE.GPL` file and source README.

Original source:
https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

The original README identifies the dataset with the GNU General Public License. The included license file is GNU GPL Version 3.

Users should read the included license and preserve the original attribution and license notices when redistributing source materials. This project does not claim ownership of the original dataset.

## 6. Use in Cyberion ThreatShield

This dataset is used as a research and testing source for:

- Windows and Sysmon telemetry familiarization.
- Data dictionary preparation.
- Detection hypothesis development.
- Sigma rule engineering and testing.
- MITRE ATT&CK technique mapping.
- Threat hunting and incident investigation exercises.

A dataset filename, folder label or source-provided ATT&CK tag is not by itself proof that a particular event is malicious. Detection findings must be supported by inspection of the underlying event records and documented analysis.

## 7. Evidence and Testing Notes

- The parsed CSV is a source-provided dataset artifact.
- Dataset contents may include multiple hosts, scenarios and event providers.
- Not every event contains every possible field.
- Any rule marked as tested must have a documented test against the actual dataset records.
- Synthetic demonstration logs in the application are not substitutes for testing against this original dataset.

## 8. Dataset Integrity

The original dataset files are retained under:

`datasets/raw/EVTX-ATTACK-SAMPLES/`

The nested `.git` metadata from the downloaded source clone is not included. The dataset files, original README and license file are retained.
