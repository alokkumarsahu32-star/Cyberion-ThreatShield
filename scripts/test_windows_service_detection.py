from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from app.services.log_analyzer import detect_windows_service


def main():
    print("WINDOWS SERVICE DETECTION TEST")
    print("=" * 60)

    test_data = [
        {"Computer": "HOST-01", "EventID": 7045, "ServiceName": "SuspiciousCmdService", "ImagePath": r"C:\Windows\System32\cmd.exe"},
        {"Computer": "HOST-02", "EventID": 7045, "ServiceName": "SuspiciousCalcService", "ImagePath": r"C:\Windows\System32\calc.exe"},
        {"Computer": "HOST-03", "EventID": 7045, "ServiceName": "SuspiciousPipeService", "ImagePath": r"\\.\pipe\malicious"},
        {"Computer": "HOST-04", "EventID": 7045, "ServiceName": "LegitimateService", "ImagePath": r"C:\Windows\System32\svchost.exe"},
        {"Computer": "HOST-01", "EventID": 7045, "ServiceName": "SuspiciousCmdService", "ImagePath": r"C:\Windows\System32\cmd.exe"},
    ]

    df = pd.DataFrame(test_data)
    alerts = detect_windows_service(df)

    print("Input rows:", len(df))
    print("Generated alerts:", len(alerts))

    for alert in alerts:
        print(alert)

    assert len(alerts) == 3, f"Expected 3 alerts, got {len(alerts)}"
    assert all(a["technique_id"] == "T1543.003" for a in alerts)
    assert all(a["rule_id"] == "CT-006" for a in alerts)

    print("\nPASS: Windows service detection successful.")

    missing_columns_df = pd.DataFrame([
        {"Computer": "HOST-01", "EventID": 7045}
    ])

    assert detect_windows_service(missing_columns_df) == []
    print("PASS: Missing-column validation successful.")


if __name__ == "__main__":
    main()
