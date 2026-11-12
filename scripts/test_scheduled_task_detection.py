
import re
import pandas as pd


def clean(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def detect_scheduled_tasks(df):
    required = {
        "Computer",
        "EventID",
        "SubjectUserName",
        "TaskName",
        "TaskContent",
    }

    if not required.issubset(df.columns):
        return []

    events = df[
        df["EventID"].astype(str).str.strip() == "4698"
    ]

    alerts = []
    seen = set()

    for _, row in events.iterrows():
        host = clean(row["Computer"])
        task_name = clean(row["TaskName"])
        creator = clean(row["SubjectUserName"])
        xml = clean(row["TaskContent"])

        hidden_match = re.search(
            r"<Hidden>\s*(true|false)\s*</Hidden>",
            xml,
            re.I,
        )
        hidden = (
            hidden_match.group(1).lower() == "true"
            if hidden_match else False
        )

        command_match = re.search(
            r"<Command>(.*?)</Command>",
            xml,
            re.I | re.S,
        )
        command = (
            command_match.group(1).strip()
            if command_match else ""
        )

        suspicious_path = bool(
            re.search(
                r"\\Users\\Public\\Tools\\",
                command,
                re.I,
            )
        )

        if not hidden and not suspicious_path:
            continue

        key = (host.lower(), task_name.lower())

        if key in seen:
            continue

        seen.add(key)

        alerts.append({
            "rule_id": "CT-005",
            "technique_id": "T1053.005",
            "severity": "High",
            "title": "Suspicious Scheduled Task",
            "computer": host,
            "task_name": task_name,
            "creator": creator,
            "hidden": hidden,
            "command": command,
        })

    return alerts


if __name__ == "__main__":
    path = "tests/sample_data/scheduled_task_test_logs.csv"
    df = pd.read_csv(path)

    results = detect_scheduled_tasks(df)

    print("SCHEDULED TASK DETECTION TEST")
    print("=" * 60)
    print("Input rows:", len(df))
    print("Unique alerts:", len(results))

    for alert in results:
        print(alert)

    assert len(results) == 2, (
        f"Expected 2 unique alerts, got {len(results)}"
    )

    assert all(
        alert["technique_id"] == "T1053.005"
        for alert in results
    )

    print("\nPASS: Scheduled task detection successful.")
