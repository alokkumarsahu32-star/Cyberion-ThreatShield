from pathlib import Path
import re
import pandas as pd

DATASET = Path("datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv")


def clean(value):
    if pd.isna(value):
        return ""
    return str(value).strip().strip('"')


def extract_name(value):
    match = re.search(r'Name=\\?"([^"\\]+)', str(value))
    return match.group(1).strip() if match else ""


def detect_wmi_subscription(df):
    required = {
        "Computer", "EventID", "Operation",
        "ProviderName", "Consumer", "Filter"
    }

    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    alerts = []

    wmi = df[
        df["EventID"].astype(str).str.strip().isin(["19", "20", "21"])
    ].copy()

    for host, group in wmi.groupby("Computer"):
        filters = set()
        consumers = set()
        bindings = []

        for _, row in group.iterrows():
            event_id = str(row["EventID"]).strip()
            operation = clean(row["Operation"]).lower()

            if operation != "created":
                continue

            if event_id == "19":
                filters.add(clean(row["ProviderName"]))

            elif event_id == "20":
                consumers.add(clean(row["ProviderName"]))

            elif event_id == "21":
                consumer = extract_name(clean(row["Consumer"]))
                filter_name = extract_name(clean(row["Filter"]))

                if consumer and filter_name:
                    bindings.append((consumer, filter_name))

        for consumer, filter_name in bindings:
            if consumer in consumers and filter_name in filters:
                alerts.append({
                    "rule_id": "CT-004",
                    "technique_id": "T1546.003",
                    "severity": "High",
                    "title": "WMI Permanent Event Subscription",
                    "computer": host,
                    "consumer": consumer,
                    "filter": filter_name,
                    "message": (
                        f"Complete WMI subscription creation chain detected "
                        f"on {host}: consumer '{consumer}' is bound to "
                        f"filter '{filter_name}'."
                    )
                })

    return alerts


def main():
    df = pd.read_csv(DATASET, low_memory=False)
    alerts = detect_wmi_subscription(df)

    print("WMI DETECTION TEST")
    print("=" * 60)
    print("Alerts:", len(alerts))

    for alert in alerts:
        print(alert)

    assert len(alerts) == 1, (
        f"Expected 1 complete-chain alert, got {len(alerts)}"
    )

    assert alerts[0]["computer"] == "IEWIN7"
    assert alerts[0]["consumer"] == "BotConsumer23"
    assert alerts[0]["filter"] == "BotFilter82"
    assert alerts[0]["technique_id"] == "T1546.003"

    print("\nPASS: Complete WMI subscription chain detected correctly.")


if __name__ == "__main__":
    main()
