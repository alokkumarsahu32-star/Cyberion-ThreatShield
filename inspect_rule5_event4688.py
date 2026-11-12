import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"
df = pd.read_csv(path, low_memory=False)

events = df[df["EventID"].astype(str).str.strip() == "4688"].copy()

print("RULE 5: WINDOWS PROCESS CREATION")
print("Total dataset records:", len(df))
print("Event ID 4688 records:", len(events))

if events.empty:
    print("No Event ID 4688 records found.")
    raise SystemExit

print("\nSOURCE FILE DISTRIBUTION:")
print(events["EVTX_FileName"].value_counts().to_string())

print("\nTACTIC LABEL DISTRIBUTION:")
print(events["EVTX_Tactic"].value_counts().to_string())

def get_field(row, field):
    candidates = [
        field,
        f"{{http://schemas.microsoft.com/win/2004/08/events/event}}{field}",
        f"{{http://manifests.microsoft.com/win/2004/08/windows/eventlog}}{field}"
    ]
    for col in candidates:
        if col in row.index and pd.notna(row[col]):
            value = str(row[col]).strip()
            if value and value.lower() != "nan":
                return value
    return "<EMPTY>"

fields = [
    "NewProcessName",
    "NewProcessId",
    "ProcessId",
    "CommandLine",
    "ParentProcessName",
    "CreatorProcessName",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
    "TargetUserName",
    "TargetDomainName"
]

print("\nFIELD AVAILABILITY:")
for field in fields:
    count = sum(get_field(row, field) != "<EMPTY>" for _, row in events.iterrows())
    print(f"{field}: {count}/{len(events)}")

print("\nEVENT SAMPLE DETAILS:")
for _, row in events.head(15).iterrows():
    print("\n" + "-" * 60)
    print("Time:", row.get("SystemTime", "<EMPTY>"))
    print("Computer:", row.get("Computer", "<EMPTY>"))
    print("Source file:", row.get("EVTX_FileName", "<EMPTY>"))
    print("Tactic label:", row.get("EVTX_Tactic", "<EMPTY>"))
    for field in fields:
        print(f"{field}: {get_field(row, field)}")
