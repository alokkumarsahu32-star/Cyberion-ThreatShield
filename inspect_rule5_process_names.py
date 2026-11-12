import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

events = df[df["EventID"].astype(str).str.strip() == "4688"].copy()

print("PROCESS NAME FREQUENCY:")
print(events["NewProcessName"].value_counts(dropna=False).to_string())

print("\nALL 35 PROCESS CREATION EVENTS:")
columns = [
    "SystemTime",
    "Computer",
    "NewProcessName",
    "NewProcessId",
    "ProcessId",
    "SubjectUserName",
    "SubjectDomainName",
    "EVTX_FileName",
    "EVTX_Tactic"
]

columns = [c for c in columns if c in events.columns]
print(events[columns].fillna("<EMPTY>").to_string(index=False))

print("\nUNIQUE PROCESS NAME COUNT:")
print(events["NewProcessName"].nunique())
