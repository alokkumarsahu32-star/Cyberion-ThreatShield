import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"
df = pd.read_csv(path, low_memory=False)

events = df[df["EventID"].astype(str).str.strip() == "11"].copy()

print("TOTAL DATASET RECORDS:", len(df))
print("EVENT ID 11 RECORDS:", len(events))

print("\nSOURCE FILE DISTRIBUTION:")
print(events["EVTX_FileName"].value_counts().to_string())

print("\nTACTIC LABEL DISTRIBUTION:")
print(events["EVTX_Tactic"].value_counts(dropna=False).to_string())

print("\nFIELD AVAILABILITY:")
for col in events.columns:
    values = events[col].dropna()
    values = values[values.astype(str).str.strip() != ""]
    if len(values):
        print(f"{col}: {len(values)}/{len(events)}")

print("\nFIRST 20 FILE CREATION EVENTS:")
columns = [
    "SystemTime", "Computer", "Image", "TargetFilename",
    "ProcessGuid", "ProcessId", "User",
    "EVTX_FileName", "EVTX_Tactic"
]
columns = [c for c in columns if c in events.columns]
print(events[columns].head(20).fillna("<EMPTY>").to_string(index=False))
