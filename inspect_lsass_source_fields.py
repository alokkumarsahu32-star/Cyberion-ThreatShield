import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

df["EventID_num"] = pd.to_numeric(df["EventID"], errors="coerce")

events = df[
    (df["EventID_num"] == 10)
    & df["TargetImage"].fillna("").str.lower().str.endswith("\\lsass.exe")
]

print("LSASS Event ID 10 records:", len(events))

columns = [
    "EVTX_FileName",
    "SystemTime",
    "Image",
    "SourceImage",
    "TargetImage",
    "ProcessGuid",
    "SourceProcessGUID",
    "SourceProcessId",
    "GrantedAccess"
]

available = [c for c in columns if c in events.columns]

print(events[available].to_string(index=False))
