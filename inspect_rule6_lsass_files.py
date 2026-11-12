import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

events = df[df["EventID"].astype(str).str.strip() == "11"].copy()

keywords = [
    "lsass", "mimi", "dumpert", "andrew",
    "procdump", "minidump", "notepad.bin"
]

mask = (
    events["TargetFilename"].fillna("").str.lower().apply(
        lambda path: any(word in path for word in keywords)
    )
)

matches = events[mask].copy()

columns = [
    "SystemTime", "Computer", "Image", "ProcessId",
    "ProcessGuid", "TargetFilename", "CreationUtcTime",
    "EVTX_FileName", "EVTX_Tactic"
]

columns = [c for c in columns if c in matches.columns]

print("TOTAL CANDIDATE FILE CREATION EVENTS:", len(matches))
print("\nALL MATCHING EVENTS:")
print(matches[columns].to_string(index=False))

print("\nSOURCE FILE SUMMARY:")
print(matches["EVTX_FileName"].value_counts().to_string())

print("\nPROCESS SUMMARY:")
print(matches["Image"].value_counts().to_string())
