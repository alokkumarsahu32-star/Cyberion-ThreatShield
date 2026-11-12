import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

# Normalize fields for comparison
event_id = df["EventID"].astype(str).str.strip()
application = df["Application"].fillna("").astype(str).str.lower().str.replace("/", "\\", regex=False)
dest_port = pd.to_numeric(df["DestPort"], errors="coerce")
dest_address = df["DestAddress"].fillna("").astype(str)

# Rule conditions
mask = (
    (event_id == "5156") &
    application.str.endswith("\\plink.exe") &
    (dest_port == 3389) &
    dest_address.str.startswith("127.")
)

matches = df[mask].copy()

print("TOTAL DATASET RECORDS:", len(df))
print("TOTAL EVENT ID 5156:", (event_id == "5156").sum())
print("RULE MATCHES:", len(matches))

columns = [
    "SystemTime", "Computer", "Application", "ProcessID",
    "SourceAddress", "SourcePort", "DestAddress",
    "DestPort", "Protocol", "EVTX_FileName", "EVTX_Tactic"
]
columns = [c for c in columns if c in matches.columns]

print("\nMATCHED RECORDS:")
print(matches[columns].to_string(index=False))

print("\nMATCHES BY SOURCE FILE:")
print(matches["EVTX_FileName"].value_counts().to_string())

print("\nMATCHES BY TACTIC LABEL:")
print(matches["EVTX_Tactic"].value_counts(dropna=False).to_string())
