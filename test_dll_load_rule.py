import pandas as pd

df = pd.read_csv("datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv", low_memory=False)

event_id = pd.to_numeric(df["EventID"], errors="coerce")
image = df["Image"].fillna("").astype(str).str.lower()
image_loaded = df["ImageLoaded"].fillna("").astype(str).str.lower()

dlls = (
    "\\cryptdll.dll",
    "\\samlib.dll",
    "\\hid.dll",
    "\\winscard.dll"
)

mask = (
    (event_id == 7)
    & image.str.endswith("\\powershell.exe")
    & image_loaded.str.endswith(dlls)
)

hits = df.loc[mask].copy()

print("Total dataset records:", len(df))
print("Event ID 7 records:", int((event_id == 7).sum()))
print("PowerShell DLL-load matches:", len(hits))

if not hits.empty:
    print("\nMatched scenarios:")
    print(hits["EVTX_FileName"].value_counts().to_string())

    print("\nMatched DLLs:")
    print(hits["ImageLoaded"].value_counts().to_string())

    print("\nProcess GUIDs:")
    print(hits["ProcessGuid"].dropna().drop_duplicates().to_string(index=False))
