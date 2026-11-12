import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

sources = [
    "sysmon_10_11_lsass_memdump.evtx",
    "sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx",
    "ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx"
]

data = df[df["EVTX_FileName"].isin(sources)].copy()
data["EventID"] = data["EventID"].astype(str).str.strip()
data["SystemTime"] = pd.to_datetime(data["SystemTime"], errors="coerce")

access = data[
    (data["EventID"] == "10") &
    (data["TargetImage"].fillna("").str.lower().str.endswith("\\lsass.exe"))
].copy()

files = data[
    (data["EventID"] == "11") &
    (data["TargetFilename"].fillna("").str.lower().str.endswith(".dmp"))
].copy()

access["ProcessGuid"] = access["SourceProcessGUID"].astype(str).str.lower()
files["ProcessGuid"] = files["ProcessGuid"].astype(str).str.lower()

joined = access.merge(
    files,
    on=["EVTX_FileName", "ProcessGuid"],
    suffixes=("_access", "_file")
)

joined["SecondsBetween"] = (
    joined["SystemTime_file"] - joined["SystemTime_access"]
).dt.total_seconds()

print("TOTAL MATCHES:", len(joined))
print("UNIQUE PROCESS GUIDS:", joined["ProcessGuid"].nunique())

print("\nMERGED COLUMN NAMES:")
print(joined.columns.tolist())

columns = [
    "EVTX_FileName",
    "Image_access",
    "TargetImage_access",
    "SystemTime_access",
    "SystemTime_file",
    "TargetFilename_file",
    "ProcessGuid",
    "SecondsBetween"
]

print("\nCORRELATED EVENTS:")
print(joined[columns].to_string(index=False))

print("\nUNIQUE PROCESS SUMMARY:")
print(
    joined.groupby(["EVTX_FileName", "ProcessGuid"])
    .agg(
        process_image=("Image_access", "first"),
        access_events=("SystemTime_access", "count"),
        file_events=("TargetFilename_file", "count"),
        first_access=("SystemTime_access", "min"),
        first_file=("SystemTime_file", "min")
    ).to_string()
)

print("\nEVENTS WHERE FILE CREATION OCCURRED AFTER ACCESS:")
after = joined[joined["SecondsBetween"] >= 0]
print(after[columns].to_string(index=False))

print("\nUNIQUE PROCESSES WITH ACCESS BEFORE FILE CREATION:",
      after["ProcessGuid"].nunique())
