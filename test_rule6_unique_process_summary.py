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

summary = access.groupby(
    ["EVTX_FileName", "ProcessGuid"]
).agg(
    process_image=("SourceImage", "first"),
    access_events=("SystemTime", "count"),
    first_access=("SystemTime", "min"),
    last_access=("SystemTime", "max")
).reset_index()

file_summary = files.groupby(
    ["EVTX_FileName", "ProcessGuid"]
).agg(
    dump_file=("TargetFilename", "first"),
    file_events=("SystemTime", "count"),
    first_file=("SystemTime", "min")
).reset_index()

result = summary.merge(
    file_summary,
    on=["EVTX_FileName", "ProcessGuid"],
    how="inner"
)

result["SecondsFromLastAccessToFile"] = (
    result["first_file"] - result["last_access"]
).dt.total_seconds()

print("UNIQUE PROCESS-LEVEL CORRELATIONS:", len(result))
print(result.to_string(index=False))

print("\nSTRICTLY AFTER LAST ACCESS:")
print(
    result[result["SecondsFromLastAccessToFile"] > 0]
    .to_string(index=False)
)

print("\nEQUAL OR AFTER LAST ACCESS:")
print(
    result[result["SecondsFromLastAccessToFile"] >= 0]
    .to_string(index=False)
)
