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

a = access[
    ["EVTX_FileName", "ProcessGuid", "SourceImage", "SystemTime"]
].rename(columns={
    "SourceImage": "Process",
    "SystemTime": "AccessTime"
})

f = files[
    ["EVTX_FileName", "ProcessGuid", "TargetFilename", "SystemTime"]
].rename(columns={
    "TargetFilename": "DumpFile",
    "SystemTime": "FileTime"
})

matches = a.merge(f, on=["EVTX_FileName", "ProcessGuid"])
matches["TimeDifferenceSeconds"] = (
    matches["FileTime"] - matches["AccessTime"]
).dt.total_seconds()

matches["AbsoluteTimeDifference"] = (
    matches["TimeDifferenceSeconds"].abs()
)

valid = matches[matches["AbsoluteTimeDifference"] <= 60].copy()

print("ALL SAME-PROCESS EVENT PAIRS:", len(matches))
print("PAIRS WITHIN 60 SECONDS:", len(valid))
print("UNIQUE PROCESS GUIDS WITHIN 60 SECONDS:",
      valid["ProcessGuid"].nunique())

print("\nVALIDATED CORRELATIONS:")
print(
    valid[
        [
            "Process",
            "DumpFile",
            "AccessTime",
            "FileTime",
            "TimeDifferenceSeconds"
        ]
    ].to_string(index=False)
)
