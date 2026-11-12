import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

sources = [
    "CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx",
    "ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx",
    "sysmon_10_11_lsass_memdump.evtx",
    "sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx",
    "sysmon_10_1_memdump_comsvcs_minidump.evtx",
    "sysmon_rdrleakdiag_lsass_dump.evtx"
]

subset = df[df["EVTX_FileName"].isin(sources)].copy()

print("EVENT DISTRIBUTION IN SIX SOURCE FILES:")
print(subset.groupby(["EVTX_FileName", "EventID"]).size().to_string())

access = subset[subset["EventID"].astype(str).str.strip() == "10"].copy()

print("\nTOTAL EVENT ID 10 RECORDS:", len(access))

print("\nEVENT ID 10 FIELD AVAILABILITY:")
for col in access.columns:
    values = access[col].dropna()
    values = values[values.astype(str).str.strip() != ""]
    if len(values):
        print(f"{col}: {len(values)}/{len(access)}")

print("\nALL EVENT ID 10 RECORDS:")
columns = [
    "SystemTime", "Computer", "SourceImage", "TargetImage",
    "SourceProcessGUID", "SourceProcessId", "TargetProcessGUID",
    "TargetProcessId", "GrantedAccess", "CallTrace",
    "EVTX_FileName", "EVTX_Tactic"
]
columns = [c for c in columns if c in access.columns]

print(access[columns].fillna("<EMPTY>").to_string(index=False))
