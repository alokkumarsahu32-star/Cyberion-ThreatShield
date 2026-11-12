import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

source = "DE_RDP_Tunnel_5156.evtx"
scenario = df[df["EVTX_FileName"] == source].copy()

# Windows Filtering Platform network events
network = scenario[
    scenario["EventID"].astype(str).isin(["5156", "5158"])
].copy()

# Plink process ID: decimal 3324 = hexadecimal 0x00000cfc
plink = network[
    pd.to_numeric(network["ProcessID"], errors="coerce") == 3324
]

print("ALL PLINK NETWORK EVENTS (PID 3324):")
cols = [
    "SystemTime", "EventID", "Application", "ProcessID",
    "Direction", "SourceAddress", "SourcePort",
    "DestAddress", "DestPort", "Protocol"
]
cols = [c for c in cols if c in plink.columns]
print(plink[cols].sort_values("SystemTime").to_string(index=False))

print("\nALL EVENT 5158 RECORDS:")
binds = scenario[scenario["EventID"].astype(str) == "5158"]
bind_cols = [
    "SystemTime", "Application", "ProcessID",
    "SourceAddress", "SourcePort", "DestAddress",
    "DestPort", "Protocol"
]
bind_cols = [c for c in bind_cols if c in binds.columns]
print(binds[bind_cols].to_string(index=False))

print("\nPLINK PROCESS EVENT TIME:")
process = scenario[
    (scenario["EventID"].astype(str) == "4688") &
    (scenario["NewProcessName"].astype(str).str.lower().str.endswith("\\plink.exe"))
]
print(process[["SystemTime", "NewProcessName", "NewProcessId", "ProcessId"]].to_string(index=False))
