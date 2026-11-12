import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"
df = pd.read_csv(path, low_memory=False)

source = "DE_RDP_Tunnel_5156.evtx"
scenario = df[df["EVTX_FileName"] == source].copy()

print("SCENARIO:", source)
print("Total records:", len(scenario))
print("\nEVENT ID DISTRIBUTION:")
print(scenario["EventID"].value_counts().to_string())

print("\nPLINK PROCESS EVENT:")
plink = scenario[
    (scenario["EventID"].astype(str) == "4688") &
    (scenario["NewProcessName"].astype(str).str.lower().str.endswith("\\plink.exe"))
]

cols = [
    "SystemTime", "Computer", "EventID", "NewProcessName",
    "NewProcessId", "ProcessId", "SubjectUserName",
    "SubjectDomainName", "EVTX_Tactic"
]
cols = [c for c in cols if c in plink.columns]
print(plink[cols].to_string(index=False))

print("\nNETWORK EVENT FIELD AVAILABILITY:")
network = scenario[scenario["EventID"].astype(str) == "5156"]

for col in network.columns:
    values = network[col].dropna()
    values = values[values.astype(str).str.strip() != ""]
    if len(values):
        print(f"{col}: {len(values)}/{len(network)}")

print("\nNETWORK EVENT SAMPLES:")
network_cols = [
    "SystemTime", "Computer", "Application", "ProcessID",
    "Direction", "SourceAddress", "SourcePort",
    "DestAddress", "DestPort", "Protocol"
]
network_cols = [c for c in network_cols if c in network.columns]
print(network[network_cols].head(20).to_string(index=False))
