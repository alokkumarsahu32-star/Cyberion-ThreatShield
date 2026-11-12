import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

scenario = df[df["EVTX_FileName"] == "DE_RDP_Tunnel_5156.evtx"].copy()
network = scenario[scenario["EventID"].astype(str) == "5156"].copy()

network["DestPort_num"] = pd.to_numeric(network["DestPort"], errors="coerce")

rdp = network[network["DestPort_num"] == 3389]

print("ALL EVENT 5156 CONNECTIONS TO DESTINATION PORT 3389:")
cols = [
    "SystemTime", "Application", "ProcessID",
    "SourceAddress", "SourcePort", "DestAddress",
    "DestPort", "Protocol"
]
cols = [c for c in cols if c in rdp.columns]
print(rdp[cols].to_string(index=False))

print("\nSUMMARY BY APPLICATION:")
print(rdp["Application"].value_counts(dropna=False).to_string())

print("\nTOTAL 5156 EVENTS:", len(network))
print("PORT 3389 EVENTS:", len(rdp))
