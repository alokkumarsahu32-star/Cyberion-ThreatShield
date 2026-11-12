import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"

df = pd.read_csv(path, low_memory=False)

file_name = "babyshark_mimikatz_powershell.evtx"

data = df[
    (df["EVTX_FileName"] == file_name)
    & (df["EventID"].astype(str).isin(["7", "10"]))
].copy()

data["SystemTime"] = pd.to_datetime(data["SystemTime"])

dll_names = [
    "cryptdll.dll",
    "samlib.dll",
    "hid.dll",
    "winscard.dll",
    "vaultcli.dll"
]

for _, access in data[data["EventID"].astype(str) == "10"].iterrows():

    process_guid = access["SourceProcessGUID"]
    access_time = access["SystemTime"]

    related = data[
        (data["EventID"].astype(str) == "7")
        & (data["ProcessGuid"] == process_guid)
        & (data["SystemTime"] <= access_time)
        & (data["SystemTime"] >= access_time - pd.Timedelta(seconds=30))
    ].copy()

    related["ImageLoaded"] = related["ImageLoaded"].fillna("").astype(str)

    related = related[
        related["ImageLoaded"].str.lower().apply(
            lambda x: any(name in x.lower() for name in dll_names)
        )
    ]

    print("\nLSASS ACCESS:", access_time)
    print("Process GUID:", process_guid)
    print("Matching DLL events:", len(related))

    for _, event in related.iterrows():
        difference = (access_time - event["SystemTime"]).total_seconds()
        print(event["ImageLoaded"], "|", difference, "seconds before LSASS access")