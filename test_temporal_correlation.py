import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"
df = pd.read_csv(path, low_memory=False)

df["EventID_num"] = pd.to_numeric(df["EventID"], errors="coerce")
df["EventTime"] = pd.to_datetime(df["SystemTime"], errors="coerce")

image = df["Image"].fillna("").astype(str).str.lower()
loaded = df["ImageLoaded"].fillna("").astype(str).str.lower()
source = df["SourceImage"].fillna("").astype(str).str.lower()
target = df["TargetImage"].fillna("").astype(str).str.lower()

dll_names = ("cryptdll.dll", "samlib.dll", "hid.dll", "winscard.dll")

dll_events = df[
    (df["EventID_num"] == 7)
    & image.str.endswith("\\powershell.exe")
    & loaded.str.endswith(dll_names)
].copy()

lsass_events = df[
    (df["EventID_num"] == 10)
    & source.str.endswith("\\powershell.exe")
    & target.str.endswith("\\lsass.exe")
].copy()

print("PowerShell DLL events:", len(dll_events))
print("PowerShell -> LSASS events:", len(lsass_events))

correlation_count = 0

for _, access in lsass_events.iterrows():
    guid = access["SourceProcessGUID"]
    access_time = access["EventTime"]

    prior = dll_events[
        (dll_events["ProcessGuid"] == guid)
        & (dll_events["EventTime"] < access_time)
        & (dll_events["EventTime"] >= access_time - pd.Timedelta(seconds=30))
    ].copy()

    if not prior.empty:
        correlation_count += 1

    print("\nLSASS access:", access_time)
    print("Process GUID:", guid)
    print("Prior DLL events within 30 seconds:", len(prior))

    if not prior.empty:
        prior["SecondsBeforeAccess"] = (
            access_time - prior["EventTime"]
        ).dt.total_seconds()

        print(prior[
            ["ImageLoaded", "SecondsBeforeAccess"]
        ].to_string(index=False))

print("\nTotal correlated LSASS access events:", correlation_count)
