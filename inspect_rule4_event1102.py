import pandas as pd

df = pd.read_csv(
    "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv",
    low_memory=False
)

events = df[df["EventID"].astype(str).str.strip() == "1102"].copy()

interesting = [
    "SystemTime",
    "Computer",
    "Channel",
    "ProviderName",
    "EVTX_FileName",
    "EVTX_Tactic",
]

interesting += [
    col for col in events.columns
    if any(x in col for x in [
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "SubjectUserSid",
    ])
]

interesting = list(dict.fromkeys(
    col for col in interesting if col in events.columns
))

print("EVENT ID 1102 - ALL 21 RECORDS")
print(events[interesting].fillna("<EMPTY>").to_string(index=False))

print("\nUNIQUE SOURCE FILES")
print(events["EVTX_FileName"].value_counts().to_string())

print("\nTACTIC DISTRIBUTION")
print(events["EVTX_Tactic"].value_counts().to_string())
