import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"
df = pd.read_csv(path, low_memory=False)

d = df[df["EventID"].astype(str).eq("10")].copy()

lsass = d[
    d["TargetImage"].astype(str).str.contains(
        r"\\lsass\.exe$", case=False, na=False
    )
].copy()

print("Total LSASS Event ID 10:", len(lsass))
print("\nRuleName distribution:")
print(lsass["RuleName"].value_counts(dropna=False).to_string())

print("\nSourceImage distribution:")
print(lsass["SourceImage"].value_counts(dropna=False).to_string())

print("\nT1003 tagged records:")
tagged = lsass[
    lsass["RuleName"].astype(str).str.contains("T1003", case=False, na=False)
]
print(tagged[
    ["SystemTime", "EVTX_FileName", "SourceImage", "TargetImage", "RuleName"]
].to_string(index=False))

print("\nPowerShell LSASS records:")
powershell = lsass[
    lsass["SourceImage"].astype(str).str.contains(
        "powershell.exe", case=False, na=False
    )
]
print(powershell[
    ["SystemTime", "EVTX_FileName", "SourceImage", "GrantedAccess", "RuleName"]
].to_string(index=False))