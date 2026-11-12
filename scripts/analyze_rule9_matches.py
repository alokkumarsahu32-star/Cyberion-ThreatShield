import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"

df = pd.read_csv(path, low_memory=False)

events = df[df["EventID"].astype(str).str.strip() == "11"].copy()

matches = events[
    events["TargetFilename"].fillna("").astype(str).str.lower().str.endswith(".dmp")
].copy()

print("=" * 70)
print("RULE 9 - LSASS DUMP FILE CREATION")
print("FALSE POSITIVE AND EVIDENCE ANALYSIS")
print("=" * 70)

print("\n1. MATCH COUNT:", len(matches))

print("\n2. PROCESS DISTRIBUTION:")
print(matches["Image"].value_counts().to_string())

print("\n3. TACTIC DISTRIBUTION:")
print(matches["EVTX_Tactic"].value_counts(dropna=False).to_string())

print("\n4. FILE CREATION EVIDENCE:")

columns = [
    "SystemTime", "Computer", "Image",
    "TargetFilename", "EVTX_FileName", "EVTX_Tactic"
]

columns = [c for c in columns if c in matches.columns]

print(matches[columns].drop_duplicates().to_string(index=False))

print("\n5. POTENTIAL FALSE POSITIVE REVIEW:")

for _, row in matches.iterrows():
    print("\nFile:", row.get("TargetFilename"))
    print("Process:", row.get("Image"))
    print("Scenario:", row.get("EVTX_FileName"))
    print("Assessment: Requires contextual investigation")

print("\n6. ANALYSIS LIMITATION:")
print(
    "A .dmp extension alone does not prove that the file "
    "contains LSASS memory. Legitimate crash dumps and "
    "authorized troubleshooting may also match."
)
