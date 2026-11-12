import pandas as pd

path = "datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv"
df = pd.read_csv(path, low_memory=False)

events = df[df["EventID"].astype(str).str.strip() == "1102"].copy()

# Extract the actual XML namespace fields populated in this dataset.
def get_field(row, field):
    candidates = [
        field,
        f"{{http://manifests.microsoft.com/win/2004/08/windows/eventlog}}{field}"
    ]
    for col in candidates:
        if col in row.index and pd.notna(row[col]):
            value = str(row[col]).strip()
            if value and value.lower() != "nan":
                return value
    return "<EMPTY>"

print("RULE 4: WINDOWS SECURITY AUDIT LOG CLEARED")
print("Total dataset records:", len(df))
print("Event ID 1102 records:", len(events))
print("Rule matches:", len(events))
print("Match condition: EventID == 1102")

print("\nSOURCE FILES:")
print(events["EVTX_FileName"].value_counts().to_string())

print("\nTACTIC LABEL DISTRIBUTION:")
print(events["EVTX_Tactic"].value_counts().to_string())

print("\nMATCHED EVENT DETAILS:")
for _, row in events.iterrows():
    print(
        f"Time={row.get('SystemTime', '<EMPTY>')} | "
        f"Computer={row.get('Computer', '<EMPTY>')} | "
        f"User={get_field(row, 'SubjectUserName')} | "
        f"Domain={get_field(row, 'SubjectDomainName')} | "
        f"LogonID={get_field(row, 'SubjectLogonId')} | "
        f"Source={row.get('EVTX_FileName', '<EMPTY>')} | "
        f"TacticLabel={row.get('EVTX_Tactic', '<EMPTY>')}"
    )

print("\nRESULT:")
if len(events) == 21:
    print("PASS: All 21 observed Event ID 1102 records match the rule condition.")
else:
    print("REVIEW: Match count differs from the earlier 21-record inspection.")

print("NOTE: Matches are detection events, not 21 independently confirmed attacks.")
