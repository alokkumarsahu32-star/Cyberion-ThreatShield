
import io
import re

import pandas as pd


MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ROWS = 20_000


class LogValidationError(Exception):
    pass

def clean_wmi_value(value):
    if pd.isna(value):
        return ""
    return str(value).strip().strip('"')


def extract_wmi_name(value):
    match = re.search(r'Name=\\?"([^"\\]+)', str(value))
    return match.group(1).strip() if match else ""


def detect_wmi_subscription(df):
    required = {
        "Computer", "EventID", "Operation",
        "ProviderName", "Consumer", "Filter"
    }

    if not required.issubset(df.columns):
        return []

    alerts = []

    wmi = df[
        df["EventID"].astype(str).str.strip().isin(["19", "20", "21"])
    ]

    for host, group in wmi.groupby("Computer"):
        filters = set()
        consumers = set()
        bindings = []

        for index, row in group.iterrows():
            event_id = str(row["EventID"]).strip()
            operation = clean_wmi_value(row["Operation"]).lower()

            if operation != "created":
                continue

            if event_id == "19":
                filters.add(clean_wmi_value(row["ProviderName"]))

            elif event_id == "20":
                consumers.add(clean_wmi_value(row["ProviderName"]))

            elif event_id == "21":
                consumer = extract_wmi_name(
                    clean_wmi_value(row["Consumer"])
                )
                filter_name = extract_wmi_name(
                    clean_wmi_value(row["Filter"])
                )

                if consumer and filter_name:
                    bindings.append((consumer, filter_name, index))

        for consumer, filter_name, index in bindings:
            if consumer in consumers and filter_name in filters:
                alerts.append({
                    "rule_id": "CT-004",
                    "technique_id": "T1546.003",
                    "severity": "High",
                    "title": "WMI Permanent Event Subscription",
                    "message": (
                        f"Complete WMI subscription creation chain detected "
                        f"on {host}: consumer '{consumer}' is bound to "
                        f"filter '{filter_name}'."
                    ),
                    "row": str(index + 1),
                })

    return alerts


def detect_scheduled_tasks(df):
    required = {
        "Computer",
        "EventID",
        "TaskName",
        "TaskContent",
    }

    if not required.issubset(df.columns):
        return []

    events = df[
        df["EventID"].astype(str).str.strip() == "4698"
    ]

    alerts = []
    seen = set()

    for index, row in events.iterrows():
        host = str(row["Computer"]).strip()
        task_name = str(row["TaskName"]).strip()
        xml = str(row["TaskContent"]).strip()

        if not host or not task_name or not xml:
            continue

        hidden_match = re.search(
            r"<Hidden>\s*true\s*</Hidden>",
            xml,
            re.I,
        )

        command_match = re.search(
            r"<Command>\s*(.*?)\s*</Command>",
            xml,
            re.I | re.S,
        )

        command = (
            command_match.group(1).strip()
            if command_match else ""
        )

        suspicious_path = bool(
            re.search(
                r"\\Users\\Public\\Tools\\",
                command,
                re.I,
            )
        )

        hidden = hidden_match is not None

        if not hidden and not suspicious_path:
            continue

        key = (host.lower(), task_name.lower())

        if key in seen:
            continue

        seen.add(key)

        alerts.append({
            "rule_id": "CT-005",
            "technique_id": "T1053.005",
            "severity": "High",
            "title": "Suspicious Scheduled Task",
            "message": (
                f"Suspicious scheduled task '{task_name}' "
                f"detected on {host}."
            ),
            "row": str(index + 1),
        })

    return alerts

def detect_scheduled_tasks(df):
    required = {
        "Computer",
        "EventID",
        "TaskName",
        "TaskContent",
    }

    if not required.issubset(df.columns):
        return []

    events = df[
        df["EventID"].astype(str).str.strip() == "4698"
    ]

    alerts = []
    seen = set()

    for index, row in events.iterrows():
        host = str(row["Computer"]).strip()
        task_name = str(row["TaskName"]).strip()
        xml = str(row["TaskContent"]).strip()

        if not host or not task_name or not xml:
            continue

        hidden = re.search(
            r"<Hidden>\s*true\s*</Hidden>",
            xml,
            re.I,
        ) is not None

        command_match = re.search(
            r"<Command>\s*(.*?)\s*</Command>",
            xml,
            re.I | re.S,
        )

        command = command_match.group(1).strip() if command_match else ""

        suspicious_path = bool(
            re.search(r"\\Users\\Public\\Tools\\", command, re.I)
        )

        if not hidden and not suspicious_path:
            continue

        key = (host.lower(), task_name.lower())

        if key in seen:
            continue

        seen.add(key)

        alerts.append({
            "rule_id": "CT-005",
            "technique_id": "T1053.005",
            "severity": "High",
            "title": "Suspicious Scheduled Task",
            "message": (
                f"Suspicious scheduled task '{task_name}' "
                f"detected on {host}."
            ),
            "row": str(index + 1),
        })

    return alerts


def detect_process_injection(df):
    required = {
        "Computer",
        "EventID",
        "SourceImage",
        "TargetImage",
    }

    if not required.issubset(df.columns):
        return []

    events = df[
        df["EventID"].astype(str).str.strip() == "8"
    ]

    alerts = []
    seen = set()

    suspicious_sources = (
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "jjs.exe",
        "procdump.exe",
        "procdump64.exe",
    )

    for index, row in events.iterrows():
        host = str(row["Computer"]).strip()
        source = str(row["SourceImage"]).strip()
        target = str(row["TargetImage"]).strip()

        if (
            not host
            or not source
            or not target
            or source.lower() in ("nan", "none")
            or target.lower() in ("nan", "none")
        ):
            continue

        source_lower = source.lower()
        target_lower = target.lower()

        source_suspicious = any(
            source_lower.endswith(name)
            for name in suspicious_sources
        )

        target_sensitive = any(
            name in target_lower
            for name in (
                "notepad.exe",
                "lsass.exe",
                "winlogon.exe",
                "explorer.exe",
                "svchost.exe",
                "keePass.exe".lower(),
            )
        )

        source_external = (
            source_lower.startswith("\\\\")
            or "\\users\\public\\" in source_lower
            or "\\temp\\" in source_lower
        )

        if not (
            source_suspicious
            or (source_external and target_sensitive)
        ):
            continue

        key = (
            host.lower(),
            source_lower,
            target_lower,
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append({
            "rule_id": "CT-007",
            "technique_id": "T1055",
            "severity": "High",
            "title": "Suspicious Process Injection Activity",
            "message": (
                f"Suspicious remote thread creation from "
                f"'{source}' into '{target}' detected on {host}."
            ),
            "row": str(index + 1),
        })

    return alerts


def detect_windows_service(df):
    required = {
        "Computer",
        "EventID",
        "ServiceName",
        "ImagePath",
    }

    if not required.issubset(df.columns):
        return []

    events = df[
        df["EventID"].astype(str).str.strip() == "7045"
    ]

    alerts = []
    seen = set()

    for index, row in events.iterrows():
        host = str(row["Computer"]).strip()
        service_name = str(row["ServiceName"]).strip()
        image_path = str(row["ImagePath"]).strip()

        if not host or not service_name or not image_path:
            continue

        suspicious_command = bool(
            re.search(
                r"\b(cmd\.exe|powershell(?:\.exe)?|pwsh\.exe|"
                r"wscript\.exe|cscript\.exe|mshta\.exe)\b",
                image_path,
                re.I,
            )
        )

        suspicious_binary = bool(
    re.search(
        r"\b(calc|notepad)\.exe\b",
        image_path,
        re.I,
    )
)

        suspicious_pipe = "\\\\.\\pipe\\" in image_path.lower()

        if not (
            suspicious_command
            or suspicious_binary
            or suspicious_pipe
        ):
            continue

        key = (host.lower(), service_name.lower())

        if key in seen:
            continue

        seen.add(key)

        alerts.append({
            "rule_id": "CT-006",
            "technique_id": "T1543.003",
            "severity": "High",
            "title": "Suspicious Windows Service Installation",
            "message": (
                f"Suspicious service '{service_name}' "
                f"registered on {host} with image path: {image_path}"
            ),
            "row": str(index + 1),
        })

    return alerts

def analyze_csv(content: bytes, filename: str) -> dict:
    # 1. Validate the uploaded file
    if not filename.lower().endswith(".csv"):
        raise LogValidationError("Please upload a .csv file.")

    if not content:
        raise LogValidationError("The uploaded file is empty.")

    if len(content) > MAX_FILE_BYTES:
        raise LogValidationError("File size must be 5 MB or less.")

    try:
        df = pd.read_csv(
            io.BytesIO(content),
            encoding="utf-8-sig",
            on_bad_lines="error",
            nrows=MAX_ROWS + 1,
        )
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError):
        raise LogValidationError(
            "Could not read this CSV. Check its encoding and column format."
        ) from None

    if len(df) > MAX_ROWS:
        raise LogValidationError(
            f"CSV may contain no more than {MAX_ROWS} rows."
        )

    if len(df.columns) == 0:
        raise LogValidationError("The CSV must contain column headers.")

    if len(df.columns) > 100:
        raise LogValidationError("The CSV may contain at most 100 columns.")

    if len(df) == 0:
        raise LogValidationError("The CSV contains no data rows.")

    df.columns = [str(col).strip() for col in df.columns]

    if any(not col for col in df.columns):
        raise LogValidationError("Column names cannot be blank.")

    if len(set(df.columns)) != len(df.columns):
        raise LogValidationError(
            "Duplicate column names found. Please make them unique."
        )

    df = df.fillna("")

    # 2. Prepare text for rule-based detection
    alerts = []
    row_texts = []

    for _, row in df.iterrows():
        row_texts.append(
            " ".join(str(value) for value in row.values).lower()
        )
    # 2A. Rule CT-004: WMI permanent event subscription
    alerts.extend(detect_wmi_subscription(df))

    # 2B. Rule CT-005: Suspicious Scheduled Task
    alerts.extend(detect_scheduled_tasks(df))
    # 2C. Rule CT-006: Suspicious Windows Service Installation
    alerts.extend(detect_windows_service(df))
    # 2D. Rule CT-007: Suspicious Process Injection Activity
    alerts.extend(detect_process_injection(df))
    
    # 3. Rule CT-001: repeated failed login attempts
    username_column = next(
        (col for col in df.columns if col.lower().strip() in
         ("username", "user", "user_name", "account")),
        None,
    )

    failed_login_rows = {}

    for index, text in enumerate(row_texts):
        failed_login = (
            re.search(
                r"failed login|login failed|authentication failure|"
                r"invalid password|failed authentication",
                text,
            )
            is not None
        )

        if failed_login:
            username = (
                str(df.iloc[index][username_column]).strip()
                if username_column
                else "unknown"
            )
            username = username or "unknown"
            failed_login_rows.setdefault(username, []).append(index + 1)

    for username, row_numbers in failed_login_rows.items():
        if len(row_numbers) >= 3:
            alerts.append({
                "rule_id": "CT-001",
                "severity": "High",
                "title": "Repeated Failed Login Attempts",
                "message": (
                    f"{len(row_numbers)} failed login attempts detected "
                    f"for user '{username}'."
                ),
                "row": ", ".join(map(str, row_numbers)),
            })

    # 4. Rule CT-002: suspicious encoded PowerShell
    for index, text in enumerate(row_texts):
        has_powershell = "powershell" in text or "pwsh" in text
        has_encoded_flag = re.search(
            r"-(?:enc|encodedcommand)\b|encodedcommand",
            text,
        ) is not None

        if has_powershell and has_encoded_flag:
            alerts.append({
                "rule_id": "CT-002",
                "severity": "High",
                "title": "Encoded PowerShell Command",
                "message": (
                    "A PowerShell command with an encoded-command flag "
                    "was found."
                ),
                "row": str(index + 1),
            })

    # 5. Rule CT-003: suspicious outbound connection
    for index, text in enumerate(row_texts):
        suspicious_outbound = (
            "outbound" in text
            and any(word in text for word in (
                "unusual", "suspicious", "unknown", "unauthorized"
            ))
        )

        if suspicious_outbound:
            alerts.append({
                "rule_id": "CT-003",
                "severity": "Medium",
                "title": "Suspicious Outbound Connection",
                "message": (
                    "An outbound connection contains suspicious "
                    "or unusual indicators."
                ),
                "row": str(index + 1),
            })

    # 6. Generate preview and analysis summary
    preview = df.head(10).astype(str).to_dict(orient="records")

    return {
        "filename": filename,
        "total_rows": len(df),
        "column_count": len(df.columns),
        "columns": list(df.columns),
        "rows": preview,
        "alerts": alerts,
        "alert_count": len(alerts),
        "status": (
            "Rule-based detection completed."
            if alerts
            else "Analysis completed; no configured rules were triggered."
        ),
    }
