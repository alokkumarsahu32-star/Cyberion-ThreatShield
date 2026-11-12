from pathlib import Path

import yaml


RULES_DIR = Path(__file__).resolve().parents[2] / "detection_rules"


def load_detection_rules():
    rules = []
    errors = []

    if not RULES_DIR.exists():
        return {
            "rules": [],
            "errors": ["Detection rules directory not found."],
            "total": 0,
            "individual_count": 0,
            "correlation_count": 0,
        }

    for file_path in sorted(RULES_DIR.glob("*.yml")):
        try:
            raw_content = file_path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw_content)

            if not isinstance(data, dict):
                raise ValueError("YAML content must be a valid mapping.")

            is_correlation = isinstance(data.get("correlation"), dict)

            rule = {
                "filename": file_path.name,
                "title": str(data.get("title", file_path.stem)),
                "id": str(data.get("id", "")),
                "name": str(data.get("name", "")),
                "status": str(data.get("status", "unknown")),
                "level": str(data.get("level", "unknown")).lower(),
                "description": str(data.get("description", "")),
                "tags": data.get("tags", []),
                "references": data.get("references", []),
                "logsource": data.get("logsource", {}),
                "detection": data.get("detection", {}),
                "falsepositives": data.get("falsepositives", []),
                "correlation": data.get("correlation", {}),
                "rule_type": "correlation" if is_correlation else "individual",
                "raw_yaml": raw_content,
            }

            if not isinstance(rule["tags"], list):
                rule["tags"] = []

            if not isinstance(rule["references"], list):
                rule["references"] = []

            if not isinstance(rule["falsepositives"], list):
                rule["falsepositives"] = []

            if not isinstance(rule["logsource"], dict):
                rule["logsource"] = {}

            if not isinstance(rule["detection"], dict):
                rule["detection"] = {}

            if not isinstance(rule["correlation"], dict):
                rule["correlation"] = {}

            rules.append(rule)

        except Exception as exc:
            errors.append(f"{file_path.name}: {exc}")

    individual_count = sum(
        1 for rule in rules if rule["rule_type"] == "individual"
    )

    correlation_count = sum(
        1 for rule in rules if rule["rule_type"] == "correlation"
    )

    return {
        "rules": rules,
        "errors": errors,
        "total": len(rules),
        "individual_count": individual_count,
        "correlation_count": correlation_count,
    }
