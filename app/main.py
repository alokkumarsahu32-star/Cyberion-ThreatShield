
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.core.database import Base, engine, get_db, SessionLocal
from app.core.security import hash_password, verify_password
from app.models import User
import hmac
import secrets

from fastapi import File, UploadFile
from app.services.log_analyzer import analyze_csv, LogValidationError
from app.services.detection_rules import load_detection_rules

BASE_DIR = Path(__file__).resolve().parent


def initialize_database():
    Base.metadata.create_all(bind=engine)

    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")

    # Do not silently create an account with a hard-coded password.
    if not username or not password:
        print("Admin not seeded: configure ADMIN_USERNAME and ADMIN_PASSWORD.")
        return

    with SessionLocal() as db:
        existing_user = db.scalar(
            select(User).where(User.username == username)
        )

        if existing_user is None:
            db.add(
                User(
                    username=username,
                    password_hash=hash_password(password),
                    is_admin=True,
                    is_active=True,
                )
            )
            db.commit()
            print("Initial admin account created.")
        else:
            print("Configured admin account already exists.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Cyberion ThreatShield",
    description="Detection Engineering and Threat Hunting Platform",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET") or secrets.token_urlsafe(32),
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    max_age=60 * 60 * 8,
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/login")
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None},
    )


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.username == username))

    if (
        user is None
        or not user.is_active
        or not user.is_admin
        or not verify_password(password, user.password_hash)
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid username or password."},
            status_code=401,
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["username"] = user.username

    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/")
async def dashboard(
    request: Request,
    db: Session = Depends(get_db),
):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    user = db.get(User, user_id)

    if user is None or not user.is_active or not user.is_admin:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "project_name": "Cyberion ThreatShield",
            "version": "0.2.0",
            "username": user.username,
        },
    )


def require_admin(request: Request, db: Session):
    user_id = request.session.get("user_id")

    if not user_id:
        return None

    user = db.get(User, user_id)
    if user is None or not user.is_active or not user.is_admin:
        request.session.clear()
        return None

    return user

@app.get("/detection-rules")
async def detection_rules_page(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    result = load_detection_rules()

    return templates.TemplateResponse(
        request=request,
        name="detection_rules.html",
        context={
            "username": user.username,
            "rules": result["rules"],
            "total": result["total"],
            "individual_count": result["individual_count"],
            "correlation_count": result["correlation_count"],
            "errors": result["errors"],
        },
    )

@app.get("/logs")
async def logs_page(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    csrf_token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = csrf_token

    return templates.TemplateResponse(
        request=request,
        name="log_analyzer.html",
        context={
            "error": None,
            "message": None,
            "result": None,
            "csrf_token": csrf_token,
        },
    )



@app.post("/logs/analyze")
async def analyze_logs(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    expected_token = request.session.get("csrf_token", "")

    if not expected_token or not hmac.compare_digest(
        expected_token, csrf_token
    ):
        new_csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = new_csrf_token

        return templates.TemplateResponse(
            request=request,
            name="log_analyzer.html",
            context={
                "error": "Invalid form token. Refresh the page and try again.",
                "message": None,
                "result": None,
                "csrf_token": new_csrf_token,
            },
            status_code=403,
        )

    content = await file.read(5 * 1024 * 1024 + 1)
    filename = file.filename or ""

    try:
        result = analyze_csv(content, filename)

    except LogValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="log_analyzer.html",
            context={
                "error": str(exc),
                "message": None,
                "result": None,
                "csrf_token": expected_token,
            },
            status_code=400,
        )

    finally:
        await file.close()

    return templates.TemplateResponse(
        request=request,
        name="log_analyzer.html",
        context={
            "error": None,
            "message": "CSV validation completed.",
            "result": result,
            "csrf_token": expected_token,
        },
    )


@app.get("/health")
async def health():
    return {"status": "ok", "application": "Cyberion ThreatShield"}


@app.get("/attack-coverage")
async def attack_coverage_page(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    sigma_techniques = [
        {
            "id": "T1021.002",
            "name": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "rule": "WIN-5145",
        },
        {
            "id": "T1572",
            "name": "Protocol Tunneling",
            "tactic": "Command and Control",
            "rule": "WIN-5156",
        },
        {
            "id": "T1070.001",
            "name": "Clear Windows Event Logs",
            "tactic": "Defense Evasion",
            "rule": "WIN-SEC-1102",
        },
        {
            "id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "rule": "WIN-SYSMON-1 Embedded PowerShell; WIN-SYSMON-1 Encoded PowerShell",
        },
        {
            "id": "T1562.001",
            "name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "rule": "WIN-SYSMON-1 Embedded PowerShell",
        },
        {
            "id": "T1027.010",
            "name": "Command Obfuscation",
            "tactic": "Defense Evasion",
            "rule": "WIN-SYSMON-1 Encoded PowerShell",
        },
        {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "rule": "WIN-SYSMON-10; WIN-SYSMON-11; WIN-SYSMON-8; CORR-002; CORR-003",
        },
        {
            "id": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "rule": "WIN-SYSMON-10 PowerShell; WIN-SYSMON-10 Suspicious LSASS; CORR-001",
        },
        {
            "id": "T1218.005",
            "name": "System Binary Proxy Execution: Mshta",
            "tactic": "Defense Evasion",
            "rule": "WIN-SYSMON-3",
        },
        {
            "id": "T1547.004",
            "name": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
            "tactic": "Persistence",
            "rule": "WIN-SYSMON-13",
        },
    ]

    log_analyzer_techniques = [
        {
            "id": "T1546.003",
            "name": "Event Triggered Execution: WMI Event Subscription",
            "tactic": "Persistence",
            "rule": "CT-004",
            "test": "test_wmi_subscription_detection.py",
        },
        {
            "id": "T1053.005",
            "name": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Execution, Persistence",
            "rule": "CT-005",
            "test": "test_scheduled_task_detection.py",
        },
        {
            "id": "T1543.003",
            "name": "Create or Modify System Process: Windows Service",
            "tactic": "Persistence",
            "rule": "CT-006",
            "test": "test_windows_service_detection.py",
        },
    ]

    return templates.TemplateResponse(
        request=request,
        name="attack_coverage.html",
        context={
            "username": user.username,
            "sigma_techniques": sigma_techniques,
            "log_analyzer_techniques": log_analyzer_techniques,
            "total_techniques": 13,
            "target_techniques": 20,
            "remaining_techniques": 7,
            "tactic_count": 6,
            "sigma_file_count": 17,
            "individual_count": 14,
            "correlation_count": 3,
        },
    )
@app.get("/threat-hunting")
async def threat_hunting_page(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    hunt_reports = [
        {
            "id": "HUNT-01",
            "title": "LSASS Remote Thread Creation Followed by Process Access",
            "objective": (
                "Investigate whether an attacker creates a remote thread "
                "targeting LSASS and accesses LSASS from the same source "
                "process within 60 seconds."
            ),
            "data_source": "EVTX-ATTACK-SAMPLES",
            "events": "Sysmon Event ID 8 and Event ID 10",
            "method": (
                "Filtered Event ID 8 and Event ID 10 records targeting "
                "lsass.exe. Correlated using source Process GUID and "
                "Computer, requiring Event ID 10 within 0-60 seconds "
                "after Event ID 8."
            ),
            "results": [
                "Unique Event ID 8 LSASS records: 2",
                "Event ID 10 LSASS records: 26",
                "GUID-matched pairs: 1",
                "Correlated pairs within 60 seconds: 1",
            ],
            "evidence": [
                "Host: IEWIN7",
                r"Source process: \\VBOXSVR\HTools\voice_mail.msg.exe",
                "Source Process GUID: {365abb72-4055-5cc8-0000-0010769d0b00}",
                "Event ID 8 timestamp: 2019-04-30 12:43:43.784",
                "Event ID 10 timestamp: 2019-04-30 12:43:43.784",
                "Time difference: 0 seconds",
                "Source EVTX: CA_sysmon_hashdump_cmd_meterpreter.evtx",
            ],
            "assessment": (
                "The correlated events support the hypothesis of suspicious "
                "LSASS interaction and warrant investigation for possible "
                "credential-dumping activity. This evidence does not "
                "independently prove successful credential extraction."
            ),
            "conclusion": (
                "One confirmed same-host, same-source-process correlation "
                "was identified between remote thread creation targeting "
                "LSASS and subsequent LSASS process access."
            ),
        },
        {
            "id": "HUNT-02",
            "title": "LSASS Access Correlated with Dump File Creation",
            "objective": (
                "Investigate whether processes accessing LSASS also create "
                ".dmp files within a 60-second window, using matching "
                "process GUIDs and hostnames."
            ),
            "data_source": "EVTX-ATTACK-SAMPLES",
            "events": "Sysmon Event ID 10 and Event ID 11",
            "method": (
                "Filtered Event ID 10 records targeting lsass.exe and "
                "Event ID 11 records creating .dmp files. Matched Computer "
                "and process GUID, then calculated timestamp differences "
                "within an absolute 60-second window."
            ),
            "results": [
                "GUID-matched event pairs: 16",
                "Correlated pairs within 60 seconds: 16",
                "Unique correlated process GUIDs: 5",
                "Hosts observed: 3",
                "Observed time differences: approximately -0.472 to +0.473 seconds",
            ],
            "evidence": [
                "MSEDGEWIN10: services.exe associated with lsass.dmp",
                "PC04.example.corp: procdump.exe and taskmgr.exe associated with LSASS-named dump files",
                "alice.insecurebank.local: Outflank-Dumpert.exe, rundll32.exe and AndrewSpecial.exe associated with dump-file creation",
            ],
            "assessment": (
                "The offline dataset test identified process-level "
                "correlations between LSASS access and dump-file creation. "
                "Correlation alone does not prove that every dump file "
                "contains LSASS memory or that credentials were extracted."
            ),
            "conclusion": (
                "PASS: 16 correlated event pairs were identified within "
                "the configured 60-second window. Duplicate event-pair "
                "matches must not be interpreted as 16 unique incidents."
            ),
        },
    ]

    return templates.TemplateResponse(
        request=request,
        name="threat_hunting.html",
        context={
            "username": user.username,
            "hunt_reports": hunt_reports,
        },
    )


@app.get("/incident-cases")
async def incident_cases_page(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="incident_cases.html",
        context={
            "username": user.username,
        },
    )


REPORT_GROUPS = [
    {
        "category": "Detection Rule Test Reports",
        "reports": [
            {"id": "test-5145-mask", "title": "WIN-5145 Access Mask Analysis", "path": "docs/rule_test_reports/WIN-5145-Access-Mask-Analysis.md"},
            {"id": "test-5145-share", "title": "WIN-5145 Admin Share File Access", "path": "docs/rule_test_reports/WIN-5145-Admin-Share-File-Access-Test-Report.md"},
            {"id": "test-5156-plink", "title": "WIN-5156 Plink Loopback RDP", "path": "docs/rule_test_reports/WIN-5156-Plink-Loopback-RDP-Test-Report.md"},
            {"id": "test-1102", "title": "WIN-SEC-1102 Security Log Cleared", "path": "docs/rule_test_reports/WIN-SEC-1102-Security-Log-Cleared-Test-Report.md"},
            {"id": "test-powershell-bypass", "title": "Embedded PowerShell Execution Policy Bypass", "path": "docs/rule_test_reports/WIN-SYSMON-1-Embedded-PowerShell-Execution-Policy-Bypass-Test-Report.md"},
            {"id": "test-encoded-powershell", "title": "Encoded PowerShell Command", "path": "docs/rule_test_reports/WIN-SYSMON-1-Encoded-PowerShell-Command-Test-Report.md"},
            {"id": "test-lsass-access", "title": "LSASS Access", "path": "docs/rule_test_reports/WIN-SYSMON-10-LSASS-Access-Test-Report.md"},
            {"id": "test-lsass-process", "title": "LSASS Process Access", "path": "docs/rule_test_reports/WIN-SYSMON-10-LSASS-Process-Access-Test-Report.md"},
            {"id": "test-powershell-lsass", "title": "PowerShell LSASS Access", "path": "docs/rule_test_reports/WIN-SYSMON-10-PowerShell-LSASS-Access-Test-Report.md"},
            {"id": "test-dump-file", "title": "LSASS Dump File Creation", "path": "docs/rule_test_reports/WIN-SYSMON-11-LSASS-Dump-File-Creation-Test-Report.md"},
            {"id": "test-winlogon", "title": "Winlogon Shell Modification", "path": "docs/rule_test_reports/WIN-SYSMON-13-Winlogon-Shell-Modification-Test-Report.md"},
            {"id": "test-mshta", "title": "Mshta Outbound Network Connection", "path": "docs/rule_test_reports/WIN-SYSMON-3-MSHTA-Outbound-Network-Connection-Test-Report.md"},
            {"id": "test-dll", "title": "PowerShell Credential DLL Load", "path": "docs/rule_test_reports/WIN-SYSMON-7-PowerShell-Credential-DLL-Load-Test-Report.md"},
            {"id": "test-remote-thread", "title": "LSASS Remote Thread Creation", "path": "docs/rule_test_reports/WIN-SYSMON-8-LSASS-Remote-Thread-Creation-Test-Report.md"},
            {"id": "test-corr-001", "title": "Correlation 001 - PowerShell LSASS DLL Sequence", "path": "docs/rule_test_reports/WIN-SYSMON-CORR-001-PowerShell-LSASS-DLL-Sequence-Test-Report.md"},
            {"id": "test-corr-002", "title": "Correlation 002 - LSASS Access Dump Creation", "path": "docs/rule_test_reports/WIN-SYSMON-CORR-002-LSASS-Access-Dump-Creation-Test-Report.md"},
            {"id": "test-corr-003", "title": "Correlation 003 - LSASS Remote Thread Process Access", "path": "docs/rule_test_reports/WIN-SYSMON-CORR-003-LSASS-Remote-Thread-Process-Access-Test-Report.md"},
            {"id": "test-correlation-review", "title": "PowerShell LSASS Correlation Investigation", "path": "docs/rule_test_reports/WIN-SYSMON-Correlation-PowerShell-LSASS-Investigation.md"}
        ]
    },
    {
        "category": "Rule Tuning Reports",
        "reports": [
            {"id": "tuning-5145", "title": "WIN-5145 Admin Share File Access Tuning", "path": "docs/rule_tuning_reports/WIN-5145-Admin-Share-File-Access-Tuning-Report.md"},
            {"id": "tuning-5156", "title": "WIN-5156 Plink Loopback RDP Tuning", "path": "docs/rule_tuning_reports/WIN-5156-Plink-Loopback-RDP-Tuning-Report.md"},
            {"id": "tuning-lsass", "title": "Suspicious LSASS Access Tuning", "path": "docs/rule_tuning_reports/WIN-SYSMON-10-Suspicious-LSASS-Access-Tuning-Report.md"},
            {"id": "tuning-corr-002", "title": "LSASS Access Dump Creation Tuning Review", "path": "docs/rule_tuning_reports/WIN-SYSMON-CORR-002-LSASS-Access-Dump-Creation-Tuning-Review.md"}
        ]
    },
    {
        "category": "Threat Hunting Reports",
        "reports": [
            {"id": "hunt-01", "title": "HUNT-01 LSASS Remote Thread Process Access", "path": "docs/threat_hunting/HUNT-01-LSASS-Remote-Thread-Process-Access.md"},
            {"id": "hunt-02", "title": "HUNT-02 LSASS Access Dump Creation", "path": "docs/threat_hunting/HUNT-02-LSASS-Access-Dump-Creation.md"}
        ]
    },
    {
        "category": "Incident Investigation Cases",
        "reports": [
            {"id": "case-01", "title": "CASE-01 LSASS Credential Dumping Investigation", "path": "docs/incident_cases/CASE-01-LSASS-Credential-Dumping-Investigation.md"},
            {"id": "case-02", "title": "CASE-02 Windows Security Log Clearing", "path": "docs/incident_cases/CASE-02-WINDOWS-SECURITY-LOG-CLEARING.md"}
        ]
    },
    {
        "category": "Incident Response Playbooks",
        "reports": [
            {"id": "pb-01", "title": "PB-01 LSASS Credential Dumping Response", "path": "playbooks/PB-01-LSASS-Credential-Dumping-Response.md"},
            {"id": "pb-02", "title": "PB-02 Suspicious PowerShell Execution Response", "path": "playbooks/PB-02-Suspicious-PowerShell-Execution-Response.md"},
            {"id": "pb-03", "title": "PB-03 Malicious Process Network Activity Response", "path": "playbooks/PB-03-Malicious-Process-Network-Activity-Response.md"}
        ]
    },
    {
        "category": "IOC Research",
        "reports": [
            {"id": "ioc-01", "title": "IOC-RESEARCH-01 LSASS Dump Activity", "path": "ioc_research/IOC-RESEARCH-01-LSASS-DUMP-ACTIVITY.md"}
        ]
    },
    {
        "category": "Project Documentation",
        "reports": [
            {"id": "executive-summary", "title": "Executive Summary", "path": "docs/executive_summary/EXECUTIVE-SUMMARY.md"},
            {"id": "methodology", "title": "Project Methodology", "path": "docs/methodology/PROJECT-METHODOLOGY.md"},
            {"id": "presentation", "title": "Final Presentation - 15 Slides", "path": "docs/presentation/CYBERION-THREATSHIELD-FINAL-PRESENTATION.md"}
        ]
    }
]


@app.get("/reports-coverage")
async def reports_coverage_page(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    total_reports = sum(len(group["reports"]) for group in REPORT_GROUPS)

    return templates.TemplateResponse(
        request=request,
        name="reports_coverage.html",
        context={
            "username": user.username,
            "report_groups": REPORT_GROUPS,
            "total_reports": total_reports,
        },
    )


@app.get("/reports/view/{report_id}")
async def view_project_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)

    if user is None:
        return RedirectResponse("/login", status_code=303)

    allowed_report = next(
        (
            report
            for group in REPORT_GROUPS
            for report in group["reports"]
            if report["id"] == report_id
        ),
        None,
    )

    if allowed_report is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Report not found")

    project_root = BASE_DIR.parent.resolve()
    report_path = (project_root / allowed_report["path"]).resolve()

    if not report_path.is_relative_to(project_root) or not report_path.is_file():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        path=str(report_path),
        media_type="text/plain",
    )
