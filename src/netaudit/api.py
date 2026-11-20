"""HTTP surface: HTML for humans, JSON and SARIF for pipelines."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from . import __version__, engine, parser, reporters, scoring, store
from .models import Finding, Severity
from .rulepacks import load_rulepack

BASE_DIR = Path(__file__).parent
MAX_UPLOAD_BYTES = parser.MAX_BYTES

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    store.init_db()
    yield


app = FastAPI(
    title="NetAudit",
    version=__version__,
    summary="Configuration hardening auditor for FortiGate and Cisco IOS",
    description=(
        "Upload a device configuration, get scored findings with remediation. "
        "Configs are parsed as text and never executed."
    ),
    lifespan=lifespan,
)


async def _read_upload(file: UploadFile) -> bytes:
    """Read one byte past the limit instead of buffering whatever was posted.

    ``await file.read()`` pulls the whole body into memory before the size check
    runs, so a 4 GB upload is 4 GB of RAM in a container that is not sized for
    it. Reading ``MAX + 1`` is enough to know the upload is too big.
    """

    payload = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"config exceeds {MAX_UPLOAD_BYTES} bytes")
    return payload


def analyse(filename: str, payload: bytes, pack: str, per_object: bool = False) -> dict[str, Any]:
    """Run one audit and persist it. Shared by the HTML form and the JSON API."""

    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"config exceeds {MAX_UPLOAD_BYTES} bytes")

    raw = payload.decode("utf-8", errors="replace")
    vendor = parser.detect_vendor(raw)
    if vendor == "unknown":
        raise HTTPException(415, "vendor could not be detected from the uploaded config")

    requested = pack.strip().lower()
    if requested not in {"", "auto"} and requested != vendor:
        raise HTTPException(
            400, f"rulepack {requested!r} does not match detected vendor {vendor!r}"
        )

    selected = vendor if requested in {"", "auto"} else requested
    try:
        config = parser.parse(raw, vendor)
        findings = engine.evaluate(config, load_rulepack(selected), per_object=per_object)
    except ValueError as exc:  # RulepackError is a ValueError
        raise HTTPException(400, str(exc)) from exc

    value = scoring.score(findings)
    record: dict[str, Any] = {
        "filename": Path(filename).name or "upload.conf",
        "vendor": vendor,
        "score": value,
        "grade": scoring.grade(value),
        "findings": [f.to_dict() for f in findings],
    }
    record["id"] = store.save_scan(record)
    return record


def _get(scan_id: str) -> dict[str, Any]:
    record = store.get_scan(scan_id)
    if record is None:
        raise HTTPException(404, "scan not found")
    return record


def _rehydrate(record: dict[str, Any]) -> list[Finding]:
    """Turn a stored row back into Findings so the reporters stay typed."""

    return [
        Finding(
            rule_id=raw["rule_id"],
            title=raw["title"],
            severity=Severity[raw["severity"]],
            evidence=raw["evidence"],
            remediation=raw["remediation"],
            reference=raw["reference"],
        )
        for raw in record["findings"]
    ]


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Response:
    return templates.TemplateResponse(request, "index.html", {"scans": store.recent()})


@app.post("/scan")
async def scan_form(
    file: UploadFile = File(...),
    rulepack: str = Form("auto"),
    per_object: bool = Form(False),
) -> Response:
    record = analyse(file.filename or "upload.conf", await _read_upload(file), rulepack, per_object)
    return RedirectResponse(f"/scans/{record['id']}", status_code=303)


@app.post("/api/scans")
async def scan_api(
    file: UploadFile = File(...),
    rulepack: str = Form("auto"),
    fail_under: int | None = Form(None, ge=0, le=100),
    per_object: bool = Form(False),
) -> Response:
    """JSON scan endpoint. Returns 422 when ``fail_under`` is not reached."""

    record = analyse(file.filename or "upload.conf", await _read_upload(file), rulepack, per_object)
    status = 422 if fail_under is not None and record["score"] < fail_under else 200
    body = {key: record[key] for key in ("id", "vendor", "score", "grade", "findings")}
    return Response(json.dumps(body, indent=2), media_type="application/json", status_code=status)


@app.get("/api/scans")
def list_scans(limit: int = Query(10, ge=1, le=100)) -> Response:
    return Response(
        json.dumps({"scans": store.recent(limit)}, indent=2), media_type="application/json"
    )


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: str) -> Response:
    return templates.TemplateResponse(request, "report.html", {"scan": _get(scan_id)})


@app.get("/scans/{scan_id}/report.md", response_class=PlainTextResponse)
def scan_markdown(scan_id: str) -> Response:
    record = _get(scan_id)
    return PlainTextResponse(
        reporters.markdown(
            record["filename"],
            record["vendor"],
            record["score"],
            record["grade"],
            _rehydrate(record),
        )
    )


@app.get("/scans/{scan_id}/report.sarif")
def scan_sarif(scan_id: str) -> Response:
    record = _get(scan_id)
    return Response(
        reporters.sarif(record["filename"], _rehydrate(record)),
        media_type="application/sarif+json",
    )
