from pathlib import Path
from typing import Optional, Literal
import time
import os

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Query, Response
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import STATIC_DIR, OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT
from app.database import init_db, list_scans, get_scan, delete_scan, set_setting, get_setting
from app.schemas import (
    CodeReviewRequest, CodeReviewResponse, FixGenerationRequest, PatchPreview,
    PatchApplyRequest, PatchApplyResponse, ErrorExplanationRequest, ErrorExplanationResponse,
    GitDiffReviewRequest, GitDiffReviewResponse, DependencyScanRequest, DependencyScanResponse,
    ScanComparisonResponse, ConfigUpdate, Finding
)
from app.security_scanner.redaction import scrub_secrets, SECRET_PATTERNS
from app.security_scanner.rules import local_checks, run_deterministic_rules
from app.services.ollama_client import (
    call_ollama, check_ollama_status, get_configured_model,
    get_configured_ollama_url, get_configured_timeout
)
from app.services.code_review import perform_code_review, calculate_risk_score
from app.services.repo_scanner import extract_safe_zip, scan_local_directory, analyze_repository_files
from app.services.fix_generator import generate_fix_preview, apply_patch_to_file
from app.services.dependency_scanner import scan_dependencies
from app.services.error_explainer import explain_error
from app.services.git_review import analyze_git_diff
from app.services.report_exporter import export_markdown_report, export_json_report, export_sarif_report

from fastapi.middleware.cors import CORSMiddleware

# Initialize database schema
init_db()

app = FastAPI(
    title="DevGuard AI",
    version="2.0.0",
    description="Advanced Local-First AI Code Security & Quality Platform powered by Ollama."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# Legacy CodeRequest class for backward compatibility
class CodeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=150_000)
    language: str = Field(default="auto", max_length=50)
    question: str = Field(default="Review this code for likely bugs, security risks, and maintainability issues.", max_length=1500)


# ==========================================
# Frontend Page & Health
# ==========================================

@app.get("/")
def index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(index_path)


@app.get("/api/health")
def health():
    return check_ollama_status()


@app.get("/api/models")
def get_models():
    status_info = check_ollama_status()
    return {
        "models": status_info.get("models", []),
        "default_model": get_configured_model(),
        "ollama_url": get_configured_ollama_url(),
        "timeout": get_configured_timeout(),
        "ollama_status": status_info.get("ollama", "disconnected")
    }


# ==========================================
# Code Review Endpoints
# ==========================================

@app.post("/api/analyze")
def legacy_analyze_code(request: CodeRequest):
    """Preserves exact legacy endpoint behavior for existing clients."""
    code, redactions = scrub_secrets(request.code)
    findings = local_checks(code)
    prompt = (
        f"Language: {request.language}\nQuestion: {request.question}\n\n"
        "Review the code below. Use headings: Summary, Findings (severity and line where possible), "
        "Recommended fixes, Tests to run. Be specific, distinguish likely issues from confirmed facts, "
        "and do not invent execution results. Possible secrets have been redacted.\n\n"
        f"```text\n{code[:40000]}\n```"
    )
    analysis = call_ollama(prompt)
    return {
        "analysis": analysis,
        "findings": findings,
        "secret_redactions": redactions,
        "model": get_configured_model(),
        "mode": "local Ollama + deterministic checks"
    }


@app.post("/api/review", response_model=CodeReviewResponse)
def advanced_code_review(request: CodeReviewRequest):
    """Advanced structured AI code review with full parameters."""
    return perform_code_review(request)


# ==========================================
# Repository & Archive Endpoints
# ==========================================

@app.post("/api/analyze-archive")
async def analyze_archive(
    file: UploadFile = File(...),
    question: str = Form("Summarize the project, identify likely bugs/security concerns, and suggest safe next steps."),
    analysis_type: str = Form("security"),
    analysis_depth: str = Form("standard"),
    severity_filter: str = Form("all"),
    model_name: Optional[str] = Form(None)
):
    """Processes uploaded ZIP project with safe extraction and bounded Ollama context."""
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip file containing source code.")

    raw = await file.read()
    files, scanned_names, skipped_names, redactions = extract_safe_zip(raw)

    resp = analyze_repository_files(
        project_name=file.filename,
        files=files,
        scanned_names=scanned_names,
        skipped_names=skipped_names,
        redactions=redactions,
        analysis_type=analysis_type,
        analysis_depth=analysis_depth,
        severity_filter=severity_filter,
        custom_instructions=question,
        model_name=model_name
    )

    # Return compatible format that satisfies both legacy and new frontend
    return {
        "scan_id": resp.scan_id,
        "analysis": resp.summary,
        "summary": resp.summary,
        "findings": [f.model_dump() for f in resp.findings],
        "files_scanned": resp.files_scanned,
        "files_skipped": resp.files_skipped,
        "file_count": len(resp.files_scanned),
        "secret_redactions": resp.secret_redactions,
        "model": resp.model_used,
        "model_used": resp.model_used,
        "risk_score": resp.risk_score,
        "risk_score_rationale": resp.risk_score_rationale,
        "duration_ms": resp.duration_ms,
        "mode": "local Ollama + repository scan"
    }


@app.post("/api/analyze-local", response_model=CodeReviewResponse)
def analyze_local(
    directory_path: str = Form(...),
    question: Optional[str] = Form("Review local repository directory"),
    analysis_type: str = Form("security"),
    analysis_depth: str = Form("standard"),
    severity_filter: str = Form("all"),
    model_name: Optional[str] = Form(None)
):
    """Safely scans a local directory on disk without leaving system boundaries."""
    files, scanned_names, skipped_names, redactions = scan_local_directory(directory_path)
    proj_name = Path(directory_path).name or "Local Directory"
    return analyze_repository_files(
        project_name=proj_name,
        files=files,
        scanned_names=scanned_names,
        skipped_names=skipped_names,
        redactions=redactions,
        analysis_type=analysis_type,
        analysis_depth=analysis_depth,
        severity_filter=severity_filter,
        custom_instructions=question or "",
        model_name=model_name
    )


# ==========================================
# Fix Generator & Patch Preview
# ==========================================

@app.post("/api/generate-fix", response_model=PatchPreview)
def generate_fix(request: FixGenerationRequest):
    """Generates an actionable fix explanation, unified diff, and verification check."""
    return generate_fix_preview(request)


@app.post("/api/apply-patch", response_model=PatchApplyResponse)
def apply_patch(request: PatchApplyRequest):
    """Applies user-approved patch to disk with strict containment and rollback backup."""
    return apply_patch_to_file(request)


# ==========================================
# Error Explainer & Debugger
# ==========================================

@app.post("/api/explain-error", response_model=ErrorExplanationResponse)
def explain_runtime_error(request: ErrorExplanationRequest):
    """Produces structured debugging analysis and test recommendations for errors."""
    return explain_error(request)


# ==========================================
# Git Diff Security Review
# ==========================================

@app.post("/api/git-review", response_model=GitDiffReviewResponse)
def review_git_diff(request: GitDiffReviewRequest):
    """Inspects changes introduced by Git commits or uncommitted diff."""
    return analyze_git_diff(request)


# ==========================================
# Dependency Security
# ==========================================

@app.post("/api/scan-dependencies", response_model=DependencyScanResponse)
def scan_project_dependencies(request: DependencyScanRequest):
    """Extracts manifest packages and optionally checks authoritative OSV advisory database."""
    return scan_dependencies(request)


# ==========================================
# Scan History & Reports
# ==========================================

@app.get("/api/scans")
def get_scan_history(query: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=200)):
    """Retrieves previous scan history from persistent SQLite database."""
    return list_scans(query=query, limit=limit)


@app.get("/api/scans/{scan_id}")
def get_scan_details(scan_id: str):
    """Fetches full scan details, files scanned/skipped, and findings."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")
    return scan


@app.delete("/api/scans/{scan_id}")
def remove_scan(scan_id: str):
    """Deletes stored scan metadata and findings."""
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")
    return {"message": f"Scan '{scan_id}' successfully deleted.", "scan_id": scan_id}


@app.get("/api/scans/{scan_id}/report")
def download_scan_report(scan_id: str, format: Literal["markdown", "json", "sarif"] = "markdown"):
    """Exports scan report in Markdown, JSON, or OASIS SARIF 2.1.0 standard schema."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")

    if format == "markdown":
        md = export_markdown_report(scan)
        return Response(content=md, media_type="text/markdown", headers={
            "Content-Disposition": f"attachment; filename=devguard-report-{scan_id}.md"
        })
    elif format == "sarif":
        sarif_data = export_sarif_report(scan)
        return JSONResponse(content=sarif_data, headers={
            "Content-Disposition": f"attachment; filename=devguard-report-{scan_id}.sarif.json"
        })
    else:
        json_str = export_json_report(scan)
        return Response(content=json_str, media_type="application/json", headers={
            "Content-Disposition": f"attachment; filename=devguard-report-{scan_id}.json"
        })


@app.post("/api/scans/compare", response_model=ScanComparisonResponse)
def compare_scans(scan_a_id: str = Form(...), scan_b_id: str = Form(...)):
    """Compares two historical scans to identify new, resolved, and persistent findings."""
    scan_a = get_scan(scan_a_id)
    scan_b = get_scan(scan_b_id)
    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="One or both scan IDs could not be located.")

    a_titles = {f.title for f in scan_a.findings}
    b_titles = {f.title for f in scan_b.findings}

    new_findings = [f for f in scan_b.findings if f.title not in a_titles]
    resolved_findings = [f for f in scan_a.findings if f.title not in b_titles]
    common_findings = [f for f in scan_b.findings if f.title in a_titles]

    delta = None
    if scan_a.summary.risk_score is not None and scan_b.summary.risk_score is not None:
        delta = scan_b.summary.risk_score - scan_a.summary.risk_score

    return ScanComparisonResponse(
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        scan_a_date=scan_a.summary.created_at,
        scan_b_date=scan_b.summary.created_at,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        common_findings=common_findings,
        risk_score_delta=delta
    )


# ==========================================
# Settings Configuration
# ==========================================

@app.get("/api/settings")
def fetch_settings():
    return {
        "ollama_url": get_configured_ollama_url(),
        "default_model": get_configured_model(),
        "timeout": get_configured_timeout(),
        "online_dependency_check": get_setting("enable_online_dep_check", "false") == "true"
    }


@app.post("/api/settings")
def update_settings(cfg: ConfigUpdate):
    if cfg.ollama_url is not None:
        set_setting("ollama_url", cfg.ollama_url.strip())
    if cfg.default_model is not None:
        set_setting("default_model", cfg.default_model.strip())
    if cfg.timeout is not None:
        set_setting("ollama_timeout", str(cfg.timeout))
    if cfg.enable_online_dep_check is not None:
        set_setting("enable_online_dep_check", "true" if cfg.enable_online_dep_check else "false")
    return {"status": "ok", "message": "Settings updated successfully."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
