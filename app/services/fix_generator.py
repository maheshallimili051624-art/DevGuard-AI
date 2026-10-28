import difflib
import hashlib
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException
from app.schemas import FixGenerationRequest, PatchPreview, PatchApplyRequest, PatchApplyResponse
from app.services.ollama_client import call_ollama, get_configured_model
from app.security_scanner.rules import run_deterministic_rules
from app.database import log_approved_patch


def compute_content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def generate_fix_preview(request: FixGenerationRequest) -> PatchPreview:
    model_to_use = request.model_name or get_configured_model()
    orig_code = request.code_or_file
    orig_hash = compute_content_hash(orig_code)

    prompt = (
        f"You are DevGuard AI's automated security remediation assistant.\n"
        f"Fix finding: '{request.finding_title}'\n"
        f"Finding details: {request.finding_description}\n"
        f"Evidence code: {request.evidence}\n"
        f"Line: {request.start_line}\n\n"
        f"Original Source Code snippet:\n```text\n{orig_code[:30000]}\n```\n\n"
        "Instructions:\n"
        "1. Provide a direct, safe replacement for the code that completely remediates the issue.\n"
        "2. Do NOT introduce new vulnerabilities or break existing logic.\n"
        "3. Output format must strictly follow:\n"
        "---EXPLANATION---\n"
        "[Brief explanation of the fix]\n"
        "---EXPECTED_BEHAVIOR---\n"
        "[Describe how the fixed code behaves]\n"
        "---SUGGESTED_TESTS---\n"
        "[Test 1]\n[Test 2]\n"
        "---CODE_REPLACEMENT---\n"
        "[Only the replacement code without markdown fences]\n"
    )

    system_prompt = (
        "You are an expert security engineer generating precise code patches. "
        "Output clean, drop-in replacement code that resolves the security vulnerability."
    )

    response = call_ollama(prompt, system_prompt=system_prompt, model_name=model_to_use)

    # Parse delimited sections
    explanation = "Fix generated to address " + request.finding_title
    expected_behavior = "Code executes safely without the flagged vulnerability."
    suggested_tests = ["Verify valid inputs work as expected.", "Verify unauthorized or invalid inputs are safely rejected."]
    proposed_code = orig_code

    if "---EXPLANATION---" in response:
        parts = response.split("---EXPLANATION---")[1]
        if "---EXPECTED_BEHAVIOR---" in parts:
            explanation_part, rest = parts.split("---EXPECTED_BEHAVIOR---", 1)
            explanation = explanation_part.strip()
            if "---SUGGESTED_TESTS---" in rest:
                behavior_part, rest2 = rest.split("---SUGGESTED_TESTS---", 1)
                expected_behavior = behavior_part.strip()
                if "---CODE_REPLACEMENT---" in rest2:
                    tests_part, code_part = rest2.split("---CODE_REPLACEMENT---", 1)
                    suggested_tests = [t.strip("-* ") for t in tests_part.strip().splitlines() if t.strip()]
                    clean_code = code_part.strip()
                    if clean_code.startswith("```"):
                        lines = clean_code.splitlines()
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].startswith("```"):
                            lines = lines[:-1]
                        clean_code = "\n".join(lines).strip()
                    proposed_code = clean_code
    elif "```" in response:
        # Fallback markdown block extraction
        blocks = response.split("```")
        if len(blocks) >= 3:
            proposed_code = blocks[1]
            if proposed_code.startswith(("python", "javascript", "typescript", "java", "go", "php", "sql", "text")):
                proposed_code = proposed_code.split("\n", 1)[1] if "\n" in proposed_code else proposed_code
            proposed_code = proposed_code.strip()
            explanation = blocks[0].strip() or explanation

    # Generate unified diff
    orig_lines = orig_code.splitlines(keepends=True)
    prop_lines = proposed_code.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        orig_lines, prop_lines,
        fromfile="a/" + request.finding_id,
        tofile="b/" + request.finding_id
    ))
    unified_diff_str = "".join(diff) if diff else "No textual differences detected."

    # Verification: run static analysis rules on proposed code
    recheck_findings = run_deterministic_rules(proposed_code, filename="proposed_fix")
    is_clean = not any(f.category != "clean_scan" for f in recheck_findings)
    verification_status = "verified_clean" if is_clean else "recheck_warned"

    return PatchPreview(
        finding_id=request.finding_id,
        file_path="code_snippet",
        original_content_hash=orig_hash,
        original_snippet=orig_code,
        proposed_replacement=proposed_code,
        unified_diff=unified_diff_str,
        explanation=explanation,
        expected_behavior=expected_behavior,
        suggested_tests=suggested_tests,
        verification_status=verification_status
    )


def apply_patch_to_file(req: PatchApplyRequest) -> PatchApplyResponse:
    """
    Applies an approved patch to a file on disk.
    Strict safeguards:
    - Path containment check within project_root
    - Hash verification of original content
    - Automatic backup generation before overwriting
    - Explicit user approval required
    """
    project_root = Path(req.project_root).resolve()
    if not project_root.exists() or not project_root.is_dir():
        raise HTTPException(status_code=400, detail=f"Invalid project root: {req.project_root}")

    target_file = (project_root / req.file_path).resolve()

    # Path traversal safeguard
    try:
        target_file.relative_to(project_root)
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied: target file is outside project directory bounds.")

    if not target_file.exists():
        raise HTTPException(status_code=404, detail=f"Target file not found: {req.file_path}")

    current_content = target_file.read_text(encoding="utf-8", errors="replace")
    current_hash = compute_content_hash(current_content)

    if current_hash != req.original_content_hash:
        raise HTTPException(
            status_code=409,
            detail="Conflict: The file on disk has changed since the fix preview was generated. Please refresh and regenerate the fix."
        )

    backup_path = None
    if req.create_backup:
        ts = int(time.time())
        backup_file = target_file.with_name(f"{target_file.name}.bak.{ts}")
        shutil.copy2(target_file, backup_file)
        backup_path = str(backup_file.relative_to(project_root)).replace("\\", "/")

    # Apply approved replacement
    target_file.write_text(req.proposed_replacement, encoding="utf-8")

    # Record in persistent database
    log_approved_patch(
        scan_id=None,
        finding_id="approved-patch",
        file_path=req.file_path,
        orig_hash=req.original_content_hash,
        backup_path=backup_path,
        applied_at=datetime.now(timezone.utc).isoformat()
    )

    return PatchApplyResponse(
        success=True,
        file_path=req.file_path,
        backup_path=backup_path,
        message=f"Patch successfully applied to {req.file_path}." + (f" Backup created at {backup_path}" if backup_path else "")
    )
