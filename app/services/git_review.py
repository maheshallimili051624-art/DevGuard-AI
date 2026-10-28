import re
import shutil
import subprocess
from pathlib import Path
from fastapi import HTTPException
from app.schemas import GitDiffReviewRequest, GitDiffReviewResponse, Finding
from app.security_scanner.rules import run_deterministic_rules
from app.services.ollama_client import call_ollama, get_configured_model


def validate_git_ref(ref: str) -> bool:
    """Disallows shell metacharacters or dangerous options in git refs."""
    if not ref:
        return True
    return bool(re.match(r"^[a-zA-Z0-9_\-\.\/\^~]+$", ref))


def analyze_git_diff(req: GitDiffReviewRequest) -> GitDiffReviewResponse:
    git_bin = shutil.which("git")
    if not git_bin:
        raise HTTPException(
            status_code=400,
            detail="Git executable was not found on system PATH. Install Git from https://git-scm.com or add it to PATH."
        )

    repo_path = Path(req.repository_path).resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Specified repository path does not exist or is not a directory: {req.repository_path}"
        )

    # Verify is a git repository
    try:
        check_repo = subprocess.run(
            [git_bin, "-C", str(repo_path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5
        )
        if check_repo.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail=f"Directory is not a valid Git repository ({req.repository_path}). Initialize with 'git init' or select a git clone directory."
            )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Git repository validation timed out.")

    if not validate_git_ref(req.base_ref) or (req.target_ref and not validate_git_ref(req.target_ref)):
        raise HTTPException(status_code=400, detail="Invalid git reference format. Use valid commit hashes, tags, or branch names.")

    # Build git diff command
    cmd = [git_bin, "-C", str(repo_path), "diff", f"-U{req.include_context_lines}"]
    if req.target_ref:
        cmd.append(f"{req.base_ref}..{req.target_ref}")
    elif req.base_ref:
        cmd.append(req.base_ref)

    try:
        diff_res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        raw_diff = diff_res.stdout
        if diff_res.returncode != 0 and not raw_diff:
            # Fallback to unstaged working tree diff
            fallback = subprocess.run([git_bin, "-C", str(repo_path), "diff"], capture_output=True, text=True, timeout=10)
            raw_diff = fallback.stdout
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to execute git diff: {str(exc)}")

    if not raw_diff.strip():
        return GitDiffReviewResponse(
            repository=str(repo_path),
            diff_summary="No git diff changes detected between specified refs.",
            files_changed=[],
            findings=[],
            potential_regressions=[],
            missing_tests=[],
            error_handling_gaps=[],
            model_used="local-git"
        )

    # Extract changed files from diff headers
    changed_files = re.findall(r"^\+\+\+ b/(.+)$", raw_diff, re.MULTILINE)
    changed_files = list(dict.fromkeys(changed_files))

    # Run deterministic checks on added lines in the diff
    added_lines = [line[1:] for line in raw_diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    added_text = "\n".join(added_lines)
    findings: list[Finding] = []
    if added_text:
        findings = [f for f in run_deterministic_rules(added_text, filename="git-diff-added") if f.category != "clean_scan"]

    # AI Diff Analysis
    model_to_use = req.model_name or get_configured_model()
    prompt = (
        f"You are DevGuard AI's Git Diff Security and Quality Reviewer.\n"
        f"Repository: {repo_path.name}\n"
        f"Changed Files ({len(changed_files)}): {', '.join(changed_files[:15])}\n\n"
        "Analyze the following Git diff for:\n"
        "1. Potential bugs introduced by the changes\n"
        "2. Security flaws or regressions in added/modified logic\n"
        "3. Missing test coverage for modified code\n"
        "4. Error-handling gaps\n\n"
        f"Git Diff (truncated if large):\n```diff\n{raw_diff[:35000]}\n```"
    )

    system_prompt = (
        "You are an expert code reviewer analyzing Git pull requests and commit diffs. "
        "Focus specifically on the Delta (changes) rather than unchanged context. "
        "Highlight potential regressions, missing edge-case handling, and untested logic."
    )

    ai_diff_review = call_ollama(prompt, system_prompt=system_prompt, model_name=model_to_use)

    return GitDiffReviewResponse(
        repository=str(repo_path),
        diff_summary=ai_diff_review,
        files_changed=changed_files,
        findings=findings,
        potential_regressions=["Inspect modified return types and error paths for caller compatibility."],
        missing_tests=[f"Add unit tests covering changes in {f}" for f in changed_files[:5]],
        error_handling_gaps=["Check that newly added network or I/O calls have try/except blocks."],
        model_used=model_to_use
    )
