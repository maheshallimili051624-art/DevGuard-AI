from typing import Optional, Literal
from pydantic import BaseModel, Field


SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Info"]
AnalysisType = Literal["security", "bugs", "quality", "performance", "best_practices", "full_review"]
AnalysisDepth = Literal["quick", "standard", "deep"]
SeverityFilter = Literal["all", "critical", "high", "medium", "low", "informational"]
ExperienceLevel = Literal["beginner", "intermediate", "advanced"]


class Finding(BaseModel):
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str
    file_path: str = "pasted-code"
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    evidence: str = ""
    why_it_matters: str = ""
    recommended_fix: str = ""
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    verification_status: Literal["verified_rule", "heuristic_match", "ai_hypothesis", "unverified"] = "verified_rule"
    detection_source: str = "Deterministic Rule"
    owasp_category: Optional[str] = None
    owasp_url: Optional[str] = None
    cwe_id: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class CodeReviewRequest(BaseModel):
    code: str = Field(min_length=1, max_length=150_000, description="Source code to analyze")
    language: str = Field(default="auto", max_length=50)
    analysis_type: AnalysisType = Field(default="security")
    analysis_depth: AnalysisDepth = Field(default="standard")
    severity_filter: SeverityFilter = Field(default="all")
    custom_instructions: Optional[str] = Field(default="", max_length=2000)
    max_findings: int = Field(default=50, ge=1, le=200)
    model_name: Optional[str] = Field(default=None, max_length=100)


class CodeReviewResponse(BaseModel):
    scan_id: str
    summary: str
    findings: list[Finding]
    files_scanned: list[str]
    files_skipped: list[str]
    duration_ms: int
    secret_redactions: int
    model_used: str
    analysis_type: str
    risk_score: Optional[int] = None
    risk_score_rationale: Optional[str] = None


class ArchiveReviewOptions(BaseModel):
    analysis_type: AnalysisType = "security"
    analysis_depth: AnalysisDepth = "standard"
    severity_filter: SeverityFilter = "all"
    custom_instructions: Optional[str] = ""
    model_name: Optional[str] = None
    max_findings: int = 100


class LocalDirectoryReviewRequest(BaseModel):
    directory_path: str = Field(min_length=1, max_length=500)
    analysis_type: AnalysisType = "security"
    analysis_depth: AnalysisDepth = "standard"
    severity_filter: SeverityFilter = "all"
    custom_instructions: Optional[str] = ""
    model_name: Optional[str] = None
    max_files: Optional[int] = Field(default=50, ge=1, le=200)


class FixGenerationRequest(BaseModel):
    finding_id: str
    code_or_file: str = Field(description="Raw code or relative file path")
    finding_title: str
    finding_description: str
    evidence: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    model_name: Optional[str] = None


class PatchPreview(BaseModel):
    finding_id: str
    file_path: str
    original_content_hash: str
    original_snippet: str
    proposed_replacement: str
    unified_diff: str
    explanation: str
    expected_behavior: str
    suggested_tests: list[str]
    verification_status: str


class PatchApplyRequest(BaseModel):
    project_root: str
    file_path: str
    original_content_hash: str
    proposed_replacement: str
    create_backup: bool = True


class PatchApplyResponse(BaseModel):
    success: bool
    file_path: str
    backup_path: Optional[str] = None
    message: str


class ErrorExplanationRequest(BaseModel):
    language: str = Field(default="auto", max_length=50)
    error_message: str = Field(min_length=1, max_length=5000)
    stack_trace: Optional[str] = Field(default="", max_length=10000)
    related_code: Optional[str] = Field(default="", max_length=20000)
    expected_behavior: Optional[str] = Field(default="", max_length=1000)
    actual_behavior: Optional[str] = Field(default="", max_length=1000)
    experience_level: ExperienceLevel = Field(default="intermediate")
    model_name: Optional[str] = None


class ErrorExplanationResponse(BaseModel):
    summary: str
    likely_causes: list[str]
    evidence_analysis: str
    debugging_steps: list[str]
    possible_fixes: list[str]
    suggested_tests: list[str]
    uncertainties_and_assumptions: str
    model_used: str


class GitDiffReviewRequest(BaseModel):
    repository_path: str = Field(min_length=1, max_length=500)
    base_ref: Optional[str] = Field(default="HEAD~1", max_length=100)
    target_ref: Optional[str] = Field(default="", max_length=100)
    changed_files_only: bool = True
    include_context_lines: int = Field(default=3, ge=0, le=10)
    analysis_type: AnalysisType = "security"
    model_name: Optional[str] = None


class GitDiffReviewResponse(BaseModel):
    repository: str
    diff_summary: str
    files_changed: list[str]
    findings: list[Finding]
    potential_regressions: list[str]
    missing_tests: list[str]
    error_handling_gaps: list[str]
    model_used: str


class DependencyVulnerability(BaseModel):
    ecosystem: str
    package_name: str
    installed_version: str
    vulnerability_id: str
    severity: SeverityLevel
    summary: str
    affected_versions: str
    fixed_version: Optional[str] = None
    advisory_url: Optional[str] = None
    source: str = "OSV Database"
    last_checked: str


class DependencyScanRequest(BaseModel):
    manifest_type: Literal["requirements.txt", "package.json", "package-lock.json", "pyproject.toml", "auto"] = "auto"
    content: str = Field(min_length=1, max_length=200_000)
    enable_online_lookup: bool = False


class DependencyScanResponse(BaseModel):
    manifest_type: str
    packages_parsed: int
    vulnerabilities_found: int
    vulnerabilities: list[DependencyVulnerability]
    online_lookup_performed: bool
    notice: str


class ScanHistorySummary(BaseModel):
    scan_id: str
    project_name: str
    created_at: str
    model_name: str
    analysis_type: str
    files_scanned_count: int
    files_skipped_count: int
    duration_ms: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: Optional[int] = None
    scan_status: str


class ScanDetailResponse(BaseModel):
    summary: ScanHistorySummary
    findings: list[Finding]
    files_scanned: list[str]
    files_skipped: list[str]
    ai_report: str


class ScanComparisonResponse(BaseModel):
    scan_a_id: str
    scan_b_id: str
    scan_a_date: str
    scan_b_date: str
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    common_findings: list[Finding]
    risk_score_delta: Optional[int] = None


class ConfigUpdate(BaseModel):
    ollama_url: Optional[str] = None
    default_model: Optional[str] = None
    timeout: Optional[int] = Field(default=None, ge=10, le=600)
    enable_online_dep_check: Optional[bool] = None
