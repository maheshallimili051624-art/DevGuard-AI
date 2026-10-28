import json
import sqlite3
from typing import Optional
from app.config import DATABASE_PATH
from app.schemas import Finding, ScanHistorySummary, ScanDetailResponse


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                project_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                model_name TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                files_scanned_count INTEGER NOT NULL,
                files_skipped_count INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                findings_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                info_count INTEGER NOT NULL DEFAULT 0,
                risk_score INTEGER,
                scan_status TEXT NOT NULL,
                ai_report TEXT NOT NULL
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                file_path TEXT NOT NULL,
                start_line INTEGER,
                end_line INTEGER,
                evidence TEXT,
                why_it_matters TEXT,
                recommended_fix TEXT,
                confidence REAL NOT NULL,
                verification_status TEXT NOT NULL,
                detection_source TEXT NOT NULL,
                owasp_category TEXT,
                owasp_url TEXT,
                cwe_id TEXT,
                references_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_file_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS approved_patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                finding_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                original_content_hash TEXT NOT NULL,
                backup_path TEXT,
                applied_at TEXT NOT NULL
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """)
    finally:
        conn.close()


def save_scan(
    scan_id: str,
    project_name: str,
    created_at: str,
    model_name: str,
    analysis_type: str,
    duration_ms: int,
    findings: list[Finding],
    files_scanned: list[str],
    files_skipped: list[str],
    ai_report: str,
    risk_score: Optional[int] = None,
    scan_status: str = "completed"
):
    critical_count = sum(1 for f in findings if f.severity == "Critical")
    high_count = sum(1 for f in findings if f.severity == "High")
    medium_count = sum(1 for f in findings if f.severity == "Medium")
    low_count = sum(1 for f in findings if f.severity == "Low")
    info_count = sum(1 for f in findings if f.severity == "Info")

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, project_name, created_at, model_name, analysis_type,
                    files_scanned_count, files_skipped_count, duration_ms,
                    findings_count, critical_count, high_count, medium_count,
                    low_count, info_count, risk_score, scan_status, ai_report
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, project_name, created_at, model_name, analysis_type,
                    len(files_scanned), len(files_skipped), duration_ms,
                    len(findings), critical_count, high_count, medium_count,
                    low_count, info_count, risk_score, scan_status, ai_report
                )
            )

            for f in findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, finding_id, title, description, severity, category,
                        file_path, start_line, end_line, evidence, why_it_matters,
                        recommended_fix, confidence, verification_status, detection_source,
                        owasp_category, owasp_url, cwe_id, references_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id, f.finding_id, f.title, f.description, f.severity, f.category,
                        f.file_path, f.start_line, f.end_line, f.evidence, f.why_it_matters,
                        f.recommended_fix, f.confidence, f.verification_status, f.detection_source,
                        f.owasp_category, f.owasp_url, f.cwe_id, json.dumps(f.references)
                    )
                )

            for fp in files_scanned:
                conn.execute(
                    "INSERT INTO scan_file_summaries (scan_id, file_path, status, reason) VALUES (?, ?, ?, ?)",
                    (scan_id, fp, "scanned", "Supported source file within limits")
                )
            for fp in files_skipped:
                conn.execute(
                    "INSERT INTO scan_file_summaries (scan_id, file_path, status, reason) VALUES (?, ?, ?, ?)",
                    (scan_id, fp, "skipped", "Excluded directory, sensitive name, or exceeded file limits")
                )
    finally:
        conn.close()


def list_scans(query: Optional[str] = None, limit: int = 50) -> list[ScanHistorySummary]:
    conn = get_db_connection()
    try:
        sql = "SELECT * FROM scans"
        params = []
        if query:
            sql += " WHERE project_name LIKE ? OR model_name LIKE ? OR scan_id LIKE ?"
            like_q = f"%{query}%"
            params.extend([like_q, like_q, like_q])
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return [
            ScanHistorySummary(
                scan_id=r["scan_id"],
                project_name=r["project_name"],
                created_at=r["created_at"],
                model_name=r["model_name"],
                analysis_type=r["analysis_type"],
                files_scanned_count=r["files_scanned_count"],
                files_skipped_count=r["files_skipped_count"],
                duration_ms=r["duration_ms"],
                findings_count=r["findings_count"],
                critical_count=r["critical_count"],
                high_count=r["high_count"],
                medium_count=r["medium_count"],
                low_count=r["low_count"],
                info_count=r["info_count"],
                risk_score=r["risk_score"],
                scan_status=r["scan_status"]
            )
            for r in rows
        ]
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[ScanDetailResponse]:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        
        summary = ScanHistorySummary(
            scan_id=row["scan_id"],
            project_name=row["project_name"],
            created_at=row["created_at"],
            model_name=row["model_name"],
            analysis_type=row["analysis_type"],
            files_scanned_count=row["files_scanned_count"],
            files_skipped_count=row["files_skipped_count"],
            duration_ms=row["duration_ms"],
            findings_count=row["findings_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            info_count=row["info_count"],
            risk_score=row["risk_score"],
            scan_status=row["scan_status"]
        )

        f_rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,)).fetchall()
        findings = []
        for f in f_rows:
            refs = []
            if f["references_json"]:
                try:
                    refs = json.loads(f["references_json"])
                except Exception:
                    pass
            findings.append(Finding(
                finding_id=f["finding_id"],
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                category=f["category"],
                file_path=f["file_path"],
                start_line=f["start_line"],
                end_line=f["end_line"],
                evidence=f["evidence"] or "",
                why_it_matters=f["why_it_matters"] or "",
                recommended_fix=f["recommended_fix"] or "",
                confidence=f["confidence"],
                verification_status=f["verification_status"],
                detection_source=f["detection_source"],
                owasp_category=f["owasp_category"],
                owasp_url=f["owasp_url"],
                cwe_id=f["cwe_id"],
                references=refs
            ))

        files_scanned = [
            r["file_path"] for r in conn.execute(
                "SELECT file_path FROM scan_file_summaries WHERE scan_id = ? AND status = 'scanned'", (scan_id,)
            ).fetchall()
        ]
        files_skipped = [
            r["file_path"] for r in conn.execute(
                "SELECT file_path FROM scan_file_summaries WHERE scan_id = ? AND status = 'skipped'", (scan_id,)
            ).fetchall()
        ]

        return ScanDetailResponse(
            summary=summary,
            findings=findings,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            ai_report=row["ai_report"]
        )
    finally:
        conn.close()


def delete_scan(scan_id: str) -> bool:
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def log_approved_patch(scan_id: Optional[str], finding_id: str, file_path: str, orig_hash: str, backup_path: Optional[str], applied_at: str):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO approved_patches (scan_id, finding_id, file_path, original_content_hash, backup_path, applied_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, finding_id, file_path, orig_hash, backup_path, applied_at)
            )
    finally:
        conn.close()


def set_setting(key: str, value: str):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))
    finally:
        conn.close()


def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()
