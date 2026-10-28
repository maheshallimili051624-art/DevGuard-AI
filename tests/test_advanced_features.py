import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.database import init_db, save_scan, get_scan, list_scans, delete_scan
from app.schemas import Finding, CodeReviewRequest, FixGenerationRequest, PatchApplyRequest, DependencyScanRequest
from app.security_scanner.redaction import scrub_secrets
from app.security_scanner.rules import run_deterministic_rules
from app.security_scanner.ast_analyzer import analyze_python_ast
from app.services.repo_scanner import extract_safe_zip, scan_local_directory
from app.services.dependency_scanner import parse_requirements_txt, parse_package_json, parse_pyproject_toml, scan_dependencies
from app.services.fix_generator import generate_fix_preview, apply_patch_to_file, compute_content_hash
from app.services.report_exporter import export_markdown_report, export_sarif_report
from app.services.error_explainer import explain_error
from app.schemas import ErrorExplanationRequest


class TestDevGuardAdvancedFeatures(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_secret_redaction_advanced_patterns(self):
        test_content = (
            'const key = "sk-1234567890abcdef1234567890";\n'
            'const secret = "ghp_123456789012345678901234567890123456";\n'
            'const aws = "AKIAIOSFODNN7EXAMPLE";\n'
            'api_key = "abcdef123456789";\n'
        )
        cleaned, count = scrub_secrets(test_content)
        self.assertGreaterEqual(count, 3)
        self.assertNotIn("sk-1234567890abcdef", cleaned)
        self.assertNotIn("ghp_1234567890", cleaned)
        self.assertIn("[REDACTED_POSSIBLE_SECRET]", cleaned)

    def test_deterministic_rules_comprehensive(self):
        # 1. SQL Injection
        findings_sqli = run_deterministic_rules("cursor.execute('SELECT * FROM users WHERE id = ' + user_id)", "db.py")
        self.assertTrue(any(f.category == "sql_injection" for f in findings_sqli))

        # 2. Command Injection
        findings_cmd = run_deterministic_rules("import os\nos.system('rm -rf ' + path)", "cmd.py")
        self.assertTrue(any(f.category == "command_injection" for f in findings_cmd))

        # 3. Dynamic Evaluation
        findings_eval = run_deterministic_rules("eval('2 + 2')", "calc.py")
        self.assertTrue(any(f.category == "dynamic_evaluation" for f in findings_eval))

        # 4. Insecure Deserialization
        findings_pickle = run_deterministic_rules("import pickle\npickle.loads(data)", "load.py")
        self.assertTrue(any(f.category == "insecure_deserialization" for f in findings_pickle))

        # 5. Disabled TLS Verification
        findings_tls = run_deterministic_rules("requests.get('https://example.com', verify=False)", "net.py")
        self.assertTrue(any(f.category == "tls_disabled" for f in findings_tls))

        # 6. Weak Cryptography
        findings_crypto = run_deterministic_rules("import hashlib\nhashlib.md5(pwd.encode()).hexdigest()", "auth.py")
        self.assertTrue(any(f.category == "weak_crypto" for f in findings_crypto))

        # 7. Insecure Tempfile
        findings_temp = run_deterministic_rules("import tempfile\ntempfile.mktemp()", "tmp.py")
        self.assertTrue(any(f.category == "insecure_temporary_file" for f in findings_temp))

    def test_python_ast_analyzer_direct(self):
        python_code = """
import os, subprocess, pickle

eval("print(1)")
exec("x = 2")
os.system("ls")
subprocess.Popen(["echo", "hi"], shell=True)
pickle.loads(b"data")
"""
        ast_findings = analyze_python_ast(python_code, "test.py")
        categories = {f.category for f in ast_findings}
        self.assertIn("dynamic_evaluation", categories)
        self.assertIn("code_injection", categories)
        self.assertIn("command_injection", categories)
        self.assertIn("insecure_deserialization", categories)

    def test_zip_path_traversal_prevention(self):
        # Create an in-memory zip archive containing a zip slip payload
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:")
            zf.writestr("valid.py", "print('hello world')")
            zf.writestr(".git/config", "[core]")
            zf.writestr(".env", "SECRET=12345")
        
        raw_zip = zip_buf.getvalue()
        selected, scanned, skipped, redactions = extract_safe_zip(raw_zip)

        # Ensure path traversal and sensitive files were rejected
        scanned_files = [f["name"] for f in selected]
        self.assertIn("valid.py", scanned_files)
        self.assertNotIn("../../etc/passwd", scanned_files)
        self.assertNotIn(".env", scanned_files)
        self.assertNotIn(".git/config", scanned_files)
        self.assertTrue(any("path traversal" in s for s in skipped))
        self.assertTrue(any("sensitive" in s for s in skipped))

    def test_local_directory_scanner(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "app.py").write_text("print('safe app')", encoding="utf-8")
            (tmp_path / ".env").write_text("API_KEY=secret123", encoding="utf-8")
            node_dir = tmp_path / "node_modules"
            node_dir.mkdir()
            (node_dir / "dep.js").write_text("console.log('node')", encoding="utf-8")

            selected, scanned, skipped, _ = scan_local_directory(str(tmp_path))
            self.assertIn("app.py", scanned)
            self.assertNotIn(".env", scanned)
            self.assertNotIn("node_modules/dep.js", scanned)

    def test_dependency_parsers(self):
        req_content = "fastapi>=0.115\nrequests==2.31.0\n# comment\npydantic>=2.0"
        parsed_py = parse_requirements_txt(req_content)
        self.assertEqual(len(parsed_py), 3)
        self.assertEqual(parsed_py[0][0], "fastapi")

        pkg_json = json.dumps({
            "dependencies": {"express": "^4.18.2"},
            "devDependencies": {"mocha": "~10.2.0"}
        })
        parsed_js = parse_package_json(pkg_json)
        self.assertEqual(len(parsed_js), 2)
        self.assertTrue(any(p[0] == "express" for p in parsed_js))

    def test_sqlite_scan_persistence_and_sarif(self):
        scan_id = "test-scan-123"
        f = Finding(
            finding_id="RULE-1",
            title="SQL Injection",
            description="Concatenation in query",
            severity="High",
            category="sql_injection",
            file_path="server.py",
            start_line=10,
            end_line=10,
            evidence="query = 'SELECT * ' + id",
            why_it_matters="Data exfiltration",
            recommended_fix="Use params",
            confidence=0.9,
            verification_status="verified_rule",
            detection_source="Deterministic Rule",
            references=["https://owasp.org"]
        )
        save_scan(
            scan_id=scan_id,
            project_name="Test Project",
            created_at="2026-10-28T12:00:00Z",
            model_name="gemma4:e2b",
            analysis_type="security",
            duration_ms=250,
            findings=[f],
            files_scanned=["server.py"],
            files_skipped=[],
            ai_report="Test AI report",
            risk_score=15
        )

        detail = get_scan(scan_id)
        self.assertIsNotNone(detail)
        self.assertEqual(detail.summary.project_name, "Test Project")
        self.assertEqual(len(detail.findings), 1)
        self.assertEqual(detail.findings[0].title, "SQL Injection")

        # Test SARIF export
        sarif = export_sarif_report(detail)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "DevGuard AI")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

        # Test Markdown export
        md = export_markdown_report(detail)
        self.assertIn("# DevGuard AI Security & Quality Report", md)
        self.assertIn("SQL Injection", md)

        # Cleanup
        delete_scan(scan_id)
        self.assertIsNone(get_scan(scan_id))

    def test_patch_apply_safeguards(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "vuln.py"
            orig_content = "eval(user_input)\n"
            file_path.write_text(orig_content, encoding="utf-8")
            orig_hash = compute_content_hash(orig_content)

            # Test successful apply with backup
            req = PatchApplyRequest(
                project_root=tmp_dir,
                file_path="vuln.py",
                original_content_hash=orig_hash,
                proposed_replacement="ast.literal_eval(user_input)\n",
                create_backup=True
            )
            res = apply_patch_to_file(req)
            self.assertTrue(res.success)
            self.assertIsNotNone(res.backup_path)
            self.assertEqual(file_path.read_text(encoding="utf-8"), "ast.literal_eval(user_input)\n")

            # Test conflict rejection if hash changed
            file_path.write_text("changed_externally = True\n", encoding="utf-8")
            with self.assertRaises(Exception):
                apply_patch_to_file(req)


if __name__ == "__main__":
    unittest.main()
