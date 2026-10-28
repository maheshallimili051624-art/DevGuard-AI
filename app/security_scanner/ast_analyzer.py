import ast
import uuid
from typing import Optional
from app.schemas import Finding
from app.security_scanner.owasp_mapping import get_owasp_mapping


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_code: str):
        self.filename = filename
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.findings: list[Finding] = []

    def _get_evidence(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", None)
        if lineno and 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        attr_name = ""
        full_call = ""

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_call = func_name
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                full_call = f"{node.func.value.id}.{attr_name}"
            else:
                full_call = f"*.{attr_name}"

        # 1. eval()
        if func_name == "eval":
            owasp_cat, owasp_url, _ = get_owasp_mapping("dynamic_evaluation")
            self.findings.append(Finding(
                finding_id=f"ast-eval-{uuid.uuid4().hex[:6]}",
                title="Unsafe Dynamic Evaluation via eval()",
                description="eval() interprets arbitrary strings as Python code, allowing remote code execution if input is untrusted.",
                severity="High",
                category="dynamic_evaluation",
                file_path=self.filename,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                evidence=self._get_evidence(node),
                why_it_matters="If any user-controlled input reaches eval(), an attacker can execute arbitrary operating system and interpreter commands.",
                recommended_fix="Use ast.literal_eval() for safely parsing literals, or refactor to use explicit dictionary lookups.",
                confidence=0.95,
                verification_status="verified_rule",
                detection_source="Python AST Analyzer",
                owasp_category=owasp_cat,
                owasp_url=owasp_url,
                cwe_id="CWE-95",
                references=["https://cwe.mitre.org/data/definitions/95.html"]
            ))

        # 2. exec()
        if func_name == "exec":
            owasp_cat, owasp_url, _ = get_owasp_mapping("code_injection")
            self.findings.append(Finding(
                finding_id=f"ast-exec-{uuid.uuid4().hex[:6]}",
                title="Unsafe Code Execution via exec()",
                description="exec() runs arbitrary Python statements dynamically.",
                severity="High",
                category="code_injection",
                file_path=self.filename,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                evidence=self._get_evidence(node),
                why_it_matters="Untrusted input passed to exec() grants full code execution capabilities inside the application process.",
                recommended_fix="Eliminate dynamic code execution. Use static functions, polymorphism, or data-driven design patterns.",
                confidence=0.95,
                verification_status="verified_rule",
                detection_source="Python AST Analyzer",
                owasp_category=owasp_cat,
                owasp_url=owasp_url,
                cwe_id="CWE-94",
                references=["https://cwe.mitre.org/data/definitions/94.html"]
            ))

        # 3. os.system() and subprocess with shell=True
        if full_call in {"os.system", "os.popen"} or (attr_name in {"system", "popen"} and "os" in full_call):
            owasp_cat, owasp_url, _ = get_owasp_mapping("command_injection")
            self.findings.append(Finding(
                finding_id=f"ast-cmdinj-{uuid.uuid4().hex[:6]}",
                title="Command Execution via os.system",
                description="Executing shell commands through os.system() creates command injection risks when input is unsanitized.",
                severity="High",
                category="command_injection",
                file_path=self.filename,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                evidence=self._get_evidence(node),
                why_it_matters="Command injection allows adversaries to run unauthorized commands with the privileges of the Python server.",
                recommended_fix="Use the subprocess module with an argument list and shell=False, e.g., subprocess.run(['cmd', arg], shell=False).",
                confidence=0.9,
                verification_status="verified_rule",
                detection_source="Python AST Analyzer",
                owasp_category=owasp_cat,
                owasp_url=owasp_url,
                cwe_id="CWE-78",
                references=["https://cwe.mitre.org/data/definitions/78.html"]
            ))

        if "subprocess" in full_call or attr_name in {"Popen", "run", "call", "check_output", "check_call"}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    owasp_cat, owasp_url, _ = get_owasp_mapping("command_injection")
                    self.findings.append(Finding(
                        finding_id=f"ast-subproc-shell-{uuid.uuid4().hex[:6]}",
                        title="Subprocess Invoked with shell=True",
                        description="Passing shell=True to subprocess spawns an intermediate system shell that parses shell metacharacters.",
                        severity="High",
                        category="command_injection",
                        file_path=self.filename,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        evidence=self._get_evidence(node),
                        why_it_matters="Allows command chaining (;, |, &&) if any part of the command contains user-influenced strings.",
                        recommended_fix="Pass command arguments as a list and set shell=False (default behavior).",
                        confidence=0.95,
                        verification_status="verified_rule",
                        detection_source="Python AST Analyzer",
                        owasp_category=owasp_cat,
                        owasp_url=owasp_url,
                        cwe_id="CWE-78",
                        references=["https://cwe.mitre.org/data/definitions/78.html"]
                    ))

        # 4. Insecure Deserialization (pickle.loads, yaml.load without safe loader)
        if full_call in {"pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"} or (attr_name in {"loads", "load"} and "pickle" in full_call):
            owasp_cat, owasp_url, _ = get_owasp_mapping("insecure_deserialization")
            self.findings.append(Finding(
                finding_id=f"ast-pickle-{uuid.uuid4().hex[:6]}",
                title="Insecure Deserialization via pickle",
                description="Python's pickle module is not secure against erroneous or maliciously constructed data.",
                severity="Critical",
                category="insecure_deserialization",
                file_path=self.filename,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                evidence=self._get_evidence(node),
                why_it_matters="Pickle payloads can execute arbitrary Python callables during unpickling via __reduce__, resulting in full remote code execution.",
                recommended_fix="Never unpickle data from untrusted sources. Use safer data interchange formats such as JSON or Protocol Buffers.",
                confidence=0.98,
                verification_status="verified_rule",
                detection_source="Python AST Analyzer",
                owasp_category=owasp_cat,
                owasp_url=owasp_url,
                cwe_id="CWE-502",
                references=["https://cwe.mitre.org/data/definitions/502.html"]
            ))

        if full_call in {"yaml.load"} or (attr_name == "load" and "yaml" in full_call):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg in {"Loader"} and isinstance(kw.value, (ast.Name, ast.Attribute)):
                    val_id = getattr(kw.value, "id", "") or getattr(kw.value, "attr", "")
                    if "safe" in val_id.lower():
                        has_safe_loader = True
            if not has_safe_loader and len(node.args) < 2:
                owasp_cat, owasp_url, _ = get_owasp_mapping("insecure_deserialization")
                self.findings.append(Finding(
                    finding_id=f"ast-yaml-unsafe-{uuid.uuid4().hex[:6]}",
                    title="Unsafe YAML Loading via yaml.load()",
                    description="PyYAML's default yaml.load() can instantiate arbitrary Python objects.",
                    severity="High",
                    category="insecure_deserialization",
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    evidence=self._get_evidence(node),
                    why_it_matters="Malicious YAML tags like !!python/object/apply can trigger arbitrary code execution during parsing.",
                    recommended_fix="Use yaml.safe_load(data) instead of yaml.load().",
                    confidence=0.95,
                    verification_status="verified_rule",
                    detection_source="Python AST Analyzer",
                    owasp_category=owasp_cat,
                    owasp_url=owasp_url,
                    cwe_id="CWE-502",
                    references=["https://cwe.mitre.org/data/definitions/502.html"]
                ))

        # 5. Disabled TLS Verification (requests.get/post/etc verify=False)
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                owasp_cat, owasp_url, _ = get_owasp_mapping("tls_disabled")
                self.findings.append(Finding(
                    finding_id=f"ast-tls-disabled-{uuid.uuid4().hex[:6]}",
                    title="Disabled TLS Certificate Verification (verify=False)",
                    description="Passing verify=False disables SSL/TLS certificate validation in network requests.",
                    severity="Medium",
                    category="tls_disabled",
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    evidence=self._get_evidence(node),
                    why_it_matters="Allows man-in-the-middle (MITM) attackers to intercept and tamper with encrypted communications and credentials.",
                    recommended_fix="Keep certificate verification enabled (verify=True or provide path to a trusted CA bundle).",
                    confidence=0.95,
                    verification_status="verified_rule",
                    detection_source="Python AST Analyzer",
                    owasp_category=owasp_cat,
                    owasp_url=owasp_url,
                    cwe_id="CWE-295",
                    references=["https://cwe.mitre.org/data/definitions/295.html"]
                ))

        # 6. Weak Cryptography (hashlib.md5, hashlib.sha1)
        if full_call in {"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new"} or (attr_name in {"md5", "sha1"} and "hashlib" in full_call):
            owasp_cat, owasp_url, _ = get_owasp_mapping("weak_crypto")
            self.findings.append(Finding(
                finding_id=f"ast-weak-hash-{uuid.uuid4().hex[:6]}",
                title=f"Weak Cryptographic Hash Algorithm ({attr_name.upper()})",
                description=f"{attr_name.upper()} is cryptographically broken and vulnerable to collision attacks.",
                severity="Medium",
                category="weak_crypto",
                file_path=self.filename,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                evidence=self._get_evidence(node),
                why_it_matters="Collisions can be generated in reasonable time, breaking integrity verification or password hashing.",
                recommended_fix="Use SHA-256 (hashlib.sha256) for general hashing, or Argon2id / bcrypt for password storage.",
                confidence=0.9,
                verification_status="verified_rule",
                detection_source="Python AST Analyzer",
                owasp_category=owasp_cat,
                owasp_url=owasp_url,
                cwe_id="CWE-327",
                references=["https://cwe.mitre.org/data/definitions/327.html"]
            ))

        # 7. Insecure Temporary File (tempfile.mktemp)
        if full_call == "tempfile.mktemp" or (attr_name == "mktemp" and "tempfile" in full_call):
            owasp_cat, owasp_url, _ = get_owasp_mapping("insecure_temporary_file")
            self.findings.append(Finding(
                finding_id=f"ast-mktemp-{uuid.uuid4().hex[:6]}",
                title="Insecure Temporary File Generation via mktemp()",
                description="mktemp() returns a filename without creating the file, introducing a Time-of-Check to Time-of-Use (TOCTOU) race condition.",
                severity="Medium",
                category="insecure_temporary_file",
                file_path=self.filename,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                evidence=self._get_evidence(node),
                why_it_matters="An attacker can create a symlink at the destination between filename generation and file opening.",
                recommended_fix="Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() which atomically create and open the file.",
                confidence=0.95,
                verification_status="verified_rule",
                detection_source="Python AST Analyzer",
                owasp_category=owasp_cat,
                owasp_url=owasp_url,
                cwe_id="CWE-377",
                references=["https://cwe.mitre.org/data/definitions/377.html"]
            ))

        # 8. SQL query concatenation in cursor.execute
        if attr_name in {"execute", "executemany"}:
            if node.args and isinstance(node.args[0], ast.BinOp) and isinstance(node.args[0].op, ast.Add):
                owasp_cat, owasp_url, _ = get_owasp_mapping("sql_injection")
                self.findings.append(Finding(
                    finding_id=f"ast-sqli-concat-{uuid.uuid4().hex[:6]}",
                    title="SQL Query Constructed via String Concatenation",
                    description="Passing dynamically concatenated strings to execute() is a primary cause of SQL Injection.",
                    severity="High",
                    category="sql_injection",
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    evidence=self._get_evidence(node),
                    why_it_matters="Untrusted data can alter query structure to bypass authentication or extract sensitive data.",
                    recommended_fix="Use parameterized queries, e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)).",
                    confidence=0.92,
                    verification_status="verified_rule",
                    detection_source="Python AST Analyzer",
                    owasp_category=owasp_cat,
                    owasp_url=owasp_url,
                    cwe_id="CWE-89",
                    references=["https://cwe.mitre.org/data/definitions/89.html"]
                ))
            elif node.args and isinstance(node.args[0], ast.JoinedStr):  # f-string in SQL execute
                owasp_cat, owasp_url, _ = get_owasp_mapping("sql_injection")
                self.findings.append(Finding(
                    finding_id=f"ast-sqli-fstring-{uuid.uuid4().hex[:6]}",
                    title="SQL Query Constructed via Python f-string",
                    description="Interpolating variables directly into SQL queries via f-strings exposes the database to SQL Injection.",
                    severity="High",
                    category="sql_injection",
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    evidence=self._get_evidence(node),
                    why_it_matters="Allows attackers to manipulate query clauses and execute unauthorized SQL statements.",
                    recommended_fix="Use database driver parameterization with placeholders instead of string formatting.",
                    confidence=0.92,
                    verification_status="verified_rule",
                    detection_source="Python AST Analyzer",
                    owasp_category=owasp_cat,
                    owasp_url=owasp_url,
                    cwe_id="CWE-89",
                    references=["https://cwe.mitre.org/data/definitions/89.html"]
                ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Check for DEBUG = True or app.config['DEBUG'] = True
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name.upper() in {"DEBUG", "DEBUG_MODE"}:
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    owasp_cat, owasp_url, _ = get_owasp_mapping("debug_mode")
                    self.findings.append(Finding(
                        finding_id=f"ast-debug-enabled-{uuid.uuid4().hex[:6]}",
                        title="Debug Mode Explicitly Enabled",
                        description=f"Variable '{target_name}' is set to True, which may expose interactive debuggers or verbose errors.",
                        severity="Low",
                        category="debug_mode",
                        file_path=self.filename,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        evidence=self._get_evidence(node),
                        why_it_matters="In production, debug mode can leak environment secrets and provide interactive console execution.",
                        recommended_fix="Control debug mode via environment variables (e.g., os.getenv('DEBUG', 'False').lower() == 'true') and disable in production.",
                        confidence=0.88,
                        verification_status="verified_rule",
                        detection_source="Python AST Analyzer",
                        owasp_category=owasp_cat,
                        owasp_url=owasp_url,
                        cwe_id="CWE-489",
                        references=["https://cwe.mitre.org/data/definitions/489.html"]
                    ))

        self.generic_visit(node)


def analyze_python_ast(source_code: str, filename: str = "pasted-code") -> list[Finding]:
    """
    Parses Python code using ast and returns verified findings.
    Safely ignores syntax errors for non-Python or incomplete snippets.
    """
    try:
        tree = ast.parse(source_code, filename=filename)
        visitor = PythonASTVisitor(filename=filename, source_code=source_code)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return []
    except Exception:
        return []
