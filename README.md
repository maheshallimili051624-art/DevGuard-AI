# DevGuard AI — Advanced Local-First AI Code Security Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Ollama: Supported](https://img.shields.io/badge/Ollama-Local%20AI-orange.svg)](https://ollama.com)

**DevGuard AI** is a professional, local-first code analysis, security auditing, and remediation platform. It combines deterministic static analysis rules and Python AST inspection with local Ollama language models (default: `gemma4:e2b`) to review code snippets, repositories, Git diffs, and package manifests—**without sending source code to external cloud AI APIs**.

---

## Key Features

- **Advanced AI Code Review**: Multi-language analysis (Python, JS, TS, Java, C/C++, Go, Rust, PHP, SQL) with configurable analysis types (`security`, `bugs`, `quality`, `performance`, `full_review`) and depths.
- **Deterministic Static Scanner & AST Engine**: Verified checks for SQL Injection, XSS, Command Injection, Unsafe `eval()`, Insecure Deserialization (`pickle`, unsafe YAML), Path Traversal, Disabled TLS Verification, Weak Cryptography (MD5/SHA1/DES), Insecure JWT Configurations, Insecure Temporary Files (`mktemp`), and Debug flags.
- **OWASP Top 10 & API Top 10 Mappings**: Automatic mapping to official OWASP Top 10 (2021) and OWASP API Security Top 10 (2023) categories with official references and CWE identifiers.
- **Automated Secret Redaction**: Identifies and redacts API keys (`sk-`, `ghp_`, AWS AKIA, Google AI, Stripe, Slack) and private cryptographic keys before prompt construction.
- **Repository & Archive Scanning**: In-memory ZIP archive unpacking with strict ZIP-slip path traversal prevention, file size bounds, directory exclusions (`.git`, `node_modules`, `.venv`), and safe local directory inspection.
- **AI Fix Generator & Safe Patching**: Generates unified diffs, expected behavior, and suggested verification tests. Enforces hash verification, explicit user approval, directory containment checks, and automatic timestamped backups (`<file>.bak.<ts>`).
- **Dependency Vulnerability Auditing**: Parses `requirements.txt`, `package.json`, `package-lock.json`, and `pyproject.toml` without executing dependencies. Optional online advisory querying via the OSV (Google Open Source Vulnerabilities) API with explicit network disclosures.
- **Error Explainer & Debugger**: Plain-language root cause breakdown, stack trace evidence analysis, step-by-step debugging steps, and proposed fixes tailored to developer experience levels (Beginner, Intermediate, Advanced).
- **Git Diff Security Review**: Local Git diff inspection analyzing newly introduced changes for potential bugs, regressions, error-handling gaps, and security risks.
- **Persistent Scan History & Comparison**: SQLite persistence with parameterized queries. Compare past scans, track risk scores, and delete stored metadata.
- **Standard Reports & SARIF 2.1.0 Export**: Download reports in Markdown, JSON, or OASIS SARIF 2.1.0 format for native integration into GitHub Advanced Security, VS Code SARIF Viewer, and CI/CD pipelines.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │          Web Browser UI                │
                      │    (Modern Dark Developer Dashboard)   │
                      └───────────────────▲────────────────────┘
                                          │ HTTP / REST
                      ┌───────────────────▼────────────────────┐
                      │           FastAPI Backend              │
                      │     (Validation & Route Handlers)      │
                      └───────┬──────────────┬──────────────┬──┘
                              │              │              │
             ┌────────────────▼──┐    ┌──────▼──────┐   ┌───▼────────────────┐
             │ Deterministic     │    │ SQLite DB   │   │ Local Ollama       │
             │ Security Engine   │    │ Scan History│   │ Inference Engine   │
             │ - Regex Rules     │    │ & Patches   │   │ (Default:          │
             │ - Python AST      │    │             │   │  gemma4:e2b)       │
             │ - Secret Redactor │    │             │   │                    │
             └───────────────────┘    └─────────────┘   └────────────────────┘
```

---

## Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.10 or newer (Python 3.12 recommended)
- **Ollama**: [Download Ollama](https://ollama.com/download)
- **Local Model**: This platform defaults to `gemma4:e2b`.

---

## Quick Start

### 1. Start Ollama and Pull the Model

Make sure the Ollama desktop service or daemon is running:

```bash
ollama pull gemma4:e2b
```

Verify your model is ready:

```bash
ollama list
```

### 2. Run on Windows

Simply double-click `run.bat` or run:

```cmd
run.bat
```

Or run manually using the virtual environment:

```cmd
py -m venv .venv
call .venv\Scripts\activate.bat
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 3. Run on macOS / Linux

```bash
chmod +x run.sh
./run.sh
```

Or manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 4. Open the Platform

Navigate to:
- **Web UI**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **System Health**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## Configuration

Configuration values can be set via environment variables or in a `.env` file (see `.env.example`):

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OLLAMA_URL` | `http://localhost:11434` | Endpoint for the local Ollama daemon |
| `OLLAMA_MODEL` | `gemma4:e2b` | Default Ollama model for code analysis |
| `OLLAMA_TIMEOUT` | `180` | Request timeout in seconds for local model calls |
| `DEVGUARD_DB_PATH` | `devguard.db` | Path to persistent SQLite database |
| `DEVGUARD_MAX_UPLOAD_MB` | `10` | Maximum ZIP archive upload size in megabytes |
| `DEVGUARD_MAX_FILE_BYTES` | `200000` | Maximum size in bytes per individual scanned file |
| `DEVGUARD_MAX_FILES` | `100` | Maximum number of source files analyzed per project |

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Checks Ollama connectivity and model availability |
| `GET` | `/api/models` | Discovers locally installed models in Ollama |
| `POST` | `/api/review` | Advanced structured AI code review |
| `POST` | `/api/analyze` | Backward-compatible snippet analysis endpoint |
| `POST` | `/api/analyze-archive` | Safe in-memory ZIP repository scan |
| `POST` | `/api/analyze-local` | Safe local directory scan on disk |
| `POST` | `/api/generate-fix` | Generates explanation, unified diff, and verification check |
| `POST` | `/api/apply-patch` | Safely applies user-approved patch with backup rollback |
| `POST` | `/api/explain-error` | Root-cause error explainer with debugging steps |
| `POST` | `/api/git-review` | Inspects Git commits and working-tree diffs |
| `POST` | `/api/scan-dependencies` | Offline manifest parser with optional OSV online lookup |
| `GET` | `/api/scans` | Lists persistent scan history from SQLite |
| `GET` | `/api/scans/{id}` | Fetches full scan findings, metadata, and files |
| `DELETE` | `/api/scans/{id}` | Deletes scan record from SQLite database |
| `GET` | `/api/scans/{id}/report` | Exports report in Markdown, JSON, or OASIS SARIF 2.1.0 |
| `POST` | `/api/scans/compare` | Compares two scans to track new/resolved issues |
| `GET` | `/api/settings` | Retrieves runtime settings |
| `POST` | `/api/settings` | Updates runtime configuration |

---

## Running Automated Tests

Run the full automated test suite covering deterministic rules, AST visitor, ZIP slip safety, SQLite persistence, SARIF export, patch rollback, and API endpoints:

```bash
python -m unittest discover -s tests -v
```

---

## Privacy & Security Disclosures

- **Localhost Bound**: The server binds to `127.0.0.1` by default and is designed solely for local execution. Do not expose this development server directly to the public internet.
- **No Cloud AI APIs**: Prompts are transmitted strictly to the local Ollama server running on your system.
- **Secret Redaction**: Pattern-based secret redaction masks identified credential patterns before constructing LLM prompts; however, heuristic secret detection cannot guarantee catching non-standard tokens. Always avoid placing real production secrets in source files.
- **Offline Core**: All core static analysis, AST analysis, and AI reviews operate entirely offline. If the optional online dependency check is toggled, network requests are explicitly made to `https://api.osv.dev` using only package names and versions.
- **Advisory Nature**: Heuristic findings and AI suggestions are advisory indicators requiring human developer review. They do not constitute formal proof of safety or vulnerability.

---

## License

This project is licensed under the [MIT License](LICENSE).
