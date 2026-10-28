from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DATABASE_PATH = os.getenv("DEVGUARD_DB_PATH", str(BASE_DIR / "devguard.db"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:e2b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))

# Analysis and archive constraints
MAX_UPLOAD_MB = int(os.getenv("DEVGUARD_MAX_UPLOAD_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_FILE_BYTES = int(os.getenv("DEVGUARD_MAX_FILE_BYTES", "200000"))
MAX_FILES = int(os.getenv("DEVGUARD_MAX_FILES", "100"))
MAX_CONTEXT_CHARS = int(os.getenv("DEVGUARD_MAX_CONTEXT_CHARS", "100000"))
ANALYSIS_TIMEOUT_SECONDS = int(os.getenv("DEVGUARD_ANALYSIS_TIMEOUT", "180"))

ALLOWED_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".json",
    ".md", ".txt", ".java", ".c", ".cpp", ".h", ".hpp", ".go", ".rs", ".php",
    ".sql", ".yaml", ".yml", ".toml", ".sh", ".bat", ".ps1", ".rb"
}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".next", ".nuxt", "coverage", ".pytest_cache", ".mypy_cache",
    ".idea", ".vscode", "target", "vendor", "bin", "obj"
}

SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_dsa", "id_ed25519", "credentials", "secrets.json",
    "service-account.json", "jwt.key", "private.pem"
}
