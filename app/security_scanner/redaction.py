import re

SECRET_PATTERNS = [
    # Generic credential assignment: password/secret/api_key/access_token = "..."
    re.compile(r"(?i)(api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
    # Private Key blocks
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    # OpenAI API Keys
    re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
    # GitHub Personal Access Tokens
    re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b"),
    # AWS Access Key IDs
    re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    # Stripe live keys
    re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    # Google API Keys
    re.compile(r"\bAIzaSy[0-9A-Za-z\-_]{33}\b")
]


def scrub_secrets(text: str) -> tuple[str, int]:
    """
    Replaces identified secret patterns with [REDACTED_POSSIBLE_SECRET].
    Returns (cleaned_text, total_redactions_count).
    """
    count = 0
    cleaned = text
    for pattern in SECRET_PATTERNS:
        cleaned, n = pattern.subn("[REDACTED_POSSIBLE_SECRET]", cleaned)
        count += n
    return cleaned, count
