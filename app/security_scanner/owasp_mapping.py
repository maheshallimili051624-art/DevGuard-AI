"""
OWASP Top 10 (2021) and OWASP API Security Top 10 (2023) mapping metadata.
Official references:
- https://owasp.org/Top10/
- https://owasp.org/API-Security/
"""

OWASP_2021_MAPPINGS = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "categories": ["path_traversal", "auth_bypass", "privilege_escalation", "file_operations"]
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "categories": ["hardcoded_secrets", "weak_crypto", "tls_disabled", "insecure_hashing"]
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
        "categories": ["sql_injection", "command_injection", "xss", "dynamic_evaluation", "code_injection"]
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "categories": ["insecure_temporary_file", "business_logic", "unrestricted_resource"]
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "categories": ["debug_mode", "cors_misconfig", "insecure_defaults", "verbose_errors"]
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "categories": ["vulnerable_dependency", "outdated_library"]
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "categories": ["insecure_jwt", "weak_session", "hardcoded_credentials", "weak_auth"]
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "categories": ["insecure_deserialization", "untrusted_cdn", "unsigned_code"]
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "categories": ["missing_audit_log", "log_injection"]
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "categories": ["ssrf", "unvalidated_redirect"]
    }
}

OWASP_API_2023_MAPPINGS = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization (BOLA)",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "categories": ["bola", "id_enumeration"]
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        "categories": ["insecure_jwt", "hardcoded_credentials", "weak_auth"]
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
        "categories": ["ssrf"]
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "categories": ["debug_mode", "tls_disabled", "cors_misconfig"]
    }
}


def get_owasp_mapping(category_key: str) -> tuple[str, str, str]:
    """
    Returns (owasp_category_string, owasp_url, rationale).
    If no relevant category fits, returns ("", "", "").
    """
    category_key = category_key.lower()
    for item in OWASP_2021_MAPPINGS.values():
        if category_key in item["categories"]:
            rationale = f"Mapped to OWASP Top 10 (2021) {item['id']} ({item['name']}) based on detected pattern class '{category_key}'."
            return f"{item['id']} - {item['name']}", item["url"], rationale

    for item in OWASP_API_2023_MAPPINGS.values():
        if category_key in item["categories"]:
            rationale = f"Mapped to OWASP API Security Top 10 (2023) {item['id']} ({item['name']}) based on pattern '{category_key}'."
            return f"{item['id']} - {item['name']}", item["url"], rationale

    return "", "", ""
