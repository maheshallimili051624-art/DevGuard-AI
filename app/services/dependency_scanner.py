import json
import re
from datetime import datetime, timezone
from typing import Optional
import requests
from app.schemas import DependencyScanRequest, DependencyScanResponse, DependencyVulnerability, SeverityLevel


def parse_requirements_txt(content: str) -> list[tuple[str, str, str]]:
    """
    Parses requirements.txt lines without executing code.
    Returns list of (package_name, version_spec, ecosystem).
    """
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Split on comments or environment markers
        line = line.split("#")[0].split(";")[0].strip()
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$", line)
        if match:
            pkg_name = match.group(1).lower()
            version_spec = (match.group(2) or "").strip()
            # Clean exact version e.g. ==2.3.1 -> 2.3.1
            clean_ver = re.sub(r"^[=><~^! ]+", "", version_spec) or "unknown"
            packages.append((pkg_name, clean_ver, "PyPI"))
    return packages


def parse_package_json(content: str) -> list[tuple[str, str, str]]:
    """
    Parses package.json or package-lock.json.
    Returns list of (package_name, version, ecosystem).
    """
    packages = []
    try:
        data = json.loads(content)
        # 1. Standard dependencies & devDependencies
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, ver in deps.items():
            clean_ver = re.sub(r"^[\^~>=< ]+", "", str(ver)) or "unknown"
            packages.append((name, clean_ver, "npm"))

        # 2. If package-lock.json format
        if "packages" in data and isinstance(data["packages"], dict):
            for path_key, info in data["packages"].items():
                if not path_key or not isinstance(info, dict):
                    continue
                name = path_key.replace("node_modules/", "")
                ver = info.get("version", "unknown")
                if name and ver != "unknown":
                    packages.append((name, ver, "npm"))
    except json.JSONDecodeError:
        pass
    return packages


def parse_pyproject_toml(content: str) -> list[tuple[str, str, str]]:
    """
    Parses pyproject.toml dependencies without executing external tools.
    """
    packages = []
    in_dependencies = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_dependencies = "dependencies" in line.lower()
            continue
        if in_dependencies:
            # e.g., "fastapi>=0.115"
            match = re.search(r'["\']([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*?)?["\']', line)
            if match:
                pkg_name = match.group(1).lower()
                ver_spec = (match.group(2) or "").strip()
                clean_ver = re.sub(r"^[=><~^! ]+", "", ver_spec) or "unknown"
                packages.append((pkg_name, clean_ver, "PyPI"))
    return packages


def query_osv_vulnerability(package_name: str, version: str, ecosystem: str) -> list[DependencyVulnerability]:
    """
    Queries the official OSV API (https://api.osv.dev/v1/query) for a specific package.
    """
    if version == "unknown" or not version:
        return []

    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }

    try:
        resp = requests.post(url, json=payload, timeout=6)
        if resp.status_code != 200:
            return []
        data = resp.json()
        vulns = data.get("vulns", [])
        results = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for v in vulns:
            vid = v.get("id", "UNKNOWN-VULN")
            summary = v.get("summary") or v.get("details") or "No summary provided."
            # Estimate severity from database_specific or cvss if present
            sev: SeverityLevel = "High"
            if "CRITICAL" in str(v).upper():
                sev = "Critical"
            elif "LOW" in str(v).upper():
                sev = "Low"
            elif "MODERATE" in str(v).upper() or "MEDIUM" in str(v).upper():
                sev = "Medium"

            fixed = None
            affected_ranges = []
            for aff in v.get("affected", []):
                for r in aff.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                        if "introduced" in ev:
                            affected_ranges.append(f">={ev['introduced']}")

            advisory_url = f"https://osv.dev/vulnerability/{vid}"
            for ref in v.get("references", []):
                if ref.get("type") in {"ADVISORY", "WEB"}:
                    advisory_url = ref.get("url", advisory_url)
                    break

            results.append(DependencyVulnerability(
                ecosystem=ecosystem,
                package_name=package_name,
                installed_version=version,
                vulnerability_id=vid,
                severity=sev,
                summary=summary[:300],
                affected_versions=", ".join(affected_ranges) or "Specific range",
                fixed_version=fixed,
                advisory_url=advisory_url,
                source="OSV Database (Google Open Source Vulnerabilities)",
                last_checked=now_iso
            ))
        return results
    except Exception:
        return []


def scan_dependencies(req: DependencyScanRequest) -> DependencyScanResponse:
    content = req.content
    m_type = req.manifest_type

    if m_type == "auto":
        if "{" in content and ("dependencies" in content or "devDependencies" in content):
            m_type = "package.json"
        elif "[tool." in content or "[project" in content:
            m_type = "pyproject.toml"
        else:
            m_type = "requirements.txt"

    if m_type in {"package.json", "package-lock.json"}:
        packages = parse_package_json(content)
    elif m_type == "pyproject.toml":
        packages = parse_pyproject_toml(content)
    else:
        packages = parse_requirements_txt(content)

    vulnerabilities: list[DependencyVulnerability] = []
    online_performed = False
    notice = "Local parsing complete. Dependencies identified without executing package code."

    if req.enable_online_lookup:
        online_performed = True
        notice += " Online check performed via OSV API (api.osv.dev). Network disclosure: Only package names and versions were queried."
        # Bound online lookups to first 30 packages to avoid network latency
        for pkg, ver, eco in packages[:30]:
            found_vulns = query_osv_vulnerability(pkg, ver, eco)
            vulnerabilities.extend(found_vulns)
    else:
        notice += " Online advisory scanning is currently disabled. Toggle 'Enable Online Lookup' to query the OSV vulnerability database."

    return DependencyScanResponse(
        manifest_type=m_type,
        packages_parsed=len(packages),
        vulnerabilities_found=len(vulnerabilities),
        vulnerabilities=vulnerabilities,
        online_lookup_performed=online_performed,
        notice=notice
    )
