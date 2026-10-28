import json
from app.schemas import ScanDetailResponse, Finding


def export_markdown_report(scan: ScanDetailResponse) -> str:
    s = scan.summary
    f_list = scan.findings

    lines = [
        f"# DevGuard AI Security & Quality Report",
        f"",
        f"- **Project Name:** {s.project_name}",
        f"- **Scan ID:** `{s.scan_id}`",
        f"- **Date (UTC):** {s.created_at}",
        f"- **Model Used:** `{s.model_name}`",
        f"- **Analysis Type:** {s.analysis_type}",
        f"- **Files Scanned:** {s.files_scanned_count}",
        f"- **Files Skipped:** {s.files_skipped_count}",
        f"- **Duration:** {s.duration_ms} ms",
        f"- **Calculated Risk Score:** {s.risk_score if s.risk_score is not None else 'N/A'}/100",
        f"",
        f"---",
        f"",
        f"## Findings Summary",
        f"",
        f"| Severity | Count |",
        f"| :--- | :--- |",
        f"| Critical | {s.critical_count} |",
        f"| High | {s.high_count} |",
        f"| Medium | {s.medium_count} |",
        f"| Low | {s.low_count} |",
        f"| Informational | {s.info_count} |",
        f"",
        f"---",
        f"",
        f"## Detailed Findings",
        f""
    ]

    if not f_list:
        lines.append("No security or quality findings were reported.")
    else:
        for idx, f in enumerate(f_list, 1):
            lines.extend([
                f"### {idx}. [{f.severity}] {f.title}",
                f"",
                f"- **Location:** `{f.file_path}` (Line: {f.start_line or 'N/A'})",
                f"- **Category:** `{f.category}`",
                f"- **OWASP Mapping:** {f.owasp_category or 'N/A'}",
                f"- **Confidence:** {int(f.confidence * 100)}% ({f.verification_status})",
                f"- **Source:** {f.detection_source}",
                f"",
                f"**Description:**",
                f"{f.description}",
                f"",
                f"**Why It Matters:**",
                f"{f.why_it_matters}",
                f"",
                f"**Evidence:**",
                f"```text",
                f"{f.evidence or 'None'}",
                f"```",
                f"",
                f"**Recommended Fix:**",
                f"{f.recommended_fix}",
                f"",
                f"---"
            ])

    lines.extend([
        f"",
        f"## AI Analysis & Recommendations",
        f"",
        scan.ai_report,
        f"",
        f"---",
        f"*Report generated locally by DevGuard AI. Findings are advisory and require engineering verification.*"
    ])

    return "\n".join(lines)


def export_json_report(scan: ScanDetailResponse) -> str:
    return scan.model_dump_json(indent=2)


def severity_to_sarif_level(sev: str) -> str:
    sev_upper = (sev or "").upper()
    if sev_upper in {"CRITICAL", "HIGH"}:
        return "error"
    elif sev_upper == "MEDIUM":
        return "warning"
    elif sev_upper in {"LOW", "INFO"}:
        return "note"
    return "none"


def export_sarif_report(scan: ScanDetailResponse) -> dict:
    """
    Exports findings in OASIS SARIF 2.1.0 standard schema.
    Valid schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
    """
    rules_dict = {}
    results = []

    for f in scan.findings:
        if f.category == "clean_scan":
            continue

        rule_id = f.finding_id.split("-")[0] if "-" in f.finding_id else f.finding_id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity)
                },
                "helpUri": f.owasp_url or "https://owasp.org",
                "properties": {
                    "tags": [f.category, f.owasp_category or "Security"]
                }
            }

        start_line = max(1, f.start_line or 1)
        res = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(f.severity),
            "message": {
                "text": f"{f.title}: {f.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": start_line,
                            "endLine": max(start_line, f.end_line or start_line)
                        }
                    }
                }
            ]
        }
        results.append(res)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DevGuard AI",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/DevGuard-AI",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": results
            }
        ]
    }
    return sarif
