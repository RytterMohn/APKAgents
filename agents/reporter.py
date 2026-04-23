"""
Reporter Agent.
"""

import json
import os
from datetime import datetime
from typing import Dict, List

from utils.llm import LLMError

from .base import AgentContext, AgentResult, BaseAgent


class ReporterAgent(BaseAgent):
    """Aggregate analysis results and write the primary report."""

    def __init__(self, config: Dict = None):
        super().__init__("Reporter", config)
        self.template_dir = (config or {}).get("template_dir", "templates")
        self.report_format = (config or {}).get("report_format", "markdown")

    def get_required_inputs(self) -> List[str]:
        return ["apk_info", "components", "permissions", "vulnerabilities"]

    def get_output_schema(self) -> Dict:
        return {"report_data": "dict", "report_path": "str"}

    def _build_llm_summary(self, context: AgentContext, report_data: Dict) -> Dict:
        client = self.get_llm_client(context)
        if not client:
            return {}

        payload = {
            "package_name": (report_data.get("apk_info") or {}).get("package_name", ""),
            "permissions": report_data.get("permissions", [])[:20],
            "risk_level": report_data.get("risk_level"),
            "risk_score": report_data.get("risk_score"),
            "components": {
                "activities": len((report_data.get("components") or {}).get("activities", [])),
                "exported": ((report_data.get("components") or {}).get("exported_counts") or {}),
            },
            "vulnerabilities": report_data.get("vulnerabilities", [])[:12],
            "sensitive_data": report_data.get("sensitive_data", [])[:10],
            "malware_indicators": report_data.get("malware_indicators", [])[:10],
            "llm_triage": context.llm_triage or {},
        }
        system_prompt = (
            "You are a senior Android application security reviewer. "
            "Return strict JSON only. "
            "Summarize the most important issues, likely false-positive caveats, and practical remediation order."
        )
        user_prompt = (
            "Create a concise executive summary for this APK scan. "
            "Return JSON with keys: executive_summary, key_findings, recommendations, residual_risks.\n"
            f"{json.dumps(payload, ensure_ascii=False)}"
        )

        try:
            return client.generate_json(system_prompt, user_prompt)
        except LLMError as exc:
            context.add_warning(f"LLM summary failed: {exc}")
            return {}

    def _aggregate_data(self, context: AgentContext) -> Dict:
        apk_info = getattr(context, "apk_info", {}) or {}
        components = getattr(context, "components", {}) or {}
        permissions = getattr(context, "permissions", []) or []
        sensitive_apis = getattr(context, "sensitive_apis", []) or []
        network_calls = getattr(context, "network_calls", []) or []
        crypto_usage = getattr(context, "crypto_usage", []) or []
        vulnerabilities = getattr(context, "vulnerabilities", []) or []
        malware_indicators = getattr(context, "malware_indicators", []) or []
        sensitive_data = getattr(context, "sensitive_data", []) or []
        risk_level = getattr(context, "risk_level", "unknown") or "unknown"
        risk_score = getattr(context, "risk_score", 0) or 0

        report_data = {
            "apk_info": apk_info,
            "components": components,
            "permissions": permissions,
            "sensitive_apis": sensitive_apis,
            "network_calls": network_calls,
            "crypto_usage": crypto_usage,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "malware_indicators": malware_indicators,
            "sensitive_data": sensitive_data,
            "sensitive_data_count": len(sensitive_data),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "warnings": getattr(context, "warnings", []),
            "errors": getattr(context, "errors", []),
            "llm_triage": context.llm_triage or {},
        }
        llm_summary = self._build_llm_summary(context, report_data)
        if llm_summary:
            report_data["llm_summary"] = llm_summary
            context.llm_summary = llm_summary
        return report_data

    def _generate_markdown_report(self, data: Dict) -> str:
        apk_info = data.get("apk_info", {})
        components = data.get("components", {})
        permissions = data.get("permissions", [])
        vulnerabilities = data.get("vulnerabilities", [])
        malware_indicators = data.get("malware_indicators", [])
        sensitive_data = data.get("sensitive_data", [])
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)
        analysis_date = data.get("analysis_date", "")
        exported = components.get("exported_counts", {}) or {}
        llm_summary = data.get("llm_summary", {}) or {}

        lines = [
            "# APK Analysis Report",
            "",
            "## Basic Info",
            "",
            f"- Package: `{apk_info.get('package_name', 'N/A')}`",
            f"- Version: `{apk_info.get('version_name', 'N/A')}` (`{apk_info.get('version_code', 'N/A')}`)",
            f"- Min SDK: `{apk_info.get('min_sdk', 'N/A')}`",
            f"- Target SDK: `{apk_info.get('target_sdk', 'N/A')}`",
            f"- Analysis Date: `{analysis_date}`",
            "",
            "## Risk Summary",
            "",
            f"- Risk Level: `{risk_level}`",
            f"- Risk Score: `{risk_score}` / 100",
            f"- Vulnerabilities: `{len(vulnerabilities)}`",
            f"- Malware Indicators: `{len(malware_indicators)}`",
            f"- Sensitive Data Findings: `{len(sensitive_data)}`",
        ]

        if llm_summary:
            lines.extend(
                [
                    "",
                    "## LLM Executive Summary",
                    "",
                    llm_summary.get("executive_summary", ""),
                    "",
                ]
            )
            key_findings = llm_summary.get("key_findings", []) or []
            if key_findings:
                lines.append("### Key Findings")
                lines.extend([f"- {item}" for item in key_findings])
                lines.append("")

        lines.extend(["## Permissions", ""])
        if permissions:
            lines.extend([f"- `{perm}`" for perm in permissions[:50]])
            if len(permissions) > 50:
                lines.append(f"- ... and {len(permissions) - 50} more")
        else:
            lines.append("- None detected")

        lines.extend(
            [
                "",
                "## Components",
                "",
                f"- Activities: `{len(components.get('activities', []))}` (`{exported.get('activities', 0)}` exported)",
                f"- Services: `{len(components.get('services', []))}` (`{exported.get('services', 0)}` exported)",
                f"- Receivers: `{len(components.get('receivers', []))}` (`{exported.get('receivers', 0)}` exported)",
                f"- Providers: `{len(components.get('providers', []))}` (`{exported.get('providers', 0)}` exported)",
                "",
                "## Findings",
                "",
            ]
        )

        if vulnerabilities:
            for vuln in vulnerabilities[:20]:
                lines.extend(
                    [
                        f"### {vuln.get('name', 'Unknown')}",
                        "",
                        f"- ID: `{vuln.get('id', 'N/A')}`",
                        f"- Severity: `{vuln.get('severity', 'unknown')}`",
                        f"- CWE: `{vuln.get('cwe', 'N/A')}`",
                        f"- CVSS: `{vuln.get('cvss', 'N/A')}`",
                        f"- Location: `{vuln.get('location', 'N/A')}`",
                        f"- Description: {vuln.get('description', 'N/A')}",
                        f"- Remediation: {vuln.get('remediation', 'N/A')}",
                        "",
                    ]
                )
            if len(vulnerabilities) > 20:
                lines.append(f"- ... {len(vulnerabilities) - 20} additional findings omitted from markdown summary")
        else:
            lines.append("- No vulnerabilities detected")

        if malware_indicators:
            lines.extend(["", "## Malware Indicators", ""])
            for item in malware_indicators:
                lines.append(
                    f"- `{item.get('name', 'Unknown')}` ({item.get('severity', 'unknown')}): {item.get('description', '')}"
                )

        if sensitive_data:
            lines.extend(["", "## Sensitive Data", ""])
            for item in sensitive_data:
                lines.append(
                    f"- `{item.get('name', 'Unknown')}` at `{item.get('location', 'N/A')}`: `{item.get('matched', '')[:80]}`"
                )

        lines.extend(["", "## Recommendations", ""])
        recommendations = llm_summary.get("recommendations") or self.get_recommendations(vulnerabilities)
        for index, rec in enumerate(recommendations, 1):
            lines.append(f"{index}. {rec}")

        residual_risks = llm_summary.get("residual_risks", []) or []
        if residual_risks:
            lines.extend(["", "## Residual Risks", ""])
            lines.extend([f"- {item}" for item in residual_risks])

        lines.extend(["", "---", "", "*Generated by APKAgents*"])
        return "\n".join(lines)

    def _generate_json_report(self, data: Dict) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _generate_html_report(self, data: Dict) -> str:
        apk_info = data.get("apk_info", {})
        vulnerabilities = data.get("vulnerabilities", [])
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)
        llm_summary = data.get("llm_summary", {}) or {}

        items = []
        for vuln in vulnerabilities[:20]:
            items.append(
                "<div class='finding'>"
                f"<h3>{vuln.get('name', 'Unknown')}</h3>"
                f"<p><strong>Severity:</strong> {vuln.get('severity', 'unknown')}</p>"
                f"<p><strong>Location:</strong> <code>{vuln.get('location', 'N/A')}</code></p>"
                f"<p>{vuln.get('description', '')}</p>"
                "</div>"
            )

        if not items:
            items.append("<p>No vulnerabilities detected.</p>")

        llm_block = ""
        if llm_summary:
            llm_block = (
                "<section><h2>LLM Executive Summary</h2>"
                f"<p>{llm_summary.get('executive_summary', '')}</p>"
                "</section>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APK Analysis Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; background: #f7f7f7; color: #222; }}
    main {{ max-width: 960px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 8px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #eee; }}
    .finding {{ border-left: 4px solid #d97706; padding: 12px 16px; margin: 12px 0; background: #fffbeb; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <main>
    <h1>APK Analysis Report</h1>
    <p>Package: <code>{apk_info.get('package_name', 'N/A')}</code></p>
    <p>Version: <code>{apk_info.get('version_name', 'N/A')}</code> (<code>{apk_info.get('version_code', 'N/A')}</code>)</p>
    <p>Risk: <span class="badge">{risk_level}</span> Score: <strong>{risk_score}</strong>/100</p>
    {llm_block}
    <h2>Findings</h2>
    {''.join(items)}
  </main>
</body>
</html>"""

    def _generate_report(self, data: Dict) -> str:
        if self.report_format == "json":
            return self._generate_json_report(data)
        if self.report_format == "html":
            return self._generate_html_report(data)
        return self._generate_markdown_report(data)

    def _save_report(self, context: AgentContext, content: str) -> str:
        os.makedirs(context.output_dir, exist_ok=True)
        package_name = (getattr(context, "apk_info", {}) or {}).get("package_name", "app")
        extension = {"json": "json", "html": "html"}.get(self.report_format, "md")
        report_path = os.path.join(context.output_dir, f"{package_name}_report.{extension}")
        with open(report_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return report_path

    def get_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        if not vulnerabilities:
            return [
                "Keep dependencies up to date and rerun static analysis regularly.",
                "Review exported components and permission usage before release.",
            ]

        recommendations = []
        seen = set()
        mapping = {
            "VULN-001": "Review WebView configuration and disable unnecessary JavaScript exposure.",
            "VULN-002": "Restrict broadcast and intent flows with explicit permissions.",
            "VULN-003": "Use SecureRandom instead of predictable random sources.",
            "VULN-004": "Fix certificate validation and avoid insecure TrustManager implementations.",
            "VULN-005": "Disable debug flags in release builds.",
            "VULN-006": "Review addJavascriptInterface exposure and reduce reachable methods.",
            "VULN-007": "Use private file modes and tighten filesystem permissions.",
            "VULN-008": "Remove sensitive data from logs in production builds.",
            "VULN-009": "Avoid loading code from untrusted paths at runtime.",
            "VULN-010": "Use parameterized queries to prevent SQL injection.",
        }
        for vuln in vulnerabilities:
            vuln_id = vuln.get("id")
            if vuln_id in mapping and vuln_id not in seen:
                recommendations.append(mapping[vuln_id])
                seen.add(vuln_id)
        if len(recommendations) < 2:
            recommendations.append("Prioritize high-severity findings first and verify fixes with another scan.")
        return recommendations

    def execute(self, context: AgentContext) -> AgentResult:
        self.log_info(context, "Generating report")

        try:
            report_data = self._aggregate_data(context)
            report_content = self._generate_report(report_data)
            report_path = self._save_report(context, report_content)
            context.report_data = report_data
            context.report_path = report_path
            return AgentResult.success_result(
                message="Report generated",
                data={"report_data": report_data, "report_path": report_path},
                artifacts=[report_path],
            )
        except Exception as exc:
            self.log_error(context, f"Report generation failed: {exc}")
            return AgentResult.error_result(f"Report generation failed: {exc}")
