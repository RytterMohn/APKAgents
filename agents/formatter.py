"""
Formatter Agent.
"""

import json
import os
from typing import Dict, List

from .base import AgentContext, AgentResult, BaseAgent


class FormatterAgent(BaseAgent):
    """Write final markdown, html and json reports."""

    def __init__(self, config: Dict = None):
        super().__init__("Formatter", config)
        self.template_dir = (config or {}).get("template_dir", "templates")

    def get_required_inputs(self) -> List[str]:
        return ["report_data"]

    def get_output_schema(self) -> Dict:
        return {
            "formatted_output": "dict",
            "markdown_report": "str",
            "html_report": "str",
            "json_report": "str",
        }

    def _format_markdown(self, data: Dict) -> str:
        apk_info = data.get("apk_info", {})
        components = data.get("components", {})
        permissions = data.get("permissions", [])
        vulnerabilities = data.get("vulnerabilities", [])
        malware_indicators = data.get("malware_indicators", [])
        sensitive_data = data.get("sensitive_data", [])
        network_calls = data.get("network_calls", [])
        crypto_usage = data.get("crypto_usage", [])
        llm_summary = data.get("llm_summary", {}) or {}
        llm_triage = data.get("llm_triage", {}) or {}
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)
        analysis_date = data.get("analysis_date", "")
        exported = components.get("exported_counts", {}) or {}

        lines = [
            "# APK Security Analysis Report",
            "",
            f"- Analysis date: `{analysis_date}`",
            f"- Package: `{apk_info.get('package_name', 'N/A')}`",
            f"- Version: `{apk_info.get('version_name', 'N/A')}` (`{apk_info.get('version_code', 'N/A')}`)",
            f"- Min SDK: `{apk_info.get('min_sdk', 'N/A')}`",
            f"- Target SDK: `{apk_info.get('target_sdk', 'N/A')}`",
            "",
            "## Summary",
            "",
            f"- Risk level: `{risk_level}`",
            f"- Risk score: `{risk_score}` / 100",
            f"- Vulnerabilities: `{len(vulnerabilities)}`",
            f"- Malware indicators: `{len(malware_indicators)}`",
            f"- Sensitive data findings: `{len(sensitive_data)}`",
        ]

        if llm_summary:
            lines.extend(
                [
                    "",
                    "## LLM Executive Summary",
                    "",
                    llm_summary.get("executive_summary", ""),
                ]
            )

            key_findings = llm_summary.get("key_findings", []) or []
            if key_findings:
                lines.extend(["", "### Key Findings", ""])
                lines.extend([f"- {item}" for item in key_findings])

            recommendations = llm_summary.get("recommendations", []) or []
            if recommendations:
                lines.extend(["", "### LLM Recommendations", ""])
                lines.extend([f"{index}. {item}" for index, item in enumerate(recommendations, 1)])

            residual_risks = llm_summary.get("residual_risks", []) or []
            if residual_risks:
                lines.extend(["", "### Residual Risks", ""])
                lines.extend([f"- {item}" for item in residual_risks])

        if llm_triage:
            priority_findings = llm_triage.get("priority_findings", []) or []
            if priority_findings:
                lines.extend(["", "## LLM Triage", ""])
                for item in priority_findings:
                    lines.append(f"- Candidate `{item.get('index', 'N/A')}`: {item.get('reason', '')}")

        lines.extend(["", "## Permissions", ""])
        if permissions:
            lines.extend([f"- `{perm}`" for perm in permissions])
        else:
            lines.append("- None")

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
                "## Vulnerabilities",
                "",
            ]
        )

        if vulnerabilities:
            for vuln in vulnerabilities[:20]:
                lines.extend(
                    [
                        f"### {vuln.get('name', 'Unknown')}",
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
                lines.append(f"- ... {len(vulnerabilities) - 20} more findings omitted")
        else:
            lines.append("- No rule-based vulnerability findings.")

        lines.extend(["", "## Malware Indicators", ""])
        if malware_indicators:
            for item in malware_indicators:
                lines.extend(
                    [
                        f"### {item.get('name', 'Unknown')}",
                        f"- Category: `{item.get('category', 'unknown')}`",
                        f"- Severity: `{item.get('severity', 'unknown')}`",
                        f"- Confidence: `{item.get('confidence', 'unknown')}`",
                        f"- Description: {item.get('description', '')}",
                        "",
                    ]
                )
        else:
            lines.append("- None")

        lines.extend(["", "## Sensitive Data", ""])
        if sensitive_data:
            for item in sensitive_data:
                lines.append(
                    f"- `{item.get('name', 'Unknown')}` at `{item.get('location', 'N/A')}`: `{item.get('matched', '')[:80]}`"
                )
        else:
            lines.append("- None")

        lines.extend(["", "## Network Calls", ""])
        if network_calls:
            for call in network_calls[:20]:
                lines.append(
                    f"- `{call.get('url', 'N/A')}` via `{call.get('class', 'N/A')}->{call.get('method', 'N/A')}`"
                )
        else:
            lines.append("- None")

        lines.extend(["", "## Crypto Usage", ""])
        if crypto_usage:
            for item in crypto_usage[:20]:
                lines.append(f"- `{item.get('type', 'unknown')}` in `{item.get('class', 'N/A')}`")
        else:
            lines.append("- None")

        lines.extend(["", "---", "", "*Generated by APKAgents*"])
        return "\n".join(lines)

    def _format_html(self, data: Dict) -> str:
        apk_info = data.get("apk_info", {})
        vulnerabilities = data.get("vulnerabilities", [])
        malware_indicators = data.get("malware_indicators", [])
        llm_summary = data.get("llm_summary", {}) or {}
        llm_triage = data.get("llm_triage", {}) or {}
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)

        vuln_html = "".join(
            [
                "<div class='card'>"
                f"<h3>{v.get('name', 'Unknown')}</h3>"
                f"<p><strong>Severity:</strong> {v.get('severity', 'unknown')}</p>"
                f"<p><strong>Location:</strong> <code>{v.get('location', 'N/A')}</code></p>"
                f"<p>{v.get('description', '')}</p>"
                "</div>"
                for v in vulnerabilities[:20]
            ]
        ) or "<p>No rule-based vulnerability findings.</p>"

        malware_html = "".join(
            [
                "<div class='card'>"
                f"<h3>{m.get('name', 'Unknown')}</h3>"
                f"<p><strong>Category:</strong> {m.get('category', 'unknown')}</p>"
                f"<p><strong>Severity:</strong> {m.get('severity', 'unknown')}</p>"
                f"<p>{m.get('description', '')}</p>"
                "</div>"
                for m in malware_indicators
            ]
        ) or "<p>No malware indicators.</p>"

        llm_block = ""
        if llm_summary:
            key_findings = "".join(f"<li>{item}</li>" for item in (llm_summary.get("key_findings", []) or []))
            recommendations = "".join(f"<li>{item}</li>" for item in (llm_summary.get("recommendations", []) or []))
            residual_risks = "".join(f"<li>{item}</li>" for item in (llm_summary.get("residual_risks", []) or []))
            llm_block = f"""
            <section>
              <h2>LLM Executive Summary</h2>
              <p>{llm_summary.get('executive_summary', '')}</p>
              <h3>Key Findings</h3>
              <ul>{key_findings}</ul>
              <h3>Recommendations</h3>
              <ol>{recommendations}</ol>
              <h3>Residual Risks</h3>
              <ul>{residual_risks}</ul>
            </section>
            """

        triage_block = ""
        priority_findings = llm_triage.get("priority_findings", []) or []
        if priority_findings:
            triage_items = "".join(
                f"<li>Candidate <code>{item.get('index', 'N/A')}</code>: {item.get('reason', '')}</li>"
                for item in priority_findings
            )
            triage_block = f"<section><h2>LLM Triage</h2><ul>{triage_items}</ul></section>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APK Security Analysis Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f5f7fb; color: #172033; }}
    main {{ max-width: 1000px; margin: 24px auto; background: white; padding: 24px; border-radius: 12px; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0 24px; }}
    .stat {{ background: #eef2ff; padding: 16px; border-radius: 10px; }}
    .card {{ border-left: 4px solid #2563eb; padding: 12px 16px; margin: 12px 0; background: #f8fafc; }}
    code {{ background: #e2e8f0; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <main>
    <h1>APK Security Analysis Report</h1>
    <p>Package: <code>{apk_info.get('package_name', 'N/A')}</code></p>
    <p>Version: <code>{apk_info.get('version_name', 'N/A')}</code> (<code>{apk_info.get('version_code', 'N/A')}</code>)</p>
    <div class="summary">
      <div class="stat"><strong>Risk level</strong><br>{risk_level}</div>
      <div class="stat"><strong>Risk score</strong><br>{risk_score}/100</div>
      <div class="stat"><strong>Vulnerabilities</strong><br>{len(vulnerabilities)}</div>
      <div class="stat"><strong>Malware indicators</strong><br>{len(malware_indicators)}</div>
    </div>
    {llm_block}
    {triage_block}
    <h2>Vulnerabilities</h2>
    {vuln_html}
    <h2>Malware Indicators</h2>
    {malware_html}
  </main>
</body>
</html>"""

    def _format_json(self, data: Dict) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _save_markdown(self, output_dir: str, content: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "report.md")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def _save_html(self, output_dir: str, content: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "report.html")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def _save_json(self, output_dir: str, content: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "report.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def execute(self, context: AgentContext) -> AgentResult:
        self.log_info(context, "Formatting output")

        if not context.report_data:
            return AgentResult.error_result("No report data found")

        try:
            markdown_report = self._format_markdown(context.report_data)
            html_report = self._format_html(context.report_data)
            json_report = self._format_json(context.report_data)

            output_dir = context.output_dir
            markdown_path = self._save_markdown(output_dir, markdown_report)
            html_path = self._save_html(output_dir, html_report)
            json_path = self._save_json(output_dir, json_report)

            context.markdown_report = markdown_path
            context.html_report = html_path
            context.json_report = json_path
            context.formatted_output = {
                "markdown": markdown_path,
                "html": html_path,
                "json": json_path,
            }

            return AgentResult.success_result(
                message="Formatting completed",
                data={
                    "formatted_output": context.formatted_output,
                    "markdown_report": markdown_path,
                    "html_report": html_path,
                    "json_report": json_path,
                },
                artifacts=[markdown_path, html_path, json_path],
            )
        except Exception as exc:
            self.log_error(context, f"Formatting failed: {exc}")
            return AgentResult.error_result(f"Formatting failed: {exc}")
