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
            "# APK 安全分析报告",
            "",
            f"- 分析时间：`{analysis_date}`",
            f"- 包名：`{apk_info.get('package_name', 'N/A')}`",
            f"- 版本：`{apk_info.get('version_name', 'N/A')}` (`{apk_info.get('version_code', 'N/A')}`)",
            f"- 最低 SDK：`{apk_info.get('min_sdk', 'N/A')}`",
            f"- 目标 SDK：`{apk_info.get('target_sdk', 'N/A')}`",
            "",
            "## 风险概览",
            "",
            f"- 风险等级：`{risk_level}`",
            f"- 风险评分：`{risk_score}` / 100",
            f"- 规则漏洞：`{len(vulnerabilities)}`",
            f"- 恶意指标：`{len(malware_indicators)}`",
            f"- 敏感数据：`{len(sensitive_data)}`",
        ]

        if llm_summary:
            lines.extend(
                [
                    "",
                    "## LLM 总结",
                    "",
                    llm_summary.get("executive_summary", ""),
                ]
            )

            key_findings = llm_summary.get("key_findings", []) or []
            if key_findings:
                lines.extend(["", "### 重点问题", ""])
                lines.extend([f"- {item}" for item in key_findings])

            recommendations = llm_summary.get("recommendations", []) or []
            if recommendations:
                lines.extend(["", "### 修复建议", ""])
                lines.extend([f"{index}. {item}" for index, item in enumerate(recommendations, 1)])

            residual_risks = llm_summary.get("residual_risks", []) or []
            if residual_risks:
                lines.extend(["", "### 残余风险", ""])
                lines.extend([f"- {item}" for item in residual_risks])

        if llm_triage:
            priority_findings = llm_triage.get("priority_findings", []) or []
            if priority_findings:
                lines.extend(["", "## LLM 复核", ""])
                for item in priority_findings:
                    lines.append(f"- 候选项 `{item.get('index', 'N/A')}`：{item.get('reason', '')}")

        lines.extend(["", "## 权限信息", ""])
        if permissions:
            lines.extend([f"- `{perm}`" for perm in permissions])
        else:
            lines.append("- 无")

        lines.extend(
            [
                "",
                "## 组件暴露面",
                "",
                f"- Activity：`{len(components.get('activities', []))}`（导出 `{exported.get('activities', 0)}`）",
                f"- Service：`{len(components.get('services', []))}`（导出 `{exported.get('services', 0)}`）",
                f"- Receiver：`{len(components.get('receivers', []))}`（导出 `{exported.get('receivers', 0)}`）",
                f"- Provider：`{len(components.get('providers', []))}`（导出 `{exported.get('providers', 0)}`）",
                "",
                "## 规则扫描结果",
                "",
            ]
        )

        if vulnerabilities:
            for vuln in vulnerabilities[:20]:
                lines.extend(
                    [
                        f"### {vuln.get('name', 'Unknown')}",
                        f"- ID：`{vuln.get('id', 'N/A')}`",
                        f"- 严重程度：`{vuln.get('severity', 'unknown')}`",
                        f"- CWE：`{vuln.get('cwe', 'N/A')}`",
                        f"- CVSS：`{vuln.get('cvss', 'N/A')}`",
                        f"- 位置：`{vuln.get('location', 'N/A')}`",
                        f"- 描述：{vuln.get('description', 'N/A')}",
                        f"- 修复建议：{vuln.get('remediation', 'N/A')}",
                        "",
                    ]
                )
            if len(vulnerabilities) > 20:
                lines.append(f"- 其余 {len(vulnerabilities) - 20} 条规则命中已省略")
        else:
            lines.append("- 未发现规则漏洞")

        lines.extend(["", "## 恶意软件指标", ""])
        if malware_indicators:
            for item in malware_indicators:
                lines.extend(
                    [
                        f"### {item.get('name', 'Unknown')}",
                        f"- 类别：`{item.get('category', 'unknown')}`",
                        f"- 严重程度：`{item.get('severity', 'unknown')}`",
                        f"- 置信度：`{item.get('confidence', 'unknown')}`",
                        f"- 描述：{item.get('description', '')}",
                        "",
                    ]
                )
        else:
            lines.append("- 无")

        lines.extend(["", "## 敏感数据结果", ""])
        if sensitive_data:
            for item in sensitive_data:
                lines.append(
                    f"- `{item.get('name', 'Unknown')}` @ `{item.get('location', 'N/A')}`：`{item.get('matched', '')[:80]}`"
                )
        else:
            lines.append("- 无")

        lines.extend(["", "## 网络通信", ""])
        if network_calls:
            for call in network_calls[:20]:
                lines.append(
                    f"- `{call.get('url', 'N/A')}` via `{call.get('class', 'N/A')}->{call.get('method', 'N/A')}`"
                )
        else:
            lines.append("- 无")

        lines.extend(["", "## 加密相关", ""])
        if crypto_usage:
            for item in crypto_usage[:20]:
                lines.append(f"- `{item.get('type', 'unknown')}` in `{item.get('class', 'N/A')}`")
        else:
            lines.append("- 无")

        lines.extend(["", "---", "", "*Generated by APKAgents*"])
        return "\n".join(lines)

    def _format_html(self, data: Dict) -> str:
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

        risk_class = f"risk-{risk_level.lower()}"

        def render_list(items: List[str]) -> str:
            if not items:
                return "<p class='empty'>无</p>"
            return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"

        llm_block = ""
        if llm_summary:
            llm_block = f"""
            <section class="panel panel-highlight">
              <div class="panel-head">
                <h2>LLM 结论</h2>
                <span class="pill">AI Review</span>
              </div>
              <p class="lead">{llm_summary.get('executive_summary', '')}</p>
              <div class="two-col">
                <div>
                  <h3>重点问题</h3>
                  {render_list(llm_summary.get('key_findings', []) or [])}
                </div>
                <div>
                  <h3>修复建议</h3>
                  <ol>{"".join(f"<li>{item}</li>" for item in (llm_summary.get('recommendations', []) or []))}</ol>
                </div>
              </div>
              <h3>残余风险</h3>
              {render_list(llm_summary.get('residual_risks', []) or [])}
            </section>
            """

        triage_block = ""
        priority_findings = llm_triage.get("priority_findings", []) or []
        if priority_findings:
            triage_block = (
                "<section class='panel'><div class='panel-head'><h2>LLM 复核</h2></div><ul>"
                + "".join(
                    f"<li><code>{item.get('index', 'N/A')}</code> {item.get('reason', '')}</li>"
                    for item in priority_findings
                )
                + "</ul></section>"
            )

        vuln_html = "".join(
            [
                "<article class='finding-card'>"
                f"<div class='finding-meta'><span class='badge severity-{v.get('severity', 'unknown')}'>{v.get('severity', 'unknown')}</span><span>{v.get('id', 'N/A')}</span></div>"
                f"<h3>{v.get('name', 'Unknown')}</h3>"
                f"<p>{v.get('description', '')}</p>"
                f"<p><strong>位置：</strong><code>{v.get('location', 'N/A')}</code></p>"
                f"<p><strong>修复建议：</strong>{v.get('remediation', '')}</p>"
                "</article>"
                for v in vulnerabilities[:20]
            ]
        ) or "<p class='empty'>未发现规则漏洞</p>"

        malware_html = "".join(
            [
                "<article class='finding-card compact'>"
                f"<div class='finding-meta'><span class='badge severity-{m.get('severity', 'unknown')}'>{m.get('severity', 'unknown')}</span><span>{m.get('category', 'unknown')}</span></div>"
                f"<h3>{m.get('name', 'Unknown')}</h3>"
                f"<p>{m.get('description', '')}</p>"
                f"<p><strong>置信度：</strong>{m.get('confidence', 'unknown')}</p>"
                "</article>"
                for m in malware_indicators
            ]
        ) or "<p class='empty'>未发现恶意软件指标</p>"

        sensitive_html = (
            "<div class='table-like'>"
            + "".join(
                f"<div class='row'><div>{item.get('name', 'Unknown')}</div><div><code>{item.get('location', 'N/A')}</code></div><div><code>{item.get('matched', '')[:80]}</code></div></div>"
                for item in sensitive_data[:20]
            )
            + "</div>"
            if sensitive_data
            else "<p class='empty'>未发现敏感数据</p>"
        )

        network_html = (
            "<ul class='mono-list'>"
            + "".join(
                f"<li><code>{call.get('url', 'N/A')}</code> via {call.get('class', 'N/A')}->{call.get('method', 'N/A')}</li>"
                for call in network_calls[:20]
            )
            + "</ul>"
            if network_calls
            else "<p class='empty'>未发现网络通信特征</p>"
        )

        crypto_html = (
            "<ul class='mono-list'>"
            + "".join(
                f"<li><code>{item.get('type', 'unknown')}</code> in {item.get('class', 'N/A')}</li>"
                for item in crypto_usage[:20]
            )
            + "</ul>"
            if crypto_usage
            else "<p class='empty'>未发现加密相关特征</p>"
        )

        permissions_html = render_list([f"<code>{perm}</code>" for perm in permissions]) if permissions else "<p class='empty'>无</p>"

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APK 安全分析报告</title>
  <style>
    :root {{
      --bg: #f4f1ea;
      --paper: #fffdf8;
      --ink: #1c1b19;
      --muted: #6f6a61;
      --line: #ddd4c5;
      --accent: #a23e2a;
      --accent-soft: #f4ddd5;
      --panel: #f9f5ee;
      --critical: #8b1e1e;
      --high: #b45309;
      --medium: #c98b00;
      --low: #2f6f4f;
      --info: #4a6fa5;
      --shadow: 0 16px 50px rgba(35, 28, 20, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      background:
        radial-gradient(circle at top right, rgba(162, 62, 42, 0.08), transparent 30%),
        linear-gradient(180deg, #f7f4ee 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    .page {{
      max-width: 1220px;
      margin: 32px auto;
      padding: 0 20px 40px;
    }}
    .hero {{
      background: linear-gradient(135deg, #fdf8f1 0%, #f5e7d7 100%);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 28px;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      right: -80px;
      top: -80px;
      width: 220px;
      height: 220px;
      border-radius: 50%;
      background: rgba(162, 62, 42, 0.08);
    }}
    .eyebrow {{
      display: inline-block;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(162, 62, 42, 0.12);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    h1 {{
      margin: 14px 0 10px;
      font-size: 36px;
      line-height: 1.1;
    }}
    .hero-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }}
    .meta-card {{
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(221, 212, 197, 0.9);
      border-radius: 16px;
      padding: 14px 16px;
      backdrop-filter: blur(6px);
    }}
    .meta-card .label {{
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .meta-card .value {{
      font-size: 18px;
      font-weight: 700;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0;
    }}
    .stat {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      box-shadow: var(--shadow);
    }}
    .stat .label {{
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 8px;
    }}
    .stat .value {{
      font-size: 28px;
      font-weight: 800;
    }}
    .risk-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 14px;
      border-radius: 999px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .risk-critical {{ background: rgba(139, 30, 30, 0.12); color: var(--critical); }}
    .risk-high {{ background: rgba(180, 83, 9, 0.12); color: var(--high); }}
    .risk-medium {{ background: rgba(201, 139, 0, 0.12); color: var(--medium); }}
    .risk-low {{ background: rgba(47, 111, 79, 0.12); color: var(--low); }}
    .risk-info {{ background: rgba(74, 111, 165, 0.12); color: var(--info); }}
    .layout {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 20px;
      margin-top: 20px;
    }}
    .panel {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 22px;
      box-shadow: var(--shadow);
      margin-bottom: 20px;
    }}
    .panel-highlight {{
      background: linear-gradient(180deg, #fffaf4 0%, #fff5ec 100%);
      border-color: #e8cbb9;
    }}
    .panel-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }}
    h2 {{
      margin: 0;
      font-size: 22px;
    }}
    h3 {{
      margin: 14px 0 8px;
      font-size: 16px;
    }}
    .pill {{
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
    }}
    .lead {{
      margin: 0;
      font-size: 15px;
      line-height: 1.8;
      color: #2b2925;
    }}
    .two-col {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 20px;
    }}
    ul, ol {{
      margin: 10px 0 0;
      padding-left: 20px;
      line-height: 1.75;
    }}
    .finding-list {{
      display: grid;
      gap: 14px;
    }}
    .finding-card {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      background: #fffefa;
    }}
    .finding-card.compact {{
      background: #faf7f1;
    }}
    .finding-card h3 {{
      margin-top: 8px;
      margin-bottom: 8px;
    }}
    .finding-meta {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      font-size: 12px;
      color: var(--muted);
    }}
    .badge {{
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .severity-critical {{ background: rgba(139, 30, 30, 0.12); color: var(--critical); }}
    .severity-high {{ background: rgba(180, 83, 9, 0.12); color: var(--high); }}
    .severity-medium {{ background: rgba(201, 139, 0, 0.14); color: var(--medium); }}
    .severity-low {{ background: rgba(47, 111, 79, 0.12); color: var(--low); }}
    .severity-info {{ background: rgba(74, 111, 165, 0.12); color: var(--info); }}
    .table-like {{
      border: 1px solid var(--line);
      border-radius: 14px;
      overflow: hidden;
    }}
    .row {{
      display: grid;
      grid-template-columns: 1fr 1.2fr 1.2fr;
      gap: 12px;
      padding: 12px 14px;
      border-top: 1px solid var(--line);
    }}
    .row:first-child {{
      border-top: 0;
    }}
    .mono-list {{
      list-style: none;
      padding: 0;
      margin: 0;
    }}
    .mono-list li {{
      padding: 10px 0;
      border-top: 1px solid var(--line);
    }}
    .mono-list li:first-child {{
      border-top: 0;
    }}
    code {{
      font-family: "Cascadia Code", "Consolas", monospace;
      background: #f2eee7;
      padding: 2px 6px;
      border-radius: 6px;
      word-break: break-all;
    }}
    .empty {{
      color: var(--muted);
      margin: 0;
    }}
    .footer {{
      text-align: center;
      color: var(--muted);
      font-size: 13px;
      margin-top: 8px;
    }}
    @media (max-width: 960px) {{
      .layout {{
        grid-template-columns: 1fr;
      }}
      .two-col {{
        grid-template-columns: 1fr;
      }}
      .row {{
        grid-template-columns: 1fr;
      }}
      h1 {{
        font-size: 28px;
      }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <span class="eyebrow">APKAgents Report</span>
      <h1>APK 安全分析报告</h1>
      <p class="lead">面向 APK 的自动化安全分析结果，结合规则扫描、结构化静态分析与 LLM 归纳，输出适合审计阅读的综合报告。</p>
      <div class="hero-meta">
        <div class="meta-card">
          <div class="label">包名</div>
          <div class="value"><code>{apk_info.get('package_name', 'N/A')}</code></div>
        </div>
        <div class="meta-card">
          <div class="label">版本</div>
          <div class="value">{apk_info.get('version_name', 'N/A')} ({apk_info.get('version_code', 'N/A')})</div>
        </div>
        <div class="meta-card">
          <div class="label">分析时间</div>
          <div class="value">{analysis_date}</div>
        </div>
      </div>
    </section>

    <section class="summary-grid">
      <div class="stat">
        <div class="label">风险等级</div>
        <div class="value"><span class="risk-pill {risk_class}">{risk_level}</span></div>
      </div>
      <div class="stat">
        <div class="label">风险评分</div>
        <div class="value">{risk_score}</div>
      </div>
      <div class="stat">
        <div class="label">规则漏洞</div>
        <div class="value">{len(vulnerabilities)}</div>
      </div>
      <div class="stat">
        <div class="label">恶意指标</div>
        <div class="value">{len(malware_indicators)}</div>
      </div>
      <div class="stat">
        <div class="label">敏感数据</div>
        <div class="value">{len(sensitive_data)}</div>
      </div>
      <div class="stat">
        <div class="label">导出 Activity</div>
        <div class="value">{exported.get('activities', 0)}</div>
      </div>
    </section>

    {llm_block}
    {triage_block}

    <div class="layout">
      <div>
        <section class="panel">
          <div class="panel-head">
            <h2>规则扫描结果</h2>
            <span class="pill">{len(vulnerabilities)} Findings</span>
          </div>
          <div class="finding-list">
            {vuln_html}
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h2>恶意软件指标</h2>
            <span class="pill">{len(malware_indicators)} Indicators</span>
          </div>
          <div class="finding-list">
            {malware_html}
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h2>敏感数据结果</h2>
          </div>
          {sensitive_html}
        </section>
      </div>

      <div>
        <section class="panel">
          <div class="panel-head">
            <h2>权限信息</h2>
          </div>
          {permissions_html}
        </section>

        <section class="panel">
          <div class="panel-head">
            <h2>组件暴露面</h2>
          </div>
          <ul>
            <li>Activity：<strong>{len(components.get('activities', []))}</strong>（导出 {exported.get('activities', 0)}）</li>
            <li>Service：<strong>{len(components.get('services', []))}</strong>（导出 {exported.get('services', 0)}）</li>
            <li>Receiver：<strong>{len(components.get('receivers', []))}</strong>（导出 {exported.get('receivers', 0)}）</li>
            <li>Provider：<strong>{len(components.get('providers', []))}</strong>（导出 {exported.get('providers', 0)}）</li>
          </ul>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h2>网络通信</h2>
          </div>
          {network_html}
        </section>

        <section class="panel">
          <div class="panel-head">
            <h2>加密相关</h2>
          </div>
          {crypto_html}
        </section>
      </div>
    </div>

    <div class="footer">Generated by APKAgents</div>
  </div>
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
