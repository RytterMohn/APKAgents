"""
Formatter Agent - 格式化Agent
负责格式化输出报告
"""

import os
import json
import re
from datetime import datetime
from typing import Dict, List
from .base import BaseAgent, AgentContext, AgentResult


class FormatterAgent(BaseAgent):
    """
    格式化Agent
    负责:
    - 格式化代码片段
    - 美化输出报告
    - 生成可视化图表
    - 转换不同格式(Markdown/HTML/JSON)
    """

    def __init__(self, config: Dict = None):
        super().__init__("Formatter", config)
        self.template_dir = config.get("template_dir", "templates")

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["report_data"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "formatted_output": "dict",
            "markdown_report": "str",
            "html_report": "str",
            "json_report": "str"
        }

    def _format_markdown(self, data: Dict) -> str:
        """格式化为Markdown报告"""
        apk_info = data.get("apk_info", {})
        components = data.get("components", {})
        permissions = data.get("permissions", [])
        vulnerabilities = data.get("vulnerabilities", [])
        malware_indicators = data.get("malware_indicators", [])
        sensitive_data = data.get("sensitive_data", [])
        network_calls = data.get("network_calls", [])
        crypto_usage = data.get("crypto_usage", [])
        sensitive_apis = data.get("sensitive_apis", [])
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)
        analysis_date = data.get("analysis_date", "")

        md = f"""# 📱 APK安全分析报告

> 生成时间: {analysis_date}

---

## 📋 目录

1. [基本信息](#基本信息)
2. [风险评估](#风险评估)
3. [权限分析](#权限分析)
4. [组件分析](#组件分析)
5. [安全问题](#安全问题)
6. [恶意软件检测](#恶意软件检测)
7. [敏感数据](#敏感数据)
8. [网络通信](#网络通信)
9. [加密使用](#加密使用)
10. [修复建议](#修复建议)

---

## 基本信息

| 属性 | 值 |
|:-----|:---|
| **包名** | `{apk_info.get("package_name", "N/A")}` |
| **版本名称** | {apk_info.get("version_name", "N/A")} |
| **版本号** | {apk_info.get("version_code", "N/A")} |
| **最低SDK** | Android {apk_info.get("min_sdk", "N/A")} |
| **目标SDK** | Android {apk_info.get("target_sdk", "N/A")} |

---

## 风险评估

### 风险等级

| 等级 | 评分 | 状态 |
|:-----|:-----|:-----|
| 🔴 Critical | 80-100 | {"需立即修复" if risk_level == "critical" else "建议关注"} |
| 🟠 High | 60-79 | {"建议尽快修复" if risk_level == "high" else "建议关注"} |
| 🟡 Medium | 40-59 | {"建议关注" if risk_level == "medium" else "风险可控"} |
| 🟢 Low | 0-39 | {"风险可控" if risk_level == "low" else "安全"} |

> **当前风险评分**: **{risk_score}** / 100 ({risk_level.upper()})

### 统计摘要

| 类别 | 数量 |
|:-----|-----:|
| 安全漏洞 | {len(vulnerabilities)} |
| 恶意软件特征 | {len(malware_indicators)} |
| 敏感数据泄露 | {len(sensitive_data)} |
| 网络调用 | {len(network_calls)} |
| 加密使用 | {len(crypto_usage)} |

---

## 权限分析

声明了 **{len(permissions)}** 项权限：

```
"""

        # 分组显示权限
        dangerous_perms = [p for p in permissions if "DANGEROUS" in p.upper() or "PERMISSION" in p.upper()]
        if dangerous_perms:
            md += "# 🔴 危险权限\n"
            for perm in dangerous_perms[:30]:
                md += f"- {perm}\n"
            if len(dangerous_perms) > 30:
                md += f"- ... 还有 {len(dangerous_perms) - 30} 项\n"
            md += "\n"

        normal_perms = [p for p in permissions if p not in dangerous_perms]
        if normal_perms:
            md += "# ⚪ 普通权限\n"
            for perm in normal_perms[:20]:
                md += f"- {perm}\n"
            if len(normal_perms) > 20:
                md += f"- ... 还有 {len(normal_perms) - 20} 项\n"

        md += """```

---

## 组件分析

"""

        # 组件统计表格
        exported = components.get("exported_counts", {})
        md += f"""| 组件类型 | 总数 | Exported | 详情 |
|:---------|-----:|---------:|:-----|
| Activity | {len(components.get("activities", []))} | {exported.get("activities", 0)} | [查看列表](#activity列表) |
| Service | {len(components.get("services", []))} | {exported.get("services", 0)} | [查看列表](#service列表) |
| Receiver | {len(components.get("receivers", []))} | {exported.get("receivers", 0)} | [查看列表](#receiver列表) |
| Provider | {len(components.get("providers", []))} | {exported.get("providers", 0)} | [查看列表](#provider列表) |

"""

        # 显示部分组件
        activities = components.get("activities", [])[:10]
        if activities:
            md += "### Activity列表\n\n"
            for a in activities:
                exported_icon = "📤" if a.get("exported") else "🔒"
                md += f"- {exported_icon} {a.get('name', 'Unknown')}\n"
            if len(components.get("activities", [])) > 10:
                md += f"- ... 还有 {len(components.get('activities', [])) - 10} 个\n"

        md += """

---

## 安全问题

"""

        if vulnerabilities:
            severity_order = ["critical", "high", "medium", "low"]
            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

            sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.index(x.get("severity", "medium")) if x.get("severity") in severity_order else 2)

            for vuln in sorted_vulns:
                severity = vuln.get("severity", "medium")
                icon = severity_icons.get(severity, "⚪")
                md += f"""### {icon} {vuln.get("name", "Unknown")}

| 属性 | 值 |
|:-----|:---|
| **ID** | `{vuln.get("id", "N/A")}` |
| **严重程度** | {severity.upper()} |
| **CWE** | {vuln.get("cwe", "N/A")} |
| **CVSS** | {vuln.get("cvss", "N/A")} |

**描述**: {vuln.get("description", "N/A")}

**位置**: `{vuln.get("location", "N/A")}`

**修复建议**: {vuln.get("remediation", "N/A")}

---
"""
        else:
            md += "✅ 未发现安全漏洞\n\n"

        md += """---

## 恶意软件检测

"""

        if malware_indicators:
            for malware in malware_indicators:
                severity = malware.get("severity", "medium").upper()
                md += f"""### ⚠️ {malware.get("name", "Unknown")}

| 属性 | 值 |
|:-----|:---|
| **类别** | {malware.get("category", "N/A")} |
| **严重程度** | {severity} |
| **置信度** | {malware.get("confidence", "N/A")} |

{malware.get("description", "")}

---
"""
        else:
            md += "✅ 未检测到恶意软件特征\n\n"

        md += """---

## 敏感数据

"""

        if sensitive_data:
            for data_item in sensitive_data:
                severity = data_item.get("severity", "medium").upper()
                md += f"""### 🔍 {data_item.get("name", "Unknown")}

- **类型**: {data_item.get("type", "N/A")}
- **严重程度**: {severity}
- **位置**: `{data_item.get("location", "N/A")}`
- **匹配内容**: `{data_item.get("matched", "")[:80]}...`

"""
        else:
            md += "✅ 未发现敏感数据泄露\n\n"

        md += """---

## 网络通信

"""

        if network_calls:
            md += "| URL | 加密 | 类 | 方法 |\n"
            md += "|:-----|:-----|:-----|:-----|\n"
            for call in network_calls[:20]:
                enc = call.get("encryption", "http")
                icon = "🔒" if enc == "https" else "🔓"
                md += f"| {icon} {call.get('url', 'N/A')[:40]}... | {enc} | {call.get('class', 'N/A')[:20]} | {call.get('method', 'N/A')[:15]} |\n"
        else:
            md += "未发现网络通信\n\n"

        md += """---

## 加密使用

"""

        if crypto_usage:
            md += "| 类型 | 类 | 方法 |\n"
            md += "|:-----|:-----|:-----|\n"
            for crypto in crypto_usage[:20]:
                md += f"| {crypto.get('type', 'N/A')} | {crypto.get('class', 'N/A')[:25]} | {crypto.get('method', 'N/A')} |\n"
        else:
            md += "未发现加密使用\n\n"

        md += """---

## 修复建议

"""

        # 生成修复建议
        vuln_ids = [v.get("id") for v in vulnerabilities]
        recommendations = []

        if "VULN-001" in vuln_ids:
            recommendations.append("**WebView安全**: 禁用不必要的JavaScript，启用白名单验证")
        if "VULN-002" in vuln_ids:
            recommendations.append("**Intent安全**: 使用LocalBroadcastManager或带权限的广播")
        if "VULN-003" in vuln_ids:
            recommendations.append("**随机数**: 使用java.security.SecureRandom替代java.util.Random")
        if "VULN-004" in vuln_ids:
            recommendations.append("**SSL证书**: 修复证书验证，使用正确的TrustManager")
        if "VULN-005" in vuln_ids:
            recommendations.append("**调试标志**: 发布版本关闭debuggable")
        if "VULN-006" in vuln_ids:
            recommendations.append("**JS接口**: 审查addJavascriptInterface，限制暴露接口")
        if "VULN-007" in vuln_ids:
            recommendations.append("**文件权限**: 使用MODE_PRIVATE，避免全局可读/可写")
        if "VULN-008" in vuln_ids:
            recommendations.append("**日志安全**: 发布版本禁用日志输出")
        if "VULN-009" in vuln_ids:
            recommendations.append("**动态加载**: 避免从不可信位置加载代码")
        if "VULN-010" in vuln_ids:
            recommendations.append("**SQL注入**: 使用参数化查询")

        if not recommendations:
            recommendations.append("保持当前安全实践，定期更新依赖库版本")
            recommendations.append("继续进行安全代码审计")

        for i, rec in enumerate(recommendations, 1):
            md += f"{i}. {rec}\n"

        md += f"""

---

*本报告由APKAgents自动生成*
"""

        return md

    def _format_html(self, data: Dict) -> str:
        """格式化为HTML报告"""
        apk_info = data.get("apk_info", {})
        components = data.get("components", {})
        vulnerabilities = data.get("vulnerabilities", [])
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)

        # 生成图表数据
        charts = self.generate_charts(data)

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK安全分析报告 - {apk_info.get("package_name", "APK")}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }}
        header {{ background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 40px; text-align: center; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.9; font-size: 0.95em; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #1e3c72; border-left: 4px solid #667eea; padding-left: 15px; margin-bottom: 20px; font-size: 1.5em; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        .info-card {{ background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 20px; border-radius: 10px; }}
        .info-card .label {{ color: #666; font-size: 0.9em; margin-bottom: 5px; }}
        .info-card .value {{ color: #1e3c72; font-size: 1.2em; font-weight: bold; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; color: white; font-weight: bold; font-size: 1.1em; }}
        .risk-critical {{ background: linear-gradient(135deg, #d32f2f, #b71c1c); }}
        .risk-high {{ background: linear-gradient(135deg, #f57c00, #e65100); }}
        .risk-medium {{ background: linear-gradient(135deg, #fbc02d, #f9a825); color: #333; }}
        .risk-low {{ background: linear-gradient(135deg, #4caf50, #2e7d32); }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .chart-container {{ background: #fafafa; padding: 20px; border-radius: 10px; border: 1px solid #eee; }}
        .vuln-list {{ display: grid; gap: 15px; }}
        .vuln-item {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 5px solid; }}
        .vuln-critical {{ border-left-color: #d32f2f; background: linear-gradient(135deg, #ffebee, #ffcdd2); }}
        .vuln-high {{ border-left-color: #f57c00; background: linear-gradient(135deg, #fff3e0, #ffe0b2); }}
        .vuln-medium {{ border-left-color: #fbc02d; background: linear-gradient(135deg, #fffde7, #fff9c4); }}
        .vuln-low {{ border-left-color: #4caf50; background: linear-gradient(135deg, #e8f5e9, #c8e6c9); }}
        .vuln-item h3 {{ margin-bottom: 10px; color: #333; }}
        .vuln-item .meta-info {{ display: flex; gap: 15px; flex-wrap: wrap; margin: 10px 0; }}
        .vuln-item .tag {{ background: rgba(255,255,255,0.7); padding: 3px 10px; border-radius: 3px; font-size: 0.85em; }}
        .code-block {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .toc {{ background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 30px; }}
        .toc ul {{ list-style: none; }}
        .toc li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        .toc a {{ color: #667eea; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}
        footer {{ background: #1e3c72; color: white; text-align: center; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📱 APK安全分析报告</h1>
            <div class="meta">
                <p>包名: <strong>{apk_info.get("package_name", "N/A")}</strong></p>
                <p>版本: {apk_info.get("version_name", "N/A")} ({apk_info.get("version_code", "N/A")}) | 目标SDK: {apk_info.get("target_sdk", "N/A")}</p>
            </div>
        </header>

        <div class="content">
            <div class="section">
                <h2>📊 风险评估</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="label">风险等级</div>
                        <div class="value"><span class="risk-badge risk-{risk_level}">{risk_level.upper()}</span></div>
                    </div>
                    <div class="info-card">
                        <div class="label">风险评分</div>
                        <div class="value">{risk_score}/100</div>
                    </div>
                    <div class="info-card">
                        <div class="label">安全漏洞</div>
                        <div class="value">{len(vulnerabilities)}</div>
                    </div>
                    <div class="info-card">
                        <div class="label">Exported组件</div>
                        <div class="value">{sum(components.get("exported_counts", {}).values())}</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📈 安全态势图表</h2>
                <div class="charts-grid">
                    <div class="chart-container">
                        <canvas id="vulnChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="componentChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="riskChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🐛 安全问题</h2>
                <div class="vuln-list">
"""

        # 漏洞列表
        severity_order = ["critical", "high", "medium", "low"]
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

        sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.index(x.get("severity", "medium")) if x.get("severity") in severity_order else 2)

        for vuln in sorted_vulns[:15]:
            severity = vuln.get("severity", "medium")
            icon = severity_icons.get(severity, "⚪")
            html += f"""
                    <div class="vuln-item vuln-{severity}">
                        <h3>{icon} {vuln.get("name", "Unknown")}</h3>
                        <div class="meta-info">
                            <span class="tag">ID: {vuln.get("id", "N/A")}</span>
                            <span class="tag">严重程度: {severity.upper()}</span>
                            <span class="tag">CWE: {vuln.get("cwe", "N/A")}</span>
                            <span class="tag">CVSS: {vuln.get("cvss", "N/A")}</span>
                        </div>
                        <p>{vuln.get("description", "")}</p>
                        <p><strong>位置:</strong> <code>{vuln.get("location", "")}</code></p>
                        <p><strong>修复建议:</strong> {vuln.get("remediation", "")}</p>
                    </div>
"""

        if not vulnerabilities:
            html += "<p>✅ 未发现安全漏洞</p>"

        html += """
                </div>
            </div>
        </div>

        <footer>
            <p>本报告由APKAgents自动生成 | 生成时间: """ + data.get("analysis_date", "") + """</p>
        </footer>
    </div>

    <script>
        // Chart.js 配置
"""

        # 注入图表配置
        html += f"""
        // 漏洞分布图
        const vulnChart = new Chart(document.getElementById('vulnChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['严重', '高危', '中危', '低危'],
                datasets: [{{
                    data: [{charts.get('critical', 0)}, {charts.get('high', 0)}, {charts.get('medium', 0)}, {charts.get('low', 0)}],
                    backgroundColor: ['#d32f2f', '#f57c00', '#fbc02d', '#4caf50']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    title: {{ display: true, text: '漏洞严重程度分布' }},
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});

        // 组件分布图
        const componentChart = new Chart(document.getElementById('componentChart'), {{
            type: 'bar',
            data: {{
                labels: ['Activity', 'Service', 'Receiver', 'Provider'],
                datasets: [{{
                    label: '组件数量',
                    data: [{len(components.get('activities', []))}, {len(components.get('services', []))}, {len(components.get('receivers', []))}, {len(components.get('providers', []))}],
                    backgroundColor: ['#667eea', '#764ba2', '#f093fb', '#f5576c']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ title: {{ display: true, text: 'Android组件分布' }}, legend: {{ display: false }} }}
            }}
        }});

        // 风险评分图
        const riskChart = new Chart(document.getElementById('riskChart'), {{
            type: 'pie',
            data: {{
                labels: ['安全', '风险'],
                datasets: [{{
                    data: [{100 - risk_score}, {risk_score}],
                    backgroundColor: ['#4caf50', '#f44336']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ title: {{ display: true, text: '风险评分占比' }}, legend: {{ position: 'bottom' }} }}
            }}
        }});
"""

        html += """
    </script>
</body>
</html>"""

        return html

    def generate_charts(self, data: Dict) -> Dict:
        """生成Chart.js图表配置数据"""
        vulnerabilities = data.get("vulnerabilities", [])
        components = data.get("components", {})
        permissions = data.get("permissions", [])
        sensitive_data = data.get("sensitive_data", [])

        # 漏洞严重程度统计
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # 组件统计
        component_counts = {
            "activity": len(components.get("activities", [])),
            "service": len(components.get("services", [])),
            "receiver": len(components.get("receivers", [])),
            "provider": len(components.get("providers", []))
        }

        # 敏感数据类型统计
        sensitive_types = {}
        for sd in sensitive_data:
            sd_type = sd.get("type", "unknown")
            sensitive_types[sd_type] = sensitive_types.get(sd_type, 0) + 1

        return {
            "vulnerabilities": severity_counts,
            "components": component_counts,
            "permissions_count": len(permissions),
            "sensitive_data_types": sensitive_types,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"]
        }

    def highlight_code(self, code: str, language: str = "java") -> str:
        """代码高亮（生成带样式的HTML）"""
        # 简单的语法高亮实现
        keywords = {
            "java": ["public", "private", "protected", "class", "interface", "extends", "implements",
                    "static", "final", "void", "int", "String", "boolean", "return", "if", "else",
                    "try", "catch", "throw", "new", "this", "super", "import", "package"],
            "smali": [".method", ".end method", ".field", ".class", ".super", ".annotation",
                      "invoke-", "return-", "const-string", "const", "move-result"]
        }

        lang_keywords = keywords.get(language.lower(), [])

        # 转义HTML
        escaped = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # 高亮关键词
        for kw in lang_keywords:
            escaped = re.sub(
                r'\b(' + re.escape(kw) + r')\b',
                r'<span style="color: #0000ff; font-weight: bold;">\1</span>',
                escaped
            )

        # 高亮字符串
        escaped = re.sub(
            r'(".*?")',
            r'<span style="color: #008000;">\1</span>',
            escaped
        )

        # 高亮注释
        escaped = re.sub(
            r'(//.*?)$',
            r'<span style="color: #808080; font-style: italic;">\1</span>',
            escaped,
            flags=re.MULTILINE
        )

        # 高亮数字
        escaped = re.sub(
            r'\b(\d+)\b',
            r'<span style="color: #ff0000;">\1</span>',
            escaped
        )

        return f'<pre class="code-highlight"><code class="language-{language}">{escaped}</code></pre>'

    def _format_json(self, data: Dict) -> str:
        """格式化为JSON"""
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _save_markdown(self, output_dir: str, content: str) -> str:
        """保存Markdown报告"""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "report.md")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def _save_html(self, output_dir: str, content: str) -> str:
        """保存HTML报告"""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "report.html")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def _save_json(self, output_dir: str, content: str) -> str:
        """保存JSON报告"""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "report.json")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def execute(self, context: AgentContext) -> AgentResult:
        """格式化报告"""
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
                "json": json_path
            }

            return AgentResult.success_result(
                message="Formatting completed",
                data={
                    "formatted_output": context.formatted_output,
                    "markdown_report": markdown_path,
                    "html_report": html_path,
                    "json_report": json_path
                },
                artifacts=[markdown_path, html_path, json_path]
            )

        except Exception as e:
            self.log_error(context, f"Formatting failed: {str(e)}")
            return AgentResult.error_result(f"Formatting failed: {str(e)}")