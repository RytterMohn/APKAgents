"""
Reporter Agent - 报告Agent
负责汇总分析结果生成报告
"""

import os
import json
from datetime import datetime
from typing import List, Dict
from .base import BaseAgent, AgentContext, AgentResult


class ReporterAgent(BaseAgent):
    """
    报告Agent
    负责:
    - 汇总所有分析结果
    - 生成结构化报告
    - 生成风险评估摘要
    - 提供修复建议
    - 支持多种输出格式
    """

    def __init__(self, config: Dict = None):
        super().__init__("Reporter", config)
        self.template_dir = config.get("template_dir", "templates")
        self.report_format = config.get("report_format", "markdown")

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["apk_info", "components", "permissions", "vulnerabilities"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "report_data": "dict",
            "report_path": "str"
        }

    def _aggregate_data(self, context: AgentContext) -> Dict:
        """汇总所有分析数据"""
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

        return {
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
            "errors": getattr(context, "errors", [])
        }

    def _generate_report(self, data: Dict) -> str:
        """生成报告内容"""
        if self.report_format == "json":
            return self._generate_json_report(data)
        elif self.report_format == "html":
            return self._generate_html_report(data)
        else:
            return self._generate_markdown_report(data)

    def _generate_markdown_report(self, data: Dict) -> str:
        """生成Markdown格式报告"""
        apk_info = data.get("apk_info", {})
        components = data.get("components", {})
        permissions = data.get("permissions", [])
        vulnerabilities = data.get("vulnerabilities", [])
        malware_indicators = data.get("malware_indicators", [])
        sensitive_data = data.get("sensitive_data", [])
        risk_level = data.get("risk_level", "unknown")
        risk_score = data.get("risk_score", 0)
        analysis_date = data.get("analysis_date", "")

        report = f"""# APK安全分析报告

## 基本信息

| 属性 | 值 |
|------|-----|
| 包名 | {apk_info.get("package_name", "N/A")} |
| 版本 | {apk_info.get("version_name", "N/A")} ({apk_info.get("version_code", "N/A")}) |
| 最低SDK | {apk_info.get("min_sdk", "N/A")} |
| 目标SDK | {apk_info.get("target_sdk", "N/A")} |
| 分析时间 | {analysis_date} |

## 风险评估

- **总体风险等级**: {risk_level.upper()}
- **风险评分**: {risk_score}/100
- **漏洞数量**: {len(vulnerabilities)}
- **恶意软件特征**: {len(malware_indicators)}
- **敏感数据泄露**: {len(sensitive_data)}

---

## 权限分析

共声明 **{len(permissions)}** 项权限：

"""

        if permissions:
            report += "```\n"
            for perm in permissions[:50]:
                report += f"- {perm}\n"
            if len(permissions) > 50:
                report += f"- ... 还有 {len(permissions) - 50} 项权限\n"
            report += "```\n"

        report += """

## 组件分析

"""

        exported = components.get("exported_counts", {})
        report += f"- **Activity**: {len(components.get("activities", []))} 个 ({exported.get("activities", 0)} 个exported)\n"
        report += f"- **Service**: {len(components.get("services", []))} 个 ({exported.get("services", 0)} 个exported)\n"
        report += f"- **BroadcastReceiver**: {len(components.get("receivers", []))} 个 ({exported.get("receivers", 0)} 个exported)\n"
        report += f"- **ContentProvider**: {len(components.get("providers", []))} 个 ({exported.get("providers", 0)} 个exported)\n"

        report += """

## 安全问题

"""

        if vulnerabilities:
            severity_colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "medium")
                icon = severity_colors.get(severity, "⚪")
                report += f"""### {icon} {vuln.get("name", "Unknown")}

- **ID**: {vuln.get("id", "N/A")}
- **严重程度**: {severity.upper()}
- **CWE**: {vuln.get("cwe", "N/A")}
- **描述**: {vuln.get("description", "N/A")}
- **位置**: `{vuln.get("location", "N/A")}`
- **修复建议**: {vuln.get("remediation", "N/A")}

"""
        else:
            report += "未发现安全漏洞。\n"

        if malware_indicators:
            report += """

## 恶意软件特征

"""
            for malware in malware_indicators:
                report += f"""- **{malware.get("name", "Unknown")}** ({malware.get("severity", "").upper()})
  - 类别: {malware.get("category", "N/A")}
  - 置信度: {malware.get("confidence", "N/A")}
  - 描述: {malware.get("description", "N/A")}

"""

        if sensitive_data:
            report += """

## 敏感数据泄露

"""
            for data_item in sensitive_data:
                report += f"""- **{data_item.get("name", "Unknown")}** ({data_item.get("severity", "").upper()})
  - 类型: {data_item.get("type", "N/A")}
  - 位置: `{data_item.get("location", "N/A")}`
  - 匹配内容: `{data_item.get("matched", "")[:50]}...`

"""

        report += f"""

---

## 执行摘要

{self.get_executive_summary(data)}

## 修复建议

"""
        recommendations = self.get_recommendations(vulnerabilities)
        for i, rec in enumerate(recommendations, 1):
            report += f"{i}. {rec}\n"

        report += """

---

*本报告由APKAgents自动生成*
"""
        return report

    def _generate_json_report(self, data: Dict) -> str:
        """生成JSON格式报告"""
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _generate_html_report(self, data: Dict) -> str:
        """生成HTML格式报告"""
        apk_info = data.get("apk_info", {})
        risk_level = data.get("risk_level", "unknown")
        vulnerabilities = data.get("vulnerabilities", [])

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK安全分析报告 - {apk_info.get("package_name", "N/A")}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .info-table td {{ padding: 10px; border: 1px solid #ddd; }}
        .info-table td:first-child {{ font-weight: bold; background: #f9f9f9; width: 200px; }}
        .risk-critical {{ background: #d32f2f; color: white; padding: 5px 15px; border-radius: 3px; }}
        .risk-high {{ background: #f57c00; color: white; padding: 5px 15px; border-radius: 3px; }}
        .risk-medium {{ background: #fbc02d; color: #333; padding: 5px 15px; border-radius: 3px; }}
        .risk-low {{ background: #4caf50; color: white; padding: 5px 15px; border-radius: 3px; }}
        .vuln-item {{ border-left: 4px solid #f57c00; padding: 15px; margin: 10px 0; background: #fff8e1; }}
        .vuln-critical {{ border-left-color: #d32f2f; background: #ffebee; }}
        .vuln-high {{ border-left-color: #f57c00; background: #fff8e1; }}
        .vuln-medium {{ border-left-color: #fbc02d; background: #fffde7; }}
        .vuln-low {{ border-left-color: #4caf50; background: #e8f5e9; }}
        code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>APK安全分析报告</h1>

        <h2>基本信息</h2>
        <table class="info-table">
            <tr><td>包名</td><td>{apk_info.get("package_name", "N/A")}</td></tr>
            <tr><td>版本</td><td>{apk_info.get("version_name", "N/A")} ({apk_info.get("version_code", "N/A")})</td></tr>
            <tr><td>最低SDK</td><td>{apk_info.get("min_sdk", "N/A")}</td></tr>
            <tr><td>目标SDK</td><td>{apk_info.get("target_sdk", "N/A")}</td></tr>
            <tr><td>分析时间</td><td>{data.get("analysis_date", "")}</td></tr>
        </table>

        <h2>风险评估</h2>
        <p>风险等级: <span class="risk-{risk_level}">{risk_level.upper()}</span></p>
        <p>风险评分: {data.get("risk_score", 0)}/100</p>
        <p>漏洞数量: {len(vulnerabilities)}</p>

        <h2>安全问题</h2>
"""
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium")
            html += f"""        <div class="vuln-item vuln-{severity}">
            <strong>{vuln.get("name", "Unknown")}</strong> [{vuln.get("severity", "").upper()}]
            <p>{vuln.get("description", "")}</p>
            <p>位置: <code>{vuln.get("location", "")}</code></p>
            <p>修复建议: {vuln.get("remediation", "")}</p>
        </div>
"""

        html += """
        <h2>修复建议</h2>
        <ol>
"""
        for rec in self.get_recommendations(vulnerabilities):
            html += f"            <li>{rec}</li>\n"

        html += """        </ol>
        <p><em>本报告由APKAgents自动生成</em></p>
    </div>
</body>
</html>"""
        return html

    def _save_report(self, context: AgentContext, content: str) -> str:
        """保存报告文件"""
        output_dir = context.output_dir
        os.makedirs(output_dir, exist_ok=True)

        apk_info = getattr(context, "apk_info", {}) or {}
        package_name = apk_info.get("package_name", "app")

        if self.report_format == "json":
            filename = f"{package_name}_report.json"
        elif self.report_format == "html":
            filename = f"{package_name}_report.html"
        else:
            filename = f"{package_name}_report.md"

        report_path = os.path.join(output_dir, filename)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)

        return report_path

    def get_executive_summary(self, data: Dict) -> str:
        """生成执行摘要"""
        risk_level = data.get("risk_level", "unknown")
        vuln_count = data.get("vulnerability_count", 0)
        malware_count = len(data.get("malware_indicators", []))
        sensitive_count = data.get("sensitive_data_count", 0)
        apk_info = data.get("apk_info", {})
        package_name = apk_info.get("package_name", "Unknown")

        summary_parts = []

        if risk_level == "critical":
            summary_parts.append(f"应用 {package_name} 存在严重安全风险，建议立即修复。")
        elif risk_level == "high":
            summary_parts.append(f"应用 {package_name} 存在较高安全风险，建议尽快修复。")
        elif risk_level == "medium":
            summary_parts.append(f"应用 {package_name} 存在中等安全风险，建议关注并修复。")
        elif risk_level == "low":
            summary_parts.append(f"应用 {package_name} 安全状况良好，仅有少量低危问题。")
        else:
            summary_parts.append(f"应用 {package_name} 分析完成，未发现明显安全问题。")

        if vuln_count > 0:
            summary_parts.append(f"发现 {vuln_count} 个安全漏洞。")

        if malware_count > 0:
            summary_parts.append(f"检测到 {malware_count} 个恶意软件特征。")

        if sensitive_count > 0:
            summary_parts.append(f"发现 {sensitive_count} 处敏感数据泄露风险。")

        return " ".join(summary_parts)

    def get_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """生成修复建议"""
        recommendations = []

        if not vulnerabilities:
            recommendations.append("保持当前安全实践，定期更新依赖库版本。")
            recommendations.append("继续进行安全代码审计，确保新功能符合安全规范。")
            return recommendations

        seen_categories = set()

        for vuln in vulnerabilities:
            vuln_id = vuln.get("id", "")
            name = vuln.get("name", "")

            if vuln_id == "VULN-001" and "webview" not in seen_categories:
                recommendations.append("审查WebView配置，禁用不必要的JavaScript，启用白名单验证。")
                seen_categories.add("webview")

            elif vuln_id == "VULN-002" and "intent" not in seen_categories:
                recommendations.append("使用LocalBroadcastManager或带权限的广播发送敏感数据。")
                seen_categories.add("intent")

            elif vuln_id == "VULN-003" and "random" not in seen_categories:
                recommendations.append("使用java.security.SecureRandom替代java.util.Random。")
                seen_categories.add("random")

            elif vuln_id == "VULN-004" and "ssl" not in seen_categories:
                recommendations.append("修复SSL证书验证问题，使用正确的TrustManager实现。")
                seen_categories.add("ssl")

            elif vuln_id == "VULN-005" and "debug" not in seen_categories:
                recommendations.append("发布版本关闭Android:debuggable标志。")
                seen_categories.add("debug")

            elif vuln_id == "VULN-006" and "jsinterface" not in seen_categories:
                recommendations.append("审查addJavascriptInterface使用，限制暴露的接口。")
                seen_categories.add("jsinterface")

            elif vuln_id == "VULN-007" and "fileperm" not in seen_categories:
                recommendations.append("使用MODE_PRIVATE或适当的文件权限，避免全局可读/可写。")
                seen_categories.add("fileperm")

            elif vuln_id == "VULN-008" and "log" not in seen_categories:
                recommendations.append("发布版本禁用日志输出或使用代码混淆。")
                seen_categories.add("log")

            elif vuln_id == "VULN-009" and "dexclass" not in seen_categories:
                recommendations.append("避免从不可信位置动态加载代码。")
                seen_categories.add("dexclass")

            elif vuln_id == "VULN-010" and "sql" not in seen_categories:
                recommendations.append("使用参数化查询替代字符串拼接，防止SQL注入。")
                seen_categories.add("sql")

        if len(recommendations) < 3:
            recommendations.append("定期进行安全评估和代码审计。")
            recommendations.append("保持依赖库更新到最新安全版本。")

        return recommendations

    def execute(self, context: AgentContext) -> AgentResult:
        """生成报告"""
        self.log_info(context, "Generating report")

        try:
            report_data = self._aggregate_data(context)
            report_content = self._generate_report(report_data)
            report_path = self._save_report(context, report_content)

            context.report_data = report_data
            context.report_path = report_path

            return AgentResult.success_result(
                message="Report generated",
                data={
                    "report_data": report_data,
                    "report_path": report_path
                },
                artifacts=[report_path]
            )

        except Exception as e:
            self.log_error(context, f"Report generation failed: {str(e)}")
            return AgentResult.error_result(f"Report generation failed: {str(e)}")