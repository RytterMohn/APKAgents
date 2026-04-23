"""
Scanner Agent - 扫描Agent
负责漏洞扫描和恶意软件检测
"""

import os
import re
import json
from typing import List, Dict, Tuple
from .base import BaseAgent, AgentContext, AgentResult
from rules.loader import (
    load_vulnerability_rules,
    load_malware_indicators,
    load_sensitive_data_patterns
)


class ScannerAgent(BaseAgent):
    """
    扫描Agent
    负责:
    - 漏洞扫描
    - 恶意软件检测
    - 敏感数据泄露检测
    - 不安全配置检测
    - 第三方库漏洞检测
    """

    def __init__(self, config: Dict = None):
        super().__init__("Scanner", config)
        self.rules_dir = config.get("rules_dir", "rules")
        self.vulnerability_rules = []
        self.malware_indicators = []
        self.sensitive_data_patterns = []
        self._load_rules()

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["extracted_dir", "java_sources", "permissions", "sensitive_apis"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "vulnerabilities": "list",
            "malware_indicators": "list",
            "sensitive_data": "list",
            "risk_level": "str",
            "risk_score": "float"
        }

    def _load_rules(self):
        """加载扫描规则"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_dir = os.path.join(base_dir, self.rules_dir)

        vuln_file = os.path.join(rules_dir, "vulnerability_rules.json")
        malware_file = os.path.join(rules_dir, "malware_indicators.json")
        sensitive_file = os.path.join(rules_dir, "sensitive_data_patterns.json")

        self.vulnerability_rules = load_vulnerability_rules(vuln_file)
        self.malware_indicators = load_malware_indicators(malware_file)
        self.sensitive_data_patterns = load_sensitive_data_patterns(sensitive_file)

    def _scan_vulnerabilities(self, context: AgentContext, rules: List) -> List[Dict]:
        """漏洞扫描"""
        findings = []

        for rule in rules:
            for java_dir in context.java_sources:
                if not os.path.exists(java_dir):
                    continue

                for root, dirs, files in os.walk(java_dir):
                    for f in files:
                        if not f.endswith((".java", ".smali")):
                            continue

                        file_path = os.path.join(root, f)
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                                content = fp.read()

                            if rule.matches(content):
                                findings.append({
                                    "id": rule.id,
                                    "name": rule.name,
                                    "severity": rule.severity,
                                    "cwe": rule.cwe,
                                    "cvss": rule.cvss,
                                    "description": rule.description,
                                    "location": os.path.relpath(file_path, context.extracted_dir),
                                    "remediation": rule.remediation
                                })
                        except Exception:
                            continue

        return findings

    def _check_malware(self, context: AgentContext) -> List[Dict]:
        """恶意软件检测"""
        findings = []
        permissions = getattr(context, "permissions", [])
        sensitive_apis = getattr(context, "sensitive_apis", [])

        api_list = [f"{api.get('class', '')}->{api.get('method', '')}" for api in sensitive_apis]

        for indicator in self.malware_indicators:
            if indicator.check_permissions(permissions) or indicator.check_apis(api_list):
                findings.append({
                    "id": indicator.id,
                    "name": indicator.name,
                    "category": indicator.category,
                    "severity": indicator.severity,
                    "description": indicator.description,
                    "confidence": "high" if indicator.check_apis(api_list) else "medium"
                })

        return findings

    def _check_sensitive_data(self, context: AgentContext) -> List[Dict]:
        """敏感数据泄露检测"""
        findings = []

        for java_dir in context.java_sources:
            if not os.path.exists(java_dir):
                continue

            for root, dirs, files in os.walk(java_dir):
                for f in files:
                    if not f.endswith((".java", ".xml", ".properties")):
                        continue

                    file_path = os.path.join(root, f)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()

                        for pattern in self.sensitive_data_patterns:
                            regex = pattern.regex
                            if not regex:
                                continue

                            matches = re.finditer(regex, content, re.IGNORECASE)
                            for match in matches:
                                matched_text = match.group(0)
                                if any(fp in matched_text for fp in pattern.false_positives):
                                    continue

                                findings.append({
                                    "id": pattern.id,
                                    "type": pattern.type,
                                    "name": pattern.name,
                                    "severity": pattern.severity,
                                    "location": os.path.relpath(file_path, context.extracted_dir),
                                    "matched": matched_text[:100]
                                })
                    except Exception:
                        continue

        return findings

    def _calculate_risk(
        self,
        vulnerabilities: List[Dict],
        malware_indicators: List[Dict],
        sensitive_data: List[Dict]
    ) -> Tuple[str, float]:
        """计算风险等级和评分"""
        score = 0.0

        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            score += severity_weights.get(severity, 4)

        for malware in malware_indicators:
            severity = malware.get("severity", "medium").lower()
            score += severity_weights.get(severity, 4) * 1.5

        for data in sensitive_data:
            severity = data.get("severity", "medium").lower()
            score += severity_weights.get(severity, 4)

        score = min(score, 100)

        if score >= 80:
            risk_level = "critical"
        elif score >= 60:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        elif score >= 20:
            risk_level = "low"
        else:
            risk_level = "info"

        return risk_level, round(score, 2)

    def check_third_party_libs(self, context: AgentContext) -> List[Dict]:
        """第三方库漏洞检测"""
        findings = []

        known_vulnerable_libs = {
            "okhttp": {"cve": "CVE-2021-0342", "version": "<4.9.0", "severity": "high"},
            "retrofit": {"cve": "CVE-2020-11012", "version": "<2.9.0", "severity": "medium"},
            "gson": {"cve": "CVE-2021-23938", "version": "<2.8.9", "severity": "medium"},
            "jackson-databind": {"cve": "CVE-2020-36518", "version": "<2.13.0", "severity": "high"},
            "apache-http": {"cve": "CVE-2021-4104", "version": "<4.9.0", "severity": "high"},
            "glide": {"cve": "CVE-2020-11037", "version": "<4.11.0", "severity": "medium"},
            "picasso": {"cve": "CVE-2020-11038", "version": "<2.8", "severity": "medium"},
            "rxjava": {"cve": "CVE-2021-43497", "version": "<3.0.13", "severity": "high"},
            "butterknife": {"cve": "CVE-2021-4105", "version": "<10.2.3", "severity": "medium"},
            "dagger": {"cve": "CVE-2021-4106", "version": "<2.42", "severity": "medium"}
        }

        for java_dir in context.java_sources:
            if not os.path.exists(java_dir):
                continue

            for root, dirs, files in os.walk(java_dir):
                for f in files:
                    if f.endswith("build.gradle") or f.endswith("pom.xml"):
                        file_path = os.path.join(root, f)
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                                content = fp.read()

                            for lib_name, lib_info in known_vulnerable_libs.items():
                                if lib_name in content.lower():
                                    findings.append({
                                        "library": lib_name,
                                        "cve": lib_info["cve"],
                                        "affected_version": lib_info["version"],
                                        "severity": lib_info["severity"],
                                        "location": os.path.relpath(file_path, context.extracted_dir)
                                    })
                        except Exception:
                            continue

        return findings

    def execute(self, context: AgentContext) -> AgentResult:
        """执行漏洞扫描"""
        self.log_info(context, "Starting vulnerability scan")

        vulnerabilities = []
        malware_indicators = []
        sensitive_data = []

        try:
            # 1. 执行漏洞扫描
            vulnerabilities = self._scan_vulnerabilities(context, self.vulnerability_rules)

            # 2. 恶意软件检测
            if self.config.get("malware_check", True):
                malware_indicators = self._check_malware(context)

            # 3. 敏感数据检测
            if self.config.get("sensitive_data_check", True):
                sensitive_data = self._check_sensitive_data(context)

            # 4. 计算风险等级
            risk_level, risk_score = self._calculate_risk(
                vulnerabilities, malware_indicators, sensitive_data
            )

            # 5. 第三方库检测（可选）
            third_party_vulns = []
            if self.config.get("check_third_party_libs", False):
                third_party_vulns = self.check_third_party_libs(context)

            # 更新context
            context.vulnerabilities = vulnerabilities
            context.malware_indicators = malware_indicators
            context.sensitive_data = sensitive_data
            context.risk_level = risk_level
            context.risk_score = risk_score
            context.third_party_vulns = third_party_vulns

            return AgentResult.success_result(
                message="Scan completed",
                data={
                    "vulnerabilities": vulnerabilities,
                    "malware_indicators": malware_indicators,
                    "sensitive_data": sensitive_data,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "third_party_vulns": third_party_vulns
                }
            )

        except Exception as e:
            self.log_error(context, f"Scan failed: {str(e)}")
            return AgentResult.error_result(f"Scan failed: {str(e)}")