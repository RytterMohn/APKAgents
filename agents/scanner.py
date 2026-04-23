"""
Scanner Agent.
"""

import json
import os
import re
from typing import Dict, List, Tuple

from rules.loader import (
    load_malware_indicators,
    load_sensitive_data_patterns,
    load_vulnerability_rules,
)
from utils.llm import LLMError

from .base import AgentContext, AgentResult, BaseAgent


class ScannerAgent(BaseAgent):
    """Rule-based scanning plus optional LLM triage."""

    def __init__(self, config: Dict = None):
        super().__init__("Scanner", config)
        config = config or {}
        self.rules_dir = config.get("rules_dir", "rules")
        self.vulnerability_rules = []
        self.malware_indicators = []
        self.sensitive_data_patterns = []
        self._load_rules()

    def get_required_inputs(self) -> List[str]:
        return ["extracted_dir", "java_sources", "permissions", "sensitive_apis"]

    def get_output_schema(self) -> Dict:
        return {
            "vulnerabilities": "list",
            "malware_indicators": "list",
            "sensitive_data": "list",
            "risk_level": "str",
            "risk_score": "float",
        }

    def _load_rules(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_dir = os.path.join(base_dir, self.rules_dir)
        self.vulnerability_rules = load_vulnerability_rules(os.path.join(rules_dir, "vulnerability_rules.json"))
        self.malware_indicators = load_malware_indicators(os.path.join(rules_dir, "malware_indicators.json"))
        self.sensitive_data_patterns = load_sensitive_data_patterns(os.path.join(rules_dir, "sensitive_data_patterns.json"))

    def _package_path_fragment(self, context: AgentContext) -> str:
        package_name = ((context.apk_info or {}).get("package_name") or "").replace(".", "/")
        return package_name

    def _is_relevant_source(self, file_path: str, package_path: str) -> bool:
        normalized = file_path.replace("\\", "/").lower()
        if package_path and package_path.lower() in normalized:
            return True
        third_party_markers = [
            "/androidx/",
            "/kotlin/",
            "/kotlinx/",
            "/java/",
            "/javax/",
            "/com/google/",
            "/okhttp3/",
            "/okio/",
        ]
        return not any(marker in normalized for marker in third_party_markers)

    def _scan_vulnerabilities(self, context: AgentContext, rules: List) -> List[Dict]:
        findings = []
        package_path = self._package_path_fragment(context)

        for rule in rules:
            for java_dir in context.java_sources:
                if not os.path.exists(java_dir):
                    continue

                for root, _, files in os.walk(java_dir):
                    for filename in files:
                        if not filename.endswith((".java", ".smali", ".xml")):
                            continue

                        file_path = os.path.join(root, filename)
                        if not self._is_relevant_source(file_path, package_path):
                            continue

                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                                content = handle.read()
                            if rule.matches(content):
                                findings.append(
                                    {
                                        "id": rule.id,
                                        "name": rule.name,
                                        "severity": rule.severity,
                                        "cwe": rule.cwe,
                                        "cvss": rule.cvss,
                                        "description": rule.description,
                                        "location": os.path.relpath(file_path, context.extracted_dir),
                                        "remediation": rule.remediation,
                                    }
                                )
                        except Exception:
                            continue

        return findings

    def _check_malware(self, context: AgentContext) -> List[Dict]:
        findings = []
        permissions = getattr(context, "permissions", []) or []
        sensitive_apis = getattr(context, "sensitive_apis", []) or []
        api_list = [f"{api.get('class', '')}->{api.get('method', '')}" for api in sensitive_apis]

        for indicator in self.malware_indicators:
            if indicator.check_permissions(permissions) or indicator.check_apis(api_list):
                findings.append(
                    {
                        "id": indicator.id,
                        "name": indicator.name,
                        "category": indicator.category,
                        "severity": indicator.severity,
                        "description": indicator.description,
                        "confidence": "high" if indicator.check_apis(api_list) else "medium",
                    }
                )
        return findings

    def _check_sensitive_data(self, context: AgentContext) -> List[Dict]:
        findings = []
        package_path = self._package_path_fragment(context)

        for java_dir in context.java_sources:
            if not os.path.exists(java_dir):
                continue

            for root, _, files in os.walk(java_dir):
                for filename in files:
                    if not filename.endswith((".java", ".xml", ".properties")):
                        continue

                    file_path = os.path.join(root, filename)
                    if not self._is_relevant_source(file_path, package_path):
                        continue

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                            content = handle.read()
                        for pattern in self.sensitive_data_patterns:
                            if not pattern.regex:
                                continue
                            for match in re.finditer(pattern.regex, content, re.IGNORECASE):
                                matched_text = match.group(0)
                                if any(false_positive in matched_text for false_positive in pattern.false_positives):
                                    continue
                                findings.append(
                                    {
                                        "id": pattern.id,
                                        "type": pattern.type,
                                        "name": pattern.name,
                                        "severity": pattern.severity,
                                        "location": os.path.relpath(file_path, context.extracted_dir),
                                        "matched": matched_text[:100],
                                    }
                                )
                    except Exception:
                        continue

        return findings

    def _dedupe_findings(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        deduped = []
        for finding in findings:
            key = (finding.get("id"), finding.get("location"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _llm_triage(self, context: AgentContext, vulnerabilities: List[Dict], sensitive_data: List[Dict]) -> Tuple[List[Dict], List[Dict], Dict]:
        client = self.get_llm_client(context)
        if not client:
            return vulnerabilities, sensitive_data, {}

        candidates = []
        for index, item in enumerate(vulnerabilities[:60]):
            candidates.append(
                {
                    "index": index,
                    "kind": "vulnerability",
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "severity": item.get("severity"),
                    "location": item.get("location"),
                    "description": item.get("description"),
                }
            )
        base_index = len(candidates)
        for offset, item in enumerate(sensitive_data[:20]):
            candidates.append(
                {
                    "index": base_index + offset,
                    "kind": "sensitive_data",
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "severity": item.get("severity"),
                    "location": item.get("location"),
                    "description": item.get("matched", ""),
                }
            )

        if not candidates:
            return vulnerabilities, sensitive_data, {}

        payload = {
            "package_name": (context.apk_info or {}).get("package_name", ""),
            "activities": len((context.components or {}).get("activities", [])),
            "exported_activities": ((context.components or {}).get("exported_counts", {}) or {}).get("activities", 0),
            "permissions": context.permissions or [],
            "candidates": candidates,
        }
        system_prompt = (
            "You are a mobile security triage agent. "
            "Return strict JSON only. "
            "Keep findings that look relevant to the app's own code or clearly risky. "
            "Drop findings that are likely standard library, framework, or low-value duplicates."
        )
        user_prompt = (
            "Review these Android static-analysis findings and triage them.\n"
            "Return JSON with keys: summary, keep_indexes, drop_indexes, priority_findings, recommendations.\n"
            "priority_findings must be a list of objects with index and reason.\n"
            f"{json.dumps(payload, ensure_ascii=False)}"
        )

        try:
            result = client.generate_json(system_prompt, user_prompt)
        except LLMError as exc:
            context.add_warning(f"LLM triage failed: {exc}")
            return vulnerabilities, sensitive_data, {}

        keep_indexes = set(idx for idx in result.get("keep_indexes", []) if isinstance(idx, int))
        if not keep_indexes:
            return vulnerabilities, sensitive_data, result

        kept_vulnerabilities = [item for idx, item in enumerate(vulnerabilities[:60]) if idx in keep_indexes]
        if len(vulnerabilities) > 60:
            kept_vulnerabilities.extend(vulnerabilities[60:])

        sensitive_offset = len(vulnerabilities[:60])
        kept_sensitive_data = []
        for offset, item in enumerate(sensitive_data[:20]):
            if sensitive_offset + offset in keep_indexes:
                kept_sensitive_data.append(item)
        if len(sensitive_data) > 20:
            kept_sensitive_data.extend(sensitive_data[20:])

        return kept_vulnerabilities, kept_sensitive_data, result

    def _calculate_risk(self, vulnerabilities: List[Dict], malware_indicators: List[Dict], sensitive_data: List[Dict]) -> Tuple[str, float]:
        score = 0.0
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

        for vuln in vulnerabilities:
            score += severity_weights.get(vuln.get("severity", "medium").lower(), 4)
        for malware in malware_indicators:
            score += severity_weights.get(malware.get("severity", "medium").lower(), 4) * 1.5
        for data_item in sensitive_data:
            score += severity_weights.get(data_item.get("severity", "medium").lower(), 4)

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
        findings = []
        known_vulnerable_libs = {
            "okhttp": {"cve": "CVE-2021-0342", "version": "<4.9.0", "severity": "high"},
            "retrofit": {"cve": "CVE-2020-11012", "version": "<2.9.0", "severity": "medium"},
            "gson": {"cve": "CVE-2021-23938", "version": "<2.8.9", "severity": "medium"},
        }

        for java_dir in context.java_sources:
            if not os.path.exists(java_dir):
                continue
            for root, _, files in os.walk(java_dir):
                for filename in files:
                    if not filename.endswith(("build.gradle", "pom.xml")):
                        continue
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                            content = handle.read().lower()
                        for lib_name, lib_info in known_vulnerable_libs.items():
                            if lib_name in content:
                                findings.append(
                                    {
                                        "library": lib_name,
                                        "cve": lib_info["cve"],
                                        "affected_version": lib_info["version"],
                                        "severity": lib_info["severity"],
                                        "location": os.path.relpath(file_path, context.extracted_dir),
                                    }
                                )
                    except Exception:
                        continue
        return findings

    def execute(self, context: AgentContext) -> AgentResult:
        self.log_info(context, "Starting vulnerability scan")

        try:
            vulnerabilities = self._dedupe_findings(self._scan_vulnerabilities(context, self.vulnerability_rules))
            malware_indicators = self._check_malware(context) if self.config.get("malware_check", True) else []
            sensitive_data = self._dedupe_findings(self._check_sensitive_data(context)) if self.config.get("sensitive_data_check", True) else []
            vulnerabilities, sensitive_data, llm_triage = self._llm_triage(context, vulnerabilities, sensitive_data)
            risk_level, risk_score = self._calculate_risk(vulnerabilities, malware_indicators, sensitive_data)
            third_party_vulns = self.check_third_party_libs(context) if self.config.get("check_third_party_libs", False) else []

            context.vulnerabilities = vulnerabilities
            context.malware_indicators = malware_indicators
            context.sensitive_data = sensitive_data
            context.risk_level = risk_level
            context.risk_score = risk_score
            context.third_party_vulns = third_party_vulns
            context.llm_triage = llm_triage or None

            return AgentResult.success_result(
                message="Scan completed",
                data={
                    "vulnerabilities": vulnerabilities,
                    "malware_indicators": malware_indicators,
                    "sensitive_data": sensitive_data,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "third_party_vulns": third_party_vulns,
                    "llm_triage": llm_triage,
                },
            )
        except Exception as exc:
            self.log_error(context, f"Scan failed: {exc}")
            return AgentResult.error_result(f"Scan failed: {exc}")
