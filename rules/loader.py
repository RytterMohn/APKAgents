"""
Loader
规则加载器
"""

import os
import json
from typing import List, Dict
from .schema import VulnerabilityRule, MalwareIndicator, SensitiveDataPattern


def load_vulnerability_rules(rules_file: str) -> List[VulnerabilityRule]:
    """
    加载漏洞规则

    Args:
        rules_file: 规则文件路径

    Returns:
        漏洞规则列表
    """
    rules = []

    if not os.path.exists(rules_file):
        return rules

    with open(rules_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data.get("rules", []):
        rule = VulnerabilityRule(
            id=item.get("id", ""),
            name=item.get("name", ""),
            description=item.get("description", ""),
            severity=item.get("severity", "medium"),
            cwe=item.get("cwe"),
            cvss=item.get("cvss"),
            patterns=item.get("patterns", []),
            remediation=item.get("remediation", "")
        )
        rules.append(rule)

    return rules


def load_malware_indicators(indicators_file: str) -> List[MalwareIndicator]:
    """
    加载恶意软件特征

    Args:
        indicators_file: 特征文件路径

    Returns:
        恶意软件特征列表
    """
    indicators = []

    if not os.path.exists(indicators_file):
        return indicators

    with open(indicators_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data.get("indicators", []):
        indicator = MalwareIndicator(
            id=item.get("id", ""),
            name=item.get("name", ""),
            category=item.get("category", ""),
            severity=item.get("severity", "medium"),
            indicators=item.get("indicators", {}),
            description=item.get("description", "")
        )
        indicators.append(indicator)

    return indicators


def load_sensitive_data_patterns(patterns_file: str) -> List[SensitiveDataPattern]:
    """
    加载敏感数据模式

    Args:
        patterns_file: 模式文件路径

    Returns:
        敏感数据模式列表
    """
    patterns = []

    if not os.path.exists(patterns_file):
        return patterns

    with open(patterns_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data.get("patterns", []):
        pattern = SensitiveDataPattern(
            id=item.get("id", ""),
            name=item.get("name", ""),
            type=item.get("type", ""),
            regex=item.get("regex", ""),
            severity=item.get("severity", "medium"),
            false_positives=item.get("false_positives", [])
        )
        patterns.append(pattern)

    return patterns