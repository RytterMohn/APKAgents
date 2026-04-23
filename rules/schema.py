"""
Schema
规则数据结构定义
"""

from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class VulnerabilityRule:
    """漏洞规则"""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    patterns: List[Dict] = None
    remediation: str = ""

    def matches(self, code_content: str) -> bool:
        """检查代码是否匹配"""
        if not self.patterns:
            return False

        for pattern in self.patterns:
            pattern_type = pattern.get("type", "")
            pattern_str = pattern.get("pattern", "")

            if pattern_type == "code" and pattern_str in code_content:
                return True

        return False


@dataclass
class MalwareIndicator:
    """恶意软件特征"""
    id: str
    name: str
    category: str
    severity: str
    indicators: Dict
    description: str = ""

    def check_permissions(self, permissions: List[str]) -> bool:
        """检查权限是否匹配"""
        required = self.indicators.get("permissions", [])
        return any(p in permissions for p in required)

    def check_apis(self, apis: List[str]) -> bool:
        """检查API是否匹配"""
        required = self.indicators.get("apis", [])
        return any(api in apis for api in required)


@dataclass
class SensitiveDataPattern:
    """敏感数据模式"""
    id: str
    name: str
    type: str
    regex: str
    severity: str
    false_positives: List[str] = None

    def __post_init__(self):
        if self.false_positives is None:
            self.false_positives = []