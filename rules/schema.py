"""
Rule data structures.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class VulnerabilityRule:
    id: str
    name: str
    description: str
    severity: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    patterns: List[Dict] = None
    remediation: str = ""

    def matches(self, code_content: str) -> bool:
        if not self.patterns:
            return False

        for pattern in self.patterns:
            pattern_str = pattern.get("pattern", "")
            pattern_type = pattern.get("type", "")
            if not pattern_str or pattern_type not in {"code", "api", "manifest"}:
                continue
            try:
                if re.search(pattern_str, code_content, re.IGNORECASE | re.MULTILINE):
                    return True
            except re.error:
                if pattern_str in code_content:
                    return True
        return False


@dataclass
class MalwareIndicator:
    id: str
    name: str
    category: str
    severity: str
    indicators: Dict
    description: str = ""

    def check_permissions(self, permissions: List[str]) -> bool:
        required = self.indicators.get("permissions", [])
        return any(item in permissions for item in required)

    def check_apis(self, apis: List[str]) -> bool:
        required = self.indicators.get("apis", [])
        return any(item in apis for item in required)


@dataclass
class SensitiveDataPattern:
    id: str
    name: str
    type: str
    regex: str
    severity: str
    false_positives: List[str] = None

    def __post_init__(self):
        if self.false_positives is None:
            self.false_positives = []
