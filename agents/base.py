"""
Base agent classes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from utils.llm import LLMClient


@dataclass
class AgentContext:
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    apk_path: str = ""
    output_dir: str = ""
    config: Dict[str, Any] = field(default_factory=dict)

    extracted_dir: Optional[str] = None
    manifest_data: Optional[Dict] = None
    manifest_xml: Optional[str] = None
    dex_files: Optional[List[str]] = None
    signature_info: Optional[Dict] = None
    resource_files: Optional[List[str]] = None

    decompiled_dir: Optional[str] = None
    java_sources: Optional[List[str]] = None
    smali_files: Optional[List[str]] = None
    jar_files: Optional[List[str]] = None

    apk_info: Optional[Dict] = None
    components: Optional[Dict] = None
    permissions: Optional[List[str]] = None
    sensitive_apis: Optional[List[Dict]] = None
    network_calls: Optional[List[Dict]] = None
    crypto_usage: Optional[List[Dict]] = None

    vulnerabilities: Optional[List[Dict]] = None
    malware_indicators: Optional[List[Dict]] = None
    sensitive_data: Optional[List[Dict]] = None
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    llm_triage: Optional[Dict] = None
    llm_summary: Optional[Dict] = None

    report_data: Optional[Dict] = None
    report_path: Optional[str] = None

    formatted_output: Optional[Dict] = None
    markdown_report: Optional[str] = None
    html_report: Optional[str] = None
    json_report: Optional[str] = None

    shared_data: Dict[str, Any] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        self.errors.append(error)

    def add_warning(self, warning: str):
        self.warnings.append(warning)

    def get_duration(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


@dataclass
class AgentResult:
    success: bool = False
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @classmethod
    def success_result(cls, message: str = "", data: Dict = None, artifacts: List = None):
        return cls(success=True, message=message, data=data or {}, artifacts=artifacts or [])

    @classmethod
    def error_result(cls, message: str = "", errors: List = None):
        return cls(success=False, message=message, errors=errors or [message])


class BaseAgent(ABC):
    def __init__(self, name: str = None, config: Dict = None):
        self.name = name or self.__class__.__name__
        self.config = config or {}

    @abstractmethod
    def execute(self, context: AgentContext) -> AgentResult:
        pass

    @abstractmethod
    def get_required_inputs(self) -> List[str]:
        pass

    @abstractmethod
    def get_output_schema(self) -> Dict:
        pass

    def validate_inputs(self, context: AgentContext) -> tuple[bool, str]:
        missing = []
        for field_name in self.get_required_inputs():
            if getattr(context, field_name, None) is None:
                missing.append(field_name)
        if missing:
            return False, f"Missing required inputs: {', '.join(missing)}"
        return True, ""

    def log_info(self, context: AgentContext, message: str):
        print(f"[{self.name}] INFO: {message}")

    def log_error(self, context: AgentContext, message: str):
        print(f"[{self.name}] ERROR: {message}")

    def log_warning(self, context: AgentContext, message: str):
        print(f"[{self.name}] WARNING: {message}")

    def get_llm_client(self, context: AgentContext) -> Optional[LLMClient]:
        cache_key = "_llm_client"
        if cache_key not in context.shared_data:
            client = LLMClient((context.config or {}).get("api", {}))
            context.shared_data[cache_key] = client if client.is_enabled() else None
        return context.shared_data[cache_key]
