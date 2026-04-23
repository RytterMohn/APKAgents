"""
Base Agent Classes
定义所有Agent的基类和通用数据结构
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid


@dataclass
class AgentContext:
    """
    Agent执行上下文，所有Agent共享的数据容器
    在Orchestrator调度下在Agent之间传递
    """
    # 任务基础信息
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    apk_path: str = ""
    output_dir: str = ""
    config: Dict[str, Any] = field(default_factory=dict)

    # ========== Extractor Agent 输出 ==========
    extracted_dir: Optional[str] = None  # 解包后的目录
    manifest_data: Optional[Dict] = None  # Manifest数据
    manifest_xml: Optional[str] = None    # Manifest XML路径
    dex_files: Optional[List[str]] = None  # DEX文件列表
    signature_info: Optional[Dict] = None  # 签名信息
    resource_files: Optional[List[str]] = None  # 资源文件

    # ========== Decompiler Agent 输出 ==========
    decompiled_dir: Optional[str] = None  # 反编译后的目录
    java_sources: Optional[List[str]] = None  # Java源码列表
    smali_files: Optional[List[str]] = None  # Smali文件列表
    jar_files: Optional[List[str]] = None  # JAR文件列表

    # ========== Analyzer Agent 输出 ==========
    apk_info: Optional[Dict] = None  # APK基本信息
    components: Optional[Dict] = None  # 组件信息
    permissions: Optional[List[str]] = None  # 权限列表
    sensitive_apis: Optional[List[Dict]] = None  # 敏感API调用
    network_calls: Optional[List[Dict]] = None  # 网络通信分析
    crypto_usage: Optional[List[Dict]] = None  # 加密使用分析

    # ========== Scanner Agent 输出 ==========
    vulnerabilities: Optional[List[Dict]] = None  # 漏洞列表
    malware_indicators: Optional[List[Dict]] = None  # 恶意软件特征
    sensitive_data: Optional[List[Dict]] = None  # 敏感数据泄露
    risk_level: Optional[str] = None  # 风险等级
    risk_score: Optional[float] = None  # 风险评分(0-100)

    # ========== Reporter Agent 输出 ==========
    report_data: Optional[Dict] = None  # 报告数据
    report_path: Optional[str] = None  # 报告路径

    # ========== Formatter Agent 输出 ==========
    formatted_output: Optional[Dict] = None  # 格式化输出
    markdown_report: Optional[str] = None  # Markdown报告
    html_report: Optional[str] = None  # HTML报告
    json_report: Optional[str] = None  # JSON报告

    # ========== 共享数据 ==========
    shared_data: Dict[str, Any] = field(default_factory=dict)  # Agent间共享的自定义数据

    # 元数据
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        """添加错误信息"""
        self.errors.append(error)

    def add_warning(self, warning: str):
        """添加警告信息"""
        self.warnings.append(warning)

    def get_duration(self) -> Optional[float]:
        """获取执行时长（秒）"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


@dataclass
class AgentResult:
    """
    Agent执行结果
    """
    success: bool = False
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)  # 产生的文件列表
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @classmethod
    def success_result(cls, message: str = "", data: Dict = None, artifacts: List = None):
        """创建成功结果"""
        return cls(
            success=True,
            message=message,
            data=data or {},
            artifacts=artifacts or []
        )

    @classmethod
    def error_result(cls, message: str = "", errors: List = None):
        """创建错误结果"""
        return cls(
            success=False,
            message=message,
            errors=errors or [message]
        )


class BaseAgent(ABC):
    """
    所有Agent的基类
    定义通用接口和方法
    """

    def __init__(self, name: str = None, config: Dict = None):
        self.name = name or self.__class__.__name__
        self.config = config or {}

    @abstractmethod
    def execute(self, context: AgentContext) -> AgentResult:
        """
        执行Agent的核心逻辑

        Args:
            context: AgentContext，包含输入数据和配置

        Returns:
            AgentResult: 执行结果
        """
        pass

    @abstractmethod
    def get_required_inputs(self) -> List[str]:
        """
        返回该Agent需要的输入字段（context中的属性名）

        Returns:
            List[str]: 输入字段列表
            例如: ["apk_path", "output_dir"]
        """
        pass

    @abstractmethod
    def get_output_schema(self) -> Dict:
        """
        返回该Agent输出的数据结构定义

        Returns:
            Dict: 输出schema
            例如: {
                "extracted_dir": "str",
                "manifest_data": "dict",
                "dex_files": "list"
            }
        """
        pass

    def validate_inputs(self, context: AgentContext) -> tuple[bool, str]:
        """
        验证输入是否满足要求

        Args:
            context: AgentContext

        Returns:
            (is_valid, error_message)
        """
        required = self.get_required_inputs()
        missing = []

        for field in required:
            value = getattr(context, field, None)
            if value is None:
                missing.append(field)

        if missing:
            return False, f"Missing required inputs: {', '.join(missing)}"

        return True, ""

    def log_info(self, context: AgentContext, message: str):
        """记录信息日志"""
        print(f"[{self.name}] INFO: {message}")

    def log_error(self, context: AgentContext, message: str):
        """记录错误日志"""
        print(f"[{self.name}] ERROR: {message}")

    def log_warning(self, context: AgentContext, message: str):
        """记录警告日志"""
        print(f"[{self.name}] WARNING: {message}")