"""
Exceptions
自定义异常类
"""


class AgentError(Exception):
    """Agent基础异常"""
    pass


class ExtractionError(AgentError):
    """解包异常"""
    pass


class DecompileError(AgentError):
    """反编译异常"""
    pass


class AnalysisError(AgentError):
    """分析异常"""
    pass


class ScanError(AgentError):
    """扫描异常"""
    pass


class ReportError(AgentError):
    """报告生成异常"""
    pass


class ConfigurationError(AgentError):
    """配置异常"""
    pass


class ToolNotFoundError(AgentError):
    """工具未找到异常"""
    pass


class ValidationError(AgentError):
    """验证异常"""
    pass


class RuleError(AgentError):
    """规则加载异常"""
    pass