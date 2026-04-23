"""
Orchestrator Agent - 总调度Agent
负责协调其他Agent的工作流程
"""

from typing import List, Dict
from .base import BaseAgent, AgentContext, AgentResult
from .extractor import ExtractorAgent
from .decompiler import DecompilerAgent
from .analyzer import AnalyzerAgent
from .scanner import ScannerAgent
from .reporter import ReporterAgent
from .formatter import FormatterAgent


class OrchestratorAgent(BaseAgent):
    """
    总调度Agent
    负责:
    - 接收用户提交的APK文件
    - 协调其他Agent的工作流程
    - 管理分析任务的状态和进度
    - 汇总各Agent的分析结果
    - 处理错误和异常情况
    """

    def __init__(self, config: Dict = None):
        super().__init__("Orchestrator", config)
        self.agents = {}
        self._init_agents()

    def _init_agents(self):
        """初始化所有子Agent"""
        self.agents = {
            "extractor": ExtractorAgent(self.config.get("extractor", {})),
            "decompiler": DecompilerAgent(self.config.get("decompiler", {})),
            "analyzer": AnalyzerAgent(self.config.get("analyzer", {})),
            "scanner": ScannerAgent(self.config.get("scanner", {})),
            "reporter": ReporterAgent(self.config.get("reporter", {})),
            "formatter": FormatterAgent(self.config.get("formatter", {})),
        }

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["apk_path", "output_dir"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "report_path": "str",
            "markdown_report": "str",
            "html_report": "str",
            "json_report": "str"
        }

    def execute(self, context: AgentContext) -> AgentResult:
        """
        执行完整的工作流程

        Workflow:
        1. Extractor - 解包APK
        2. Decompiler - 反编译DEX
        3. Analyzer - 静态分析
        4. Scanner - 漏洞扫描
        5. Reporter - 生成报告
        6. Formatter - 格式化输出
        """
        context.start_time = __import__('datetime').datetime.now()
        self.log_info(context, f"Starting APK analysis: {context.apk_path}")

        # 定义执行顺序和依赖关系
        workflow = [
            ("extractor", ["Extractor Agent"]),
            ("decompiler", ["Decompiler Agent"]),
            ("analyzer", ["Analyzer Agent"]),
            ("scanner", ["Scanner Agent"]),
            ("reporter", ["Reporter Agent"]),
            ("formatter", ["Formatter Agent"]),
        ]

        for agent_key, agent_names in workflow:
            # 检查是否启用该Agent
            if not self.config.get("enabled", {}).get(agent_key, True):
                self.log_info(context, f"Skipping {agent_key} (disabled)")
                continue

            agent = self.agents.get(agent_key)
            if not agent:
                continue

            # 检查输入
            is_valid, error = agent.validate_inputs(context)
            if not is_valid:
                context.add_error(f"{agent.name}: {error}")
                # 根据配置决定是否继续
                if self.config.get("stop_on_error", True):
                    return AgentResult.error_result(error)

            # 执行Agent
            self.log_info(context, f"Running {agent.name}...")
            try:
                result = agent.execute(context)

                if result.success:
                    self.log_info(context, f"{agent.name} completed successfully")
                    # 将结果数据合并到context
                    for key, value in result.data.items():
                        setattr(context, key, value)
                else:
                    context.add_error(f"{agent.name} failed: {result.message}")
                    if self.config.get("stop_on_error", True):
                        return AgentResult.error_result(
                            f"Workflow failed at {agent.name}",
                            result.errors
                        )

            except Exception as e:
                error_msg = f"{agent.name} exception: {str(e)}"
                context.add_error(error_msg)
                self.log_error(context, error_msg)
                if self.config.get("stop_on_error", True):
                    return AgentResult.error_result(error_msg)

        context.end_time = __import__('datetime').datetime.now()

        # 返回最终结果
        return AgentResult.success_result(
            message="Analysis completed",
            data={
                "report_path": context.report_path,
                "markdown_report": context.markdown_report,
                "html_report": context.html_report,
                "json_report": context.json_report,
                "task_id": context.task_id,
                "duration": context.get_duration(),
            },
            artifacts=[context.report_path] if context.report_path else []
        )

    def execute_single(self, context: AgentContext, agent_name: str) -> AgentResult:
        """
        执行单个Agent（用于调试或重试）

        Args:
            context: AgentContext
            agent_name: Agent名称 (extractor/decompiler/analyzer/scanner/reporter/formatter)
        """
        agent = self.agents.get(agent_name)
        if not agent:
            return AgentResult.error_result(f"Unknown agent: {agent_name}")

        return agent.execute(context)

    def get_workflow_status(self, context: AgentContext) -> Dict:
        """
        获取工作流程状态

        Returns:
            已执行/跳过的Agent列表
        """
        status = {
            "task_id": context.task_id,
            "duration": context.get_duration(),
            "errors": context.errors,
            "warnings": context.warnings,
            "stages_completed": []
        }

        # 检查各阶段是否完成
        if context.extracted_dir:
            status["stages_completed"].append("extractor")
        if context.decompiled_dir:
            status["stages_completed"].append("decompiler")
        if context.components:
            status["stages_completed"].append("analyzer")
        if context.vulnerabilities:
            status["stages_completed"].append("scanner")
        if context.report_data:
            status["stages_completed"].append("reporter")
        if context.formatted_output:
            status["stages_completed"].append("formatter")

        return status