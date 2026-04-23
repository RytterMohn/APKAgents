# Agents 目录

本目录包含所有Agent的实现，每个Agent是一个独立的功能单元。

## 目录结构

```
agents/
├── __init__.py           # 模块入口，导出所有Agent
├── base.py               # Agent基类，定义通用接口
├── orchestrator.py       # 总调度Agent
├── extractor.py          # 解包Agent
├── decompiler.py         # 反编译Agent
├── analyzer.py           # 分析Agent
├── scanner.py            # 扫描Agent
├── reporter.py           # 报告Agent
└── formatter.py          # 格式化Agent
```

## Agent交互接口规范

所有Agent继承自 `BaseAgent`，必须实现以下接口：

### 基础接口

```python
class BaseAgent(ABC):
    """所有Agent的基类"""

    @abstractmethod
    def execute(self, context: AgentContext) -> AgentResult:
        """
        执行Agent的核心逻辑

        Args:
            context: 包含输入数据和配置

        Returns:
            AgentResult: 执行结果
        """
        pass

    @abstractmethod
    def get_required_inputs(self) -> List[str]:
        """
        返回该Agent需要的输入字段

        Returns:
            List[str]: 输入字段列表
        """
        pass

    @abstractmethod
    def get_output_schema(self) -> Dict:
        """
        返回该Agent输出的数据结构

        Returns:
            Dict: 输出schema定义
        """
        pass
```

### AgentContext 定义

```python
@dataclass
class AgentContext:
    """Agent执行上下文，所有Agent共享的数据容器"""
    task_id: str                    # 任务ID
    apk_path: str                   # APK文件路径
    output_dir: str                 # 输出目录
    config: Dict                    # 全局配置

    # Extractor Agent 输出
    extracted_dir: str = None       # 解包后的目录
    manifest_data: Dict = None      # Manifest数据
    dex_files: List[str] = None     # DEX文件列表
    signature_info: Dict = None     # 签名信息

    # Decompiler Agent 输出
    decompiled_dir: str = None      # 反编译后的目录
    java_sources: List[str] = None  # Java源码列表
    smali_files: List[str] = None   # Smali文件列表

    # Analyzer Agent 输出
    components: Dict = None         # 组件信息
    permissions: List[str] = None   # 权限列表
    sensitive_apis: List[Dict] = None  # 敏感API调用

    # Scanner Agent 输出
    vulnerabilities: List[Dict] = None  # 漏洞列表
    risk_level: str = None          # 风险等级

    # 共享数据
    shared_data: Dict = None        # Agent间共享的自定义数据
```

### AgentResult 定义

```python
@dataclass
class AgentResult:
    """Agent执行结果"""
    success: bool                   # 是否成功
    message: str                    # 执行信息
    data: Dict                      # 输出数据
    artifacts: List[str] = None     # 产生的文件列表
    errors: List[str] = None        # 错误列表
    warnings: List[str] = None      # 警告列表
```

## Agent调用流程图

```
Orchestrator
    │
    ├──► Extractor.execute(context)
    │        输入: apk_path, output_dir, config
    │        输出: extracted_dir, manifest_data, dex_files, signature_info
    │
    ├──► Decompiler.execute(context)
    │        输入: dex_files (来自context)
    │        输出: decompiled_dir, java_sources, smali_files
    │
    ├──► Analyzer.execute(context)
    │        输入: extracted_dir, manifest_data, decompiled_dir
    │        输出: components, permissions, sensitive_apis
    │
    ├──► Scanner.execute(context)
    │        输入: extracted_dir, decompiled_dir, java_sources
    │        输出: vulnerabilities, risk_level
    │
    ├──► Reporter.execute(context)
    │        输入: 所有上述输出
    │        输出: report_data
    │
    └──► Formatter.execute(context)
             输入: report_data
             输出: formatted_output (markdown/html/json)
```

## Agent间数据传递规则

1. **Orchestrator** 负责创建 `AgentContext` 并在每步执行后更新context
2. 每个Agent从context读取自己的输入，将输出写回context
3. 下一个Agent可以读取前一个Agent的输出作为输入
4. 所有Agent都可以向 `shared_data` 写入自定义数据供其他Agent使用

## 错误处理

- Agent执行失败应返回 `success=False` 和详细的错误信息
- Orchestrator会根据配置决定是停止还是跳过失败的Agent
- 错误信息会累积到最终的报告中

## 使用示例

```python
from agents import OrchestratorAgent, AgentContext

# 创建上下文
context = AgentContext(
    task_id="task_001",
    apk_path="/path/to/apk",
    output_dir="/output",
    config={}
)

# 创建并执行
agent = OrchestratorAgent()
result = agent.execute(context)

# 获取结果
if result.success:
    print(result.artifacts)
```