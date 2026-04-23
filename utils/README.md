# Utils 目录

本目录包含工具函数和通用辅助功能。

## 目录结构

```
utils/
├── __init__.py
├── file_utils.py            # 文件操作工具
├── path_utils.py            # 路径处理工具
├── config.py                # 配置加载
├── logger.py                # 日志工具
├── validators.py            # 数据验证
├── exceptions.py            # 自定义异常
└── constants.py             # 常量定义
```

## 核心工具函数

### file_utils.py

```python
from utils import ensure_dir, copy_file, get_file_hash, calculate_apk_size

# 确保目录存在
ensure_dir("/output/dir")

# 复制文件
copy_file("source.apk", "backup.apk")

# 计算文件哈希
md5_hash = get_file_hash("app.apk", "md5")
sha256_hash = get_file_hash("app.apk", "sha256")

# APK大小格式化
size_str = calculate_apk_size("app.apk")  # "15.2 MB"
```

### path_utils.py

```python
from utils import (
    get_apk_name,
    get_output_path,
    create_task_dir,
    get_relative_path,
    normalize_path
)

# 获取APK名称（不含扩展名）
name = get_apk_name("/path/to/app.apk")  # "app"

# 获取输出路径
output = get_output_path("/path/to/app.apk", "output")
# "output/app_20240101_120000/"

# 创建任务目录
task_dir = create_task_dir("output", "app")
# 创建并返回: output/app_20240101_120000/

# 规范化路径
normalized = normalize_path("path\\to\\file")  # "path/to/file"
```

### config.py

```python
from utils import Config

# 加载配置
config = Config("config.yaml")

# 获取值
api_key = config.get("api.key")
debug = config.get("debug", False)  # 默认值

# 设置值
config.set("output.format", "markdown")

# 保存配置
config.save()

# 获取配置节
tools_config = config.get_section("tools")
```

### logger.py

```python
from utils import Logger, get_logger

# 初始化日志
logger = Logger(
    name="APKAgent",
    level="DEBUG",
    log_file="output/agent.log"
)

# 使用日志
logger.debug("调试信息")
logger.info("普通信息")
logger.warning("警告信息")
logger.error("错误信息")

# 获取已配置的logger
log = get_logger("Extractor")
log.info("Extracting APK...")
```

### validators.py

```python
from utils import (
    validate_apk_path,
    validate_config,
    validate_manifest,
    validate_version
)

# 验证APK路径
is_valid, error = validate_apk_path("app.apk")
if not is_valid:
    raise ValueError(error)

# 验证配置
errors = validate_config(config_dict)
if errors:
    print(f"配置错误: {errors}")

# 验证版本号
if validate_version("1.0.0"):
    print("版本号格式正确")
```

### exceptions.py

```python
from utils import (
    AgentError,
    ExtractionError,
    DecompileError,
    AnalysisError,
    ScanError,
    ReportError,
    ConfigurationError,
    ToolNotFoundError
)

# 抛出异常
raise AgentError("Agent执行失败")

# 捕获异常
try:
    agent.execute(context)
except ExtractionError as e:
    print(f"解包失败: {e}")
except ToolNotFoundError as e:
    print(f"工具未找到: {e}")
```

### constants.py

```python
from utils import (
    RiskLevel,        # 风险等级常量
    Severity,         # 严重程度常量
    FileType,         # 文件类型常量
    ComponentType     # 组件类型常量
)

# 使用常量
RiskLevel.CRITICAL  # "critical"
RiskLevel.HIGH      # "high"
RiskLevel.MEDIUM    # "medium"
RiskLevel.LOW       # "low"

ComponentType.ACTIVITY   # "activity"
ComponentType.SERVICE    # "service"
ComponentType.RECEIVER   # "receiver"
ComponentType.PROVIDER   # "provider"
```

## 通用数据类

```python
from utils.dataclasses import (
    APKInfo,
    Vulnerability,
    Component,
    Permission,
    AnalysisResult
)

# 创建数据结构
apk_info = APKInfo(
    package="com.example.app",
    version="1.0.0",
    version_code=1,
    min_sdk=21,
    target_sdk=33
)

vuln = Vulnerability(
    id="VULN-001",
    name="不安全的WebView",
    severity=Severity.HIGH,
    cwe="CWE-79",
    description="...",
    remediation="..."
)
```

## 使用示例

```python
from utils import Config, Logger, ensure_dir, get_file_hash
from utils.exceptions import ExtractionError

# 完整使用示例
config = Config.load("config.yaml")
logger = Logger("main").get_logger()

output_dir = "output/analysis"
ensure_dir(output_dir)

try:
    # 执行分析...
    pass
except ExtractionError as e:
    logger.error(f"解包失败: {e}")
    raise
```