# Config 目录

本目录包含系统配置文件。

## 目录结构

```
config/
├── __init__.py
├── default.yaml           # 默认配置
├── tools.yaml             # 工具路径配置
├── rules.yaml             # 规则配置
└── templates/             # 配置模板
    └── .env.example       # 环境变量示例
```

## 配置文件说明

### default.yaml - 主配置

```yaml
# 应用配置
app:
  name: "APK Multi-Agent Analyzer"
  version: "1.0.0"
  debug: false

# 分析配置
analysis:
  # 是否并行执行独立任务
  parallel: true
  # 最大并行任务数
  max_workers: 4
  # 超时时间（秒）
  timeout: 300
  # 是否跳过已存在的输出
  skip_existing: false

# 输出配置
output:
  # 输出格式: markdown, html, json, all
  format: ["markdown", "html", "json"]
  # 输出目录
  base_dir: "output"
  # 是否压缩输出
  compress: false

# 日志配置
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  file: "output/agent.log"
  max_size: 10MB
  backup_count: 5

# API配置 (Claude API)
api:
  provider: "anthropic"
  model: "claude-sonnet-4-6"
  max_tokens: 4096
  temperature: 0.7
  cache: true  # 启用prompt缓存

# Agent配置
agents:
  # 是否启用某个Agent
  enabled:
    extractor: true
    decompiler: true
    analyzer: true
    scanner: true
    reporter: true
    formatter: true

  # Agent特定配置
  extractor:
    decode_resources: true
    decode_sources: false

  analyzer:
    # 深度分析模式
    deep_analysis: true
    # 分析内容
    check_permissions: true
    check_components: true
    check_network: true
    check_crypto: true
    check_storage: true

  scanner:
    # 漏洞规则路径
    rules_dir: "rules"
    # 使用外部工具
    use_mobsf: false
    use_quark: true
    # 恶意软件检测
    malware_check: true
```

### tools.yaml - 工具路径配置

```yaml
# 工具基础目录
base_dir: "D:/tools"

tools:
  # apktool 配置
  apktool:
    path: "D:/tools/apktool.bat"
    version_command: "apktool version"
    # apktol版本（自动检测后填充）
    version: ""

  # jadx 配置
  jadx:
    path: "D:/tools/jadx/bin/jadx.bat"
    # jadx.conf 配置
    conf: "D:/tools/jadx/conf/jadx.conf"
    version: ""

  # dex2jar 配置
  dex2jar:
    path: "D:/tools/dex2jar/d2j-dex2jar.bat"
    version: ""

  # aapt 配置 (Android Asset Packaging Tool)
  aapt:
    path: "D:/tools/android-sdk/build-tools/33.0.0/aapt.exe"
    version: ""

  # apksigner 配置
  apksigner:
    path: "D:/tools/android-sdk/build-tools/33.0.0/apksigner.bat"
    version: ""

# Python包
python_tools:
  androguard:
    package: "androguard"
    version: "3.4.0"

  quark_engine:
    package: "quark-engine"
    version: "24.4.1"

  mobsf:
    package: "mobsf"
    # 如果使用REST API
    api_url: "http://localhost:8000"
    api_key: ""
```

### rules.yaml - 规则配置

```yaml
# 漏洞检测规则
vulnerability:
  # 规则文件路径
  rules_file: "rules/vulnerability_rules.json"
  # 启用哪些规则（按ID前缀过滤）
  enabled_rules:
    - "VULN-*"
  # 禁用哪些规则
  disabled_rules: []
  # 严重程度阈值（低于此级别的漏洞不报告）
  severity_threshold: "low"

# 恶意软件检测
malware:
  # 特征文件
  indicators_file: "rules/malware_indicators.json"
  # 是否启用
  enabled: true
  # 置信度阈值
  confidence_threshold: 0.7

# 敏感数据检测
sensitive_data:
  # 模式文件
  patterns_file: "rules/sensitive_data_patterns.json"
  # 启用哪些模式
  enabled_patterns:
    - "SENS-*"
  # 生成告警
  alert_on_find: true
```

### templates/.env.example - 环境变量

```bash
# Claude API 配置
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx

# 输出目录
OUTPUT_DIR=output

# 调试模式
DEBUG=false

# 日志级别
LOG_LEVEL=INFO
```

## 使用示例

```python
from utils import Config

# 加载配置
config = Config("config/default.yaml")
config.merge("config/tools.yaml")

# 访问配置
app_name = config.get("app.name")
tools_path = config.get("tools.apktool.path")

# 修改配置
config.set("analysis.timeout", 600)
config.save()
```

## 环境变量覆盖

配置可以通过环境变量覆盖：

```bash
export ANTHROPIC_API_KEY="your-key"
export OUTPUT_DIR="custom_output"
export DEBUG="true"
```

优先级: 环境变量 > 用户配置 > 默认配置