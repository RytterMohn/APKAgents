# APK Multi-Agent Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square" alt="Status">
</p>

APK多Agent自动分析系统，基于LangChain + CrewAI架构实现自动化APK安全分析、漏洞扫描和报告生成。

## ✨ 特性

- 🤖 **多Agent协作** - 7个专业Agent分工协作：解包、反编译、分析、扫描、报告
- 🔍 **静态分析** - 权限分析、组件分析、敏感API检测、网络通信分析
- 🛡️ **漏洞扫描** - 内置10+条漏洞检测规则，覆盖常见Android安全风险
- 🦠 **恶意软件检测** - 8类恶意软件特征检测
- 🔑 **敏感数据检测** - 硬编码密码、API密钥、私钥等敏感信息扫描
- 📊 **多格式报告** - 支持Markdown、HTML、JSON格式输出

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Agent                        │
│                      (总调度Agent)                           │
└─────────────────────────────────────────────────────────────┘
           │            │            │            │
    ┌──────┴──────┐ ┌───┴────┐ ┌────┴────┐ ┌───┴──────┐
    │ Extractor   │ │Analyzer│ │ Scanner │ │ Reporter │
    │ (解包)      │ │ (分析) │ │ (扫描)  │ │ (报告)   │
    └─────────────┘ └────────┘ └─────────┘ └──────────┘
```

## 📁 项目结构

```
APKAgents/
├── agents/                    # Agent实现
│   ├── orchestrator.py       # 总调度Agent
│   ├── extractor.py          # 解包Agent
│   ├── decompiler.py         # 反编译Agent
│   ├── analyzer.py           # 分析Agent
│   ├── scanner.py            # 扫描Agent
│   ├── reporter.py           # 报告Agent
│   └── formatter.py          # 格式化Agent
├── tools/                     # 工具封装
│   ├── apktool_wrapper.py
│   ├── jadx_wrapper.py
│   └── androguard_wrapper.py
├── rules/                     # 扫描规则
│   ├── vulnerability_rules.json
│   ├── malware_indicators.json
│   └── sensitive_data_patterns.json
├── config/                    # 配置文件
├── utils/                     # 工具函数
├── templates/                 # 报告模板
├── main.py                    # 入口文件
└── requirements.txt           # 依赖
```

## 🚀 快速开始

### 1. 安装依赖

```bash
# 克隆项目
git clone https://github.com/yourusername/APKAgents.git
cd APKAgents

# 安装Python依赖
pip install -r requirements.txt
```

### 2. 安装系统工具

| 工具 | 要求 | 说明 |
|------|------|------|
| Java | JDK 17+ | apktool和jadx需要 |
| apktool | 2.9+ | APK解包 |
| jadx | 1.4+ | DEX反编译 |
| aapt | - | APK信息提取 |
| apksigner | - | 签名验证 |

下载后添加到系统PATH，或在 `config/tools.yaml` 中配置路径。

### 3. 运行分析

```bash
# 基本用法
python main.py your_app.apk

# 指定输出目录
python main.py your_app.apk -o output

# 跳过反编译（更快）
python main.py your_app.apk --no-decompile

# 详细输出
python main.py your_app.apk -v
```

## 📖 使用示例

```python
from agents import OrchestratorAgent, AgentContext

# 创建上下文
context = AgentContext(
    apk_path="app.apk",
    output_dir="output",
    config={}
)

# 执行分析
agent = OrchestratorAgent()
result = agent.execute(context)

# 获取报告
print(result.data["markdown_report"])
```

## ⚙️ 配置

编辑 `config/default.yaml` 自定义分析行为：

```yaml
analysis:
  parallel: true
  max_workers: 4
  timeout: 300

agents:
  enabled:
    extractor: true
    decompiler: true
    analyzer: true
    scanner: true
    reporter: true
    formatter: true
```

## 📊 检测规则

### 漏洞规则 (10条)

- VULN-001: 不安全的WebView配置
- VULN-002: 不安全的Intent广播
- VULN-003: 不安全的随机数生成
- VULN-004: 不安全的信任管理器
- VULN-005: 调试标志启用
- VULN-006: WebView远程代码执行
- VULN-007: 不安全的文件权限
- VULN-008: 日志泄露敏感信息
- VULN-009: 动态加载代码
- VULN-010: SQL注入

### 恶意软件特征 (8类)

- MAL-001: 短信窃取器
- MAL-002: 间谍软件
- MAL-003: 电话扣费
- MAL-004: 银行木马
- MAL-005: Root提权
- MAL-006: 远程控制
- MAL-007: 勒索软件
- MAL-008: 广告软件

### 敏感数据模式 (12种)

- API密钥、AWS密钥、私钥
- 硬编码密码、JWT Token
- 数据库连接字符串
- 信用卡号、IP地址等

## 🔧 开发

```bash
# 运行测试
python -m pytest tests/

# 代码格式化
black agents/ tools/ utils/

# 类型检查
mypy agents/ --ignore-missing-imports
```

## 📝 输出示例

分析完成后，会在输出目录生成：

```
output/
├── report.md      # Markdown报告
├── report.html    # HTML报告
└── report.json    # JSON报告
```

## 🤝 贡献

欢迎提交Issue和Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/xxx`)
3. 提交更改 (`git commit -m 'Add xxx'`)
4. 推送分支 (`git push origin feature/xxx`)
5. 创建Pull Request

## 📄 许可证

MIT License - 查看 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [apktool](https://github.com/iBotPeaches/Apktool) - APK解包
- [jadx](https://github.com/skylot/jadx) - DEX反编译
- [Androguard](https://github.com/androguard/androguard) - 静态分析
- [LangChain](https://github.com/langchain-ai/langchain) - LLM框架
- [CrewAI](https://github.com/crewAIInc/crewAI) - 多Agent框架