# APKAgents

一个面向 Android APK 的多 Agent 安全分析工具。  
它把解包、反编译、静态规则扫描、恶意行为检测，以及可选的 LLM 复核与总结串成一条自动化分析流水线，输出适合阅读和二次处理的安全报告。

## 项目特点

- 多 Agent 协作
  将 APK 分析过程拆分为解包、反编译、分析、扫描、报告、格式化等多个职责明确的 Agent。
- 静态安全分析
  提取权限、组件导出情况、基础元数据，并结合源码或反编译结果进行规则扫描。
- 规则 + LLM 双层机制
  先用确定性的规则发现候选问题，再用可选 LLM 做结果归纳、降噪和修复建议生成。
- 多格式报告输出
  默认生成 `Markdown`、`HTML`、`JSON` 三种报告。
- 适合继续扩展
  当前结构已经具备继续拆分为更细粒度安全 Agent 的基础。

## 当前 Agent 流程

项目当前采用编排式多 Agent 流程：

1. `ExtractorAgent`
   负责 APK 解包、Manifest/资源/签名信息提取。
2. `DecompilerAgent`
   负责调用反编译工具，产出 Java/Smali 等分析材料。
3. `AnalyzerAgent`
   负责提取 APK 基本信息、权限、组件暴露面等结构化数据。
4. `ScannerAgent`
   负责漏洞规则扫描、敏感数据检测、恶意软件指标检测，并可接入 LLM 进行结果复核。
5. `ReporterAgent`
   负责汇总所有 Agent 结果，并在启用 LLM 时生成总结、重点问题、修复建议与残余风险。
6. `FormatterAgent`
   负责将最终结果格式化为 `Markdown / HTML / JSON`。
7. `OrchestratorAgent`
   负责调度整个分析工作流。

## 项目结构

```text
APKAgents/
├─ agents/        # 多 Agent 核心实现
├─ config/        # 配置文件
├─ rules/         # 扫描规则
├─ templates/     # 模板与说明
├─ tools/         # 外部工具封装
├─ utils/         # 通用工具与 LLM Client
├─ main.py        # 命令行入口
└─ requirements.txt
```

## 环境要求

- Python `3.10+`
- Java 运行环境
- 本地可用的 Android 分析工具，例如：
  - `apktool`
  - `jadx`
  - `aapt`
  - `apksigner`

## 安装

```bash
git clone https://github.com/yourusername/APKAgents.git
cd APKAgents
pip install -r requirements.txt
```

## 快速开始

基础用法：

```bash
python main.py sample.apk
```

指定输出目录：

```bash
python main.py sample.apk -o output
```

启用详细日志：

```bash
python main.py sample.apk -v
```

## 配置说明

默认配置文件：

- [config/default.yaml](config/default.yaml)

本地运行配置示例：

- [config/local-run.example.yaml](config/local-run.example.yaml)

建议做法是：

1. 复制 `config/local-run.example.yaml`
2. 填入你自己的本地工具路径
3. 按需填写 LLM 网关地址、模型名和 API Key
4. 本地使用，不要提交到仓库

## LLM 支持

项目可以在 **不启用 LLM** 的情况下运行。  
启用后，LLM 主要用于：

- 结果归纳
- 误报压缩
- 风险总结
- 修复建议生成

当前实现使用兼容 Anthropic `messages` 接口风格的客户端。如果你的网关支持这一协议，可以直接接入。

## 输出结果

一次分析通常会生成：

```text
output/
├─ report.md
├─ report.html
└─ report.json
```

其中：

- `report.md` 适合阅读和提交审计记录
- `report.html` 适合直接浏览
- `report.json` 适合机器处理或后续平台集成

## 当前阶段说明

这个项目现在更接近：

`工具链分析 + 规则扫描 + LLM 二次总结`

它已经具备多 Agent 的结构，但目前仍偏向“流水线式分工”。  
如果后续继续扩展，可以进一步拆分为更强的安全角色，例如：

- 攻击面 Agent
- 隐私风险 Agent
- 代码风险 Agent
- 误报复核 Agent
- 审计汇总 Agent

## 开发建议

提交到 GitHub 前，建议不要包含：

- 本地输出目录
- `__pycache__`
- JVM 崩溃日志
- 真实 API Key
- 个人机器绝对路径
- 本地专用配置文件

本仓库已通过 `.gitignore` 处理这些常见内容。

## License

MIT，详见 [LICENSE](LICENSE)。
