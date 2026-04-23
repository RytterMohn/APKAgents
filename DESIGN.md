# APK 多Agent分析系统设计书

## 1. 项目概述

本项目是一个基于多Agent架构的APK自动分析系统，通过多个专业化的Agent协作完成APK的全面安全分析和漏洞检测。

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Agent                        │
│                      (总调度Agent)                           │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Extractor     │    │ Analyzer      │    │ Reporter      │
│ Agent         │    │ Agent         │    │ Agent         │
│ (解包Agent)   │    │ (分析Agent)   │    │ (报告Agent)   │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Scanner       │    │ Decompiler    │    │ Formatter     │
│ Agent         │    │ Agent         │    │ Agent         │
│ (扫描Agent)   │    │ (反编译Agent) │    │ (格式化Agent) │
└───────────────┘    └───────────────┘    └───────────────┘
```

## 3. 开源工具清单

### 3.1 APK处理工具

| 工具名称 | 用途 | 编程语言 |
|---------|------|----------|
| [apktool](https://github.com/iBotPeaches/Apktool) | APK解包、重打包、XML解析 | Java |
| [jadx](https://github.com/skylot/jadx) | DEX反编译为Java源码 | Java |
| [dex2jar](https://github.com/pxb1988/dex2jar) | DEX转换为JAR文件 | Java |
| [apk签名工具](https://github.com/appium/sign) | APK签名/验签 | Java |

### 3.2 静态分析工具

| 工具名称 | 用途 | 编程语言 |
|---------|------|----------|
| [Androguard](https://github.com/androguard/androguard) | Android应用静态分析 | Python |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework) | 移动安全框架 | Python |
| [AXMLPrinter2](https://github.com/rednaga/AXMLPrinter2) | 二进制XML转换为可读XML | Java |
| [AXML](https://github.com/tusdk/AXML) | AndroidManifest.xml解析 | Go |

### 3.3 动态分析工具

| 工具名称 | 用途 | 编程语言 |
|---------|------|----------|
| [Frida](https://github.com/frida/frida) | 动态插桩框架 | Python/C |
| [ objection](https://github.com/sensepost/objection) | 运行时移动设备分析 | Python |
| [AndroTickler](https://github.com/mwrlabs/AndroTickler) | 动态分析工具集合 | Java |

### 3.4 恶意软件分析

| 工具名称 | 用途 | 编程语言 |
|---------|------|----------|
| [Quark-Engine](https://github.com/quark-engine/quark-engine) | 恶意软件检测 | Python |
| [CAPEv2](https://github.com/CAPEsandbox/CAPEv2) | 恶意软件分析沙箱 | Python |

### 3.5 二进制分析

| 工具名称 | 用途 | 编程语言 |
|---------|------|----------|
| [radare2](https://github.com/radareorg/radare2) | 逆向工程框架 | C |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 软件逆向工程 | Java |
| [ capstone](https://github.com/capstone-engine/capstone) | 反汇编框架 | C/Python |

### 3.6 Agent框架

| 框架名称 | 用途 |
|---------|------|
| [CrewAI](https://github.com/crewAIInc/crewAI) | 多Agent协作框架 |
| [AutoGen](https://github.com/microsoft/autogen) | 多Agent对话框架 |
| [LangChain](https://github.com/langchain-ai/langchain) | LLM应用开发框架 |

## 4. Agent职责划分

### 4.1 Orchestrator Agent (总调度Agent)

**职责**:
- 接收用户提交的APK文件
- 协调其他Agent的工作流程
- 管理分析任务的状态和进度
- 汇总各Agent的分析结果
- 处理错误和异常情况

**技术实现**:
- 基于LangChain构建
- 使用Claude API进行决策
- 维护任务状态机

### 4.2 Extractor Agent (解包Agent)

**职责**:
- 验证APK文件格式
- 使用apktool解包APK
- 提取AndroidManifest.xml
- 提取资源文件(assets, res, lib等)
- 提取DEX文件
- 验证签名信息

**使用工具**:
- apktool
- AXMLPrinter2
- apksigner

**输出**:
- 解包后的目录结构
- 可读的AndroidManifest.xml
- DEX文件列表
- 签名信息摘要

### 4.3 Decompiler Agent (反编译Agent)

**职责**:
- 将DEX文件转换为JAR
- 使用jadx反编译为Java源码
- 提取Smali代码
- 识别代码结构和类继承关系

**使用工具**:
- dex2jar
- jadx
- baksmali

**输出**:
- Java源码文件
- Smali代码
- 类结构树

### 4.4 Analyzer Agent (分析Agent)

**职责**:
- 分析AndroidManifest.xml中的组件
- 检测声明的权限列表
- 识别Activity、Service、BroadcastReceiver、ContentProvider
- 分析代码中的敏感API调用
- 检测Intent通信安全
- 分析加密/解密实现

**使用工具**:
- Androguard
- 自定义Python脚本

**输出**:
- 组件分析报告
- 权限分析报告
- 敏感操作分析
- 安全问题列表

### 4.5 Scanner Agent (扫描Agent)

**职责**:
- 漏洞扫描
- 恶意软件检测
- 敏感数据泄露检测
- 不安全配置检测
- 第三方库漏洞检测

**使用工具**:
- MobSF
- Quark-Engine
- 自定义规则库

**输出**:
- 漏洞列表(带CVSS评分)
- 风险等级评估
- 修复建议

### 4.6 Reporter Agent (报告Agent)

**职责**:
- 汇总所有分析结果
- 生成结构化报告
- 生成风险评估摘要
- 提供修复建议
- 支持多种输出格式(Markdown, HTML, JSON)

**使用工具**:
- 自定义报告模板
- Markdown生成库
- HTML模板引擎

**输出**:
- 综合分析报告
- 技术细节报告
- 执行摘要

### 4.7 Formatter Agent (格式化Agent)

**职责**:
- 格式化代码片段
- 美化输出报告
- 生成可视化图表
- 整理分析数据

**使用工具**:
- Pygments(代码高亮)
- Matplotlib(图表)
- Jinja2(模板)

**输出**:
- 格式化的报告文件
- 分析数据可视化

## 5. 工作流程

```
用户提交APK
      │
      ▼
┌─────────────────┐
│ Orchestrator    │
│ 接收并验证APK    │
└─────────────────┘
      │
      ├──────────────────┐
      ▼                  ▼
┌───────────┐    ┌───────────────┐
│ Extractor │    │ Decompiler    │
│ 解包APK   │    │ 反编译DEX     │
└───────────┘    └───────────────┘
      │                  │
      ▼                  ▼
┌───────────┐    ┌───────────────┐
│ Analyzer  │    │ Scanner       │
│ 静态分析  │    │ 漏洞扫描      │
└───────────┘    └───────────────┘
      │                  │
      └────────┬─────────┘
               ▼
      ┌─────────────────┐
      │ Reporter        │
      │ 生成综合报告    │
      └─────────────────┘
               │
               ▼
      ┌─────────────────┐
      │ Formatter       │
      │ 格式化输出      │
      └─────────────────┘
               │
               ▼
      返回分析报告
```

## 6. 技术栈

- **核心语言**: Python 3.10+
- **LLM**: Claude API
- **Agent框架**: LangChain + CrewAI
- **APK工具**: apktool, jadx, Androguard
- **数据库**: SQLite(用于存储扫描结果)
- **报告**: Markdown, HTML, JSON

## 7. 目录结构

```
apk-agents/
├── agents/                    # Agent实现
│   ├── __init__.py
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
│   ├── vulnerabilities.json
│   └── malware_indicators.json
├── templates/                 # 报告模板
│   ├── report.md
│   └── report.html
├── utils/                     # 工具函数
│   ├── file_utils.py
│   └── config.py
├── config.yaml                # 配置文件
├── main.py                    # 入口文件
└── requirements.txt           # 依赖
```

## 8. 安装依赖

```bash
pip install langchain crewai anthropic
pip install androguard jadx-tools
pip install pyyaml markdown
pip install matplotlib jinja2
```

## 9. 使用示例

```python
from agents import OrchestratorAgent

agent = OrchestratorAgent()
result = agent.analyze("sample.apk")
print(result)
```

---

**版本**: 1.0
**创建日期**: 2026-04-22