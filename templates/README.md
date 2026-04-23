# Templates 目录

本目录包含报告生成的模板文件。

## 目录结构

```
templates/
├── __init__.py
├── markdown/                   # Markdown模板
│   ├── report.md              # 综合分析报告模板
│   ├── summary.md             # 执行摘要模板
│   ├── vulnerability.md       # 漏洞详情模板
│   └── component.md           # 组件分析模板
├── html/                       # HTML模板
│   ├── report.html            # HTML报告主模板
│   ├── styles.css             # 样式文件
│   └── chart.js               # 图表脚本
└── json/                       # JSON模板
    └── report.json            # JSON报告结构
```

## 模板变量

### 综合报告模板变量

```markdown
# {{ title }}

## 基本信息
- **APK文件**: {{ apk_name }}
- **包名**: {{ package_name }}
- **版本**: {{ version }} ({{ version_code }})
- **分析时间**: {{ analysis_date }}
- **分析工具**: {{ tool_version }}

## 风险评估
- **总体风险等级**: {{ risk_level }}
- **漏洞数量**: {{ vulnerability_count }}
- **敏感数据泄露**: {{ sensitive_data_count }}

## 权限分析
{{ permissions_table }}

## 组件分析
{{ components_table }}

## 安全问题
{{ vulnerability_list }}

## 修复建议
{{ recommendations }}
```

### HTML模板变量

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
        <h1>{{ title }}</h1>
        <div class="meta">
            <span>包名: {{ package_name }}</span>
            <span>版本: {{ version }}</span>
        </div>
    </header>

    <section id="summary">
        <h2>风险摘要</h2>
        <div class="risk-badge {{ risk_level }}">{{ risk_level }}</div>
    </section>

    <section id="vulnerabilities">
        <h2>安全问题</h2>
        {{ vulnerability_items }}
    </section>
</body>
</html>
```

## 使用示例

```python
from templates import MarkdownReporter, HTMLReporter, JSONReporter

# Markdown报告
md_reporter = MarkdownReporter()
md_content = md_reporter.render(
    template="report.md",
    data={
        "title": "APK安全分析报告",
        "apk_name": "app.apk",
        "package_name": "com.example.app",
        "version": "1.0.0",
        "risk_level": "中",
        # ...
    }
)
md_reporter.save("report.md", md_content)

# HTML报告
html_reporter = HTMLReporter()
html_content = html_reporter.render("report.html", data)
html_reporter.save("report.html", html_content)

# JSON报告
json_reporter = JSONReporter()
json_data = json_reporter.render("report.json", data)
json_reporter.save("report.json", json_data)
```

## 图表模板 (chart.js)

```javascript
// 漏洞等级分布饼图
const vulnerabilityChart = {
    type: 'pie',
    data: {
        labels: ['严重', '高危', '中危', '低危'],
        datasets: [{
            data: [{{ critical }}, {{ high }}, {{ medium }}, {{ low }}],
            backgroundColor: ['#d32f2f', '#f57c00', '#fbc02d', '#4caf50']
        }]
    }
};

// 权限使用情况
const permissionsChart = {
    type: 'bar',
    data: {
        labels: {{ permission_names }},
        datasets: [{
            label: '权限使用次数',
            data: {{ permission_counts }}
        }]
    }
};
```

## 自定义模板

创建自定义模板：

```python
# 1. 创建模板文件
# templates/markdown/custom_report.md

# 2. 使用自定义模板
reporter = MarkdownReporter()
content = reporter.render("custom_report.md", data)
```