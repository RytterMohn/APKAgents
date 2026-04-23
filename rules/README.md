# Rules 目录

本目录包含扫描规则和检测模式，用于漏洞扫描和恶意软件检测。

## 目录结构

```
rules/
├── __init__.py
├── schema.py                    # 规则定义schema
├── vulnerability_rules.json     # 漏洞检测规则
├── malware_indicators.json      # 恶意软件特征
├── sensitive_data_patterns.json # 敏感数据模式
└── api_rules.json               # 敏感API检测规则
```

## 规则格式

### 漏洞检测规则 (vulnerability_rules.json)

```json
{
  "rules": [
    {
      "id": "VULN-001",
      "name": "不安全的WebView配置",
      "description": "WebView启用JavaScript可能导致XSS攻击",
      "severity": "high",
      "cwe": "CWE-79",
      "cvss": 7.5,
      "patterns": [
        {
          "type": "code",
          "pattern": "setJavaScriptEnabled.*true",
          "file_types": ["java", "smali"]
        }
      ],
      "remediation": "禁用不必要的JavaScript，启用白名单验证"
    },
    {
      "id": "VULN-002",
      "name": "不安全的Intent广播",
      "description": "敏感数据通过不安全的Intent广播可能被窃取",
      "severity": "medium",
      "cwe": "CWE-925",
      "cvss": 6.5,
      "patterns": [
        {
          "type": "api",
          "class": "android.content.Context",
          "method": "sendBroadcast",
          "params": ".*"
        }
      ],
      "remediation": "使用LocalBroadcastManager或带权限的广播"
    }
  ]
}
```

### 恶意软件特征 (malware_indicators.json)

```json
{
  "indicators": [
    {
      "id": "MAL-001",
      "name": "短信窃取器",
      "category": "data_theft",
      "severity": "critical",
      "indicators": {
        "permissions": [
          "android.permission.READ_SMS",
          "android.permission.RECEIVE_SMS",
          "android.permission.SEND_SMS"
        ],
        "apis": [
          "android.telephony.SmsManager->sendTextMessage",
          "android.telephony.SmsManager->sendMultipartTextMessage"
        ],
        "strings": [
          "sms://",
          "premium.sms"
        ]
      },
      "description": "尝试读取或发送短信的恶意软件"
    },
    {
      "id": "MAL-002",
      "name": "间谍软件",
      "category": "surveillance",
      "severity": "critical",
      "indicators": {
        "permissions": [
          "android.permission.RECORD_AUDIO",
          "android.permission.CAMERA",
          "android.permission.ACCESS_FINE_LOCATION"
        ],
        "apis": [
          "android.media.MediaRecorder->start",
          "android.hardware.Camera->open"
        ]
      }
    }
  ]
}
```

### 敏感数据模式 (sensitive_data_patterns.json)

```json
{
  "patterns": [
    {
      "id": "SENS-001",
      "name": "API密钥",
      "type": "secret",
      "regex": "(?i)(api[_-]?key|apikey)\\s*[=:>]\\s*['\"]?([a-zA-Z0-9]{20,})",
      "severity": "high",
      "false_positives": ["API_KEY_NAME", "api_key_test"]
    },
    {
      "id": "SENS-002",
      "name": "硬编码密码",
      "type": "credential",
      "regex": "(?i)(password|passwd|pwd)\\s*[=:>]\\s*['\"]([^'\"]{6,})",
      "severity": "high"
    },
    {
      "id": "SENS-003",
      "name": "私钥文件",
      "type": "key",
      "regex": "-----BEGIN.*PRIVATE KEY-----",
      "severity": "critical"
    }
  ]
}
```

### 敏感API规则 (api_rules.json)

```json
{
  "rules": [
    {
      "category": "network",
      "apis": [
        {
          "pattern": "Ljava/net/HttpURLConnection;",
          "risk": "明文HTTP通信",
          "severity": "medium"
        },
        {
          "pattern": "Ljavax/net/ssl/SSLContext;",
          "risk": "自定义SSL配置",
          "severity": "medium"
        }
      ]
    },
    {
      "category": "crypto",
      "apis": [
        {
          "pattern": "Ljava/security/MessageDigest;->getInstance",
          "risk": "加密操作",
          "severity": "low"
        },
        {
          "pattern": "Ljavax/crypto/Cipher;->getInstance",
          "risk": "加密操作",
          "severity": "low"
        }
      ]
    },
    {
      "category": "file",
      "apis": [
        {
          "pattern": "Ljava/io/File;-><init>",
          "risk": "文件操作",
          "severity": "low"
        }
      ]
    }
  ]
}
```

## 使用示例

```python
from rules import VulnerabilityRules, MalwareIndicators, SensitiveDataPatterns

# 加载漏洞规则
vuln_rules = VulnerabilityRules()
rules = vuln_rules.get_all()

# 检测代码
for rule in rules:
    if rule.matches(code_content):
        print(f"发现漏洞: {rule.name}")

# 加载恶意软件特征
malware_indicators = MalwareIndicators()
if malware_indicators.check_permissions(permissions):
    print("发现可疑权限")

# 搜索敏感数据
sdp = SensitiveDataPatterns()
findings = sdp.scan_files([file1, file2])
```

## 规则优先级

1. **严重 (critical)**: 立即报告
2. **高 (high)**: 需要关注
3. **中 (medium)**: 建议修复
4. **低 (low)**: 信息性

## 自定义规则

可以在项目根目录创建 `custom_rules/` 目录添加自定义规则：

```
custom_rules/
├── vulnerabilities.json
├── malware.json
└── patterns.json
```

这些规则会合并到默认规则中。