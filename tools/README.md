# Tools 目录

本目录包含对第三方APK分析工具的封装，提供统一的Python接口。

## 目录结构

```
tools/
├── __init__.py               # 导出所有工具封装
├── base.py                   # 工具基类
├── apktool_wrapper.py        # apktool封装
├── jadx_wrapper.py           # jadx封装
├── androguard_wrapper.py    # Androguard封装
├── dex2jar_wrapper.py       # dex2jar封装
└── sign_tool.py             # 签名工具封装
```

## 工具接口规范

所有工具封装继承自 `BaseTool`：

```python
class BaseTool(ABC):
    """工具基类"""

    @abstractmethod
    def is_available(self) -> bool:
        """检查工具是否可用"""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """获取工具版本"""
        pass
```

## 工具使用说明

### ApktoolWrapper

```python
from tools import ApktoolWrapper

tool = ApktoolWrapper()

# 检查工具
if not tool.is_available():
    raise RuntimeError("apktool not found")

# 解包APK
result = tool.decode(
    apk_path="app.apk",
    output_dir="output/app_decoded",
    force=True
)
# result: { "success": bool, "output_dir": str, "files": List[str] }

# 重新打包
result = tool.build(
    decoded_dir="output/app_decoded",
    output_apk="output/app_rebuilt.apk"
)
```

### JadxWrapper

```python
from tools import JadxWrapper

tool = JadxWrapper()

# 检查工具
if not tool.is_available():
    raise RuntimeError("jadx not found")

# 反编译APK
result = tool.decompile(
    apk_path="app.apk",
    output_dir="output/java_sources",
    sources=True,      # 保留源码
    deobf=False        # 不混淆
)
# result: { "success": bool, "output_dir": str, "files": List[str] }

# 单独反编译DEX
result = tool.decompile_dex(
    dex_path="classes.dex",
    output_dir="output/dex_decompiled"
)
```

### AndroguardWrapper

```python
from tools import AndroguardWrapper

tool = AndroguardWrapper()

# 加载APK
apk = tool.load_apk("app.apk")

# 获取基本信息
info = tool.get_basic_info(apk)
# { "package": str, "version": str, "min_sdk": int, "target_sdk": int }

# 获取权限列表
permissions = tool.get_permissions(apk)
# List[str]: ["android.permission.INTERNET", ...]

# 获取组件
components = tool.get_components(apk)
# { "activities": [...], "services": [...], "receivers": [...], "providers": [...] }

# 分析敏感API
sensitive_apis = tool.find_sensitive_apis(
    apk,
    ["Landroid/telephony/SmsManager;->sendTextMessage", ...]
)
# List[Dict]: [{ "class": str, "method": str, "line": int }, ...]

# 搜索字符串
results = tool.search_strings(apk, "password")
# List[Dict]: [{ "file": str, "strings": [...], ... }]

# 分析网络通信
network_calls = tool.analyze_network_calls(apk)
# List[Dict]: [{ "url": str, "method": str, "encryption": str }, ...]
```

### Dex2JarWrapper

```python
from tools import Dex2JarWrapper

tool = Dex2JarWrapper()

# DEX转JAR
result = tool.dex2jar(
    dex_path="classes.dex",
    output_jar="classes.jar"
)
# result: { "success": bool, "output_jar": str }
```

### SignTool

```python
from tools import SignTool

tool = SignTool()

# 签名APK
result = tool.sign(
    apk_path="app.apk",
    keystore="release.keystore",
    key_alias="mykey",
    store_password="password",
    key_password="password"
)

# 验证签名
result = tool.verify("app.apk")
# { "valid": bool, "signers": [...], "details": Dict }
```

## 工具配置

在 `config/tools.yaml` 中配置工具路径：

```yaml
tools:
  apktool:
    path: "D:/tools/apktool.bat"  # Windows
    # path: "/usr/local/bin/apktool"  # Linux/Mac

  jadx:
    path: "D:/tools/jadx/bin/jadx.bat"

  androguard:
    # Python包，无需配置路径
    version: "3.4.0"

  dex2jar:
    path: "D:/tools/dex2jar/d2j-dex2jar.bat"
```

## 安装第三方工具

### apktool
```bash
# Windows: 下载 apktool_*.jar 并重命名为 apktool.jar
# 添加到 PATH
```

### jadx
```bash
# 下载 release 包，解压后添加到 PATH
```

### Androguard
```bash
pip install androguard
```