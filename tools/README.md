# Tools

`tools/` 目录封装了 APK 分析过程中依赖的外部工具，统一提供 Python 调用接口。

## 当前封装

- `apktool_wrapper.py`
- `jadx_wrapper.py`
- `androguard_wrapper.py`
- `dex2jar_wrapper.py`
- `sign_tool.py`

## 配置示例

在 `config/tools.yaml` 中填写你自己的工具路径：

```yaml
tools:
  apktool:
    path: "<YOUR_TOOL_DIR>/apktool.bat"

  jadx:
    path: "<YOUR_TOOL_DIR>/jadx/bin/jadx.bat"

  dex2jar:
    path: "<YOUR_TOOL_DIR>/dex2jar/d2j-dex2jar.bat"

  aapt:
    path: "<YOUR_ANDROID_SDK>/build-tools/<VERSION>/aapt.exe"

  apksigner:
    path: "<YOUR_ANDROID_SDK>/build-tools/<VERSION>/apksigner.bat"
```

## 注意事项

- 不要把本机绝对路径写死到开源文档里。
- 不要提交包含私有工具目录的配置文件。
- 如果需要公开示例，使用占位符路径。
