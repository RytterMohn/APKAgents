# Config

`config/` 目录保存项目运行所需的配置文件。

## 文件说明

- `default.yaml`：默认配置。
- `tools.yaml`：工具路径示例配置。
- `rules.yaml`：规则与扫描策略配置。
- `local-run.example.yaml`：本地私有配置模板，复制后自行填写。

## 隐私建议

公开仓库中建议只保留模板，不要提交：

- 真实 API Key
- 本机绝对路径
- 私有网关地址
- 本地专用 `local-run.yaml`

## tools.yaml 示例

```yaml
base_dir: "<YOUR_TOOL_DIR>"

tools:
  apktool:
    path: "<YOUR_TOOL_DIR>/apktool.bat"

  jadx:
    path: "<YOUR_TOOL_DIR>/jadx/bin/jadx.bat"
    conf: "<YOUR_TOOL_DIR>/jadx/conf/jadx.conf"

  aapt:
    path: "<YOUR_ANDROID_SDK>/build-tools/<VERSION>/aapt.exe"

  apksigner:
    path: "<YOUR_ANDROID_SDK>/build-tools/<VERSION>/apksigner.bat"
```

## 环境变量示例

```bash
APKAGENTS_API_KEY=YOUR_API_KEY
```

## 使用方式

1. 复制 `local-run.example.yaml` 为本地私有配置文件。
2. 按你的机器填写工具路径和 LLM 网关信息。
3. 将真实密钥放到环境变量中。
4. 确保私有配置不进入 Git。
