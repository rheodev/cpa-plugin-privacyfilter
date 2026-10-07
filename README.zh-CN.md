# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

CLIProxyAPI 的隐私过滤插件，用于在请求发送给模型前自动识别并脱敏敏感信息。

学 AI 就上 L 站：[linux.do](https://linux.do/)。

本项目基于 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
实现核心过滤能力，并适配 [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的 CPA 插件 ABI。

## 作用

当 CLIProxyAPI 收到请求时，插件会在请求离开本地进程前扫描支持的文本字段。如果检测到敏感内容，请求体会被改写为脱敏后的内容。

典型场景：

- 防止 API Key 和 Token 意外泄露
- 在提示词发送给模型前移除个人联系方式
- 对 LLM 请求流量应用 Gitleaks 风格的密钥检测
- 将过滤逻辑保留在 CLIProxyAPI 插件链路内

## 功能

- CLIProxyAPI 插件运行时的请求拦截器
- 脱敏邮箱、手机号、密钥、连接串、证书等敏感内容
- 使用内置 Gitleaks 规则 `rules/gitleaks.toml`
- 支持自定义 Gitleaks 规则文件
- 支持 OpenAI Chat / Completions、OpenAI Responses、Claude、Gemini 和 Gemini CLI 请求体
- 可按模型名或来源格式跳过过滤
- 可构建为 Linux、macOS、Windows 原生共享库

## 环境要求

- Go 1.26+
- 启用 CGO
- 已安装 `make`

## 构建

克隆并构建插件：

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter

make build
```

默认会在仓库根目录生成共享库：

- Linux: `privacyfilter.so`
- macOS: `privacyfilter.dylib`
- Windows: `privacyfilter.dll`

指定平台构建：

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

使用 `BUILD_DIR` 指定输出目录：

```bash
BUILD_DIR=dist make build
```

## 在 CLIProxyAPI 中使用

将共享库放入 CLIProxyAPI 的插件目录即可。Gitleaks 规则已内嵌到二进制中，无需额外文件：

```text
privacyfilter/
└── privacyfilter.so        # 或 privacyfilter.dylib / privacyfilter.dll
```

然后在 CLIProxyAPI 中启用 `privacyfilter` 插件。

插件注册信息：

- 名称：`privacyfilter`
- 能力：`RequestInterceptor`
- 作者：`rheodev`

## 配置

插件在 CLIProxyAPI 主配置文件（`config.yaml`）中配置。`plugins.configs.<id>` 下，
宿主字段（`enabled`、`priority`）由 CLIProxyAPI 处理，其余 YAML 子树原样透传给插件。

启用插件：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
```

启用并自定义规则：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      gitleaks_toml: ""        # 为空时使用内嵌规则（或共享库旁的 rules/gitleaks.toml）
      skip_models:
        - gpt-4
      skip_formats:
        - openai
```

插件字段说明：

| 字段              | 类型     | 默认值  | 说明                             |
|-----------------|--------|------|--------------------------------|
| `gitleaks_toml` | string | `""` | 自定义 gitleaks 规则文件路径，支持相对插件目录路径 |
| `skip_models`   | array  | `[]` | 命中的模型不做脱敏                      |
| `skip_formats`  | array  | `[]` | 命中的来源格式不做脱敏                    |

当 `gitleaks_toml` 为空、且共享库旁不存在 `rules/gitleaks.toml` 时，插件使用构建时内嵌到二进制中的规则。

### 配置错误

- 启动时（`plugin.register`）配置无效会导致注册失败。CLIProxyAPI 会在日志中给出原因，插件不会启用，
  可通过 `GET /v0/management/plugins` 确认 `effective_enabled: true`。
- 热更新时（`plugin.reconfigure`）配置无效会被拒绝，插件**继续使用上一份有效配置脱敏**，不会因为一处笔误静默停止过滤。
  宿主日志会输出类似 `privacy filter rejected new config, still using the previous valid config: ...` 的错误，并指出出错字段。
  修正配置后再次保存即可生效。

### 日志

插件日志通过宿主的 `host.log` 回调输出，遵循 CLIProxyAPI 的日志级别、格式和输出位置，并带上请求 ID。
每次拦截只要有脱敏就输出一行，列出被脱敏字段的 JSON 路径，例如 `privacy filter redacted 2 field(s): messages[0].content, system`。
不会记录请求原文。

## 工作方式

插件在 before-auth 和 after-auth 两个请求拦截阶段都会脱敏，两个阶段看到的都是客户端格式的请求体（executor 翻译之前）。
after-auth 这一遍用来拦住请求链后面其他插件加进来的文本，例如优先级更低的 before-auth 拦截器或优先级更高的 after-auth 拦截器。
脱敏是幂等的，已经脱敏过的文本不会产生新的命中：

1. 检查 `skip_models` 和 `skip_formats`。
2. 将请求体解析为 JSON。
3. 处理所有支持的提示词字段（见下表）。
4. 只修改自由文本。
5. 检测到敏感内容后，用占位符替换原文。
6. 解析失败或未命中可处理字段时，请求保持不变。

各客户端格式的脱敏字段：

| 格式                 | 字段                                                                                  |
|--------------------|-------------------------------------------------------------------------------------|
| OpenAI Chat        | `messages[].content`（字符串或 `text` 分段）                                               |
| OpenAI 图片 / 视频      | 图片和视频生成请求的 `prompt`（字符串或字符串数组）                                                    |
| OpenAI Responses   | `instructions`、`input`（字符串）、`input[].content`、`function_call_output` 的 `output`     |
| Claude             | `system`、`messages[].content` 文本块、`tool_result` 内容                                   |
| Gemini             | `systemInstruction` / `system_instruction` 和 `contents[].parts[].text`               |
| Gemini CLI         | 顶层 `request` 对象内的上述 Gemini 字段                                                       |

以下内容有意不修改：工具调用参数（`function_call.arguments`、Claude `tool_use.input`、Gemini `functionCall` /
`functionResponse`）、图片、文件、Claude `thinking` 块，以及标记了 `thought: true` 的 Gemini 分段（其文本与
`thoughtSignature` 绑定，修改后上游会拒绝请求）。

OpenAI Completions 请求通过 `messages` 覆盖：宿主在调用拦截器之前会先把它转成 chat completions 格式。

`skip_formats` 的常见取值是宿主的来源格式名，例如 `openai`、`openai-response`、`claude`、`gemini`、`gemini-cli`、`openai-image`、`openai-video`。

支持的请求体示例：

```json
{
  "model": "gpt-4",
  "messages": [
    { "role": "user", "content": "Email me at user@example.com" }
  ]
}
```

```json
{
  "model": "gpt-4",
  "input": "My GitHub token is ghp_xxx"
}
```

## 规则

内置规则在构建时内嵌到共享库中，来源：

```text
rules/gitleaks.toml
```

运行时按以下顺序解析规则：

1. 配置项 `gitleaks_toml`（若设置）
2. 共享库旁的 `rules/gitleaks.toml` 附带文件
3. 构建时内嵌的规则（默认）

更新内嵌规则并重新构建：

```bash
make update-rules
make build
```

也可以通过 `gitleaks_toml` 指定自己的规则文件：

```yaml
gitleaks_toml: custom/gitleaks.toml
```

相对路径会基于插件目录解析。

## 开发

常用命令：

```bash
go test ./...
make build
make clean
```

主要文件：

```text
main.go                 插件元数据和构建入口
abi.go                  CLIProxyAPI 插件 ABI 适配
interceptor.go          请求拦截和脱敏逻辑
config.go               YAML 配置解析
rules/gitleaks.toml     内置检测规则
```

依赖说明：

```text
privacyfilter => github.com/rheodev/privacy-filter
```

## 来源

- 核心过滤逻辑：[packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- 插件运行时：[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
