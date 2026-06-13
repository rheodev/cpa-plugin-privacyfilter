# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

CLIProxyAPI 的隐私过滤插件，用于在请求发送给模型前自动识别并脱敏敏感信息。

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
- 支持 OpenAI 风格的 `messages` 和 `input` 请求体
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

将共享库和规则目录放在同一个插件目录中：

```text
privacyfilter/
├── privacyfilter.so        # 或 privacyfilter.dylib / privacyfilter.dll
└── rules/
    └── gitleaks.toml
```

然后在 CLIProxyAPI 中启用 `privacyfilter` 插件。

插件注册信息：

- 名称：`privacyfilter`
- 能力：`RequestInterceptor`
- 作者：`rheodev`

## 配置

插件接收来自 CLIProxyAPI 的 YAML 配置。

最小配置：

```yaml
{}
```

自定义配置：

```yaml
gitleaks_toml: ""      # 为空时使用插件目录下的 rules/gitleaks.toml
skip_models:
  - gpt-4
skip_formats:
  - openai
```

字段说明：

| 字段              | 类型     | 默认值  | 说明                             |
|-----------------|--------|------|--------------------------------|
| `gitleaks_toml` | string | `""` | 自定义 gitleaks 规则文件路径，支持相对插件目录路径 |
| `skip_models`   | array  | `[]` | 命中的模型不做脱敏                      |
| `skip_formats`  | array  | `[]` | 命中的来源格式不做脱敏                    |

## 工作方式

插件会在 before-auth 和 after-auth 请求拦截阶段运行，然后解析 JSON 请求体：

1. 检查 `skip_models` 和 `skip_formats`。
2. 将请求体解析为 JSON。
3. 优先处理 `messages`，没有时处理 `input`。
4. 只修改文本字段。
5. 检测到敏感内容后，用占位符替换原文。
6. 解析失败或未命中可处理字段时，请求保持不变。

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

内置规则位于：

```text
rules/gitleaks.toml
```

更新内置规则：

```bash
make update-rules
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
privacyfilter => github.com/packyme/privacy-filter
```

## 来源

- 核心过滤逻辑：[packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- 插件运行时：[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
