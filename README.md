# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A native privacy filter plugin for CLIProxyAPI. It intercepts model requests, detects sensitive text, and redacts it
before the request is forwarded to an upstream provider.

AI learners and builders can join the Linux.do community: [linux.do](https://linux.do/).

This project uses [packyme/privacy-filter](https://github.com/packyme/privacy-filter) for the core filtering logic and
adapts it to the CPA plugin ABI from [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

## What It Does

When CLIProxyAPI receives a request, this plugin scans supported text fields before the request leaves the local
process. If sensitive content is found, the request body is rewritten with redacted placeholders.

Typical use cases:

- Prevent accidental leakage of API keys and tokens
- Remove personal contact information before sending prompts to models
- Apply Gitleaks-style secret detection to LLM traffic
- Keep filtering local to the CLIProxyAPI plugin pipeline

## Features

- Request interceptor for the CLIProxyAPI plugin runtime
- Redacts emails, phone numbers, secrets, connection strings, certificates, and similar sensitive data
- Uses built-in Gitleaks rules from `rules/gitleaks.toml`
- Supports custom Gitleaks rule files
- Handles OpenAI Chat / Completions, OpenAI Responses, Claude, Gemini, and Gemini CLI request bodies
- Can skip filtering by model name or source format
- Builds as a native shared library for Linux, macOS, and Windows

## Requirements

- Go 1.26+
- CGO enabled
- `make`

## Build

Clone and build the plugin:

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter

make build
```

The default build writes the shared library to the repository root:

- Linux: `privacyfilter.so`
- macOS: `privacyfilter.dylib`
- Windows: `privacyfilter.dll`

Build for a specific platform:

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

Use `BUILD_DIR` to place build output elsewhere:

```bash
BUILD_DIR=dist make build
```

## Use with CLIProxyAPI

Place the shared library in your CLIProxyAPI plugin directory. The gitleaks
rules are embedded in the binary, so no extra files are required:

```text
privacyfilter/
└── privacyfilter.so        # or privacyfilter.dylib / privacyfilter.dll
```

Then enable the `privacyfilter` plugin in CLIProxyAPI.

Plugin metadata:

- Name: `privacyfilter`
- Capability: `RequestInterceptor`
- Author: `rheodev`

## Configuration

The plugin is configured inside CLIProxyAPI's main config file (`config.yaml`).
Under `plugins.configs.<id>`, the host-owned fields (`enabled`, `priority`) are
consumed by CLIProxyAPI, and the remaining YAML subtree is passed to the plugin
verbatim.

Enable the plugin:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
```

Enable with custom rules:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      gitleaks_toml: ""        # Empty uses embedded rules (or rules/gitleaks.toml sidecar)
      skip_models:
        - gpt-4
      skip_formats:
        - openai
```

Plugin fields:

| Field           | Type   | Default | Description                                                                            |
|-----------------|--------|---------|----------------------------------------------------------------------------------------|
| `gitleaks_toml` | string | `""`    | Custom gitleaks rule file path. Relative paths are resolved from the plugin directory. |
| `skip_models`   | array  | `[]`    | Models that should skip redaction.                                                     |
| `skip_formats`  | array  | `[]`    | Source formats that should skip redaction.                                             |

When `gitleaks_toml` is empty and no `rules/gitleaks.toml` sidecar file exists,
the plugin uses the rules embedded in the binary at build time.

### Invalid configuration

- At startup (`plugin.register`), an invalid config makes registration fail. CLIProxyAPI logs the reason and the
  plugin is not enabled, so check `GET /v0/management/plugins` for `effective_enabled: true`.
- On a hot reload (`plugin.reconfigure`), an invalid config is rejected and the plugin **keeps redacting with the
  previous valid config**, so a typo cannot silently turn filtering off. The host log shows an error such as
  `privacy filter rejected new config, still using the previous valid config: ...` naming the bad field. Fix the
  config and save again to apply it.

### Logging

Plugin logs go through the host's `host.log` callback, so they follow CLIProxyAPI's log level, format, and output and
carry the request ID. Each interception pass that redacts something produces one line listing the JSON paths of the redacted fields, for
example `privacy filter redacted 2 field(s): messages[0].content, system`. Request text is never logged.

## How It Works

The plugin redacts in both the before-auth and after-auth request interception hooks. Both see the client-format
body (before executor translation). The after-auth pass catches text that other plugins add later in the chain, for
example a lower-priority before-auth interceptor or a higher-priority after-auth interceptor. Redaction is
idempotent, so text that is already clean produces no new hits.

1. Checks `skip_models` and `skip_formats`.
2. Parses the request body as JSON.
3. Redacts every supported prompt field (see the table below).
4. Edits free-form text only.
5. Replaces detected sensitive data with placeholders.
6. Leaves the request unchanged if parsing fails or no supported field is found.

Redacted fields by client format:

| Format                  | Fields                                                                                             |
|-------------------------|----------------------------------------------------------------------------------------------------|
| OpenAI Chat             | `messages[].content` (string or `text` parts)                                                      |
| OpenAI image / video    | `prompt` (string or list of strings) of image and video generation requests                        |
| OpenAI Responses        | `instructions`, `input` (string), `input[].content`, `function_call_output` `output`               |
| Claude                  | `system`, `messages[].content` text blocks, `tool_result` content                                  |
| Gemini                  | `systemInstruction` / `system_instruction` and `contents[].parts[].text`                           |
| Gemini CLI              | The same Gemini fields inside the top-level `request` object                                       |

Left untouched on purpose: tool call arguments (`function_call.arguments`, Claude `tool_use.input`, Gemini
`functionCall` / `functionResponse`), images, files, Claude `thinking` blocks, and Gemini parts marked
`thought: true` (their text is bound to a `thoughtSignature`, so editing it would make the upstream reject the request).

OpenAI Completions requests are covered through `messages`: the host converts them to chat completions before
interceptors run.

Common `skip_formats` values are the host's source format names, such as `openai`, `openai-response`, `claude`,
`gemini`, `gemini-cli`, `openai-image`, and `openai-video`.

Supported request shapes include:

```json
{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "Email me at user@example.com"
    }
  ]
}
```

```json
{
  "model": "gpt-4",
  "input": "My GitHub token is ghp_xxx"
}
```

## Rules

Built-in rules are embedded into the shared library at build time from:

```text
rules/gitleaks.toml
```

At runtime the plugin resolves rules in this order:

1. `gitleaks_toml` config value, if set
2. `rules/gitleaks.toml` sidecar next to the shared library
3. The rules embedded at build time (default)

Update embedded rules and rebuild:

```bash
make update-rules
make build
```

You can also set `gitleaks_toml` to use your own rule file:

```yaml
gitleaks_toml: custom/gitleaks.toml
```

Relative paths are resolved from the plugin directory.

## Development

Common commands:

```bash
go test ./...
make build
make clean
```

Main files:

```text
main.go                 Plugin metadata and build entry
abi.go                  CLIProxyAPI plugin ABI adapter
interceptor.go          Request interception and redaction logic
config.go               YAML configuration parsing
rules/gitleaks.toml     Built-in detection rules
```

Dependency note:

```text
privacyfilter => github.com/rheodev/privacy-filter
```

## Credits

- Core filtering logic: [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
