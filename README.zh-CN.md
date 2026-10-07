# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的隐私过滤插件。它位于编程助手与模型提供商之间，在请求离开你的机器之前把主机名、IP 地址、邮箱、人名和客户名、路径、序列号、账号之类的标识替换为透明的替身，再把真实值放回回答里。模型把替身当作真实的东西来用，管理系统、改配置、写工具调用，却始终不知道实际的名称和 ID。

插件有两种模式。`redact` 是默认值，也就是原版插件：检测到的密钥、联系方式和证件号码变成 `[EMAIL]`、`[SECRET]` 之类的标签，单向。`pseudonymize` 是本分支存在的理由：你列表里的值，加上检测器找到的一切，都变成同形状的稳定假名，回答被翻译回来，流式与否都一样。两种模式在检测上并不互斥。假名模式把原版插件的自动检测作为最后一层运行，排在你的列表和结构模式之后，因此 `redact` 能找到的东西这里也都能找到。区别在于命中之后怎么办：扔掉，还是换成模型能用、客户端拿回原值的东西。本文档面向 `pseudonymize`；`redact` 见[脱敏模式](#脱敏模式)。

## 一眼看懂

一个请求，四个站点。客户端发送真实值，插件把它们换成同形状的假名，模型用它看到的假名作答，插件在客户端读到回答之前把原值放回去。映射关系从不离开本机。

```mermaid
flowchart LR
    C["你的客户端"] -- "1 原始值" --> P["代理上的插件"]
    P -- "2 假名" --> M["模型提供商"]
    M -- "3 带假名的回答" --> P
    P -- "4 放回原值" --> C
```

| 站点 | 文本 |
|---|---|
| 客户端发送的 | Ingrid Muster reports that helios-nas01 (10.20.30.7) does not answer since the last change to /home/imuster/projekte/muster-gmbh/deploy.sh. |
| 模型收到的 | Lea Schuricht reports that h-5aa7c84ea894 (100.67.154.131) does not answer since the last change to /home/d-d828a9564f55/d-11d2d4de326e/d-69bb4ff312ad/deploy.sh. |
| 模型回答的 | h-5aa7c84ea894 is reachable at 100.67.154.131 again. The change in /home/d-d828a9564f55/d-11d2d4de326e/d-69bb4ff312ad/deploy.sh reverted the route, I told Lea Schuricht. |
| 客户端得到的 | helios-nas01 is reachable at 10.20.30.7 again. The change in /home/imuster/projekte/muster-gmbh/deploy.sh reverted the route, I told Ingrid Muster. |

每一类值都有自己形状的假名，所以模型仍能分清主机和地址、路径和序列号。左列是离开你编辑器的内容，右列是提供商存下的内容。下面的值都是虚构的；假名由插件在一次测试运行中生成：

| kind | 你发送的 | 模型看到的 |
|---|---|---|
| `host` | `helios-nas01` | `h-5aa7c84ea894` |
| `domain` | `muster-gmbh.de` | `d-27133c5f173b.invalid` |
| `person` | `Ingrid Muster` | `Lea Schuricht` |
| `email` | `ingrid.muster@muster-gmbh.de` | `u-065c3e6cd8a3@d-27133c5f173b.invalid` |
| `cidr` | `10.20.0.0/16` | `100.67.0.0/16` |
| `ipv4` | `10.20.30.7` | `100.67.154.131` |
| `ipv6` | `2a01:4f8:1c17:6f3::2` | `fdff:5046:5346:7dbe:ca22:4379:1d53:1cb` |
| `mac` | `3c:97:0e:4b:12:aa` | `02:c2:6d:ef:67:18` |
| `iban` | `DE89370400440532013000` | `DE54000007939311999813` |
| `uuid` | `6f1c2a3e-9b4d-4e0f-8a7b-1c2d3e4f5a6b` | `7f1831a6-ee87-f63c-d5d3-d1fae42c754e` |
| `hexid` | `9e3f4a1b8c2d4e5f6a7b8c9d0e1f2a3b` | `504655b52880c8edb9f6934fa6b8610c` |
| `fingerprint` | `SHA256:Qz7vL2pXk9aRtY4mN8wS1bC3dF5gH6jK0lZ2xV4uB7e` | `SHA256:PFUmI8bPkOxwMjsrOW8GfFbhNfWfgwkT79IkC2OaggL` |
| `serial` | `Serial Number: C02ZK3XYLVDL` | `Serial Number: PF-LTDIE7M2VT1R` |
| `path_segment` | `/home/imuster/projekte/muster-gmbh/deploy.sh` | `/home/d-d828a9564f55/d-11d2d4de326e/d-69bb4ff312ad/deploy.sh` |
| `secret` | `ghp_Q7v2Kd9Lm4Xs8Wb1Zc6Nf3Hj5Rt0Yp2Gu7Ea` | `PF_76877c8a06b5` |

同一个值在整个会话里得到同一个假名，所以模型能提到三条消息之前看到的主机。另一个会话得到另一套假名。有哪些 kind、各自用于什么，见 [kind](#kind)。

## 为什么

编程助手发给模型的一切最终都落在别人的服务器上：提示词、它读取的文件、它运行的每条命令的输出。对顾问、管理员或小公司来说，那就是整个工作日的明文：客户名称、背后的人、他们的邮箱、主机名和网络地址、项目所在的路径、机器序列号、磁盘和分区标识、SSH 指纹、账号。提供商的一次泄露、一张传票、一次训练数据的失误或一张仪表盘截图，暴露的就不是某一个秘密，而是谁与谁在什么项目上用哪些机器协作的全图。这张图对攻击者的价值超过任何一个密码。

只做脱敏是不够的，因为读到 `[REDACTED]` 的模型无法再推理主机、路径或网络，它写回的工具调用也没法用。假名模式在让提供商尽量少持有信息的同时保持请求可用：每个敏感值在请求离开本机前被替换为同形状的稳定假名，原值在客户端看到回答之前被放回。模型对待 `h-e2ba…` 和 `100.71.4.18` 与对待真实名称完全一样，提供商只存储假名，映射永远不离开本地进程。

被替换的内容来自三个来源。**词条列表**是一个纯文本文件，装着你自己的值：客户名称、主机、域名、人名、网段、账号。**结构模式**不需要列表，靠自身形状就能识别：IP 地址、MAC、邮箱地址、UUID、SSH 指纹、带标签的序列号、IBAN。**原版插件的检测**最后运行，带着它识别 API Key、令牌和连接串的 Gitleaks 规则，以及电话、证件号码和银行卡的识别器，抓住前两者都没列出的东西。与插件一起分发的脚本 `machine-ids.py` 把一台机器的标识填进词条列表，新主机一分钟内即可覆盖。

## 安装

你需要一个运行中的 CLIProxyAPI、发布包或构建后 `dist/` 里的两个文件（见[从源码构建](#从源码构建)），以及运行辅助脚本的 Python 3。

1. 把共享库和脚本放进 CLIProxyAPI 的插件目录。这是 `config.yaml` 里 `plugins.dir` 指定的目录，通常是 `plugins/`：

   ```text
   plugins/
   ├── privacyfilter.so        # 插件
   ├── machine-ids.py          # 填写词条列表，见下文
   ├── pseudonym.secret        # 第 2 步创建一次
   └── terms.txt               # 你的词条列表，第 3 步
   ```

2. 创建密钥。假名由它派生；没有它插件拒绝启动。任意随机字节，至少 32 个：

   ```bash
   head -c 48 /dev/urandom | base64 > plugins/pseudonym.secret
   chmod 600 plugins/pseudonym.secret
   ```

3. 创建词条列表。最快的办法是脚本，它会询问要做什么并写出文件；在运行代理的那台机器上用 `sudo` 运行，以便读取硬件序列号：

   ```bash
   sudo python3 plugins/machine-ids.py
   ```

   或者从空文件开始手工填写，见[词条列表](#词条列表)。

4. 在 `config.yaml` 中启用插件。普通安装只需要这些：

   ```yaml
   plugins:
     enabled: true
     dir: "plugins"
     configs:
       privacyfilter:
         enabled: true
         mode: pseudonymize
         terms_file: terms.txt      # 相对插件目录
   ```

5. 重启代理，在日志中找到插件：

   ```text
   pluginhost: plugin loaded plugin_id=privacyfilter version=... path=plugins/privacyfilter.so
   ```

   从此每个请求记录一行，按 kind 和数量说明替换了什么，从不记录值本身：

   ```text
   privacyfilter: request pseudonymized ... replacements="host=33 ipv4=1 email=12 path_segment=247 ..."
   ```

插件只在启动时读取密钥和词条列表。每次修改 `terms.txt` 后重启代理。pseudonymize 模式的设置若出错，无论是缺少密钥、词条列表不可读还是某个词条被拒绝，都不会阻止注册：插件照常注册，并以一个指出故障、从不写出值的 400 错误回答每一个请求，直到配置修好并重启代理。否则代理会在没有过滤器的情况下启动，唯一的痕迹只是日志里的一行。

## 词条列表

词条列表是 `terms_file` 指定的文件，在上面的布局中是 `plugins/terms.txt`。它是你唯一需要维护的文件。每一行是一个不得以明文离开本机的值，加上它是哪一类东西，插件据此渲染同形状的假名。

### 格式

```text
# 井号之后是注释。空行跳过。

nuc                                  # 字面值；没有 kind 时视为主机名
nuc host                             # 同上，写明 kind
example-gmbh.de domain               # 域名
markus person ignore_case            # 人名；ignore_case 同时匹配 "Markus" 和 "MARKUS"
100.113.172.0/24 cidr                 # 网段；其中的地址保留结构
DE02000079396869187879 iban          # 账号
kunde-x path_segment                 # 不得出现在路径里的目录名
{regex: "(?i)\\bnuc(?:\\.[a-z0-9-]+)*\\b", kind: host}   # 正则表达式，YAML 形式
{value: "Müller & Söhne", kind: person}                   # 含空格的字面值，YAML 形式
```

普通行按空白切分：第一个词是值，可选的第二个词是 kind，`ignore_case` 一词设置该标志。含空格或以 `{`、`#` 开头的值用 YAML 形式，键与 `config.yaml` 中 `terms` 条目相同：`value` 或 `regex`、`kind`、`ignore_case`。

词条只在词边界匹配：`nuc` 匹配 `nuc`、`nuc.local`、`nuc_old` 和 `NUC-2`，但不匹配 `nucleus`。字母和数字连成一个词，其他一切包括下划线都是边界。正则表达式和字面值遵守同一规则：落在更长单词内部的命中会被丢弃，因为假名会和单词其余部分粘在一起，永远无法还原。表达式里不要用 `^` 和 `$`：它针对整条消息运行，不是针对单行。

### kind

kind 决定假名长什么样。模型看到的东西与原值形状相同，所以能正常工作；回答返回时插件也能分辨假名和真实值。

| kind           | 用于                                       | 假名                                   |
|----------------|--------------------------------------------|----------------------------------------|
| `host`         | 主机名，带不带域名都行                     | `h-<12 位十六进制>`                    |
| `domain`       | 域名、DNS 搜索域                           | `d-<12 位十六进制>.invalid`            |
| `ipv4`         | 单个 IPv4 地址                             | `100.64.0.0/10` 内的地址               |
| `ipv6`         | 单个 IPv6 地址                             | `fd00::/8` 内一个固定 `/48` 中的地址 |
| `cidr`         | 网段；其中的地址保留所属网络               | 同前缀长度，落在同一范围内             |
| `mac`          | MAC 地址、BSSID                            | `02:xx:xx:xx:xx:xx`                    |
| `email`        | 邮箱地址                                   | `u-<12 位十六进制>@d-<12 位十六进制>.invalid` |
| `person`       | 人名；客户如果是人也算                     | 固定列表中的虚构人名；单个词只映射为名 |
| `iban`         | 账号                                       | 同国家同长度，校验位有效               |
| `uuid`         | 磁盘、分区、机器和产品 UUID                | 版本位为 `f` 的 UUID                   |
| `hexid`        | 32 位或 `0x` 前缀 16 位十六进制标识：WWN、machine-id | 同形式，以 `5046` 或 `0x5046` 开头 |
| `fingerprint`  | SSH 密钥指纹                               | `SHA256:PF` + 41 个字母数字            |
| `serial`       | 序列号                                     | `PF-<12 位大写字母数字>`               |
| `path_segment` | 目录名，在路径内替换                       | `d-<12 位十六进制>`                    |
| `filename`     | 文件名；扩展名保留。仅路径层在 `filenames: all` 时使用 | `f-<12 位十六进制><扩展名>`     |
| `secret`       | 其他一切                                   | `PF_<12 位十六进制>`                   |

同一个值在整个会话内得到同一个假名，另一个会话得到另一套假名。假名由密钥派生，不存储在任何地方。

### 什么该进列表，什么不该

- **名字，不是单词。** 词条在任何以单词形式出现的地方都会被替换。名为 `backup` 的主机让 `rsync --backup` 在模型眼里变成乱码，名为 `admin` 的用户会破坏配置文件里的每一个 `admin`。这类条目不要写，或者用只匹配你所指形式的正则，比如主机名后接域名。
- **给系统起不是单词的名字。** 上面这条对客户容易做到，对自己的机器却难，因为短主机名方便，而且脚本会把它收集进来。名为 `time`、`cut` 或 `mail` 的机器会让每条含有这个词的 shell 命令、选项和句子都变成假名。往返仍然正常，客户端拿回原词，但模型在命令该在的地方读到的是一串十六进制。给机器、共享、服务或 Wi-Fi 起名时，选一个别处不会出现的标记：数字后缀（`nas01` 而不是 `nas`）、生造的词、带连字符的名字。脚本会标出同时是本机命令的主机名；给机器改名，或者保留词条并接受噪音。
- **模式已经能抓到的可以不写。** IP 地址、MAC、邮箱、UUID、指纹和带标签的序列号会被自动检测，原版插件的自动检测连同它的 Gitleaks 规则还会抓到 API Key、令牌、连接串、电话和证件号码以及银行卡号。当模型需要看到它们的结构时才放进列表：把你的网段作为 `cidr` 词条，主机、网关和邻居在模型眼里就留在同一个网络里。
- **永远不被替换的地址。** 回环、未指定、广播、组播、链路本地和文档网段保持原样，模型仍能看出 `bind` 到回环是怎么回事。`100.64.0.0/10` 内的真实地址（Tailscale 分配的网段）和以 `02:` 开头的 MAC（Docker 给容器的前缀）虽然与假名同住一个范围，但会像其他值一样被替换：插件靠会话的映射表而不是靠形状来辨认自己的假名。唯一拒绝的是覆盖整个 `100.64.0.0/10` 或固定 ULA `/48` 的 `cidr` 词条，因为这样的网络只能映射到自身。
- **一个文件，多台机器。** 每台机器可以加入自己的块，见下一章。插件启动时丢弃完全重复的条目，出现在三个块里的网关只是一个词条。
- **文件是明文。** 它装的正是插件要挡在线路之外的那些值。让它和它的备份只对代理的用户可读，永远不要把它粘贴进经过代理的会话。

`config.yaml` 中的 `terms` 接受同样的 YAML 形式条目，适合少数几个值；文件才是你维护的列表。

### 路径与文件名

像 `/home/mwendler/Projekte/kunde-x/src/main.go` 这样的路径，敏感的部分在中间：登录名、客户。用 `path.enabled: true` 开启的路径层按斜杠拆开路径，对目录和文件名区别对待，因为它们扮演的角色不同。

**目录**在未知时被替换。内置列表里的几百个普通名字，`home`、`usr`、`etc`、`src`、`build`、`docs`、`node_modules` 之类，保持原样，所以模型仍能看到主目录和源码树。其他所有目录都变成 `d-<12 位十六进制>`，不管它是否在你的词条列表里。这是给没人想到要列出的客户目录准备的安全网：能标识某人的名字即使列表不认识也会消失。模型在那里工作不需要真实名字。整个会话中同一个目录它看到的是同一个假名，把它写进工具调用，客户端拿回真实路径，文件落在该落的地方。模型失去的是名字的含义：它无法从 `d-<hex>` 看出某个目录放的是媒体文件。这妨碍工作时，把无害的名字加进 `path.preserve`，或者设 `replace_unknown: false` 只替换同时是词条的目录，代价是失去安全网。

这张网有边缘。路径层靠形状识别路径。带开头标记的路径以斜杠、`~/`、`./`、`../` 或 `$HOME/` 这样的变量开头。带斜杠的裸词元，也就是 `git status`、编译器或测试工具打印路径的那种写法，在下列情况下算作路径：最后一段带文件扩展名、以斜杠结尾或是隐藏名 `kunde-x/.gitignore`，第一段以点开头，或者某一段是 `-home-<user>-<project>` 形式的压平工作目录，即 Claude Code 给会话记录目录取名用的形状，这种形式没有任何斜杠也单独算作路径。所以 `kunde-x/vertrag.pdf`、`.config/kunde-x/bin`、`kunde-x/` 和 `projects/-home-user-kunde-x` 对路径层来说是路径，而 `and/or`、`km/h`、`origin/main`、`github.com/rheodev/x`、`@scope/pkg`、sed 表达式、日期和分数不是，标签里的斜杠 `</p>` 或 `<br/>` 也不是。diff 行开头的标记，即行首的 `+` 或 `-`，是一个边界：`+/home/alice/kunde/x.go` 和 `-kunde-x/build/` 从标记后面的字符读起，标记留在原处，所以对模型来说新增行仍然是新增行。留在网外的有：没有文件名也没有结尾斜杠的裸目录路径 `kunde-x/sub`；diff 头里的 `a/` 和 `b/` 前缀；`file://` 或 `http://` 地址里的路径；Windows 路径；内部带点的第一段 `.hidden.dir/x`，因为主机名和模块路径正是这个样子；以及直接位于根之下的压平目录 `-tmp-kunde-x`，它只在绝对形式下被兜住。这些写法里的未知目录以明文留下。词条列表里的目录在所有这些写法里都是安全的，因为词条无论名字出现在哪里都会匹配。更宽的网的代价是偶尔有形状像路径的无害词对，比如 `Input/Output.md`，它的第一个词会作为目录假名出站。

名字里带空格的目录在 Markdown 链接里写作 `Kunden%20Akten`，因为裸空格会结束链接目标。路径层在编码空格处把这样的段拆开：每个词各得一个假名，`%20` 留在它们之间，`d-…%20d-…`，模型由此看到有一个空格要解码。两种写法都能回来：按原样引用的链接，以及解码了空格的路径，后者是工具调用需要的那种；这些词带的假名与工具用真实空格列出该目录时相同。编码文件名里的词属于文件名，遵循下面的文件名规则。只有编码空格会被拆出来；ASCII 之外的字母，比如 `ü` 的 `%C3%BC`，留在它所在的词里，见[已知限制](#已知限制)。

名字里的真实空格按会话写它的三种方式来读。shell 给路径加引号，`cd "/home/alice/Kunden Akten/Berichte"`，路径一直延伸到同一行的闭引号；shell 用反斜杠转义空格，`Kunden\ Akten`，路径在反斜杠之后继续；工具参数只装着路径本身，`/home/alice/Kunden Akten/Berichte`，当空格后面的词自带斜杠时，路径越过空格继续。引号里的裸路径也整体读入，比如 `git status` 打印带空格路径的写法 ` M "kunde-x/epub/Kunden und Akten.epub"`：形状按引号内的全部文本判断，所以末尾的扩展名或斜杠即使前面有空格也算数，而第一段不能含空格，冒号也结束用来判断形状的文本，因为引号里斜杠周围的词既可能是名字也可能是一句话，`"fix kunde-x/x.go"`、`"detect/paths: fix paths.go"`。三种形式下，名字的每个词各得一个假名，空格留在它们之间，`d-… d-…`，模型由此看到名字里有空格，并按命令的需要加引号或转义；无论它写回哪种写法都能还原，因为这些词是逐个还原的。没有任何迹象表明名字还在继续时，空格就结束路径：路径后面的散文仍是散文，文件名即使在引号里也结束路径，所以 `"x.go: fix the test"` 是一个文件名加一句话。这条规则漏掉的情况见[已知限制](#已知限制)。

**文件名**默认不动。`README.md`、`main.go`、`config.yaml` 说的是文件是什么，它们在上百万个仓库里都一样，也是模型在目录树里定位的索引：替换它们保护不了任何东西，却让每个 `ls` 失去意义。以客户命名的文件带着客户的名字，而那个名字是词条，词条层在文件名内的词边界处找到它：`kunde-x-vertrag.pdf` 出站时是 `d-<hex>-vertrag.pdf`。没有扩展名的文件名，`Makefile`、`LICENSE`，在保留列表里，常见的隐藏文件 `.gitignore`、`.editorconfig` 也在；其他没有扩展名的名字按目录处理。`path.filenames: all` 把保留列表之外的每个文件名替换为 `f-<12 位十六进制><扩展名>`。

```yaml
path:
  enabled: true
  replace_unknown: true    # 目录：替换所有未知目录（默认）；false 只替换词条
  filenames: terms         # 文件名：只在词条匹配处替换（默认）；all 替换所有
  preserve: [media-files]  # 你自己的、不标识任何人、应保持可读的目录名
```

插件在回程中从不替换。模型编造的、碰巧像假名的文件名会原样到达客户端；使用默认值时模型看到的是真实文件名，没有可模仿的模式。模型自己命名的目录或文件在出站时也保持明文，所以模型在每个列表里都能看到自己起的名字；见[它做什么，不做什么](#它做什么不做什么)。

## 用 machine-ids.py 填写列表

`machine-ids.py` 收集它所运行机器的标识，按上面的格式写出。它只需要 Python 3，只读本地来源，没有任何数据离开本机。在终端上不带参数启动时会询问要做什么：

```text
$ sudo python3 plugins/machine-ids.py
machine-ids: collects the identifiers of this machine as a term list for the privacyfilter plugin.
Include the other machines of the LAN (mDNS, reverse DNS of the neighbour table)? [y/N]
Include container and VM interfaces (veth, docker, virbr)? [y/N]
Merge into /opt/cliproxyapi/plugins/terms.txt (a backup is written first)? [Y/n]
… host names
… machine-id, boot id, DMI
… network interfaces, DNS, Wi-Fi, Bluetooth
… block devices, USB, battery
… SSH and GPG keys
… user accounts
… done: 93 terms
```

它收集：主机名和 mDNS 名，写成同时匹配任意域名后缀的正则；`/etc/hosts` 的条目；machine-id 和 boot id；DMI 产品 UUID 以及主板、机箱和产品的序列号（需要 root）；每个网络接口的 MAC、永久 MAC、IPv4、IPv6、网段和网关；DNS 服务器和搜索域；Wi-Fi SSID 和 BSSID；蓝牙适配器；块设备的 UUID、PARTUUID、PTUUID、序列号、WWN 和标签；USB 设备序列号；电池序列号；SSH 主机密钥和用户自己的公钥，作为指纹和密钥材料；GPG 密钥指纹；ZeroTier 节点 id；本地用户账户。`admin`、`root` 之类的通用账户名会被留在外面并附注，因为它们是单词。已经具有假名形状的值会作为注释写出并说明原因。

供脚本使用以及合并前查看的选项：

| 选项               | 作用                                                                   |
|--------------------|------------------------------------------------------------------------|
| `--stdout`         | 打印列表，不问任何问题                                                 |
| `-o FILE`          | 把列表写入文件，权限 0600                                              |
| `--summary`        | 只打印每种 kind 的数量，从不打印值                                     |
| `--merge TERMS`    | 在已有的词条文件中替换或追加本机的块，先做编号备份                     |
| `--lan`            | 加入局域网中的其他机器：avahi 的 mDNS 名、邻居表的反向 DNS             |
| `--all-interfaces` | 包含容器和虚拟机接口（veth、docker、virbr 等）                         |
| `--check TERMS`    | 读取已有的词条文件，列出其中在本机同时是命令或普通单词的每个词条；不收集任何东西 |

一台机器的块位于两条带主机名的标记注释之间。在同一台机器上再次运行脚本会替换该块，不动其他机器的块，因此代理的词条文件可以容纳你工作的每一台机器：在每台机器上用 `-o` 运行脚本，用 `scp` 把输出复制到代理，在那里合并。要复制，不要粘贴进会话。然后重启代理。

## 告诉模型

模型看得出这些值是假名：`.invalid` 是保留顶级域，`100.64.0.0/10` 是运营商级 NAT 网段，版本位为 `f` 的 UUID 不存在于任何 RFC。放任不管的话，它会对此评论、问主机名是不是占位符、去掉 `.invalid`，或者"修正"这个值。在项目的 `CLAUDE.md` 或系统提示里说明一次，它就不再这样做：

```markdown
本会话中形如 `h-<hex>` 的主机名、`d-<hex>.invalid` 的域名、`100.64.0.0/10` 内的地址、以 `02:` 开头的 MAC 及类似令牌都是假名，代理会在我看到回答之前把它们换回真实值。请把它们当作真实名称：原样使用，不要缩短或"修正"，不要去掉 `.invalid`，不要按同样形状编造新的，也不要评论它们的形式。当工具显示的目录或文件名与你创建时用的名字不同，那是代理在起作用，不是错误：按列表显示的名字使用，或者相对于你已经知道的目录来工作。
```

## 检查清单

上面的章节解释了每一块。这里是做这些事的顺序，免得漏掉什么。搭建时走一遍，之后每加一个客户、一台机器或一个项目再走一遍。

1. **密钥。** 创建 `pseudonym.secret`，权限 0600，属于代理的用户。它不是你需要记住的口令，但拿到它和你的词条列表的人能算出假名。别把它放进交给别人的备份，也别放进任何仓库。
2. **机器。** 在代理主机和你工作用的每台机器上用 `sudo` 运行 `machine-ids.py`，在能看到你网络的那台加 `--lan`。把每份输出用 `scp` 复制到代理，合并，重启。这覆盖了主机名、地址、网段、MAC、磁盘和机器标识、密钥和账户，你一个都不用敲。
3. **客户。** 对每个客户，手工加上脚本无法知道的东西：公司名如果是名字就作为 `person` 词条（`{value: "Müller & Söhne", kind: person}`），打交道的人作为带 `ignore_case` 的 `person` 词条，他们的域名作为 `domain`，主机作为 `host`，网段作为 `cidr`，账号作为 `iban`。想想名字会出现在哪里：邮件签名、工单标题、hosts 文件、VPN 配置、发票。
4. **你自己。** 你的名字、你的公司、你的域名、不是单词的登录名、你的邮箱、你的银行账户。脚本会加上本地账户和主机名，其余的由你来加。
5. **目录。** 开启 `path.enabled: true`。默认的 `replace_unknown: true` 会替换每个未知目录，所以以客户命名的项目目录即使你忘了那个客户也被覆盖。你自己的、不标识任何人的目录名妨碍工作时加进 `path.preserve`。文件名保持可读，只在词条匹配处被替换，见[路径与文件名](#路径与文件名)。
6. **单词。** 把 `terms.txt` 通读一遍，划掉每个同时是普通单词的词条：`backup`、`admin`、`data`、`test`、`nas`。这样的词条会让模型眼里的命令和配置坏掉。换成只匹配你所指形式的正则，或者交给目录层。在代理主机上运行 `machine-ids.py --check terms.txt`：它列出其中在那台机器上同时是命令或普通单词的每个词条。从现在起，给每台新机器、共享、服务和网络起一个不是单词的名字，`nas01` 而不是 `nas`，见[什么该进列表](#什么该进列表什么不该)。
7. **模型。** 把[告诉模型](#告诉模型)里的那段话放进每个经过代理的项目的 `CLAUDE.md`，或者客户端的系统提示。
8. **检查。** 重启代理，找到带词条数量的注册行。然后发一个提到客户、主机和路径的请求，读插件的日志行：它按 kind 统计替换了什么。想看得更细，给几个请求设 `audit.path`，读映射表，然后再关掉；那个文件是明文。`machine-ids.py --summary` 显示脚本找到了什么而不打印任何值。
9. **其他客户端。** 回程只还原 Claude Code 的请求格式。如果还有别的东西经过代理，把它的格式列进 `skip_formats`，或者接受它的回答带着假名到达。
10. **保持更新。** 新客户、新机器、新磁盘、新密钥：进列表之前都没有覆盖。硬件变动后重跑脚本，项目开始时加上客户，每次修改后重启代理；词条只在启动时读取。永远不要把 `terms.txt` 或脚本的输出粘贴进经过代理的会话：还没加载的就还没被替换。

## 配置

插件在 CLIProxyAPI 的 `config.yaml` 中 `plugins.configs.privacyfilter` 下配置。宿主处理 `enabled` 和 `priority`，其余全部透传给插件。完整示例：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      mode: pseudonymize
      terms_file: terms.txt          # 相对插件目录
      terms:                         # 再加几个，内联
        - {value: example-gmbh.de, kind: domain}
        - {regex: "[a-z0-9-]+\\.home\\.lan", kind: host}
        - {value: markus, kind: person, ignore_case: true}
      path:
        enabled: false               # 在你的环境中确认流式还原正常后再开启
      limits:
        mapping_ttl: 30m
      skip_models: []
      skip_formats: []
```

两种模式都读取的字段：

| 字段              | 类型     | 默认值    | 说明                                                                                   |
|-----------------|--------|--------|--------------------------------------------------------------------------------------|
| `mode`          | string | `redact` | `redact` 保持原有的单向脱敏；`pseudonymize` 启用可逆假名和还原路径。两种模式都运行原版检测。 |
| `gitleaks_toml` | string | `""`   | 自定义 gitleaks 规则文件路径，相对路径基于插件目录解析。为空时使用共享库旁的 `rules/gitleaks.toml`，否则使用构建时内嵌的规则。 |
| `skip_models`   | array  | `[]`   | 绕过插件的模型                                                                              |
| `skip_formats`  | array  | `[]`   | 绕过插件的来源格式                                                                            |

只在 `redact` 模式下读取的字段，见[脱敏模式](#脱敏模式)：

| 字段                   | 类型     | 默认值  | 说明                                                                                        |
|----------------------|--------|------|-------------------------------------------------------------------------------------------|
| `replacement`        | string | 未设置  | 用同一个标签替换所有命中，代替内置标签，例如 `[REDACTED]`。                                                      |
| `replacement_labels` | object | `{}` | 按实体类型（`email`、`secret`、`phone`、`id`、`bank_card`、`ip`）分别设置标签；按类型的标签优先于 `replacement`。 |

只在 `pseudonymize` 模式下读取的字段。`mode: redact` 会忽略它们，插件行为与原版逐字节一致：

| 字段                      | 类型     | 默认值          | 说明                                                                                                                                               |
|-------------------------|--------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `salt_secret_path`      | string | `""`         | HMAC 密钥文件。为空时使用共享库旁的 `pseudonym.secret`；相对路径基于插件目录解析。文件只能由属主读取（权限 `0600` 或更严），去除空白后至少 32 字节，否则插件拒绝启动。                                                        |
| `terms`                 | array  | `[]`         | 视为敏感的值，每项为 `{value: ..., kind: ...}` 或 `{regex: ..., kind: ...}`，可加 `ignore_case: true`。优先级高于其他所有检测层。                                              |
| `terms_file`            | string | `""`         | 词条列表，见[词条列表](#词条列表)。相对路径基于插件目录解析。                                                                                                        |
| `patterns`              | object | 除 url 外全部开启   | 结构化检测器：`ipv4`、`ipv6`、`cidr`、`mac`、`email`、`iban`、`uuid`、`hexid`、`fingerprint`、`serial` 默认 `true`；`url` 关闭。`uuid` 覆盖磁盘和机器 UUID，`hexid` 覆盖 32 位及 `0x` 前缀的 16 位十六进制标识（如 WWN、machine-id），`fingerprint` 覆盖 SSH 主机密钥指纹（`SHA256:…`），`serial` 覆盖跟在 `Serial Number:`、`ID_SERIAL_SHORT=`、`"serial":`、`iSerial`、`Seriennummer:`、`s/n:` 等标签之后的序列号。`ipv4`、`ipv6`、`email` 同时决定 packyme 层报告什么，见[关闭检测器](#关闭检测器)。 |
| `path`                  | object | 关闭           | 按路径段假名化，见[路径与文件名](#路径与文件名)：`enabled`（默认 `false`）、`replace_unknown`（默认 `true`，替换保留列表之外的所有目录；`false` 时只替换同时是词条的目录）、`filenames`（默认 `terms`，只在词条匹配处替换文件名；`all` 替换保留列表之外的所有文件名）、`preserve`（在内置常见段名列表如 `home`、`usr`、`src` 之外追加保留的名字）。 |
| `packyme`               | object | 开启           | `enabled` 控制使用 gitleaks 规则的 packyme/privacy-filter 层。                                                                                             |
| `secrets`               | object | 关闭           | betterleaks 层的 `enabled` 和 `rules_toml`。只在带 `betterleaks` 标签构建的二进制中有效；在普通构建中开启会让插件以错误拦截每一个请求，直到关闭它。                                                              |
| `restore.stream`        | bool   | `true`       | 在流式响应中还原假名。非流式响应总是被还原。                                                                                                                           |
| `limits.max_body_bytes` | int    | `33554432`   | 超过此大小的请求体被拒绝。                                                                                                                                    |
| `limits.mapping_ttl`    | string | `30m`        | 会话的映射表在最后一次使用后保留多久。每个请求、响应和流式分块都算使用，所以进行中的会话不会丢表；静默的会话在此时间后被丢弃。                                                                                                                |
| `on_error`              | string | `block`      | 检测或解析失败时的正向行为：`block` 终止请求，`passthrough` 原样转发。还原路径出错时总是原样放行。                                                                                     |
| `audit`                 | object | 关闭           | 本地审计日志：`path`（为空即关闭；相对路径相对插件目录解析）和 `max_bytes`（默认 10 MiB，文件轮转一次到 `.1`）。每条映射和每次还原都以明文写入，见[审计日志](#审计日志)。 |

插件无法解析的配置会在启动时导致注册失败：CLIProxyAPI 在日志中给出原因并在没有插件的情况下继续运行，所以每次启动后都要通过 `GET /v0/management/plugins` 确认 `effective_enabled: true`。热更新时被拒绝的配置会连同出错字段一起记入日志，之前有效的配置继续生效，一处笔误不会静默关掉过滤。`pseudonymize` 模式的设置错误则不同，比如缺少密钥或词条被拒绝：插件照常注册，并以这条消息拦截每一个请求，直到修正配置并重启代理。

### 关闭检测器

每个结构化检测器在 `patterns` 下都有自己的开关。整天和公网地址打交道、希望它们保持原样的人，或者需要模型对真实网段做推理的人，可以关掉网络类检测器，保留其余：

```yaml
    privacyfilter:
      mode: pseudonymize
      patterns:
        ipv4: false
        ipv6: false
        cidr: false
        mac: false
```

这些开关作用于每一层。原插件的检测没有自己的开关，会在凭据规则之外报告 IP 地址和邮箱；把 `ipv4`、`ipv6` 或 `email` 设为 `false` 后，它报告的同类结果也会被丢弃，所以被关掉的 kind 不会被任何一层替换。词条列表是例外：`kind: ipv4` 或 `kind: cidr` 的条目不管开关如何都会被替换，因为是你放进去的。如果 `machine-ids.py` 收集了你不想替换的地址，从文件里划掉它们。

整层关闭的方式相同：`packyme.enabled: false` 去掉原有检测及其凭据、电话和银行卡规则，`path.enabled: false` 不再动目录，`secrets.enabled` 控制 betterleaks。每次修改都需要重启代理，修改前开始的会话应当重新开始，因为它的假名会随设置改变。

## 它做什么，不做什么

插件在出站时把值替换为同形状的假名，在入站时把原值放回去。它还原的是**原样**返回的内容：正文、工具调用、代码块中的假名，流式或非流式，粘着 `.bak` 或 `-backup.tar.gz` 之类后缀的，写成大写的，以及域名和邮箱地址去掉保留后缀 `.invalid` 的写法，模型会把这个后缀认作标记并省略它。它不还原模型从假名**推导**出来的东西，因为推导值不在任何映射表里：

- 模型无法用假名计算。"X 的下一个地址"是在假名上算的，回来的是假名的邻居，不是原值的邻居。配置过的网络是例外：其中的地址保留所属网络，"同一个 /24"仍然成立，落在请求携带过的地址上的算术会被还原。
- 部分假名不会还原：令牌的最后四个字符、带通配符的前缀、被截断的令牌。模型照着其他假名的样子编出来的假名也不会，比如给新文件起的名字。
- 模型不知道假名代表什么。它无法从 `h-e2ba…` 这个名字分辨 Intel NUC 和树莓派，也会把 `100.64.0.0/10` 里的地址说成运营商级 NAT 地址。凡是从值本身而非上下文得出的结论，都是从错误的值得出的。
- 词条在任何以单词形式出现的地方都会被替换，见[什么该进列表](#什么该进列表什么不该)。
- 回环、未指定、广播、组播、链路本地和文档地址永远不被替换。
- thinking 块和工具名在两个方向都不会被触碰。

映射在会话期间存在于内存中，是派生出来的而不是存储的：同一个值在一个会话内得到同一个假名，另一个会话得到另一套假名。会话的映射表随每个请求增长，并在每个响应时被读取，所以模型从早先轮次重复的假名即使当前请求没有携带原值也会被还原。映射不会离开进程，除非设置了 `audit.path`，否则不会写盘。会话的第一条消息使用真实值、后续消息使用假名是正常的；两个方向都会被处理。

模型先写下的东西保持原样。模型用 `mkdir hallo` 创建的目录、它命名的文件、它写进测试脚本的地址或邮箱：这些值提供方早已以明文拿到，因为是模型写的；工具结果回显它们时再替换，保护不了任何东西，反而让模型看到自己的目录变成 `d-…`，它正是从这里学会编造同样形状的名字。所以正向路径区分模型的轮次和用户一方，按会话顺序，系统提示在前；模型比任何人都先拥有的值，在会话余下的部分里保持原样，无论在模型自己的轮次里还是在重复它的工具结果里。用户一方先拥有的值，模型重复它时仍被替换：模型只见过假名，它轮次里的明文是客户端还原的结果。有两样东西不管谁写的都会被替换：你的词条列表里的值，包括藏在更长的值里的，以及你的列表所列网络内的地址，因为模型猜出一个网关地址远比猜出一个客户目录容易。会话保存一份关于替换了什么、放过了什么的记忆，只存摘要不存值，在最后一个请求之后保留 24 小时，比存着原值的映射表更久：暂停和历史压缩（它会把模型起的名字重复到用户一方）不会改变这个决定。日志行在 `kept` 下计数被放过的值。模型只在 thinking 块里想到的名字没有人读到，从第一个携带它的工具调用起算。

### 已知限制

- 还原路径只处理 Anthropic Messages 格式；其他格式插件会记录警告并原样放行。若不想对这些格式做正向过滤，用 `skip_formats` 排除它们。
- thinking 块在两个方向都不会被触碰。其签名与文本绑定，因此客户端 thinking 视图中的摘要显示的是假名而非原值。
- 单独的姓氏会被渲染为名，所以单独使用的姓氏在模型回答中可能读起来像第二个名。
- 词条在词边界匹配，下划线算边界：`nuc_old` 和 `NUC_HOST` 含有主机 `nuc`。字母和数字连成一体，所以 `nucleus` 不算。前面的百分号转义虽以十六进制数字结尾，也算边界：`Kunden%20nuc` 含有 `nuc`，`%20` 或 `%2F` 之后的假名会被还原。
- 不在任何配置网络内的地址会散布在整个标记范围内，彼此没有关系。如果模型需要推理你的网络，把它们作为 `cidr` 词条加进去。
- 请求存活期间原值以明文存在于内存中，这是还原所必需的。
- 模型改写过的假名，缩短了、加了空格或回忆时错了一位数字，不在任何表里，会原样到达客户端；插件只还原自己生成的东西。模型照着插件自身的形状编出来的名字也一样，比如给一个它没见过的目录写 `d-<12 位十六进制>`，或者给新文件取名 `f-<12 位十六进制>.md`：客户端拿到的是编出来的词元，建立在它上面的命令，比如对该路径的 `sed` 或 `mkdir`，会落空或者建出一个多余的目录。这类词元在普通日志里按响应计为 `unknown` 和 `unknown_hits`，设置了 `audit.path` 时作为 `unknown` 行列出，所以产生它们的会话是可见的。模型给自己起的名字不是问题，它们保持明文，见[它做什么，不做什么](#它做什么不做什么)；助长这个习惯的是满是 `d-…` 的上下文，所以把模型必须点名的无害项目目录加进 `path.preserve` 可以让这种形状少见；在命令行上，从客户端认识的目录出发的相对路径 `cd <project> && …` 胜过凭记忆拼出的绝对路径。词条等于内置人名列表中的某个名字则没有问题：该条目会从这个插件的人名列表中剔除，日志记录一条带数量的警告，其他人名假名保持不变。
- 模型按它看到的东西加引号，而它看到的是一个普通单词。词条值若含有引号、反斜杠、shell 元字符（`$`、`;`、`&`、`|`、`<`、`>`、反引号）、`#`、`%`、`/` 或控制字符，被还原进为假名写下的命令行、配置行或补丁时，会改变那一行的作用。插件拒绝这样的值：它照常注册，但以一个指出词条文件行号和所发现字符类别、从不写出值本身的错误回答每一个请求，直到该行修好并重启代理。只有这些字符会被拒绝：任何文字的字母，无论中文、西里尔文、土耳其文还是带变音符的拉丁文，以及数字、空格、点、连字符和括号都没有问题；CIDR 形式的网络、`secret` 和 `fingerprint` 词条保留它们的斜杠，因为密钥材料、令牌和 SHA256 指纹是 base64，斜杠属于这个字母表；正则表达式不受检查。如果你确实需要这样的值，就把它写成一个不含该字符却能匹配它的正则表达式。
- 开启 `replace_unknown` 时，路径层在它按形状识别出的路径里兜住未知目录：带开头标记的路径，最后一段带扩展名、结尾斜杠或隐藏名、或第一段以点开头的裸路径，以及 `-home-<user>-<project>` 形式的压平工作目录。两者都没有的裸目录路径 `kunde-x/sub`、diff 头里的 `a/` 前缀、`file://` 或 `http://` 地址里的路径、Windows 路径，以及直接位于根之下的压平目录 `-tmp-kunde-x`，其中的未知目录以明文留下；词条列表里的目录在任何写法里都被覆盖。见[路径与文件名](#路径与文件名)。
- 只有编码空格 `%20` 会从路径段里拆出来。名字里含 ASCII 之外字母的目录，以整个编码词的一个假名出站，比如 Markdown 链接把 `Übersicht` 写成 `%C3%9Cbersicht`，模型看不到其中的字母。按原样引用的链接能回来；模型从假名解码出的路径不能，因为解码后的词不在任何表里。文件名保持可读，所以文件仍能按名字找到。
- 目录名里的真实空格只在文本表明名字还在继续时才被读进去：在引号里、在反斜杠后面，或者裸路径中空格后面的词自带斜杠。作为工具参数整体出现的裸三词名字，`/home/alice/Kunden und Akten/Berichte`，中间的词留在明文里，因为 `und` 不带斜杠，也没有别的迹象表明名字还在继续；如果余下部分既不以扩展名也不以斜杠结尾，比如没有文件的目录或本身带空格的文件名，那么第一个空格之后的一切连同其中的目录都留在明文里。加引号或转义后名字整体读入。反过来是代价：紧跟在裸路径后面的带斜杠散文词，`/home/alice/Kunden TCP/IP`，被当作路径的剩余部分，以假名出站，按原样回来。引号里跟在选项后面的路径，`"--out=/home/alice/Kunden Akten"`，对 shell 来说是加了引号的，对插件来说不是，它看到的引号在选项前面而不在斜杠前面，于是按裸路径来读。
- 带 `ß` 且 `ignore_case` 的词条不匹配全大写行里的 `SS` 写法；对匹配器来说这是两个不同的词。如果这样的行会经过过滤器，把 `SS` 写法作为第二个词条加进去。
- `path.enabled` 默认 `false`。在你的环境中确认流式还原正常后再开启：工具调用中半还原的路径比泄露一条路径危害更大。
- betterleaks 层只存在于带 `betterleaks` 标签的构建中，共享库体积约为原来的三倍。
- 用另一种形式拼出值的输出，`od -c`、`xxd`、`base64`，不会被词条列表匹配：匹配器找的是按原样写出的值。这是有意保持的。逐字节检查一个名字的模型是在确认替换是否正确，这是列表和命令不一致时它的最后手段，拿掉它只会让模型另寻他法；出去的只是一个值，一次，在需要它的那个会话里。
- 序列号只在标签之后才被检测。正文中裸露的序列号、git 提交哈希、镜像摘要或 DNS 区域序列号被有意放过，因此没有任何标签的序列号会原样到达模型。如果它重要，把它加进词条列表。
- 设 `path.filenames: all` 后，模型看到的每个文件名都是 `f-<12 位十六进制><扩展名>`。它新建文件时往往会取同样形状的名字，这个名字不在任何映射表中，会原样到达客户端。把文件改名即可，内容会正常还原。默认的 `terms` 让文件名保持可读，避免了这个问题。

## 从源码构建

环境要求：Go 1.26 或更新、启用 CGO、`make`。

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
```

默认构建把共享库写到仓库根目录：Linux 为 `privacyfilter.so`，macOS 为 `privacyfilter.dylib`，Windows 为 `privacyfilter.dll`。用 `GOOS` 和 `GOARCH` 指定平台，用 `BUILD_DIR` 指定输出目录；此时 `machine-ids.py` 会被复制到它旁边：

```bash
GOOS=linux GOARCH=amd64 BUILD_DIR=dist make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

`build/build.sh` 用 Podman 在 `golang:1.26-bookworm` 容器内为 `linux/amd64` 构建同一个共享库，因此产物可以在 `debian:bookworm-slim` 镜像中加载，与构建机器上的 glibc 无关。脚本支持 `BUILD_TAGS` 和 `VERSION`，把两个文件都输出到 `dist/`：

```bash
build/build.sh 0.4.6
```

加入 betterleaks 凭据扫描器（见 [betterleaks](#betterleaks)）；普通构建不会链接它：

```bash
BUILD_TAGS=betterleaks make build
```

插件注册信息：名称 `privacyfilter`，能力 `RequestInterceptor`，在 `pseudonymize` 模式下还有 `ResponseInterceptor`、`StreamChunkInterceptor` 和 `RequestCompletion`，Schema 版本 3，作者 `rheodev`。

## 内部工作原理

### 假名

假名是 `HMAC-SHA256(secret || salt, kind || value || attempt)` 按 kind 渲染的结果。salt 每个会话派生一次，依次取自 `X-Claude-Code-Session-Id` 请求头、`metadata.user_id`，最后是首条消息的哈希，因此后续请求得到与前一次相同的假名，模型上下文保持连贯。没有随机性，也不落盘：映射表在会话期间存在于内存中，会话的每个请求把自己的值加进去并在回程时读取整张表，会话静默 `mapping_ttl` 之后表被丢弃。

作为 `cidr` 词条给出的网络映射到标记范围内同前缀长度的一个网络。其中的每个地址都渲染进该网络，只有主机位来自地址自身的摘要；嵌套在另一个配置网络内的网络落在其父网络的假名之内。主机、网关和邻居对模型而言保持关联。不在任何配置网络内的地址散布在整个范围内。

假名形状的选择让模型能把它们与真实值区分开并仍能拿来计算：`100.64.0.0/10` 是运营商级 NAT 网段，`02:` 开头的 MAC 是本地管理地址，`.invalid` 由 RFC 2606 保留，UUID 版本位 `f` 不存在于任何 RFC 9562 版本，IBAN 银行代码以四个零开头而没有任何机构会发放，十六进制标识以 `5046` 开头，序列号以 `PF-` 开头，密钥以 `PF_` 开头。插件本身不按形状判断：它排除在第二次替换之外的，是会话映射表里已有的东西，所以真实的 Tailscale 地址或 Docker MAC 会被替换，映射表也从不发出与它的某个原值或你列表中某个词条相同的假名。人名假名来自固定的虚构人名列表；等于其中某个名字的词条会把该条目从列表中剔除。

### 正向与还原路径

正向路径遍历 JSON 请求体中的每个字符串，跳过拒绝列表上的字段（标识符、工具名、模型名、thinking 块及其签名）；在工具调用的 `input` 之下也遍历每个对象键，因为那里的键属于工具，可能带着文件名或主机名。两个方向使用同一个字节扫描器：只重新编码发生变化的字符串，其余每个字节，包括键的顺序和转义序列，都原样保留；同一对象里出现两次的键两次都会被看到；块的第一个 `type` 键对两个方向都起决定作用。正向路径按固定顺序运行检测层：词条列表、结构化模式、路径层、原版插件的检测（带 Gitleaks 规则的 packyme）、betterleaks。重叠命中被合并：靠前的层胜过靠后的层，同一层内最长者胜出。一个例外：靠后层的命中若把靠前层的命中整个包含在内，就作为整体、按自己的 kind 替换，所以带公司域名的邮箱地址按 `email` 替换而不是把本地部分留在明文里，以客户和案号命名的目录按段替换而不是留下案号，地址里的短词条也不会把地址拆开。原版检测的命中按 kind 假名化：邮箱地址作为 `email`，IP 地址作为 `ipv4` 或 `ipv6`，其余一切，密钥、电话和证件号码、银行卡，作为不透明的 `secret` 令牌，像其他假名一样被还原。还原路径在同一拒绝列表上一次扫描完响应体，只在词元边界处把假名换回原值，嵌在更长标识符里的假名不会被动。

流式响应逐块还原。因为一个假名可能被切分到两个增量中，插件会扣留文本末尾仍可能长成假名的部分，也扣留恰好在文本末尾结束的完整假名，因为下一个增量可能以字母开头，把它粘成一个更长的单词；后面跟着分隔符的假名则立即还原。扣留的部分在块结束前、消息结束前和 error 事件前以合成增量的形式发出，所以回答中途的 `overloaded_error` 不会丢失文本。紧挨在一起的假名作为一串整体还原。测试覆盖了在每个字节位置切分的情况，包括末字节恰好可以作为另一个假名开头的假名。

### 审计日志

`audit.path` 开启一个按请求记录的日志，位于共享库旁（或路径所指之处）。它用于检查插件对某个请求做了什么，不是为长期运行准备的：每一行都是明文，文件里正是插件要挡在线路之外的那些值。文件以 `0600` 权限创建，只要该选项设置着，插件启动时就记录一条警告，文件在 `max_bytes` 时轮转一次到 `.1`。每行一条记录，制表符分隔：

```text
<time>  request   <request id>  format=claude  session=header  body=<bytes>  out=<bytes>  distinct=<n>  table=<n>  kept=<n>
<time>  map       <request id>  <kind>  <original>  <pseudonym>
<time>  restored  <request id>  <pseudonym>  <original>  <count>
<time>  unknown   <request id>  <token>  <count>
<time>  complete  <request id>  outcome=succeeded  stream=true  restored_distinct=<n>  restored_total=<n>
```

`map` 行按 kind 和值排序列出该请求的整张映射表，`restored` 行列出响应中实际返回的假名及各自被换回的次数。检测到但从未返回的值只出现在 `map` 行。`unknown` 行列出响应携带的、具有插件自身形状却没有映射表行支撑的词元及各自出现的次数：模型照形状编出来的名字、回忆时错了一位数字的假名，或者从文件里引用的另一个会话的假名；对照该会话的 `map` 行就能把它们区分开。整体响应在被还原时写这些行，流在完成时写，位于其 `complete` 行之前，被增量边界切成两半的词元在那里不计数。普通日志在报告已还原响应或流的那一行里以 `unknown` 和 `unknown_hits` 两个字段给出同样的计数。被脱敏而非假名化的值不出现在此日志中，它们仍像以前一样记录在普通插件日志里。

### 脱敏模式

默认的 `mode: redact` 就是原版插件：单向，没有任何东西回来。它在 before-auth 和 after-auth 两个请求拦截阶段都会脱敏，两个阶段看到的都是客户端格式的请求体（executor 翻译之前）。after-auth 这一遍用来拦住请求链后面其他插件加进来的文本，例如优先级更低的 before-auth 拦截器或优先级更高的 after-auth 拦截器。脱敏是幂等的，已经脱敏过的文本不会产生新的命中：

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

以下内容有意不修改：工具调用参数（`function_call.arguments`、Claude `tool_use.input`、Gemini `functionCall` / `functionResponse`）、图片、文件、Claude `thinking` 块，以及标记了 `thought: true` 的 Gemini 分段（其文本与 `thoughtSignature` 绑定）。OpenAI Completions 请求通过 `messages` 覆盖：宿主在调用拦截器之前会先把它转成 chat completions 格式。`skip_formats` 的常见取值是宿主的来源格式名，例如 `openai`、`openai-response`、`claude`、`gemini`、`gemini-cli`、`openai-image`、`openai-video`。

占位符默认是库的内置标签 `[EMAIL]`、`[PHONE]`、`[ID]`、`[BANK_CARD]`、`[IP]` 和 `[SECRET]`；`replacement` 为所有命中设置同一个标签，`replacement_labels` 按实体类型分别设置，按类型的标签优先于全局标签。假名模式不受影响：它读取库的检测结果，而不是库的渲染。

每次拦截只要有脱敏就向宿主日志输出一行，列出被脱敏字段的 JSON 路径，例如 `privacy filter redacted 2 field(s): messages[0].content, system`，不会记录请求原文。这些日志通过宿主的 `host.log` 回调输出，遵循 CLIProxyAPI 的日志级别、格式和输出位置，并带上请求 ID。

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

两种模式的检测都使用 [rheodev/privacy-filter](https://github.com/rheodev/privacy-filter)（[packyme/privacy-filter](https://github.com/packyme/privacy-filter) 的分支，修复了大请求上的 panic）和 Gitleaks 规则，覆盖密钥、连接串、证书等内容。规则在构建时从 `rules/gitleaks.toml` 内嵌；运行时插件依次取配置中的 `gitleaks_toml`（若设置）、共享库旁的 `rules/gitleaks.toml`、内嵌的规则。用 `make update-rules` 更新内嵌规则并重新构建。

### betterleaks

[betterleaks](https://github.com/betterleaks/betterleaks) 是规则集更大的 gitleaks 分支。它只在 `BUILD_TAGS=betterleaks` 时被编译进来，并通过 `secrets.enabled: true` 开启。其凭据校验功能会通过 HTTP 把发现的凭据发送给对应服务商，在所有构建中都被禁用，且无法通过配置开启。`secrets.rules_toml` 指向自定义规则文件；为空时使用内嵌规则。无法编译的规则文件会导致注册失败，而不会拖垮代理。

## 开发

```bash
go test ./...
go test -tags betterleaks ./...

# 修改渲染器或示例值之后：重新生成 README 的“一眼看懂”一节
README_EXAMPLES_OUT=/tmp/examples.tsv go test -run TestRoundTrip_ReadmeExamples .
tools/readme-examples.py /tmp/examples.tsv en   # 覆盖 README.md 中的该节
tools/readme-examples.py /tmp/examples.tsv zh   # 以及 README.zh-CN.md 中的
make build
make clean
```

主要文件：

```text
main.go                 插件元数据、注册和构建入口
abi.go                  CLIProxyAPI 插件 ABI 适配
interceptor.go          请求拦截：redact 与 pseudonymize 的正向路径
response.go             非流式响应的还原路径
stream.go               流式响应的还原路径，扣留与冲刷
lifecycle.go            请求完成事件，把请求从其映射表解绑
config.go               YAML 配置解析
termsfile.go            词条文件格式
detect/                 检测层：词条、模式、路径、packyme、betterleaks
pseudo/                 HMAC 假名、按 kind 的渲染器、salt 与密钥处理
mapping/                会话级映射表、存储与还原器
payload/                JSON 遍历、拒绝列表、Anthropic SSE 事件
tools/machine-ids.py    把本机标识收集为词条文件；构建时复制到 dist/
tools/readme-examples.py 用 TestRoundTrip_ReadmeExamples 的输出生成“一眼看懂”一节
cmd/termsgen/           旧的生成器：从 ssh 配置和 hosts 生成词条文件
internal/leaktest/      端到端泄露测试：没有敏感值能通过正向路径
rules/gitleaks.toml     内置检测规则
```

依赖说明：

```text
privacyfilter => github.com/rheodev/privacy-filter
```

## 来源

- 核心过滤逻辑：[rheodev/privacy-filter](https://github.com/rheodev/privacy-filter)，派生自 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- 插件运行时：[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- 学 AI 就上 L 站：[linux.do](https://linux.do/)
