#!/usr/bin/env python3
"""Render the README section "At a glance" from the output of
TestRoundTrip_ReadmeExamples.

    README_EXAMPLES_OUT=/tmp/examples.tsv go test -run TestRoundTrip_ReadmeExamples .
    tools/readme-examples.py /tmp/examples.tsv en > section.md
    tools/readme-examples.py /tmp/examples.tsv zh > section.zh.md

The section shows values the plugin produced, not values somebody typed,
so the README cannot drift from the code. Rerun it after a change to the
renderers or to the example values in the test.
"""

import sys

TEXT = {
    "en": {
        "heading": "## At a glance",
        "intro": (
            "One request, four stations. The client sends the real values, the plugin swaps them for pseudonyms "
            "of the same shape, the model answers with the pseudonyms it saw, and the plugin puts the originals "
            "back before the client reads the answer. The mapping never leaves the machine."
        ),
        "client": "Your client",
        "plugin": "Plugin on the proxy",
        "model": "Model provider",
        "edge1": "1 original values",
        "edge2": "2 pseudonyms",
        "edge3": "3 answer with pseudonyms",
        "edge4": "4 originals put back",
        "stage_col": ("Station", "Text"),
        "stages": {
            "client_sends": "What the client sends",
            "model_receives": "What the model receives",
            "model_answers": "What the model answers",
            "client_gets": "What the client gets",
        },
        "kinds_intro": (
            "Every kind of value gets a pseudonym of its own shape, so the model can still tell a host from an "
            "address and a path from a serial number. The left column is what leaves your editor, the right column "
            "is what the provider stores. Every value below is invented; the pseudonyms were produced by the plugin "
            "in a test run:"
        ),
        "kind_col": ("Kind", "What you send", "What the model sees"),
        "outro": (
            "The same value gets the same pseudonym for the whole conversation, so the model can refer to a host "
            "it saw three messages ago. Another conversation gets other pseudonyms. Which kinds exist and what "
            "each one is for is described under [Kinds](#kinds)."
        ),
    },
    "zh": {
        "heading": "## 一眼看懂",
        "intro": (
            "一个请求，四个站点。客户端发送真实值，插件把它们换成同形状的假名，模型用它看到的假名作答，"
            "插件在客户端读到回答之前把原值放回去。映射关系从不离开本机。"
        ),
        "client": "你的客户端",
        "plugin": "代理上的插件",
        "model": "模型提供商",
        "edge1": "1 原始值",
        "edge2": "2 假名",
        "edge3": "3 带假名的回答",
        "edge4": "4 放回原值",
        "stage_col": ("站点", "文本"),
        "stages": {
            "client_sends": "客户端发送的",
            "model_receives": "模型收到的",
            "model_answers": "模型回答的",
            "client_gets": "客户端得到的",
        },
        "kinds_intro": (
            "每一类值都有自己形状的假名，所以模型仍能分清主机和地址、路径和序列号。左列是离开你编辑器的内容，"
            "右列是提供商存下的内容。下面的值都是虚构的；假名由插件在一次测试运行中生成："
        ),
        "kind_col": ("kind", "你发送的", "模型看到的"),
        "outro": (
            "同一个值在整个会话里得到同一个假名，所以模型能提到三条消息之前看到的主机。另一个会话得到另一套假名。"
            "有哪些 kind、各自用于什么，见 [kind](#kind)。"
        ),
    },
}

KIND_ORDER = [
    "host", "domain", "person", "email", "cidr", "ipv4", "ipv6", "mac",
    "iban", "uuid", "hexid", "fingerprint", "serial", "path_segment", "secret",
]


def code(s):
    return "`" + s.replace("`", "'") + "`"


def render(rows, lang):
    t = TEXT[lang]
    kinds = {}
    stages = {}
    for r in rows:
        if r[0] == "stage":
            stages[r[1]] = r[2]
        else:
            kinds[r[0]] = (r[1], r[2])
    out = [t["heading"], "", t["intro"], ""]
    out += [
        "```mermaid",
        "flowchart LR",
        f'    C["{t["client"]}"] -- "{t["edge1"]}" --> P["{t["plugin"]}"]',
        f'    P -- "{t["edge2"]}" --> M["{t["model"]}"]',
        f'    M -- "{t["edge3"]}" --> P',
        f'    P -- "{t["edge4"]}" --> C',
        "```",
        "",
        f"| {t['stage_col'][0]} | {t['stage_col'][1]} |",
        "|---|---|",
    ]
    for key in ("client_sends", "model_receives", "model_answers", "client_gets"):
        out.append(f"| {t['stages'][key]} | {stages[key]} |")
    out += ["", t["kinds_intro"], "", f"| {t['kind_col'][0]} | {t['kind_col'][1]} | {t['kind_col'][2]} |", "|---|---|---|"]
    for k in KIND_ORDER:
        orig, pseudo = kinds[k]
        out.append(f"| {code(k)} | {code(orig)} | {code(pseudo)} |")
    out += ["", t["outro"], ""]
    return "\n".join(out)


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in TEXT:
        sys.exit("usage: readme-examples.py FILE.tsv en|zh")
    with open(sys.argv[1], encoding="utf-8") as f:
        rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    sys.stdout.write(render(rows, sys.argv[2]))


if __name__ == "__main__":
    main()
