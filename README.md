# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A privacy filter plugin for [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). It sits between your coding assistant and the model provider and replaces identifiers such as host names, IP addresses, e-mail addresses, the names of people and customers, paths, serial numbers and account numbers with transparent stand-ins before a request leaves your machine, then puts the real values back into the answer. The model works with the stand-ins as if they were the real thing, administers a system, edits a config, writes a tool call, without ever knowing the actual names and IDs.

There are two modes. `redact` is the default and the original plugin: detected secrets, contact data and ID numbers become `[REDACTED]`, one way. `pseudonymize` is the reason for this fork: your own values from a list, plus everything the detectors find, become stable pseudonyms of the same shape, and the answer is translated back, streamed or not. The modes do not compete in detection. Pseudonymize runs the original plugin's automatic detection as its last layer, after your list and the structural patterns, so everything `redact` would find is found here too. The difference is what happens to a hit: thrown away, or replaced by something the model can use and the client gets back as the original. This document is written for `pseudonymize`; `redact` is described under [Redact mode](#redact-mode).

## At a glance

One request, four stations. The client sends the real values, the plugin swaps them for pseudonyms of the same shape, the model answers with the pseudonyms it saw, and the plugin puts the originals back before the client reads the answer. The mapping never leaves the machine.

```mermaid
flowchart LR
    C["Your client"] -- "1 original values" --> P["Plugin on the proxy"]
    P -- "2 pseudonyms" --> M["Model provider"]
    M -- "3 answer with pseudonyms" --> P
    P -- "4 originals put back" --> C
```

| Station | Text |
|---|---|
| What the client sends | Ingrid Muster reports that helios-nas01 (10.20.30.7) does not answer since the last change to /home/imuster/projekte/muster-gmbh/deploy.sh. |
| What the model receives | Lea Schuricht reports that h-5aa7c84ea894 (100.67.154.131) does not answer since the last change to /home/d-d828a9564f55/d-11d2d4de326e/d-69bb4ff312ad/deploy.sh. |
| What the model answers | h-5aa7c84ea894 is reachable at 100.67.154.131 again. The change in /home/d-d828a9564f55/d-11d2d4de326e/d-69bb4ff312ad/deploy.sh reverted the route, I told Lea Schuricht. |
| What the client gets | helios-nas01 is reachable at 10.20.30.7 again. The change in /home/imuster/projekte/muster-gmbh/deploy.sh reverted the route, I told Ingrid Muster. |

Every kind of value gets a pseudonym of its own shape, so the model can still tell a host from an address and a path from a serial number. The left column is what leaves your editor, the right column is what the provider stores. Every value below is invented; the pseudonyms were produced by the plugin in a test run:

| Kind | What you send | What the model sees |
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

The same value gets the same pseudonym for the whole conversation, so the model can refer to a host it saw three messages ago. Another conversation gets other pseudonyms. Which kinds exist and what each one is for is described under [Kinds](#kinds).

## Why

Everything a coding assistant sends to a model ends up on somebody else's server: the prompt, the files it reads, the output of every command it runs. For a consultant, an administrator or a small company that is the whole working day in clear text: customer names, the people behind them, their e-mail addresses, host names and addresses of their networks, the paths under which their projects live, machine serials, disk and partition identifiers, SSH fingerprints, account numbers. A single breach of the provider, a subpoena, a training-data mistake or a screenshot of a dashboard then exposes not one secret but the map of who works with whom on what, and with which machines. That map is worth more to an attacker than any one password.

Redacting such values is not enough, because a model that reads `[REDACTED]` cannot reason about the host, the path or the network any more, and the tool call it writes back is unusable. Pseudonymize mode keeps the request usable while the provider holds as little as possible: every confidential value is replaced by a stable pseudonym of the same shape before the request leaves the machine, and the original is put back into the answer before the client sees it. The model works with `h-e2ba…` and `100.71.4.18` exactly as it would with the real names, the provider only ever stores the pseudonyms, and the mapping never leaves the local process.

What gets replaced comes from three sources. The **term list** is a plain text file with your own values: customer names, hosts, domains, people, networks, account numbers. The **structural patterns** need no list and catch what has a recognisable shape on its own: IP addresses, MACs, e-mail addresses, UUIDs, SSH fingerprints, labelled serial numbers, IBANs. The **original plugin's detection** runs last, with its Gitleaks rules for API keys, tokens and connection strings and its recognisers for phone numbers, ID numbers and bank cards, and catches what neither of the first two lists. The script `machine-ids.py` that ships next to the plugin fills the term list with the identifiers of a machine, so a new host is covered in a minute.

## Installation

You need a running CLIProxyAPI, the two files from a release or from `dist/` after a build (see [Building from source](#building-from-source)), and Python 3 for the helper script.

1. Put the shared library and the script into the plugin directory of CLIProxyAPI. This is the directory named by `plugins.dir` in `config.yaml`, usually `plugins/`:

   ```text
   plugins/
   ├── privacyfilter.so        # the plugin
   ├── machine-ids.py          # fills the term list, see below
   ├── pseudonym.secret        # you create this once, step 2
   └── terms.txt               # your term list, step 3
   ```

2. Create the secret. The pseudonyms are derived from it; without it the plugin refuses to start. Any random bytes, at least 32 of them:

   ```bash
   head -c 48 /dev/urandom | base64 > plugins/pseudonym.secret
   chmod 600 plugins/pseudonym.secret
   ```

3. Create the term list. The quickest way is the script, which asks what to do and writes the file; run it on the machine the proxy runs on, with `sudo` so it can read the hardware serials:

   ```bash
   sudo python3 plugins/machine-ids.py
   ```

   Or start with an empty file and fill it by hand, see [The term list](#the-term-list).

4. Enable the plugin in `config.yaml`. This is all a normal installation needs:

   ```yaml
   plugins:
     enabled: true
     dir: "plugins"
     configs:
       privacyfilter:
         enabled: true
         mode: pseudonymize
         terms_file: terms.txt      # relative to the plugin directory
   ```

5. Restart the proxy and look for the plugin in its log:

   ```text
   pluginhost: plugin loaded plugin_id=privacyfilter version=... path=plugins/privacyfilter.so
   ```

   From now on every request logs one line with what it replaced, by kind and count, never the values:

   ```text
   privacyfilter: request pseudonymized ... replacements="host=33 ipv4=1 email=12 path_segment=247 ..."
   ```

The plugin reads the secret and the term list at start only. After every change to `terms.txt` restart the proxy. A fault in the pseudonymize set-up, a missing secret, an unreadable term list, a refused term, does not stop the registration: the plugin registers anyway and answers every request with an error 400 that names the fault, never a value, until the configuration is fixed and the proxy restarted. Without that the proxy would come up without the filter, and the only trace would be one line in its log.

## The term list

The term list is the file named by `terms_file`, `plugins/terms.txt` in the layout above. It is the one file you maintain. Every line is one value that must never leave the machine in clear text, together with the kind of thing it is, so the plugin can render a pseudonym of the same shape.

### Format

```text
# Anything after a hash is a comment. Blank lines are skipped.

nuc                                  # a literal; without a kind it is a host name
nuc host                             # the same, with the kind spelled out
example-gmbh.de domain               # a domain
markus person ignore_case            # a person; ignore_case also catches "Markus" and "MARKUS"
192.168.10.0/24 cidr                 # a network; addresses inside it keep their structure
DE89370400440532013000 iban          # an account number
kunde-x path_segment                 # a directory name that must not appear in paths
{regex: "(?i)\\bnuc(?:\\.[a-z0-9-]+)*\\b", kind: host}   # a regular expression, YAML form
{value: "Müller & Söhne", kind: person}                   # a literal with spaces, YAML form
```

A plain line is split on white space: the first word is the value, the optional second word the kind, and the word `ignore_case` sets the flag. A value that contains spaces or starts with `{` or `#` goes into the YAML form, which takes the same keys as a `terms` entry in `config.yaml`: `value` or `regex`, `kind`, `ignore_case`.

A term matches at word boundaries only: `nuc` matches in `nuc`, `nuc.local`, `nuc_old` and `NUC-2`, but not in `nucleus`. Letters and digits continue a word, everything else, including the underscore, ends it. The rule holds for a regular expression as for a literal: a hit inside a longer word is dropped, because the pseudonym would be glued to the rest of the word and could never be restored. Do not use `^` or `$` in an expression: it runs against whole messages, not against single lines.

### Kinds

The kind decides what the pseudonym looks like. The model sees something that has the same shape as the original, so it keeps working normally, and the plugin can tell a pseudonym from a real value when the answer comes back.

| Kind           | Use it for                                    | Pseudonym                                   |
|----------------|-----------------------------------------------|---------------------------------------------|
| `host`         | host names, with or without domain            | `h-<12 hex>`                                |
| `domain`       | domains, DNS search domains                   | `d-<12 hex>.invalid`                        |
| `ipv4`         | a single IPv4 address                         | an address in `100.64.0.0/10`               |
| `ipv6`         | a single IPv6 address                         | an address in a fixed `/48` of `fd00::/8`   |
| `cidr`         | a network; addresses inside keep their network | same prefix length, in the same ranges      |
| `mac`          | MAC addresses, BSSIDs                         | `02:xx:xx:xx:xx:xx`                         |
| `email`        | e-mail addresses                              | `u-<12 hex>@d-<12 hex>.invalid`             |
| `person`       | names of people; also customers, if they are people | an invented name from a fixed list; a lone word becomes a given name only |
| `iban`         | account numbers                               | same country and length, valid check digits |
| `uuid`         | disk, partition, machine and product UUIDs    | a UUID with version nibble `f`              |
| `hexid`        | 32-digit or `0x`-prefixed 16-digit hex ids: WWN, machine-id | same form, starting `5046` or `0x5046` |
| `fingerprint`  | SSH key fingerprints                          | `SHA256:PF` + 41 letters and digits         |
| `serial`       | serial numbers                                | `PF-<12 upper-case letters and digits>`     |
| `path_segment` | a directory name, replaced inside paths       | `d-<12 hex>`                                |
| `filename`     | a file name; the extension is kept. Used by the path layer with `filenames: all` only | `f-<12 hex><ext>`      |
| `secret`       | anything else                                 | `PF_<12 hex>`                               |

The same value gets the same pseudonym for the whole conversation, another conversation gets other pseudonyms. The pseudonyms are derived from the secret, not stored anywhere.

### What belongs in the list and what does not

- **Names, not words.** A term is replaced everywhere it appears as a word. A host called `backup` turns `rsync --backup` into nonsense for the model, a user called `admin` breaks every `admin` in a config file. Leave such entries out, or use a regular expression that matches only the form you mean, such as the host name followed by its domain.
- **Name your systems so that they are not words.** The rule above is easy to keep for customers and hard for your own machines, because a short host name is convenient and the script collects it. A machine called `time`, `cut` or `mail` turns every shell command, every option and every sentence that contains the word into a pseudonym. The round trip still works, the client gets the word back, but the model reads a hex token where the command stood. When you name a machine, a share, a service or a Wi-Fi, pick a token that occurs nowhere else: a number suffix (`nas01`, not `nas`), a made-up word, a name with a hyphen. The script flags a collected host name that is also a command on the machine; rename the machine, or keep the term and accept the noise.
- **What the patterns already catch can stay out.** IP addresses, MACs, e-mail addresses, UUIDs, fingerprints and labelled serials are detected on their own, and the original plugin's automatic detection with its Gitleaks rules catches API keys, tokens, connection strings, phone and ID numbers and bank cards. They belong in the list when the model has to see their structure: your networks as `cidr` terms, so that host, gateway and neighbour stay in one network for the model.
- **Addresses that are never replaced.** Loopback, unspecified, broadcast, multicast, link-local and the documentation ranges stay as they are, so the model still sees a `bind` to loopback for what it is. Real addresses in `100.64.0.0/10`, the range Tailscale hands out, and MACs with the `02:` prefix Docker gives its containers are replaced like any other value even though the pseudonyms live in the same ranges: the plugin tells its own pseudonyms apart by the mapping table of the conversation, not by their shape. The only value it refuses is a `cidr` term that covers the whole `100.64.0.0/10` or the fixed ULA `/48`, because such a network could only map onto itself.
- **One file, many machines.** Every machine can add its own block, see the next chapter. The plugin drops exact duplicates at start, so a gateway that appears in three blocks is one term.
- **The file is clear text.** It holds exactly the values the plugin exists to keep off the wire. Keep it and its backups readable by the proxy's user only, and never paste it into a conversation that runs through the proxy.

`terms` in `config.yaml` takes the same entries in YAML form and is meant for a handful of values; the file is for the list you maintain.

### Paths and file names

A path such as `/home/mwendler/Projekte/kunde-x/src/main.go` carries its confidential part in the middle: the login name, the customer. The path layer, switched on with `path.enabled: true`, takes a path apart at its slashes and treats the directories and the file name differently, because they play different roles.

**Directories** are replaced when they are unknown. A built-in list of a few hundred ordinary names, `home`, `usr`, `etc`, `src`, `build`, `docs`, `node_modules` and the like, stays as it is, so the model still sees a home directory and a source tree. Every other directory becomes `d-<12 hex>`, whether it is on your term list or not. That is the safety net for the customer directory nobody thought to list: a name that identifies somebody is gone even if the list does not know it. The model does not need the real name to work there. It sees the same pseudonym for the same directory throughout the conversation, writes it into its tool calls, and the client gets the real path back, so a file lands where it should. What the model loses is the meaning of the name: it cannot tell from `d-<hex>` that a directory holds media files. When that gets in the way, add the harmless names to `path.preserve`, or set `replace_unknown: false` to replace only directories that are also terms, at the price of the safety net.

The net has edges. The path layer recognises a path by its shape. An anchored path begins with a slash, `~/`, `./`, `../` or a variable such as `$HOME/`. A bare token with slashes, the way `git status`, a compiler or a test runner prints a path, counts as one when its last segment carries a file extension, a trailing slash or a hidden name, `kunde-x/.gitignore`, when its first segment starts with a dot, or when one of its segments is a flattened working directory of the form `-home-<user>-<project>`, the shape Claude Code names its transcript folders after, which counts on its own without any slash as well. So `kunde-x/vertrag.pdf`, `.config/kunde-x/bin`, `kunde-x/` and `projects/-home-user-kunde-x` are paths to the layer, and `and/or`, `km/h`, `origin/main`, `github.com/rheodev/x`, `@scope/pkg`, a sed expression, a date and a fraction are not, and neither is the slash of a tag, `</p>` or `<br/>`. The marker of a diff line, the `+` or `-` at the start of a line, is a boundary: `+/home/alice/kunde/x.go` and `-kunde-x/build/` are read from the character behind it, and the marker stays where it was, so an added line is still an added line for the model. What stays outside the net: a bare directory path without a file or a trailing slash, `kunde-x/sub`; the `a/` and `b/` prefixes of a diff header; a path inside a `file://` or `http://` address; a Windows path; a first segment with a dot inside it, `.hidden.dir/x`, because that is how a host or a module path looks; and a flattened directory that sits directly under its root, `-tmp-kunde-x`, which is caught in its absolute form only. An unknown directory in one of these forms stays in clear text. A directory on your term list is safe in every one of them, because the term list matches the name wherever it stands. The price of the wider net is the occasional harmless pair that has the shape of a path, `Input/Output.md`, whose first word then goes out as a directory pseudonym.

A directory with a space in its name stands in a Markdown link as `Kunden%20Akten`, because a bare space would end the link destination. The path layer divides such a segment at the encoded space: each word becomes a pseudonym of its own, and the `%20` stays between them, `d-…%20d-…`, so the model sees that there is a space to decode. Both spellings come back, the link quoted as it was and the path with the space decoded, which is the one a tool call needs, and the words carry the same pseudonyms as the directory listed with a real space. The words of an encoded file name belong to the file name and follow its rule below. Only the encoded space is divided out; a letter outside ASCII, `%C3%BC` for `ü`, stays inside its word, see [Known limits](#known-limits).

A real space in a name is read the three ways a session writes it. A shell quotes the path, `cd "/home/alice/Kunden Akten/Berichte"`, and the path runs to the closing quote on the same line; a shell escapes the space, `Kunden\ Akten`, and the path goes on behind the backslash; a tool argument holds the path and nothing else, `/home/alice/Kunden Akten/Berichte`, and the path goes on over a space when the word behind it carries a slash of its own. A bare path inside quotes, ` M "kunde-x/epub/Kunden und Akten.epub"` as git status prints a path with a space in it, is read whole as well: its shape is judged on the whole of the quoted text, so the extension or the slash at its end counts although a space stands in front of it, and the first segment has to be free of spaces and a colon ends the text the shape is judged on, because the words around a slash inside quotes are as often a sentence as a name, `"fix kunde-x/x.go"`, `"detect/paths: fix paths.go"`. In every form each word of the name gets its own pseudonym and the space stays between them, `d-… d-…`, so the model sees that the name has a space and quotes or escapes it as the command needs, and whichever spelling it writes back restores, because the words restore one by one. Where nothing says the name goes on, the space ends the path: prose behind a path stays prose, and a file name ends a path even inside quotes, so `"x.go: fix the test"` is a file and a sentence. What that rule misses stands under [Known limits](#known-limits).

**File names** are left alone by default. `README.md`, `main.go`, `config.yaml` say what a file is, they are the same in a million repositories, and they are the index by which a model finds its way around a tree: replacing them protects nothing and costs every `ls` its meaning. A file named after a customer carries the customer's name, and that name is a term, which the term layer finds inside the file name at its word boundary: `kunde-x-vertrag.pdf` goes out as `d-<hex>-vertrag.pdf`. A file name without an extension, `Makefile`, `LICENSE`, is on the preserve list, and so are the common hidden files, `.gitignore`, `.editorconfig`; other names without an extension count as directories. `path.filenames: all` replaces every file name outside the preserve list as `f-<12 hex><ext>`.

```yaml
path:
  enabled: true
  replace_unknown: true    # directories: replace every unknown one (default); false replaces terms only
  filenames: terms         # file names: replace only where a term matches (default); all replaces every one
  preserve: [media-files]  # directory names of yours that identify nobody and should stay readable
```

The plugin never replaces on the way back. A file name the model invents that happens to look like a pseudonym reaches the client as it is; with the default the model sees real file names and has no pattern to imitate. A directory or a file the model named itself stays in clear on the way out as well, so the model sees its own names in every listing; see [What it does and what it does not do](#what-it-does-and-what-it-does-not-do).

## Filling the list with machine-ids.py

`machine-ids.py` collects the identifiers of the machine it runs on and writes them in the format above. It needs nothing but Python 3, reads only local sources, and nothing leaves the machine. Started on a terminal without options it asks what to do:

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

It collects: host name and mDNS name as a regular expression that also matches the name with any domain, the entries of `/etc/hosts`, machine-id and boot id, DMI product UUID and the serials of board, chassis and product (root only), every network interface with MAC, permanent MAC, IPv4, IPv6, networks and gateways, DNS servers and search domains, Wi-Fi SSID and BSSID, Bluetooth adapters, block devices with UUID, PARTUUID, PTUUID, serial, WWN and label, USB device serials, the battery serial, SSH host keys and the user's own public keys as fingerprints and key material, GPG key fingerprints, the ZeroTier node id, and local user accounts. Generic account names such as `admin` or `root` are left out with a note, because they are words. A value that already has the shape of a pseudonym is written as a comment with the reason.

Options for scripts and for a look before merging:

| Option             | Effect                                                                                     |
|--------------------|--------------------------------------------------------------------------------------------|
| `--stdout`         | print the list, ask nothing                                                                |
| `-o FILE`          | write the list to a file, mode 0600                                                        |
| `--summary`        | print counts per kind only, never a value                                                  |
| `--merge TERMS`    | replace or append this machine's block in an existing term file, numbered backup first     |
| `--lan`            | add the other machines of the LAN: mDNS names via avahi, reverse DNS of the neighbour table |
| `--all-interfaces` | include container and VM interfaces (veth, docker, virbr, ...)                             |
| `--check TERMS`    | read an existing term file and list every term that is also a command or an ordinary word on this machine; collects nothing |

The block of a machine sits between two marker comments that carry its host name. Running the script again on the same machine replaces that block and leaves the blocks of other machines alone, so the term file of the proxy can hold every machine you work on: run the script on each machine with `-o`, copy the output to the proxy over `scp`, and merge it there. Copy it, do not paste it into a conversation. Then restart the proxy.

## Telling the model

The model does see that the values are pseudonyms: `.invalid` is a reserved top-level domain, `100.64.0.0/10` is the carrier-grade NAT range, a UUID with version nibble `f` exists in no RFC. Left to itself it comments on that, asks whether the host name is a placeholder, drops the `.invalid`, or "corrects" the value. Tell it once, in the project's `CLAUDE.md` or in the system prompt, and it stops:

```markdown
Host names like `h-<hex>`, domains like `d-<hex>.invalid`, addresses in `100.64.0.0/10`, MACs starting with `02:` and similar tokens in this session are pseudonyms that a proxy swaps back to the real values before I see the answer. Treat them as the real names: use them verbatim, never shorten or "fix" them, never drop the `.invalid`, never invent new ones in the same shape, and do not comment on their form. When a tool shows a directory or a file under a different name than the one you created it with, that is the proxy at work and not an error: use the name as the listing shows it, or work relative to a directory you already know.
```

## Checklist

The chapters above explain each piece. This is the order in which to do them, so that nothing is forgotten. Work through it once when you set up, and again whenever a customer, a machine or a project is added.

1. **The secret.** Create `pseudonym.secret`, mode 0600, owned by the proxy's user. It is not a password you need to remember, but whoever has it and your term list can compute the pseudonyms. Keep it out of backups you hand to others and out of every repository.
2. **The machines.** Run `machine-ids.py` with `sudo` on the proxy host and on every machine you work from, with `--lan` on the one that sees your network. Copy each output to the proxy with `scp`, merge it, restart. This covers host names, addresses, networks, MACs, disk and machine identifiers, keys and accounts, without you having to type any of them.
3. **The customers.** For every customer, add by hand what the script cannot know: the company name as a `person` term if it is a name (`{value: "Müller & Söhne", kind: person}`), the people you deal with as `person` terms with `ignore_case`, their domains as `domain`, their hosts as `host` and their networks as `cidr`, their account numbers as `iban`. Think of the places a name appears: e-mail signatures, ticket titles, hosts file entries, VPN configs, invoices.
4. **Yourself.** Your own name, your company, your domains, your login name if it is not a word, your e-mail addresses, your bank account. The script adds the local accounts and the host names; the rest is yours to add.
5. **The directories.** Switch on `path.enabled: true`. With the default `replace_unknown: true` every unknown directory is replaced, so a project directory named after a customer is covered even if you forgot the customer. Add directory names of your own that identify nobody to `path.preserve` when they get in the way. File names stay readable and are replaced only where a term matches inside them, see [Paths and file names](#paths-and-file-names).
6. **The words.** Read through `terms.txt` once and strike every term that is also an ordinary word: `backup`, `admin`, `data`, `test`, `nas`. Such a term breaks commands and configs for the model. Replace it by a regular expression that matches only the form you mean, or leave it to the directory layer. Run `machine-ids.py --check terms.txt` on the proxy host: it lists every term that is also a command or an ordinary word there. From now on, name every new machine, share, service and network with a token that is not a word, `nas01` rather than `nas`, see [What belongs in the list](#what-belongs-in-the-list-and-what-does-not).
7. **The model.** Put the note from [Telling the model](#telling-the-model) into the `CLAUDE.md` of every project that runs through the proxy, or into the system prompt of your client.
8. **The check.** Restart the proxy and look for the registration line with the number of terms. Then send one request that names a customer, a host and a path, and read the plugin's log line: it counts what it replaced by kind. For a closer look set `audit.path` for a few requests, read the mapping table, and switch it off again; the file is clear text. `machine-ids.py --summary` shows what the script found without printing a value.
9. **The other clients.** Only Claude Code's request format is restored on the way back. If anything else talks to the proxy, list its format under `skip_formats` or accept that its answers arrive with pseudonyms.
10. **Keeping it current.** A new customer, a new machine, a new disk, a new key: none of it is covered until it is in the list. Re-run the script after hardware changes, add the customer when the project starts, and restart the proxy after every change; terms are read at start only. Never paste `terms.txt` or the script's output into a conversation that runs through the proxy: what is not yet loaded is not yet replaced.

## Configuration

The plugin is configured in CLIProxyAPI's `config.yaml` under `plugins.configs.privacyfilter`. The host consumes `enabled` and `priority`; everything else is passed to the plugin. A complete example:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      mode: pseudonymize
      terms_file: terms.txt          # relative to the plugin directory
      terms:                         # a few more, inline
        - {value: example-gmbh.de, kind: domain}
        - {regex: "[a-z0-9-]+\\.home\\.lan", kind: host}
        - {value: markus, kind: person, ignore_case: true}
      path:
        enabled: false               # switch on once the stream restore is confirmed in your setup
      limits:
        mapping_ttl: 30m
      skip_models: []
      skip_formats: []
```

Fields read in both modes:

| Field           | Type   | Default | Description                                                                            |
|-----------------|--------|---------|----------------------------------------------------------------------------------------|
| `mode`          | string | `redact` | `redact` keeps the original one-way behaviour, `pseudonymize` enables reversible pseudonyms and the return path. Both modes run the original detection. |
| `gitleaks_toml` | string | `""`    | Custom gitleaks rule file path. Relative paths are resolved from the plugin directory. Empty uses `rules/gitleaks.toml` next to the library, or the rules embedded at build time. |
| `skip_models`   | array  | `[]`    | Models that bypass the plugin.                                                         |
| `skip_formats`  | array  | `[]`    | Source formats that bypass the plugin.                                                 |

Fields read in `pseudonymize` mode only. With `mode: redact` they are ignored and the plugin behaves byte for byte like the original:

| Field                    | Type   | Default        | Description                                                                                                                                                                                                                                                                                                               |
|--------------------------|--------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `salt_secret_path`       | string | `""`           | HMAC secret file. Empty uses `pseudonym.secret` next to the shared library; a relative path resolves from the plugin directory. The file must be readable by its owner alone (mode `0600` or tighter) and hold at least 32 bytes after trimming; the plugin refuses to start otherwise.                                     |
| `terms`                  | array  | `[]`           | Values to treat as confidential, each `{value: ..., kind: ...}` or `{regex: ..., kind: ...}` with an optional `ignore_case: true`. Takes precedence over every other detection layer.                                                                                                                                       |
| `terms_file`             | string | `""`           | The term list, see [The term list](#the-term-list). A relative path resolves from the plugin directory.                                                                                                                                                                                                                   |
| `patterns`               | object | all on but url | Structural detectors: `ipv4`, `ipv6`, `cidr`, `mac`, `email`, `iban`, `uuid`, `hexid`, `fingerprint`, `serial` default to `true`; `url` is off. `uuid` covers disk and machine UUIDs, `hexid` 32-digit and `0x`-prefixed 16-digit hex ids such as a WWN or machine-id, `fingerprint` SSH host-key fingerprints (`SHA256:…`), `serial` a serial number that follows a label such as `Serial Number:`, `ID_SERIAL_SHORT=`, `"serial":`, `iSerial`, `Seriennummer:` or `s/n:`. `ipv4`, `ipv6` and `email` also govern what the packyme layer reports, see [Switching detectors off](#switching-detectors-off). |
| `path`                   | object | disabled       | Segment-wise path pseudonymization, see [Paths and file names](#paths-and-file-names): `enabled` (default `false`), `replace_unknown` (default `true`, every directory outside the preserve list is replaced; `false` replaces only directories that are also terms), `filenames` (`terms`, the default, replaces a file name only where a term matches inside it; `all` replaces every file name outside the preserve list), `preserve` (names added to the built-in list of ordinary segments such as `home`, `usr`, `src`). |
| `packyme`                | object | enabled        | `enabled` toggles the packyme/privacy-filter layer with the gitleaks rules.                                                                                                                                                                                                                                                |
| `secrets`                | object | disabled       | `enabled` and `rules_toml` for the betterleaks layer. Only effective in a binary built with the `betterleaks` tag; enabling it in a plain build blocks every request with an error until it is switched off.                                                                                                                                                         |
| `restore.stream`         | bool   | `true`         | Restore pseudonyms in streamed responses. Non-streamed responses are always restored.                                                                                                                                                                                                                                     |
| `limits.max_body_bytes`  | int    | `33554432`     | Request bodies above this size are rejected.                                                                                                                                                                                                                                                                              |
| `limits.mapping_ttl`     | string | `30m`          | How long a conversation's mapping table is kept after its last use. Every request, response and stream chunk counts as use, so a running conversation never loses its table; a quiet one is dropped after this time.                                                                                                                                                                                                           |
| `on_error`               | string | `block`        | Forward-path behaviour when detection or parsing fails: `block` terminates the request, `passthrough` forwards it unfiltered. The return path always passes through on error.                                                                                                                                             |
| `audit`                  | object | off            | Local audit log: `path` (empty keeps it off; a relative path resolves from the plugin directory) and `max_bytes` (default 10 MiB, the file is rotated once to `.1`). Every mapping and every restore is written in clear text, see [Audit log](#audit-log).                                                             |

### Switching detectors off

Every structural detector has its own switch under `patterns`. Someone who works with public addresses all day and wants them left alone, or who needs the model to reason about real subnets, switches the network detectors off and keeps the rest:

```yaml
    privacyfilter:
      mode: pseudonymize
      patterns:
        ipv4: false
        ipv6: false
        cidr: false
        mac: false
```

The switches reach every layer. The original plugin's detection has no switches of its own and reports IP addresses and e-mail addresses next to its credential rules; with `ipv4`, `ipv6` or `email` set to `false` its findings of that kind are dropped as well, so a value of a switched-off kind is replaced by no layer. The term list is the exception: an entry with `kind: ipv4` or `kind: cidr` is replaced whatever the switches say, because you put it there. If `machine-ids.py` collected addresses you do not want replaced, strike them from the file.

Switching a layer off as a whole works the same way: `packyme.enabled: false` drops the original detection with its credential, phone and bank card rules, `path.enabled: false` leaves directories alone, `secrets.enabled` governs betterleaks. Every change needs a proxy restart, and a conversation that was started before the change should be started afresh, because its pseudonyms change with the settings.

## What it does and what it does not do

The plugin replaces values by pseudonyms of the same shape on the way out and puts the originals back on the way in. It restores what comes back **verbatim**: a pseudonym in running text, in a tool call, in a code block, streamed or not, with a suffix such as `.bak` or `-backup.tar.gz` glued to it, written in upper case, or, for a domain or an e-mail address, without the reserved `.invalid` that a model recognises as a marker and drops. It does not restore what the model **derives** from a pseudonym, because a derived value is in no mapping table:

- The model cannot compute with a pseudonym. "The next address after X" is computed on the pseudonym and comes back as the pseudonym's neighbour, not the original's. A configured network is the exception: addresses inside it keep their network, so "the same /24" holds, and arithmetic that lands on an address the request carried comes back.
- A partial pseudonym is not restored: the last four characters of a token, a prefix with a wildcard, a token cut in the middle. Nor is a pseudonym the model invented from the pattern of others, such as a name for a new file.
- The model does not know what a pseudonym stands for. It cannot tell an Intel NUC from a Raspberry Pi by the name `h-e2ba…`, and it will call a `100.64.0.0/10` address a carrier-grade NAT address. Every conclusion it draws from the value itself, rather than from the context, is drawn from the wrong value.
- A term of the list is replaced everywhere it appears as a word, see [What belongs in the list](#what-belongs-in-the-list-and-what-does-not).
- Loopback, unspecified, broadcast, multicast, link-local and the documentation addresses are never replaced.
- Thinking blocks and tool names are never touched in either direction.

The mapping lives in memory for the conversation and is derived, not stored: the same value gets the same pseudonym throughout one conversation, another conversation gets other pseudonyms. The table of a conversation grows with every request and is read on every response, so a pseudonym the model repeats from an earlier turn is restored even when the current request never carried the value. Nothing about the mapping leaves the process, and nothing is written to disk unless `audit.path` is set. A conversation that starts with the real value in the first message and continues with the pseudonym in later messages is fine; only the direction matters, and both directions are handled.

What the model writes first stays as it is. A directory the model creates with `mkdir hallo`, a file it names, an address or a mail address it puts into a test script: the provider has these in clear text already, because the model wrote them, and replacing them when a tool result echoes them would protect nothing and show the model its own directory as `d-…`, which is where it learns to invent names of that shape. So the forward path tells the model's turns from the user's side, in the order of the conversation with the system prompt first, and a value the model had before anybody else did is left standing for the rest of the conversation, in the model's own turns and in the tool results that repeat it. A value the user's side had first stays replaced when the model repeats it: the model only ever saw the pseudonym, and the clear text in its turn is the client's restore. Two things are replaced whoever wrote them: a value of your term list, inside a longer value as well, and an address inside a network your list names, because a model guesses a gateway address far more easily than a customer's directory. The conversation keeps a memory of what it has replaced and what it has left standing, as digests without the values, for 24 hours after the last request and so longer than the table with the originals: a pause and a compaction of the history, which repeats the model's names on the user's side, do not change the decision. The log line counts the values left standing under `kept`. A name the model only thought of in a thinking block is read by nobody and counts from the first tool call that carries it.

### Known limits

- Only the Anthropic Messages schema is handled on the return path; the plugin logs a warning and passes other formats through unchanged. Register it with `skip_formats` for those formats if you want no forward filtering either.
- Thinking blocks are never touched in either direction. Their signature is bound to the text, so a summary in the client's thinking view shows the pseudonyms, not the originals.
- A person pseudonym for a lone surname is rendered as a given name, so a surname used on its own may read as a second given name in the model's answer.
- A term matches at word boundaries, and the underscore is a boundary: `nuc_old` and `NUC_HOST` contain the host `nuc`. Letters and digits bind, so `nucleus` does not. A percent-escape in front is a boundary although it ends in a hex digit: `Kunden%20nuc` contains `nuc`, and a pseudonym behind `%20` or `%2F` is restored.
- Addresses outside every configured network are spread over the whole marker range without any relation to each other. Add your networks as `cidr` terms if the model has to reason about them.
- The original values are in memory in clear text while the request is alive, as they have to be for the restore.
- A pseudonym the model reshaped, shortened, wrote with a space or recalled with a slipped digit, is in no table and reaches the client as it is; the plugin restores only what it produced. The same holds for a name the model invents in the plugin's own shape, a `d-<12 hex>` for a directory it has not seen or an `f-<12 hex>.md` for a new file: the client gets the invented token, and a command built on it, a `sed` on that path or a `mkdir`, misses its target or creates a stray directory. Such tokens are counted per response in the ordinary log as `unknown` and `unknown_hits`, and with `audit.path` set they are listed as `unknown` lines, so a session that produces them is visible. The names the model gives itself are not the problem, they stay in clear, see [What it does and what it does not do](#what-it-does-and-what-it-does-not-do); what feeds the habit is a context full of `d-…`, so `path.preserve` for the harmless project directories the model has to name keeps the shape rare, and on the command line a relative path from a directory the client knows, `cd <project> && …`, beats an absolute one assembled from memory. A term that equals one of the built-in person names is fine: that entry is left out of the name list for this plugin, a warning with the count is logged, and the other person pseudonyms stay as they are.
- The model quotes what it sees, and it sees a plain word. A term value that carries a quote, a backslash, a shell metacharacter (`$`, `;`, `&`, `|`, `<`, `>`, backtick), a `#`, a `%`, a `/` or a control character would be restored into a command line, a configuration line or a patch that was written for the pseudonym, and change what that line does. The plugin refuses such a value: it registers, but answers every request with an error that names the line of the term file and the class of character it found, never the value, until the line is fixed and the proxy restarted. Only those characters are refused: letters of every script, Chinese, Cyrillic, Turkish or accented Latin, digits, spaces, dots, dashes and brackets are fine, a network in CIDR form, a `secret` and a `fingerprint` term keep their slash, because key material, tokens and SHA256 fingerprints are base64 and the slash is part of that alphabet, and a regular expression is not judged. If such a value is what you mean, write it as a regular expression that matches it without the character.
- With `replace_unknown`, the path layer catches an unknown directory in a path it recognises by its shape: an anchored path, a bare one whose last segment has a file extension, a trailing slash or a hidden name or whose first segment starts with a dot, and a flattened working directory of the form `-home-<user>-<project>`. A bare directory path without either, `kunde-x/sub`, the `a/` prefix of a diff header, a path inside a `file://` or `http://` address, a Windows path and a flattened directory directly under its root, `-tmp-kunde-x`, leave an unknown directory in clear text; a directory on the term list is covered in every form. See [Paths and file names](#paths-and-file-names).
- Only the encoded space, `%20`, is divided out of a path segment. A directory with a letter outside ASCII in its name goes out as one pseudonym for the whole encoded word, `%C3%9Cbersicht` for `Übersicht` as a Markdown link writes it, and the model cannot see the letter in it. The link quoted as it was comes back; a path the model decodes from the pseudonym does not, because the decoded word is in no table. The file name stays readable, so the file is still found by its name.
- A real space inside a directory name is read where the text says the name goes on: inside quotes, behind a backslash, or in a bare path when the word behind the space carries a slash. A bare name of three words as the whole of a tool argument, `/home/alice/Kunden und Akten/Berichte`, keeps its middle word in the clear, because `und` carries no slash and nothing else says the name goes on; quoted or escaped it is read whole. The reverse is the price: a slashed word of prose right behind a bare path, `/home/alice/Kunden TCP/IP`, is read as the rest of the path, goes out as pseudonyms and comes back as it was. A path behind an option inside the quotes, `"--out=/home/alice/Kunden Akten"`, is quoted for the shell but not for the plugin, which finds the quote in front of the option, not in front of the slash, and reads the path as a bare one.
- A term with `ß` and `ignore_case` does not match the spelling with `SS` in an all-caps line; the two are different words to the matcher. Add the `SS` spelling as a second term if such lines pass through.
- `path.enabled` defaults to `false`. Switch it on after you have seen the stream restore work in your setup: a half-restored path in a tool call does more harm than a leaked one.
- The betterleaks layer exists only in a build with the `betterleaks` tag, which roughly triples the size of the shared library.
- Output that spells a value out in another form, `od -c`, `xxd`, `base64`, passes the term list unmatched: the matcher looks for the value as written. This stays as it is on purpose. A model that inspects a name byte by byte is making sure a replacement went right, its last resort when a listing and a command disagree, and taking that away would only send it looking for another way; what leaves is one value, once, in the session that needed it.
- A serial number is only detected behind a label. A bare serial in running text, a git commit hash, an image digest or a DNS zone serial are left alone on purpose, so a serial printed without any label reaches the model unchanged. Add it to the term list if it matters.
- With `path.filenames: all`, the model sees every file name as `f-<12 hex><ext>`. When it creates a new file it tends to pick a name of the same shape, which is in no mapping table and reaches the client as is. Rename the file; the content is restored normally. The default `terms` leaves file names readable and avoids this.

## Building from source

Requirements: Go 1.26 or newer, CGO enabled, `make`.

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
```

The default build writes the shared library to the repository root, `privacyfilter.so` on Linux, `privacyfilter.dylib` on macOS, `privacyfilter.dll` on Windows. Build for a specific platform with `GOOS` and `GOARCH`, and use `BUILD_DIR` to place the output elsewhere; then `machine-ids.py` is copied next to it:

```bash
GOOS=linux GOARCH=amd64 BUILD_DIR=dist make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

`build/build.sh` builds the same library for `linux/amd64` inside a `golang:1.26-bookworm` container with Podman, so the result loads in a `debian:bookworm-slim` image regardless of the glibc on the build machine. It honours `BUILD_TAGS` and `VERSION` and writes both files to `dist/`:

```bash
build/build.sh 0.4.6
```

Include the betterleaks credential scanner (see [betterleaks](#betterleaks)); the plain build does not link it:

```bash
BUILD_TAGS=betterleaks make build
```

Plugin metadata: name `privacyfilter`, capability `RequestInterceptor`, in `pseudonymize` mode also `ResponseInterceptor`, `StreamChunkInterceptor` and `RequestCompletion`, schema version 3, author `rheodev`.

## How it works inside

### Pseudonyms

Pseudonyms are `HMAC-SHA256(secret || salt, kind || value || attempt)` rendered per kind. The salt is derived once per conversation from the `X-Claude-Code-Session-Id` header, then from `metadata.user_id`, and finally from a hash of the first message, so a follow-up request produces the same pseudonyms as the previous one and the model's context stays coherent. Nothing is random and nothing is stored on disk: the mapping table lives in memory for the conversation, every request of it adds its values and reads the whole table on the way back, and the table is dropped once the conversation has been quiet for `mapping_ttl`.

A network given as a `cidr` term maps to a network of the same prefix length inside the marker range. Every address inside it is rendered into that network, only the host bits come from the address's own digest, and a network inside another configured network lies inside that one's pseudonym. Host, gateway and neighbour stay related for the model. Addresses outside every configured network are spread over the whole range.

Pseudonym shapes are chosen so that the model can tell them from real values and still compute with them: `100.64.0.0/10` is the carrier-grade NAT range, `02:` MACs are locally administered, `.invalid` is reserved by RFC 2606, the UUID version nibble `f` exists in no RFC 9562 version, the IBAN bank code starts with four zeros no issuer hands out, hex ids start with `5046`, serials with `PF-`, secrets with `PF_`. The plugin itself does not judge by shape: what it excludes from a second replacement is what the conversation's table holds, so a real Tailscale address or Docker MAC is replaced, and a table never hands out a pseudonym that equals one of its originals or a term of your list. Person pseudonyms come from a fixed list of invented names; a term that equals one of them drops that entry from the list.

### Forward and return path

The forward path walks every string of the JSON body except those on a deny list (identifiers, tool names, model names, thinking blocks and their signatures), and below the `input` of a tool call also every object key, because there the keys belong to the tool and may carry a file name or a host. Both directions use the same byte scanner: only the strings that change are re-encoded, every other byte, key order and escape sequence included, survives as it came, a key that appears twice in one object is seen both times, and the first `type` key of a block decides for both directions. The forward path runs the detection layers in fixed order: the term list, the structural patterns, the path layer, the original plugin's detection (packyme with the Gitleaks rules), betterleaks. Overlapping hits are merged: an earlier layer wins over a later one, and inside a layer the longest wins. One exception: a hit of a later layer that contains a hit of an earlier one whole is replaced as a whole and with its own kind, so an e-mail address that carries the company domain is replaced as `email` instead of leaving the local part in clear text, a directory named after a customer and a case number is replaced as a segment instead of leaving the case number, and a short term inside an address does not break the address apart. A hit of the original detection is pseudonymized by kind: an e-mail address as `email`, an IP address as `ipv4` or `ipv6`, everything else, secrets, phone and ID numbers, bank cards, as an opaque `secret` token that is restored like any other pseudonym. The return path scans the response body in one pass over the same deny list and swaps pseudonyms back only at token boundaries, so a pseudonym embedded in a longer identifier is left alone.

Streamed responses are restored chunk by chunk. Because a pseudonym may be split across two deltas, the plugin holds back the tail of the text that could still grow into a pseudonym, and also a pseudonym that is complete but ends with the text, because the next delta may begin with a letter that glues it into a longer word; a pseudonym followed by a delimiter is restored right away. The held tail is flushed as a synthetic delta before the block ends, before the message ends and before an error event, so an `overloaded_error` in the middle of an answer loses no text. Pseudonyms that stand directly against each other are restored as a run. Splitting at every byte position is covered by the tests, including a pseudonym whose last byte could begin another one.

### Audit log

`audit.path` switches on a per-request log next to the shared library (or wherever the path points). It is meant for checking what the plugin did with a request, not for permanent operation: every line is clear text, so the file holds exactly the values the plugin exists to keep off the wire. The file is created with mode `0600`, the plugin logs a warning at start-up while the option is set, and the file is rotated once to `.1` at `max_bytes`. Lines are tab-separated, one record per line:

```text
<time>  request   <request id>  format=claude  session=header  body=<bytes>  out=<bytes>  distinct=<n>  table=<n>  kept=<n>
<time>  map       <request id>  <kind>  <original>  <pseudonym>
<time>  restored  <request id>  <pseudonym>  <original>  <count>
<time>  unknown   <request id>  <token>  <count>
<time>  complete  <request id>  outcome=succeeded  stream=true  restored_distinct=<n>  restored_total=<n>
```

`map` lines list the whole mapping table of the request sorted by kind and value, `restored` lines the pseudonyms that actually came back in the response with how often each was swapped. A value that was detected but never returned appears in `map` only. `unknown` lines list the tokens in the plugin's own shape that the response carried without a table row behind them, with how often each appeared: a name the model invented in the shape, a pseudonym it recalled with a slipped digit, or one of another conversation quoted from a file; set against the `map` lines of the session they tell these apart. For a whole response the lines are written when it is restored, for a stream at completion, in front of its `complete` line, and a token that a fragment boundary cuts in two is not counted there. The ordinary log carries the same as counts, in the fields `unknown` and `unknown_hits` of the line that reports a restored response or stream. Values that were redacted rather than pseudonymized do not appear in this log; they stay in the ordinary plugin log as before.

### Redact mode

`mode: redact`, the default, is the original plugin: one-way, nothing comes back. It runs for both before-auth and after-auth request interception hooks, then parses the JSON body:

1. Checks `skip_models` and `skip_formats`.
2. Parses the request body as JSON.
3. Handles `messages` first, then falls back to `input`.
4. Edits text fields only.
5. Replaces detected sensitive data with placeholders.
6. Leaves the request unchanged if parsing fails or no supported field is found.

Supported request shapes include OpenAI-style `messages` and `input` bodies:

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

Detection in both modes uses [packyme/privacy-filter](https://github.com/packyme/privacy-filter) with Gitleaks rules for secrets, connection strings, certificates and similar data. The rules are embedded at build time from `rules/gitleaks.toml`; at runtime the plugin takes `gitleaks_toml` from the configuration if set, else a `rules/gitleaks.toml` sidecar next to the shared library, else the embedded rules. Update the embedded rules with `make update-rules` and rebuild.

### betterleaks

[betterleaks](https://github.com/betterleaks/betterleaks) is a gitleaks fork with a larger rule set. It is compiled in only with `BUILD_TAGS=betterleaks` and switched on with `secrets.enabled: true`. Its credential validation, which would send found credentials to their providers over HTTP, is disabled in every build and cannot be enabled by configuration. `secrets.rules_toml` points to a custom rules file; empty uses the embedded rules. A rules file that does not compile fails registration instead of taking the proxy down.

## Development

```bash
go test ./...
go test -tags betterleaks ./...

# After a change to the renderers or the example values: regenerate the README section "At a glance"
README_EXAMPLES_OUT=/tmp/examples.tsv go test -run TestRoundTrip_ReadmeExamples .
tools/readme-examples.py /tmp/examples.tsv en   # paste over the section in README.md
tools/readme-examples.py /tmp/examples.tsv zh   # and in README.zh-CN.md
make build
make clean
```

Main files:

```text
main.go                 Plugin metadata, registration and build entry
abi.go                  CLIProxyAPI plugin ABI adapter
interceptor.go          Request interception: redact and pseudonymize forward paths
response.go             Return path for non-streamed responses
stream.go               Return path for streamed responses, holdback and flush
lifecycle.go            Request completion, releases the request from its table
config.go               YAML configuration parsing
termsfile.go            Term list file format
detect/                 Detection layers: terms, patterns, paths, packyme, betterleaks
pseudo/                 HMAC pseudonyms, renderers per kind, salt and secret handling
mapping/                Per-conversation mapping tables, the store and the restorer
payload/                JSON walking, deny list, Anthropic SSE events
tools/machine-ids.py    Collects this machine's identifiers as a term file; copied to dist/ by the build
tools/readme-examples.py Renders the section "At a glance" from the output of TestRoundTrip_ReadmeExamples
cmd/termsgen/           Older generator: a term file from ssh config and hosts
internal/leaktest/      End-to-end leak test: nothing confidential survives the forward path
rules/gitleaks.toml     Built-in detection rules
```

Dependency note:

```text
privacyfilter => github.com/packyme/privacy-filter
```

## Credits

- Core filtering logic: [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- AI learners and builders can join the Linux.do community: [linux.do](https://linux.do/)
