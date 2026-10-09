#!/usr/bin/env python3
"""Collect the identifiers of this machine as a term list for the privacyfilter plugin.

Writes one line per value in the term-file grammar the plugin reads
(`<value> <kind> [ignore_case]`, `#` starts a comment), so the output can be
appended to terms.txt as it is. Values that the plugin could not accept as a
term, because they already have the shape of a pseudonym, are written as
comments and say why.

Sources, all local, nothing leaves the machine:
  host name, mDNS name, /etc/hosts, machine-id, boot id, DMI (product uuid
  and the serials of board, chassis and product, root only), network
  interfaces (MAC, permanent MAC, IPv4, IPv6, networks, gateways), DNS
  servers, Wi-Fi (SSID, BSSID), Bluetooth adapters, block devices (UUID,
  PARTUUID, PTUUID, serial, WWN, label), USB device serials, battery serial,
  SSH host keys and the user's own public keys (fingerprints and key
  material), GPG key fingerprints, ZeroTier node id, local user accounts.

Usage:
  machine-ids.py                 on a terminal: asks what to do, yes or no
                                 per question, then runs; piped: list on stdout
  machine-ids.py --stdout        term list on stdout, no questions
  machine-ids.py -o ids.txt      term list into a file (mode 0600)
  machine-ids.py --summary       counts per kind only, no values
  machine-ids.py --merge terms.txt
                                 replace or append this machine's block in an
                                 existing term file, backup first; restart the
                                 proxy afterwards, terms load at start only
  sudo machine-ids.py ...        adds the DMI serials and product uuid
  machine-ids.py --lan           also the other machines of the LAN (mDNS
                                 names, reverse DNS of the neighbour table)
  machine-ids.py --check terms.txt
                                 read an existing term file and list every
                                 term that is also a command or an ordinary
                                 word on this machine; collects nothing

Only the standard library is used. External commands are optional and
skipped when missing: ip, lsblk, ssh-keygen, nmcli, gpg, zerotier-cli,
ethtool, avahi-browse, avahi-resolve-address, resolvectl.
"""

import argparse
import glob
import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor

# Kinds the plugin accepts in a term file, see detect.Kind in the plugin.
KINDS = {"host", "domain", "ipv4", "ipv6", "cidr", "mac", "email", "person",
         "iban", "uuid", "hexid", "fingerprint", "serial", "secret"}

# DMI placeholders vendors ship instead of a serial.
DMI_PLACEHOLDERS = {"", "none", "default string", "to be filled by o.e.m.",
                    "system serial number", "not specified", "not applicable",
                    "0", "00000000", "123456789", "n/a", "unknown",
                    "chassis serial number", "base board serial number"}

# Disk labels that name a role, not a machine.
GENERIC_LABELS = {"efi", "esp", "boot", "root", "swap", "home", "system",
                  "recovery", "winre", "reserved", "data", "var", "tmp", "usr"}

# Shell builtins and keywords, which shutil.which does not see, plus a few
# words every shell session contains. A host of this name turns the word into
# a pseudonym wherever it appears.
SHELL_WORDS = {"cd", "time", "test", "echo", "set", "read", "type", "exit", "kill", "wait", "jobs",
               "alias", "export", "source", "eval", "exec", "trap", "shift", "true", "false", "pwd",
               "let", "local", "return", "break", "continue", "hash", "help", "history", "dirs",
               "pushd", "popd", "ulimit", "umask", "unset", "printf", "command", "builtin", "declare",
               "readonly", "select", "times", "caller", "shopt", "disown", "bind", "logout", "fg", "bg",
               "if", "then", "else", "fi", "for", "do", "done", "while", "until", "case", "esac", "in",
               "function", "sudo", "root", "home", "tmp", "log", "logs", "bin", "lib", "etc", "opt",
               "var", "usr", "dev", "proc", "sys", "run", "mnt", "media", "boot", "config", "data",
               "main", "master", "dev", "prod", "stage", "live", "new", "old", "temp", "cache"}

# Role words people name machines after. Each is a word in prose and in
# configs, so a host of this name pollutes every text that mentions the role.
GENERIC_HOSTS = {"nas", "san", "server", "client", "host", "node", "box", "pc", "laptop", "desktop",
                 "notebook", "phone", "tablet", "printer", "scanner", "router", "switch", "gateway",
                 "firewall", "proxy", "storage", "cloud", "mail", "web", "www", "db", "database",
                 "office", "lab", "work", "workstation", "vm", "container", "camera", "tv", "media",
                 "plex", "kodi", "pihole", "dns", "dhcp", "vpn", "wifi", "ap", "iot", "hub", "bridge",
                 "monitor", "display", "kiosk", "gaming", "game", "study", "kitchen", "garage"}

# Account names that are ordinary words; a person term for them would replace
# the word in every prompt.
GENERIC_ACCOUNTS = {"admin", "administrator", "user", "ubuntu", "debian", "fedora", "pi",
                    "guest", "test", "deploy", "docker", "git", "backup", "service"}

NIL_UUID = "00000000-0000-0000-0000-000000000000"


class Terms:
    """Ordered, de-duplicated collection of (value, kind) with section comments."""

    def __init__(self):
        self.lines = []          # output lines in order
        self.seen = set()        # (value, kind)
        self.counts = Counter()  # kind -> accepted
        self.skipped = Counter() # reason -> count
        self.notes = []

    def section(self, title):
        self.lines.append("")
        self.lines.append("# " + title)

    def add(self, value, kind, ignore_case=False, note=None):
        if kind not in KINDS:
            raise ValueError(kind)
        value = (value or "").strip()
        if not value or any(c.isspace() for c in value) or value.startswith(("{", "#")):
            return
        key = (value, kind)
        if key in self.seen:
            return
        self.seen.add(key)
        why = looks_like_pseudonym(value, kind)
        if why:
            self.lines.append("# skipped (%s): %s %s" % (why, value, kind))
            self.skipped[why] += 1
            return
        line = value + " " + kind + (" ignore_case" if ignore_case else "")
        if note:
            line += "   # " + note
        self.lines.append(line)
        self.counts[kind] += 1

    def add_host_regex(self, name):
        """One regex term for a host name: the bare name and any dotted suffix.

        Written in the YAML flow form of the term file. No ^ or $: the plugin
        scans whole message strings, so an anchored expression only hits a
        string that consists of the name alone. \\b keeps "nuc" out of
        "nucleus"; (?i) replaces ignore_case, which literals only have.
        """
        name = (name or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name) or name in ("localhost",):
            return
        if looks_like_pseudonym(name, "host"):
            self.lines.append("# skipped (pseudonym shape): %s host" % name)
            self.skipped["pseudonym shape"] += 1
            return
        key = ("regex:" + name, "host")
        if key in self.seen:
            return
        self.seen.add(key)
        pattern = r"(?i)\b" + re.escape(name).replace("\\-", "-") + r"(?:\.[a-z0-9-]+)*\b"
        self.lines.append('{regex: "%s", kind: host}' % pattern.replace("\\", "\\\\"))
        self.counts["host"] += 1
        if is_word(name):
            # The term stays, the machine is real; but every occurrence of
            # the word will be replaced, in commands and prose alike.
            self.note("host %s is also a command or an ordinary word: every '%s' in any text will be "
                      "replaced; rename the machine (nas01, not nas) or accept the noise" % (name, name))

    def note(self, text):
        self.lines.append("# " + text)
        self.notes.append(text)


def looks_like_pseudonym(value, kind):
    """The plugin refuses or cannot restore terms that share a pseudonym shape."""
    v = value.lower()
    if kind == "ipv4":
        try:
            if ipaddress.ip_address(value) in ipaddress.ip_network("100.64.0.0/10"):
                return "100.64.0.0/10 is reserved for ipv4 pseudonyms"
        except ValueError:
            return None
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=False)
            if net.version == 4 and net.overlaps(ipaddress.ip_network("100.64.0.0/10")):
                return "100.64.0.0/10 is reserved for ipv4 pseudonyms"
        except ValueError:
            return None
    if kind == "ipv6":
        try:
            if ipaddress.ip_address(value) in ipaddress.ip_network("fdff:5046:5346::/48"):
                return "fdff:5046:5346::/48 is reserved for ipv6 pseudonyms"
        except ValueError:
            return None
    if kind == "mac" and v.startswith("02:"):
        return "02:… is the mac pseudonym shape"
    if kind in ("host", "domain") and re.fullmatch(r"[hdf]-[0-9a-f]{12}(\.invalid)?", v):
        return "pseudonym shape"
    if kind == "uuid" and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-f[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}", v):
        return "uuid version f is the pseudonym shape"
    if kind == "hexid" and (v.startswith("5046") or v.startswith("0x5046")):
        return "5046… is the hexid pseudonym shape"
    if kind == "fingerprint" and value.startswith("SHA256:PF"):
        return "SHA256:PF… is the fingerprint pseudonym shape"
    if kind == "serial" and re.fullmatch(r"PF-[A-Z0-9]{12}", value):
        return "PF-… is the serial pseudonym shape"
    if kind == "secret" and re.fullmatch(r"PF_[0-9a-f]{12}", value):
        return "PF_… is the secret pseudonym shape"
    return None


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return None


def progress(text):
    """One line on stderr per step, so a run of several seconds is visibly
    doing something; stdout stays the term list."""
    print("… " + text, file=sys.stderr, flush=True)


def run(*cmd):
    """stdout of a command, or None when it is missing or fails."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode == 0 else None


def run_json(*cmd):
    out = run(*cmd)
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def plausible_serial(s):
    s = (s or "").strip()
    if len(s) < 4 or s.lower() in DMI_PLACEHOLDERS or set(s) <= {"0"}:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{2,62}[A-Za-z0-9]", s))


# Interfaces of containers and VMs: their MACs and addresses change with every
# container start and would fill the list with stale entries.
VIRTUAL_PREFIXES = ("veth", "br-", "docker", "virbr", "vnet", "cni", "flannel", "lxc", "lxd", "tap", "podman")
ALL_INTERFACES = False
LAN = False


def virtual_interface(name):
    return not ALL_INTERFACES and name.startswith(VIRTUAL_PREFIXES)


# ---------------------------------------------------------------- collectors

def collect_host(t):
    t.section("host names; the regex covers the bare name and every dotted suffix (.local, .lan, .fritz.box)")
    name = socket.gethostname()
    if name:
        t.add_host_regex(name.split(".")[0])
    try:
        fqdn = socket.getfqdn()
        if fqdn and fqdn != name and "." in fqdn:
            t.add(fqdn.split(".", 1)[1], "domain", ignore_case=True)
    except OSError:
        pass
    for path in ("/etc/hostname", "/proc/sys/kernel/hostname"):
        v = read(path)
        if v:
            t.add_host_regex(v.split(".")[0])
    pretty = read("/etc/machine-info")
    if pretty:
        for line in pretty.splitlines():
            if line.startswith("PRETTY_HOSTNAME="):
                v = line.split("=", 1)[1].strip().strip('"')
                if v and " " not in v:
                    t.add_host_regex(v)

    hosts = read("/etc/hosts") or ""
    for line in hosts.splitlines():
        line = line.split("#", 1)[0].split()
        if len(line) < 2:
            continue
        addr, names = line[0], line[1:]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_multicast or addr.startswith("ff0"):
            continue
        t.add(addr, "ipv6" if ip.version == 6 else "ipv4")
        for n in names:
            if n.lower() not in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
                t.add_host_regex(n.split(".")[0])


def collect_ids(t):
    t.section("machine-id, boot id, DMI")
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        v = read(path)
        if v and re.fullmatch(r"[0-9a-f]{32}", v):
            t.add(v, "hexid", note=path)
    v = read("/proc/sys/kernel/random/boot_id")
    if v and v != NIL_UUID:
        t.add(v, "uuid", note="boot id, changes at every boot")
    dmi = "/sys/class/dmi/id/"
    unreadable = []
    for name, kind in (("product_uuid", "uuid"), ("product_serial", "serial"),
                       ("board_serial", "serial"), ("chassis_serial", "serial")):
        path = dmi + name
        if not os.path.exists(path):
            continue
        v = read(path)
        if v is None:
            unreadable.append(name)
            continue
        if kind == "uuid":
            if v.lower() != NIL_UUID and re.fullmatch(r"[0-9A-Fa-f-]{36}", v):
                t.add(v, "uuid", note="DMI " + name)
        elif plausible_serial(v):
            t.add(v, "serial", note="DMI " + name)
    if unreadable:
        t.note("not readable without root: " + ", ".join(unreadable) + " (run with sudo)")


def collect_network(t):
    t.section("network interfaces")
    links = run_json("ip", "-j", "link") or []
    addrs = run_json("ip", "-j", "addr") or []
    if not links:
        # fall back to sysfs for the MACs
        for path in glob.glob("/sys/class/net/*/address"):
            ifname = path.split("/")[-2]
            if ifname == "lo" or virtual_interface(ifname):
                continue
            v = read(path)
            if v and v != "00:00:00:00:00:00":
                t.add(v, "mac", note=ifname)
    for link in links:
        ifname = link.get("ifname", "")
        if ifname == "lo" or virtual_interface(ifname):
            continue
        mac = link.get("address", "")
        if mac and mac != "00:00:00:00:00:00" and link.get("link_type") == "ether":
            t.add(mac, "mac", note=ifname)
        perm = run("ethtool", "-P", ifname) or ""
        m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", perm.lower())
        if m and m.group(1) != "00:00:00:00:00:00" and m.group(1) != mac:
            t.add(m.group(1), "mac", note=ifname + " permanent address")
    for dev in addrs:
        ifname = dev.get("ifname", "")
        if ifname == "lo" or virtual_interface(ifname):
            continue
        for a in dev.get("addr_info", []):
            local = a.get("local", "")
            if not local:
                continue
            try:
                ip = ipaddress.ip_address(local)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_multicast:
                continue
            kind = "ipv6" if ip.version == 6 else "ipv4"
            scope = "link-local " if ip.is_link_local else ""
            t.add(local, kind, note=scope + ifname)
            plen = a.get("prefixlen")
            if plen is not None and not ip.is_link_local:
                net = ipaddress.ip_network("%s/%s" % (local, plen), strict=False)
                if kind == "ipv4" and net.prefixlen < 32 or kind == "ipv6" and net.prefixlen < 128:
                    t.add(str(net), "cidr", note=ifname)
    routes = run_json("ip", "-j", "route") or []
    routes += run_json("ip", "-j", "-6", "route") or []
    for r in routes:
        gw = r.get("gateway")
        if gw:
            try:
                ip = ipaddress.ip_address(gw)
            except ValueError:
                continue
            if not ip.is_link_local:
                t.add(gw, "ipv6" if ip.version == 6 else "ipv4", note="gateway " + r.get("dev", ""))

    t.section("DNS")
    resolv = read("/etc/resolv.conf") or ""
    for line in resolv.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                ip = ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if not ip.is_loopback and not ip.is_global:
                t.add(parts[1], "ipv6" if ip.version == 6 else "ipv4", note="nameserver")
        if len(parts) >= 2 and parts[0] in ("search", "domain"):
            for d in parts[1:]:
                t.add(d, "domain", ignore_case=True, note="search domain")
    resolvectl = run("resolvectl", "dns") or ""
    for tok in resolvectl.split():
        try:
            ip = ipaddress.ip_address(tok.split("#")[0])
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_global:
            t.add(str(ip), "ipv6" if ip.version == 6 else "ipv4", note="nameserver")

    t.section("Wi-Fi and Bluetooth")
    # --rescan no: the cached list is enough for the active connection and
    # a rescan would block for seconds.
    wifi = run("nmcli", "-t", "-f", "ACTIVE,SSID,BSSID", "dev", "wifi", "list", "--rescan", "no") or ""
    for line in wifi.splitlines():
        # nmcli escapes ":" in the BSSID as "\:"
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 3 and parts[0] == "yes":
            ssid = parts[1].replace("\\:", ":")
            bssid = ":".join(parts[2:]).replace("\\:", ":").lower()
            if ssid and " " not in ssid:
                t.add(ssid, "secret", note="SSID")
            if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", bssid):
                t.add(bssid, "mac", note="BSSID of the access point")
    for path in glob.glob("/sys/class/bluetooth/hci*/address"):
        v = read(path)
        if v and v != "00:00:00:00:00:00":
            t.add(v.lower(), "mac", note="bluetooth " + path.split("/")[-2])

    zt = run("zerotier-cli", "info") or ""
    m = re.search(r"\b([0-9a-f]{10})\b", zt)
    if m:
        t.section("ZeroTier")
        t.add(m.group(1), "secret", note="ZeroTier node id")


def collect_block(t):
    t.section("block devices")
    cols = "NAME,TYPE,UUID,PARTUUID,PTUUID,SERIAL,WWN,LABEL,PARTLABEL,MODEL"
    data = run_json("lsblk", "-J", "-o", cols)
    devs = []

    def walk(items):
        for d in items or []:
            devs.append(d)
            walk(d.get("children"))
    walk((data or {}).get("blockdevices"))
    for d in devs:
        name = d.get("name", "")
        for col, kind in (("uuid", "uuid"), ("partuuid", "uuid"), ("ptuuid", "uuid")):
            v = d.get(col)
            if not v:
                continue
            if re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", v):
                t.add(v, "uuid", note="%s %s" % (name, col))
            elif re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{2}", v):
                t.add(v, "secret", note="%s %s (MBR disk id)" % (name, col))
            elif re.fullmatch(r"[0-9A-Fa-f-]{6,}", v):
                t.add(v, "secret", note="%s %s" % (name, col))
        v = d.get("serial")
        if plausible_serial(v):
            t.add(v.strip(), "serial", note="%s serial" % name)
        v = d.get("wwn")
        if v:
            v = v.strip()
            if re.fullmatch(r"0x[0-9A-Fa-f]{16}", v):
                t.add(v, "hexid", note="%s WWN" % name)
            elif re.fullmatch(r"(eui|naa|nvme)\.[0-9A-Fa-f-]{8,}", v, re.I):
                t.add(v, "secret", note="%s WWN" % name)
        for col in ("label", "partlabel"):
            v = d.get(col)
            if v and " " not in v and v.lower() not in GENERIC_LABELS and len(v) >= 3:
                t.add(v, "secret", note="%s %s" % (name, col))
    if not devs:
        t.note("lsblk not available; /dev/disk/by-* used instead")
        for path in glob.glob("/dev/disk/by-uuid/*"):
            t.add(os.path.basename(path), "uuid")
        for path in glob.glob("/dev/disk/by-partuuid/*"):
            t.add(os.path.basename(path), "uuid")

    t.section("USB devices and battery")
    for path in sorted(glob.glob("/sys/bus/usb/devices/*/serial")):
        v = read(path)
        if plausible_serial(v):
            prod = read(os.path.dirname(path) + "/product") or "usb"
            t.add(v, "serial", note=prod.replace(" ", "_"))
    for path in glob.glob("/sys/class/power_supply/*/serial_number"):
        v = read(path)
        if plausible_serial(v):
            t.add(v, "serial", note="battery " + path.split("/")[-2])


def collect_lan(t):
    """Other machines of the LAN: the mDNS service announcements from
    avahi-browse, then every neighbour of the ARP and NDP tables resolved
    first over mDNS (avahi-resolve-address, which yields the .local name of
    a machine that announces no service) and then over the local DNS.
    Opt-in, because it takes a few seconds and lists machines that are not
    this one."""
    if not LAN:
        return
    t.section("LAN neighbours (mDNS and reverse DNS); the regex covers the bare name and every suffix")
    progress("LAN: mDNS service announcements (avahi-browse, about a second)")
    for line in (run("avahi-browse", "-atrp") or "").splitlines():
        f = line.split(";")
        if len(f) >= 8 and f[0] == "=":
            host = f[6].replace("\\.", ".")
            if host.endswith(".local"):
                host = host[:-6]
            t.add_host_regex(host.split(".")[0])
            addr = f[7]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if not ip.is_link_local and not ip.is_loopback:
                t.add(addr, "ipv6" if ip.version == 6 else "ipv4", note="mDNS " + host.split(".")[0])
    neighbours = []
    for n in run_json("ip", "-j", "neigh") or []:
        addr = n.get("dst", "")
        state = (n.get("state") or [""])[0]
        if state in ("FAILED", "INCOMPLETE") or not addr:
            continue
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_link_local or ip.is_multicast:
            continue
        neighbours.append((addr, ip, (n.get("lladdr") or "").lower()))
    progress("LAN: %d neighbours in the ARP/NDP table, resolving over mDNS in parallel (about two seconds)" % len(neighbours))
    # One avahi-resolve-address for all addresses: it answers each on its
    # own line and waits once for the silent ones, instead of once per host.
    names = {}
    # One query per address, all in parallel, each capped: avahi waits five
    # seconds for a silent host and a batched call prints nothing when it
    # is cut short, so the whole step takes as long as one silent host.
    names = {}

    def mdns(addr):
        try:
            p = subprocess.run(["avahi-resolve-address", addr], capture_output=True, text=True, timeout=2.5)
        except (OSError, subprocess.SubprocessError):
            return addr, ""
        parts = p.stdout.split()
        if len(parts) >= 2 and parts[-1].endswith(".local"):
            return addr, parts[-1]
        return addr, ""
    if neighbours and shutil.which("avahi-resolve-address"):
        with ThreadPoolExecutor(max_workers=16) as pool:
            for addr, name in pool.map(mdns, [a for a, _, _ in neighbours]):
                if name:
                    names[addr] = name
    unresolved = [a for a, _, _ in neighbours if a not in names]
    if unresolved:
        progress("LAN: %d of them without mDNS name, asking the DNS in parallel (two seconds at most)" % len(unresolved))

        # getent in a subprocess, because a reverse lookup through the C
        # library cannot be given a timeout and a silent DNS costs seconds.
        def reverse(addr):
            try:
                p = subprocess.run(["getent", "hosts", addr], capture_output=True, text=True, timeout=2)
            except (OSError, subprocess.SubprocessError):
                return addr, ""
            parts = p.stdout.split()
            return addr, parts[1] if len(parts) >= 2 else ""
        with ThreadPoolExecutor(max_workers=16) as pool:
            for addr, name in pool.map(reverse, unresolved):
                if name:
                    names[addr] = name
    for addr, ip, mac in neighbours:
        name = names.get(addr, "")
        label = name.split(".")[0] if name else "neighbour"
        t.add(addr, "ipv6" if ip.version == 6 else "ipv4", note=label)
        if mac and mac != "00:00:00:00:00:00":
            t.add(mac, "mac", note=label)
        if name and name.split(".")[0].lower() not in ("localhost",):
            t.add_host_regex(name.split(".")[0])
            suffix = name.split(".", 1)[1] if "." in name else ""
            if suffix and suffix.lower() not in ("local", "localdomain"):
                t.add(suffix, "domain", ignore_case=True, note="reverse DNS domain")
    for line in (run("resolvectl", "status") or "").splitlines():
        if "DNS Domain:" in line:
            for d in line.split(":", 1)[1].split():
                d = d.lstrip("~")
                if d and d != ".":
                    t.add(d, "domain", ignore_case=True, note="resolved DNS domain")


def collect_keys(t):
    t.section("SSH host keys and own public keys")
    pubs = sorted(glob.glob("/etc/ssh/*.pub"))
    home = os.path.expanduser("~")
    pubs += sorted(glob.glob(os.path.join(home, ".ssh", "*.pub")))
    for path in pubs:
        fp = run("ssh-keygen", "-lf", path) or ""
        m = re.search(r"(SHA256:[A-Za-z0-9+/]{43})", fp)
        label = os.path.basename(path)
        if m:
            t.add(m.group(1), "fingerprint", note=label)
        content = read(path) or ""
        parts = content.split()
        if len(parts) >= 2 and re.fullmatch(r"[A-Za-z0-9+/=]{40,}", parts[1]):
            t.add(parts[1], "secret", note=label + " key material")
    gpg = run("gpg", "--batch", "--list-keys", "--with-colons") or ""
    for line in gpg.splitlines():
        f = line.split(":")
        if f and f[0] == "fpr" and len(f) > 9 and re.fullmatch(r"[0-9A-F]{40}", f[9]):
            t.add(f[9], "secret", note="GPG fingerprint")


def collect_users(t):
    t.section("local user accounts")
    for u in pwd.getpwall():
        if u.pw_uid < 1000 or u.pw_uid >= 65534:
            continue
        if not os.path.isdir(u.pw_dir) or u.pw_shell.endswith(("nologin", "false")):
            continue
        if u.pw_name.lower() in GENERIC_ACCOUNTS:
            t.note("account %s left out: the word would be replaced everywhere it appears" % u.pw_name)
        else:
            t.add(u.pw_name, "person", ignore_case=True, note="user name")
        full = u.pw_gecos.split(",")[0].strip().replace('"', "")
        if not full or full.lower() == u.pw_name.lower():
            continue
        if " " in full:
            # a literal with spaces needs the YAML form
            t.lines.append('{value: "%s", kind: person, ignore_case: true}' % full)
            t.counts["person"] += 1
            for part in full.split():
                if len(part) >= 3:
                    t.add(part, "person", ignore_case=True, note="from full name")
        else:
            t.add(full, "person", ignore_case=True)


# ---------------------------------------------------------------- merge

BEGIN = "# --- machine-ids begin: %s ---"
END = "# --- machine-ids end: %s ---"


def is_word(name):
    """A host or account name that is also a command or an everyday word."""
    n = name.lower()
    return (n in GENERIC_ACCOUNTS or n in GENERIC_LABELS or n in SHELL_WORDS or n in GENERIC_HOSTS
            or bool(shutil.which(n)))


def check_terms(path):
    """Read a term file and print every term that is a word on this machine.

    A regex term of the form the script writes is checked by its bare name;
    other regex terms are skipped, they carry their own boundaries. Prints the
    term itself, since the person running this owns the file.
    """
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print("cannot read %s: %s" % (path, e.strerror), file=sys.stderr)
        return 1
    hits = 0
    for n, line in enumerate(lines, 1):
        s = line.split("#", 1)[0].strip() if not line.lstrip().startswith("{") else line.strip()
        if not s:
            continue
        m = re.match(r'\{regex:\s*"\(\?i\)\\\\b([a-z0-9-]+)\(\?:', s)
        if m:
            value, kind = m.group(1), "host"
        elif s.startswith("{"):
            continue
        else:
            parts = s.split()
            value, kind = parts[0], parts[1] if len(parts) > 1 else "host"
        if kind in ("host", "person", "path_segment", "domain") and re.fullmatch(r"[A-Za-z][a-z0-9-]{1,11}", value) and is_word(value):
            hits += 1
            print("line %d: %s %s   is also a command or an ordinary word here; every '%s' in any text will be replaced"
                  % (n, value, kind, value))
    print("%d of %d lines checked, %d word-like terms" % (sum(1 for l in lines if l.strip() and not l.lstrip().startswith("#")), len(lines), hits))
    return 0


def merge_into(path, block, host):
    """Replace the block of this host in the term file, or append it.

    The file keeps its owner and mode (written in place), so the root-owned
    terms.txt next to the shared library stays root-owned when run with sudo.
    A numbered backup <stem>-backup-NN<ext> is written next to it first.
    """
    begin, end = BEGIN % host, END % host
    old = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            old = f.read()
        stem, ext = os.path.splitext(path)
        n = 1
        while os.path.exists("%s-backup-%02d%s" % (stem, n, ext)):
            n += 1
        backup = "%s-backup-%02d%s" % (stem, n, ext)
        st = os.stat(path)
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, st.st_mode & 0o777)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(old)
    lines = old.splitlines()
    if begin in lines and end in lines[lines.index(begin):]:
        i = lines.index(begin)
        j = lines.index(end, i)
        del lines[i:j + 1]
        while i > 0 and lines[i - 1] == "":
            del lines[i - 1]
            i -= 1
    new = "\n".join(lines).rstrip("\n")
    new = (new + "\n\n" if new else "") + begin + "\n" + block.rstrip("\n") + "\n" + end + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    return sum(1 for l in block.splitlines() if l and not l.startswith("#"))


# ---------------------------------------------------------------- main

def ask(question, default):
    """Yes/no question on the terminal; Enter takes the default."""
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            a = input("%s [%s] " % (question, hint)).strip().lower()
        except EOFError:
            return default
        if a == "":
            return default
        if a in ("y", "yes", "j", "ja"):
            return True
        if a in ("n", "nein", "no"):
            return False


def interactive():
    """No options given: ask what to do, one question at a time."""
    print("machine-ids: collects the identifiers of this machine as a term list for the privacyfilter plugin.")
    if os.geteuid() != 0:
        print("Note: without sudo the DMI serial numbers and the product UUID are missing.")
    choices = {
        "lan": ask("Include the other machines of the LAN (mDNS, reverse DNS of the neighbour table)?", False),
        "all_interfaces": ask("Include container and VM interfaces (veth, docker, virbr)?", False),
    }
    here = os.path.dirname(os.path.abspath(__file__))
    terms = os.path.join(here, "terms.txt")
    if os.path.exists(terms) and not os.access(terms, os.W_OK):
        print("Note: %s is not writable without sudo, merging is skipped." % terms)
    elif os.path.exists(terms) and ask("Merge into %s (a backup is written first)?" % terms, True):
        choices["merge"] = terms
    elif ask("Write to a file instead of the screen?", True):
        default = os.path.join(here, "machine-ids.txt")
        try:
            path = input("File name [%s]: " % default).strip()
        except EOFError:
            path = ""
        choices["output"] = path or default
    return choices


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-o", "--output", help="write to this file (mode 0600) instead of stdout")
    ap.add_argument("--summary", action="store_true", help="print counts per kind only, never a value")
    ap.add_argument("--merge", metavar="TERMS", help="replace or append the generated block in this term file "
                    "(a numbered backup is written first; the plugin reads the file at start only)")
    ap.add_argument("--all-interfaces", action="store_true",
                    help="include container and VM interfaces (veth, br-, docker, virbr, ...)")
    ap.add_argument("--lan", action="store_true",
                    help="add the other machines of the LAN: mDNS names via avahi-browse, reverse DNS of the neighbour table")
    ap.add_argument("--stdout", action="store_true", help="print the list without asking anything")
    ap.add_argument("--check", metavar="TERMS",
                    help="list the terms of this file that are also a command or an ordinary word here, collect nothing")
    args = ap.parse_args()
    if args.check:
        return check_terms(args.check)
    if len(sys.argv) == 1 and sys.stdin.isatty():
        for k, v in interactive().items():
            setattr(args, k, v)
    global ALL_INTERFACES, LAN
    ALL_INTERFACES = args.all_interfaces
    LAN = args.lan

    t = Terms()
    t.lines.append("# machine identifiers of %s, generated by machine-ids.py; grammar: <value> [kind] [ignore_case]"
                   % socket.gethostname())
    t.lines.append("# every line holds a clear-text identifier of this machine; keep the file next to terms.txt, mode 0600")
    if os.geteuid() != 0:
        t.lines.append("# run with sudo to add the DMI serials and the product uuid")
    steps = (
        (collect_host, "host names"),
        (collect_ids, "machine-id, boot id, DMI"),
        (collect_network, "network interfaces, DNS, Wi-Fi, Bluetooth"),
        (collect_lan, "LAN neighbours" if LAN else ""),
        (collect_block, "block devices, USB, battery"),
        (collect_keys, "SSH and GPG keys"),
        (collect_users, "user accounts"),
    )
    for collector, label in steps:
        if label:
            progress(label)
        try:
            collector(t)
        except Exception as e:  # one broken source must not lose the others
            t.note("%s failed: %s" % (collector.__name__, e.__class__.__name__))
    progress("done: %d terms" % sum(t.counts.values()))

    if args.summary:
        total = sum(t.counts.values())
        print("terms: %d" % total)
        for kind in sorted(t.counts):
            print("  %-12s %d" % (kind, t.counts[kind]))
        for why in sorted(t.skipped):
            print("skipped, %s: %d" % (why, t.skipped[why]))
        for n in t.notes:
            print("note: " + n)
        return 0

    text = "\n".join(t.lines).rstrip() + "\n"
    try:
        if args.merge:
            n = merge_into(args.merge, text, socket.gethostname())
            print("%d terms merged into %s" % (n, args.merge), file=sys.stderr)
            print("restart the proxy now: docker compose restart cliproxyapi", file=sys.stderr)
            return 0
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            print("%d terms written to %s" % (sum(t.counts.values()), args.output), file=sys.stderr)
            return 0
    except OSError as e:
        print("cannot write %s: %s (run with sudo?)" % (args.merge or args.output, e.strerror), file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
