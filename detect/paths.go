package detect

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PathsConfig configures the path layer, which takes a file system path
// apart at its slashes and reports the identifying segments one by one.
// Ordinary segments, the ones every system has, stay as they are, so the
// model still sees a home directory, a source tree and two files that are
// siblings; what leaves the machine is neither the login name nor the
// customer's name.
type PathsConfig struct {
	// ReplaceUnknown reports every segment outside the preserve list. When
	// false, only segments in Known are reported, which is what the term
	// list finds anyway; the layer then only supplies the segment kinds.
	ReplaceUnknown bool
	// Preserve adds to the built-in list of ordinary segments.
	Preserve []string
	// Known are the literal values of the term list, consulted when
	// ReplaceUnknown is false.
	Known map[string]bool
	// AllFilenames reports a final segment with a file extension as
	// KindFileName like any other unknown segment. When false, the default,
	// the layer leaves file names alone: a file name says what a file is,
	// README.md, main.go, config.yaml, and is the index by which a model
	// finds its way around a tree, while the identifying part of a path
	// sits in the directories. A file named after a customer carries the
	// customer's name, which the term layer finds inside the file name at
	// its word boundary; that layer runs first and needs no help from here.
	// A final segment without an extension is treated as a directory.
	AllFilenames bool
}

// defaultPreserve are the segments that identify nothing: the standard
// directories of a Unix system, the well-known files and directories under
// them that an administrator names every day, and the conventional names of
// source trees. A segment on this list stays as it is, so the model still
// knows that it is looking at the hosts file, an SSH host key, a systemd
// unit or a block device. What identifies a machine or its owner is the
// login name, the customer's name, the project, the host name in a path,
// and those are not on the list. Device nodes such as sda1 or nvme0n1p2
// are recognised by deviceName instead of being listed.
var defaultPreserve = []string{
	// the file system hierarchy
	"home", "root", "usr", "etc", "var", "tmp", "srv", "mnt", "media", "opt",
	"bin", "sbin", "lib", "lib64", "libexec", "share", "local", "include", "src", "dev",
	"proc", "sys", "run", "boot", "log", "cache", "config", "spool", "mail", "lock",
	"backup", "backups", "snap", "flatpak", "lost+found", "srv", "efi", "EFI",
	// /etc and its well-known files and directories
	"hosts", "hostname", "passwd", "group", "shadow", "fstab", "crypttab", "mtab",
	"resolv.conf", "nsswitch.conf", "sudoers", "sudoers.d", "profile", "profile.d",
	"environment", "os-release", "machine-id", "default", "conf.d", "modules-load.d",
	"sysctl.d", "sysctl.conf", "cron.d", "cron.daily", "cron.hourly", "cron.weekly", "crontab",
	"ssh", "sshd_config", "ssh_config", "sshd_config.d", "ssh_config.d", "known_hosts",
	"authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "ssh_host_rsa_key", "ssh_host_ed25519_key",
	"ssh_host_ecdsa_key", "ssh_host_rsa_key.pub", "ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub",
	"systemd", "system", "user", "users", "network", "resolved.conf", "journald.conf", "logind.conf",
	"netplan", "NetworkManager", "system-connections", "wireguard", "iptables", "nftables.conf",
	"ufw", "fail2ban", "jail.d", "jail.local", "filter.d", "action.d",
	"nginx", "sites-available", "sites-enabled", "conf-available", "conf-enabled", "nginx.conf",
	"apache2", "httpd", "mods-available", "mods-enabled", "httpd.conf",
	"postfix", "dovecot", "samba", "smb.conf", "nfs", "exports", "cups", "avahi",
	"docker", "daemon.json", "containers", "containerd", "podman", "compose", "docker-compose.yml",
	"docker-compose.yaml", "compose.yml", "compose.yaml", "Dockerfile",
	"apt", "sources.list", "sources.list.d", "dnf", "yum.repos.d", "pacman.d", "zypp",
	"letsencrypt", "live", "archive", "renewal", "ssl", "certs", "private", "pki", "tls",
	"X11", "xorg.conf.d", "udev", "rules.d", "modprobe.d", "grub", "grub2", "grub.d", "grub.cfg",
	"security", "pam.d", "selinux", "apparmor.d", "polkit-1", "dbus-1",
	// /var, /run, /sys, /proc, /dev
	"journal", "lastlog", "wtmp", "btmp", "syslog", "messages", "auth.log", "kern.log",
	"apt", "dpkg", "rpm", "www", "html", "www-data", "mysql", "postgresql", "redis",
	"block", "class", "net", "bus", "devices", "kernel", "module", "firmware", "power_supply",
	"virtual", "dmi", "id", "cpu", "cpuinfo", "meminfo", "mounts", "cmdline", "version",
	"self", "fd", "status", "stat", "environ", "cwd", "exe", "maps",
	"disk", "by-id", "by-uuid", "by-label", "by-path", "by-partuuid", "by-partlabel",
	"mapper", "null", "zero", "random", "urandom", "stdin", "stdout", "stderr", "shm",
	"pts", "input", "snd", "dri", "bus", "usb", "tty", "console", "video", "fuse", "kvm", "loop-control",
	// kernel and boot
	"modules", "vmlinuz", "initrd.img", "initramfs", "config-", "System.map",
	// files without an extension that every repository has
	"Makefile", "makefile", "GNUmakefile", "Justfile", "justfile", "Taskfile", "Rakefile", "Gemfile", "Procfile",
	"Vagrantfile", "Jenkinsfile", "Containerfile", "Podfile", "Brewfile", "Pipfile", "Cargo.lock",
	"README", "LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS", "CONTRIBUTORS", "CONTRIBUTING", "CHANGELOG",
	"CHANGES", "HISTORY", "NEWS", "TODO", "VERSION", "INSTALL", "MANIFEST", "CODEOWNERS",
	// languages, package managers, tools
	"python", "python3", "site-packages", "dist-packages", "__pycache__", "venv", ".venv",
	"node", "npm", ".npm", "go", "pkg", "mod", ".cargo", "cargo", "registry", "rustup", ".rustup",
	"java", "jvm", "ruby", "gems", "perl", "perl5", "php", "composer",
	// source trees and user directories
	"cmd", "internal", "docs", "doc", "test", "tests", "testdata", "examples", "scripts",
	"assets", "static", "public", "templates", "migrations", "api", "app", "apps", "web",
	// media types: "application/vnd.ms-excel" has the shape of a bare path
	"application", "text", "image", "audio",
	"Users", "Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos", "Projects",
	".config", ".local", ".cache", ".git", ".github", ".vscode", ".idea", "node_modules", "vendor",
	"target", "build", "dist", "out", "obj", "release", "debug", "state", "data", "db",
	".bashrc", ".zshrc", ".profile", ".bash_profile", ".bash_history", ".zsh_history", ".gitconfig",
	".claude", ".codex", "plugins", "logs", "auths", ".ssh", ".gnupg", "address", "resolve",
	"resolve.conf", "operstate", "carrier", "mtu", "speed", "duplex", "statistics", "uevent",
}

// NewPaths builds the path layer. It reports directory segments as
// KindPathSegment and a final segment with a file extension as
// KindFileName, both with Source "paths".
func NewPaths(cfg PathsConfig) (Detector, error) {
	d := &pathsDetector{cfg: cfg, preserve: make(map[string]bool, len(defaultPreserve)+len(cfg.Preserve))}
	for _, s := range defaultPreserve {
		d.preserve[s] = true
	}
	for _, s := range cfg.Preserve {
		if strings.TrimSpace(s) == "" {
			continue
		}
		// A preserve entry names one path segment. An entry that carries a
		// slash or a glob character can never equal a single segment, so it
		// would be accepted and silently do nothing while the segment it was
		// meant to keep goes on being replaced. Name it in the error rather
		// than swallow it.
		if strings.ContainsAny(s, `/\*?[]`) {
			return nil, fmt.Errorf("detect: path.preserve entry %q is not a single segment; list the directory name alone, without a slash or a wildcard", s)
		}
		d.preserve[strings.TrimSpace(s)] = true
	}
	return d, nil
}

type pathsDetector struct {
	cfg      PathsConfig
	preserve map[string]bool
}

var _ Detector = (*pathsDetector)(nil)

// Name implements Detector.
func (d *pathsDetector) Name() string { return "paths" }

// Scan implements Detector. A path begins at a slash, at "~/", "./" or
// "../" that is not preceded by a segment character, so "and/or", "km/h"
// and "TCP/IP" are prose, and the authority of a URL, which begins with two
// slashes, is not a path. It also begins at the slash behind a shell
// variable, "$HOME/…", and at a bare token whose shape says path, which
// bareShape decides: a file extension at the end, a slash at the end, a
// hidden directory in front, or a working directory flattened into one
// name. It runs over segments of letters, digits and the characters ._-~@+%
// and ends at the first other character; an encoded space, "%20", inside a
// segment divides it into words, see segments.
func (d *pathsDetector) Scan(text string) []Match {
	if text == "" || (!strings.Contains(text, "/") && !strings.Contains(text, "-")) {
		return nil
	}
	var out []Match
	for i := 0; i < len(text); {
		start, end, ok := pathStart(text, i)
		if !ok {
			_, size := utf8.DecodeRuneInString(text[i:])
			i += max(size, 1)
			continue
		}
		out = d.segments(text, start, end, out)
		i = end
	}
	return out
}

// pathStart reports whether a path begins at text[i] and where it ends.
func pathStart(text string, i int) (start, end int, ok bool) {
	var prev rune
	if i > 0 {
		prev, _ = utf8.DecodeLastRuneInString(text[:i])
	}
	rest := text[i:]
	switch {
	case strings.HasPrefix(rest, "//"), prev == '/':
		return 0, 0, false
	case rest[0] == '/':
		// "$HOME/x" is a path from the slash on; "km/h" and ".../x" are
		// not, and neither is the slash of a closing tag, "</p>".
		if isSegmentRune(prev) && !variableBefore(text, i) {
			return 0, 0, false
		}
		end = pathEnd(text, i)
		if closingTag(text, i, end) {
			return 0, 0, false
		}
		return i, end, true
	case strings.HasPrefix(rest, "~/"), strings.HasPrefix(rest, "./"), strings.HasPrefix(rest, "../"):
		// Behind a segment character the prefix is the tail of something
		// else: the third dot of ".../x" is not "./x".
		if isSegmentRune(prev) {
			return 0, 0, false
		}
		return i, pathEnd(text, i), true
	}
	// A bare token begins only at a token boundary. Behind a segment
	// character it is the tail of a longer token, "example.com/x" seen from
	// the "com"; behind a dollar it is the name of a variable.
	if isSegmentRune(prev) || prev == '$' {
		return 0, 0, false
	}
	end = pathEnd(text, i)
	if end == i || !bareShape(text[i:end]) {
		return 0, 0, false
	}
	// The slash in front of a ">" closes a tag, "<br/>" and
	// "<input disabled/>"; it does not end a directory.
	if text[end-1] == '/' && end < len(text) && text[end] == '>' {
		return 0, 0, false
	}
	return i, end, true
}

// variableBefore reports whether the word in front of the slash at text[i]
// is a shell variable, "$HOME" or "$my_dir". A slash behind it begins a
// path; a slash behind any other word is prose. The name has to begin
// with a letter or an underscore: "$5/hour" and "US$100/month" are prices.
func variableBefore(text string, i int) bool {
	j := i
	for j > 0 {
		c := text[j-1]
		if c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			j--
			continue
		}
		break
	}
	if j == i || j == 0 || text[j-1] != '$' {
		return false
	}
	c := text[j]
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// closingTag reports whether the slash at text[i] opens the end tag of
// markup, "</p>" or "</my-component>": a "<" in front, a single segment
// behind, and ">" right after it, where end is the offset pathEnd found.
// The input redirection of the shell, "done </home/x/list.txt", has more
// than one segment and no ">" behind it and stays a path; so does a path
// in an attribute value, which has a quote or "=" in front.
func closingTag(text string, i, end int) bool {
	return i > 0 && text[i-1] == '<' && end < len(text) && text[end] == '>' &&
		strings.IndexByte(text[i+1:end], '/') < 0
}

// bareShape reports whether tok, a token that begins with neither a slash,
// a dot-slash nor a tilde, is a path by its shape alone. Four shapes are:
// a file extension at the end, "kunde/vertrag.pdf", the way a compiler and
// git status print a path; a slash at the end, "kunde/", the way ls and
// git status print a directory; a hidden directory in front,
// ".claude/projects"; and a working directory flattened into one name,
// see flattenedPath, on its own or as any segment, the way the transcript
// directory of Claude Code is listed with a session in it. Everything else
// with a slash is prose or a name that merely looks like a path, "and/or",
// "km/h", "TCP/IP", "Client/Server", "origin/main", "application/json",
// and with them the bare directory path "kunde/sub", which no rule can
// tell from those. A first segment with an inner dot is a host or a module
// path, "github.com/x/y", and belongs to the term list; a single letter in
// front is "s/x/y/", "w/o", "I/O" or the "a/" of a diff header; a scope
// "@org/pkg" is a package; two adjacent slashes never make a bare path.
func bareShape(tok string) bool {
	tok = strings.TrimRight(tok, ".")
	if tok == "" || strings.Contains(tok, "//") {
		return false
	}
	slash := strings.IndexByte(tok, '/')
	if slash < 0 {
		return flattenedPath(tok)
	}
	first := tok[:slash]
	if utf8.RuneCountInString(first) < 2 || first[0] == '@' ||
		strings.IndexByte(first[1:], '.') >= 0 || strings.IndexFunc(first, isTokenRune) < 0 {
		return false
	}
	last := tok[strings.LastIndexByte(tok, '/')+1:]
	if last == "" || first[0] == '.' || hasFileExt(last) {
		return true
	}
	for seg := range strings.SplitSeq(tok, "/") {
		if flattenedPath(seg) {
			return true
		}
	}
	return false
}

// flattenedRoots are the directories a working directory can begin with,
// as flattenedPath needs them: the roots of the file system hierarchy, the
// macOS home root and the workspace root of a container.
var flattenedRoots = map[string]bool{
	"home": true, "root": true, "usr": true, "etc": true, "var": true, "tmp": true,
	"srv": true, "mnt": true, "media": true, "opt": true, "run": true,
	"Users": true, "workspace": true, "workspaces": true,
}

// flattenedPath reports whether seg is a working directory written as one
// name, the way Claude Code names the directory that holds a project's
// transcripts: every slash and every dot of the path becomes a dash, so
// "/home/user/kunde.x" is "-home-user-kunde-x". Such a name carries the
// whole directory structure of a workspace in one word. In an absolute
// path it is one segment and is replaced as a whole; this rule does the
// same for the bare name, as ls prints it. The name begins with a dash and
// one of flattenedRoots and carries at least two more parts: one part
// behind the root is a flag, "-var-file", and a double dash is always a
// flag. A working directory right under a root, "/tmp/x", is therefore
// caught in an absolute path only.
func flattenedPath(seg string) bool {
	if len(seg) < 2 || seg[0] != '-' || seg[1] == '-' {
		return false
	}
	parts := strings.Split(seg[1:], "-")
	if !flattenedRoots[parts[0]] {
		return false
	}
	n := 0
	for _, p := range parts[1:] {
		if p != "" {
			n++
		}
	}
	return n >= 2
}

// pathEnd returns the offset just past the last segment character of the
// path that begins at start.
func pathEnd(text string, start int) int {
	i := start
	for i < len(text) {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r != '/' && !isSegmentRune(r) {
			break
		}
		i += size
	}
	return i
}

// isSegmentRune reports whether r may be part of a path segment.
func isSegmentRune(r rune) bool {
	switch r {
	case '.', '_', '-', '~', '@', '+', '%':
		return true
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// segments appends one match per reportable segment of text[start:end]. A
// segment is divided at an encoded space, "%20", the way a Markdown link
// writes a directory with a space in its name, and the words on either side
// are reported on their own with the encoded space left standing between
// them. The model then sees "d-…%20d-…", knows there is a space to decode,
// and both words come back whether it decodes or not. A segment replaced
// whole would hide the encoding behind one pseudonym: the model, seeing no
// "%20", would put the pseudonym into a file system path, the restore would
// bring the "%20" back, and the path would miss the directory.
func (d *pathsDetector) segments(text string, start, end int, out []Match) []Match {
	path := text[start:end]
	pos := 0
	for pos < len(path) {
		next := strings.IndexByte(path[pos:], '/')
		segEnd := len(path)
		if next >= 0 {
			segEnd = pos + next
		}
		seg := path[pos:segEnd]
		last := next < 0
		if last {
			// A sentence may end right after the path.
			for len(seg) > 0 && seg[len(seg)-1] == '.' {
				seg = seg[:len(seg)-1]
				segEnd--
			}
		}
		// Whether the segment is a file name is decided on the whole of
		// it: the extension sits on its last word, and the words in front
		// are parts of the same file name, not directories.
		file := last && hasFileExt(seg)
		wordStart := pos
		for word := range strings.SplitSeq(seg, encodedSpace) {
			if kind, ok := d.classify(word, file); ok {
				out = append(out, Match{
					Start:  start + wordStart,
					End:    start + wordStart + len(word),
					Value:  word,
					Kind:   kind,
					Source: "paths",
				})
			}
			wordStart += len(word) + len(encodedSpace)
		}
		if next < 0 {
			break
		}
		pos = segEnd + 1
	}
	return out
}

// classify decides whether a segment, or one word of a segment with an
// encoded space in it, is reported and as what. file says the segment is
// the file name of the path.
func (d *pathsDetector) classify(seg string, file bool) (Kind, bool) {
	switch seg {
	case "", ".", "..", "~":
		return "", false
	}
	if d.preserve[seg] || allDigits(seg) || deviceName(seg) {
		return "", false
	}
	if !d.cfg.ReplaceUnknown && !d.cfg.Known[seg] {
		return "", false
	}
	if flattenedPath(seg) {
		// A flattened working directory is a directory whatever it ends in.
		return KindPathSegment, true
	}
	if file {
		if !d.cfg.AllFilenames {
			return "", false
		}
		return KindFileName, true
	}
	return KindPathSegment, true
}

// deviceName reports whether seg is the conventional name of a device node
// or kernel object: a disk, partition, network interface, tty, loop or
// mapper device. Such a name says what a thing is, not whose it is, so it
// stays. A systemd unit name is not covered: units are named after what
// they serve, and that is often a host or a customer.
func deviceName(seg string) bool {
	return rxDevice.MatchString(seg)
}

var rxDevice = regexp.MustCompile(`^(?:` +
	`(?:sd|vd|xvd|hd)[a-z]{1,3}[0-9]*` + `|` + // sda, sdb2, vda1
	`nvme[0-9]+(?:n[0-9]+(?:p[0-9]+)?)?` + `|` + // nvme0, nvme0n1, nvme0n1p2
	`mmcblk[0-9]+(?:p[0-9]+|boot[0-9]+|rpmb)?` + `|` + // mmcblk0p1
	`(?:md|dm|loop|zram|ram|sr|fd|nbd|rbd)[0-9]+` + `|` + // md0, dm-0 below, loop3
	`dm-[0-9]+` + `|` +
	`(?:eth|en[opsx]|wl[opsx]?|ww|br|docker|virbr|veth|tap|tun|vnet|bond|team|vlan|wg|zt|tailscale)[0-9a-f][a-z0-9]*(?:\.[0-9]+)?` + `|` + // eth0, enp3s0, wlan0, eth0.100
	`br-[0-9a-f]+` + `|` + `lo` + `|` +
	`(?:tty|ttyS|ttyUSB|ttyACM|pts|hidraw|video|fb|input|event|mouse|snd|dri|card|renderD)[0-9]*` +
	`)$`)

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// hasFileExt reports whether name ends in an extension the file name
// renderer carries over: a dot that is neither first nor last, followed by
// at most sixteen letters, digits, underscores or hyphens. It mirrors the
// rule of pseudo.fileExt; a segment the renderer would not give an
// extension is still a valid file name pseudonym, only without one.
func hasFileExt(name string) bool {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 || len(name)-i > 17 {
		return false
	}
	for j := i + 1; j < len(name); j++ {
		c := name[j]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
