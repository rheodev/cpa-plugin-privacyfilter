package basics

// System administration shapes: values that sit inside commands, paths,
// addresses and configuration lines rather than in prose. Two dangers are
// examined here. First, a value that forms part of a longer token - the
// replacement must not cut the token apart or leave the value behind.
// Second, a value that carries shell metacharacters - the restorer puts the
// original back into whatever the model wrote, and if that was a command,
// the original lands in a shell.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// A host name appears in many shapes on a terminal. Each of them must come
// back exactly as it went in, and none may keep the original visible.
func TestAdmin_HostInCommandShapes(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	lines := []string{
		"ssh admin@zeus.lan",
		"scp backup.tar.gz admin@zeus.lan:/mnt/backup/",
		"curl -s https://zeus.lan:8443/api/v1/status",
		"rsync -a /srv/data/ zeus.lan:/srv/data/",
		"ping -c 3 zeus.lan",
		"Host zeus.lan\n  HostName zeus.lan\n  User admin",
		"127.0.0.1 zeus.lan zeus",
		"ssh -o ProxyJump=zeus.lan target.lan",
		"docker -H ssh://zeus.lan ps",
		"journalctl -u backup@zeus.lan.service",
		"zeus.lan.backup.tar.gz",
		"NODE=zeus.lan make deploy",
		"echo \"host: zeus.lan\" >> /etc/hosts.d/local",
	}
	for _, line := range lines {
		tab := newTable(t)
		mid := forward(line, d, tab)
		if strings.Contains(mid, "zeus.lan") {
			t.Errorf("original survived in %q -> %q", line, mid)
		}
		if got := back(mid, tab); got != line {
			t.Errorf("round trip changed the line:\n  in %q\n out %q\n via %q", line, got, mid)
		}
	}
}

// Addresses carry structure that must survive: port, prefix length, the
// brackets of IPv6.
func TestAdmin_AddressStructures(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true, MAC: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	lines := []string{
		"connect 10.42.0.7:8080",
		"ip route add 172.20.0.0/16 via 192.168.178.1",
		"listen [fd00:dead:beef::1]:443",
		"iface eth0 inet static\n  address 192.168.178.22\n  netmask 255.255.255.0",
		"MAC 02:42:ac:11:00:02 on docker0",
		"ssh -p 2222 10.42.0.7",
		"proxy_pass http://[fd00:dead:beef::2]:8080/api;",
		"ping6 fd00:dead:beef::cafe",
	}
	for _, line := range lines {
		tab := newTable(t)
		mid := forward(line, d, tab)
		if mid == line {
			t.Errorf("nothing was detected in %q", line)
		}
		if got := back(mid, tab); got != line {
			t.Errorf("round trip changed the line:\n  in %q\n out %q\n via %q", line, got, mid)
		}
		t.Logf("%q\n   -> %q", line, mid)
	}
}

// Addresses reserved for documentation appear in every manual and in most
// example configurations. Whether they are detected decides how much noise a
// pasted tutorial produces.
func TestAdmin_DocumentationAddresses(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	cases := map[string]string{
		"RFC 5737 TEST-NET-1": "192.0.2.15",
		"RFC 5737 TEST-NET-2": "198.51.100.15",
		"RFC 5737 TEST-NET-3": "203.0.113.15",
		"RFC 3849 IPv6 doc":   "2001:db8::1",
		"pseudonym range":     "100.80.13.7",
		"ordinary private":    "192.168.178.22",
		"ordinary public":     "8.8.8.8",
		"loopback":            "127.0.0.1",
		"unspecified":         "0.0.0.0",
		"broadcast":           "255.255.255.255",
	}
	for name, addr := range cases {
		tab := newTable(t)
		mid := forward(addr, d, tab)
		if mid == addr {
			t.Logf("%-20s %-22s left alone", name, addr)
		} else {
			t.Logf("%-20s %-22s -> %s", name, addr, mid)
		}
	}
}

// Column layout: an alias is longer than most originals, so tables shift.
// Nothing breaks, but the model reads a table whose columns no longer line
// up. Documented, not asserted.
func TestAdmin_TableAlignment(t *testing.T) {
	d := newTerms(t,
		detect.Term{Value: "zeus.lan", Kind: detect.KindHost},
		detect.Term{Value: "hera.lan", Kind: detect.KindHost},
	)
	tab := newTable(t)
	table := "" +
		"HOST      STATE    UPTIME\n" +
		"zeus.lan  running  12d\n" +
		"hera.lan  stopped   3d\n"
	mid := forward(table, d, tab)
	t.Logf("before:\n%s\nafter:\n%s", table, mid)
	if got := back(mid, tab); got != table {
		t.Errorf("round trip changed the table:\n%s", got)
	}
}

// The dangerous case: a term that contains shell metacharacters. The model
// writes a command around the alias, the restorer puts the original back,
// and the shell sees the result. An apostrophe in a name is enough.
func TestAdmin_TermWithShellMetacharacters(t *testing.T) {
	values := []struct {
		kind detect.Kind
		val  string
	}{
		{detect.KindPerson, "Sean O'Connor"},
		{detect.KindPathSegment, "kunde x & co"},
		{detect.KindPathSegment, "report$(date)"},
		{detect.KindPathSegment, "a;b"},
		{detect.KindPathSegment, "back`tick`"},
		{detect.KindPathSegment, "new\nline"},
	}
	for _, v := range values {
		d := newTerms(t, detect.Term{Value: v.val, Kind: v.kind})
		tab := newTable(t)
		text := "grep " + v.val + " /var/log/app.log"
		mid := forward(text, d, tab)
		if strings.Contains(mid, v.val) {
			t.Logf("not replaced at all: %q", v.val)
			continue
		}
		// This is what the model would write, quoting the alias safely.
		quoted := strings.Replace(mid, "grep ", "grep '", 1)
		quoted = strings.Replace(quoted, " /var/log", "' /var/log", 1)
		restored := back(quoted, tab)
		unsafe := strings.ContainsAny(v.val, "'\"`$;&|\n")
		t.Logf("kind=%-13s value=%-16q\n   model writes: %s\n   shell sees:   %s", v.kind, v.val, quoted, restored)
		if unsafe && strings.Contains(restored, v.val) {
			t.Logf("   -> the metacharacters of the original are now inside the quoted argument")
		}
	}
}

// The sharper version of the previous test. An alias carries neither spaces
// nor metacharacters, so the model has no reason to quote it. The restorer
// then drops the original into an unquoted position, and the shell parses
// what the model never wrote.
func TestAdmin_UnquotedAliasInCommand(t *testing.T) {
	values := []string{
		"kunde x & co",
		"report$(id)",
		"a;b",
		"back`id`",
		"two words",
		"quote'inside",
	}
	for _, val := range values {
		d := newTerms(t, detect.Term{Value: val, Kind: detect.KindPathSegment})
		tab := newTable(t)
		mid := forward("ls /mnt/"+val+"/", d, tab)
		if strings.Contains(mid, val) {
			t.Logf("not replaced: %q", val)
			continue
		}
		// The model repeats the alias unquoted, because the alias looks like
		// a harmless single token.
		cmd := back(mid, tab)
		fields := len(strings.Fields(cmd))
		meta := strings.ContainsAny(cmd, "&;`$")
		t.Logf("value=%-16q alias line %q\n   shell receives: %s\n   words=%d metacharacters=%v",
			val, mid, cmd, fields, meta)
		if fields > 2 || meta {
			t.Logf("   -> one command became something else")
		}
	}
}

// Configuration file shapes: the value sits behind a key, in quotes, or as
// part of a URL.
func TestAdmin_ConfigurationShapes(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	lines := []string{
		"server: zeus.lan",
		"server = zeus.lan",
		"server=\"zeus.lan\"",
		"- host: zeus.lan\n  port: 5432",
		"DATABASE_URL=postgres://user@zeus.lan:5432/app",
		"ExecStart=/usr/bin/backup --target zeus.lan",
		"192.168.178.10 zeus.lan # main server",
		"{\"upstream\":\"zeus.lan\"}",
	}
	for _, line := range lines {
		tab := newTable(t)
		mid := forward(line, d, tab)
		if strings.Contains(mid, "zeus.lan") {
			t.Errorf("original survived in %q -> %q", line, mid)
		}
		if got := back(mid, tab); got != line {
			t.Errorf("round trip changed the line:\n  in %q\n out %q", line, got)
		}
	}
}

// A value hidden in an encoding the scanner does not decode: base64 in a
// secret manifest, percent-encoding in a URL. A known limit, recorded here
// so it is not mistaken for a fault later.
func TestAdmin_EncodedOccurrences(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	cases := map[string]string{
		"base64":   "aG9zdDogemV1cy5sYW4=", // "host: zeus.lan"
		"percent":  "http://example.test/?h=zeus%2Elan",
		"unicode":  "zeus.lan",
		"reversed": "nal.suez",
	}
	for name, text := range cases {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if mid == text {
			t.Logf("%-9s not detected (expected): %q", name, text)
		} else {
			t.Logf("%-9s detected: %q -> %q", name, text, mid)
		}
	}
}
