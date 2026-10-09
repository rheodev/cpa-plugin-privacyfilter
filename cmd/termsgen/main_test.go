package main

import (
	"strings"
	"testing"
)

// sshConfigTestdata is an invented sample in the shape of a real
// ~/.ssh/config. It is never read from disk; parseSSHConfig consumes it
// directly from a strings.Reader so the tests never touch the real file.
const sshConfigTestdata = `
# a leading comment and a blank line above

Host bastion
    HostName BASTION.example.com
    User deploy
    Port 22

Host db1 db1-alias
    HostName db1.example.com
    Port 2222 # trailing comment after a value

Host wildcard-* other-*
    User nobody

Host *
    ForwardAgent yes

Host athene
    HostName athene.lan

Host bastion-dup
    HostName bastion.example.com

HostName=orphan.example.org
`

const hostsFileTestdata = `
127.0.0.1 localhost localhost.localdomain localhost4
::1 localhost6 ip6-localhost ip6-loopback
# a comment line
10.13.0.5 build.example.net buildbox
10.13.0.6 ATHENE.LAN
`

// TestAddHost_SkipsAddressesAndLoopback: a HostName line that carries an
// address instead of a name must not become a host term, and neither must
// the tail of the address become a domain; the loopback names of a hosts
// file are skipped as well.
func TestAddHost_SkipsAddressesAndLoopback(t *testing.T) {
	names := newNameSet()
	for _, n := range []string{
		"10.13.0.5", "192.168.2.15", "fd12:3456:789a::1", "[fd12:3456:789a::1]", "fe80::1%eth0",
		"localhost", "LOCALHOST.localdomain", "ip6-loopback", "host.docker.internal",
		"athene.lan", "build.example.net",
	} {
		names.addHost(n)
	}
	for h := range names.hosts {
		if h != "athene.lan" && h != "build.example.net" {
			t.Errorf("hosts contains %q, want only the two real names", h)
		}
	}
	if len(names.hosts) != 2 {
		t.Errorf("hosts = %v, want exactly two entries", names.hosts)
	}
	if len(names.domains) != 1 || !names.domains["example.net"] {
		t.Errorf("domains = %v, want only example.net", names.domains)
	}
}

func TestParseSSHConfig_AliasesAndHostNames(t *testing.T) {
	names := newNameSet()
	if err := parseSSHConfig(strings.NewReader(sshConfigTestdata), names); err != nil {
		t.Fatalf("parseSSHConfig() error = %v", err)
	}

	wantHosts := []string{
		"bastion",
		"bastion.example.com",
		"db1",
		"db1-alias",
		"db1.example.com",
		"athene",
		"athene.lan",
		"bastion-dup",
		"orphan.example.org",
	}
	for _, h := range wantHosts {
		if !names.hosts[h] {
			t.Errorf("hosts missing %q", h)
		}
	}

	// Wildcard patterns are aliases, not literal names, and must never
	// appear even though their HostName-less blocks were parsed.
	for _, excluded := range []string{"wildcard-*", "other-*", "*"} {
		if names.hosts[excluded] {
			t.Errorf("hosts must not contain wildcard pattern %q", excluded)
		}
	}

	// bastion.example.com and db1.example.com both have a two-label parent
	// that is not a reserved suffix.
	if !names.domains["example.com"] {
		t.Error(`domains missing "example.com"`)
	}
	// orphan.example.org contributes its own parent domain.
	if !names.domains["example.org"] {
		t.Error(`domains missing "example.org"`)
	}
	// athene.lan's parent is "lan", a single label: no domain entry.
	if names.domains["lan"] {
		t.Error(`domains must not contain "lan"`)
	}
}

func TestParseSSHConfig_CaseIsFolded(t *testing.T) {
	names := newNameSet()
	if err := parseSSHConfig(strings.NewReader(sshConfigTestdata), names); err != nil {
		t.Fatalf("parseSSHConfig() error = %v", err)
	}
	if !names.hosts["bastion.example.com"] {
		t.Fatal(`expected lower-cased "bastion.example.com" in hosts`)
	}
	if names.hosts["BASTION.example.com"] {
		t.Fatal("hosts must not keep the original casing as a separate entry")
	}
}

func TestParseHostsFile(t *testing.T) {
	names := newNameSet()
	if err := parseHostsFile(strings.NewReader(hostsFileTestdata), names); err != nil {
		t.Fatalf("parseHostsFile() error = %v", err)
	}

	wantHosts := []string{"build.example.net", "buildbox", "athene.lan"}
	for _, h := range wantHosts {
		if !names.hosts[h] {
			t.Errorf("hosts missing %q", h)
		}
	}
	if names.hosts["10.13.0.5"] || names.hosts["10.13.0.6"] || names.hosts["127.0.0.1"] {
		t.Error("hosts must not contain the address field")
	}
	if names.hosts["localhost"] || names.hosts["localhost6"] || names.hosts["ip6-loopback"] {
		t.Errorf("hosts must not contain loopback names, got %v", names.hosts)
	}
	if !names.domains["example.net"] {
		t.Error(`domains missing "example.net"`)
	}
}

func TestDedupAcrossSources(t *testing.T) {
	names := newNameSet()
	if err := parseSSHConfig(strings.NewReader(sshConfigTestdata), names); err != nil {
		t.Fatalf("parseSSHConfig() error = %v", err)
	}
	if err := parseHostsFile(strings.NewReader(hostsFileTestdata), names); err != nil {
		t.Fatalf("parseHostsFile() error = %v", err)
	}
	// athene.lan appears in both the ssh config (as HostName, lower-case
	// already) and the hosts file (as ATHENE.LAN, upper-case): one entry.
	count := 0
	for h := range names.hosts {
		if h == "athene.lan" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("athene.lan must collapse to one entry, found via map key count %d", count)
	}
}

func TestParentDomain(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantDomain string
		wantOK     bool
	}{
		{"two labels below a real domain", "db1.example.com", "example.com", true},
		{"single-label parent is skipped", "athene.lan", "", false},
		{"home.arpa is a reserved suffix", "printer.home.arpa", "", false},
		{"no dot at all", "athene", "", false},
		{"trailing dot has no parent", "athene.", "", false},
		{"bare local is a reserved suffix", "nas.local", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, ok := parentDomain(tt.input)
			if ok != tt.wantOK || domain != tt.wantDomain {
				t.Fatalf("parentDomain(%q) = (%q, %v), want (%q, %v)", tt.input, domain, ok, tt.wantDomain, tt.wantOK)
			}
		})
	}
}

func TestSplitSSHConfigLine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantKey   string
		wantValue string
		wantOK    bool
	}{
		{"space separated", "Host foo bar", "Host", "foo bar", true},
		{"equals separated no spaces", "HostName=foo.example.com", "HostName", "foo.example.com", true},
		{"equals separated with spaces", "HostName = foo.example.com", "HostName", "foo.example.com", true},
		{"comment line", "# nothing to see", "", "", false},
		{"blank line", "   ", "", "", false},
		{"trailing comment stripped", "Port 2222 # comment", "Port", "2222", true},
		{"keyword only", "ForwardAgent", "ForwardAgent", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, ok := splitSSHConfigLine(tt.line)
			if ok != tt.wantOK || key != tt.wantKey || value != tt.wantValue {
				t.Fatalf("splitSSHConfigLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.line, key, value, ok, tt.wantKey, tt.wantValue, tt.wantOK)
			}
		})
	}
}

func TestWriteTerms_SortedDedupedLowerCase(t *testing.T) {
	names := newNameSet()
	names.addHost("Zebra.example.com")
	names.addHost("alpha.example.com")
	names.addHost("ALPHA.example.com") // duplicate after lower-casing
	names.addHost("athene.lan")        // host only, no domain (parent has 1 label)

	var buf strings.Builder
	if err := writeTerms(&buf, names); err != nil {
		t.Fatalf("writeTerms() error = %v", err)
	}
	got := buf.String()

	wantLines := []string{
		"# generated by termsgen; one term per line: <literal> [kind] [ignore_case]",
		"alpha.example.com host",
		"athene.lan host",
		"zebra.example.com host",
		"example.com domain",
	}
	want := strings.Join(wantLines, "\n") + "\n"
	if got != want {
		t.Fatalf("writeTerms() =\n%s\nwant\n%s", got, want)
	}
}

func TestWriteTerms_EmptySet(t *testing.T) {
	var buf strings.Builder
	if err := writeTerms(&buf, newNameSet()); err != nil {
		t.Fatalf("writeTerms() error = %v", err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "# generated by termsgen") || strings.Count(got, "\n") != 1 {
		t.Fatalf("writeTerms() = %q, want only the header line", got)
	}
}

func TestEndToEnd_SSHAndHostsCombined(t *testing.T) {
	names := newNameSet()
	if err := parseSSHConfig(strings.NewReader(sshConfigTestdata), names); err != nil {
		t.Fatalf("parseSSHConfig() error = %v", err)
	}
	if err := parseHostsFile(strings.NewReader(hostsFileTestdata), names); err != nil {
		t.Fatalf("parseHostsFile() error = %v", err)
	}

	var buf strings.Builder
	if err := writeTerms(&buf, names); err != nil {
		t.Fatalf("writeTerms() error = %v", err)
	}
	got := buf.String()

	for _, want := range []string{
		"athene.lan host\n",
		"bastion.example.com host\n",
		"example.com domain\n",
		"example.net domain\n",
		"example.org domain\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "wildcard-*") || strings.Contains(got, "\n* ") {
		t.Errorf("output must not contain a wildcard pattern, got:\n%s", got)
	}
	if strings.Contains(got, "\nlan ") {
		t.Errorf("output must not contain the reserved single-label domain \"lan\", got:\n%s", got)
	}
}

func TestDefaultSSHConfigPath_NeverReadsAnything(t *testing.T) {
	// This only builds a path string and must not touch the filesystem;
	// there is no assertion beyond "it returns something usable".
	if p := defaultSSHConfigPath(); p == "" {
		t.Fatal("defaultSSHConfigPath() returned an empty path")
	}
}
