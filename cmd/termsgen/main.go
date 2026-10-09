// Command termsgen reads the user's OpenSSH client configuration and,
// optionally, a hosts file, and emits the terms[] YAML list that
// cpa-plugin-privacyfilter's pseudonymize mode reads its maintained list
// from. See umbauplan.md, chapter "Erkennung", section "Die gepflegte
// Liste": the user's server names follow no common suffix, they are
// scattered across the SSH config, so a generator beats hand-maintaining
// the list.
//
// The plugin itself never reads ~/.ssh/config; it runs as a service,
// possibly under a different account. This program is meant to be run
// directly by the user, who pastes its output into the plugin
// configuration.
//
// Usage:
//
//	termsgen [-ssh path] [-hosts path] [-o path]
//
// -ssh defaults to ~/.ssh/config. -hosts is empty by default, which skips
// the hosts file. -o defaults to stdout.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	sshPath := flag.String("ssh", defaultSSHConfigPath(), "path to the OpenSSH client config")
	hostsPath := flag.String("hosts", "", "path to a hosts file to include; empty skips it")
	outPath := flag.String("o", "", "output file; empty writes to stdout")
	flag.Parse()

	names := newNameSet()

	if *sshPath != "" {
		if err := readInto(*sshPath, names, parseSSHConfig); err != nil {
			fmt.Fprintf(os.Stderr, "termsgen: ssh config: %v\n", err)
			os.Exit(1)
		}
	}

	if *hostsPath != "" {
		if err := readInto(*hostsPath, names, parseHostsFile); err != nil {
			fmt.Fprintf(os.Stderr, "termsgen: hosts file: %v\n", err)
			os.Exit(1)
		}
	}

	out := io.Writer(os.Stdout)
	if *outPath != "" {
		file, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "termsgen: output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		out = file
	}

	if err := writeTerms(out, names); err != nil {
		fmt.Fprintf(os.Stderr, "termsgen: writing output: %v\n", err)
		os.Exit(1)
	}
}

// defaultSSHConfigPath returns ~/.ssh/config for the current user. It only
// builds the path string; it does not read the file. When the home
// directory cannot be determined, it falls back to the literal "~/.ssh/config",
// which fails open.Open with a clear error instead of silently reading the
// wrong file.
func defaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join("~", ".ssh", "config")
	}
	return filepath.Join(home, ".ssh", "config")
}

// readInto opens path and feeds it to parse.
func readInto(path string, names *nameSet, parse func(io.Reader, *nameSet) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return parse(f, names)
}

// nameSet collects the distinct host and domain names found across the
// inputs. Both maps are keyed by the lower-case name, so a name seen twice
// in different casing collapses into one entry.
type nameSet struct {
	hosts   map[string]bool
	domains map[string]bool
}

func newNameSet() *nameSet {
	return &nameSet{hosts: map[string]bool{}, domains: map[string]bool{}}
}

// addHost records name as a host and, when it qualifies, its parent domain.
// name is lower-cased and trimmed; an empty result after trimming is
// ignored, and so are two kinds of name that would only add noise to the
// term list: an IP address literal, which HostName lines often carry and
// which the plugin's structural patterns detect on their own (as a host
// term it would also yield a bogus "parent domain" such as "168.2.15"),
// and the loopback names every hosts file ships with.
func (s *nameSet) addHost(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || isIPLiteral(name) || loopbackNames[name] {
		return
	}
	s.hosts[name] = true
	if domain, ok := parentDomain(name); ok {
		s.domains[domain] = true
	}
}

// isIPLiteral reports whether name parses as an IPv4 or IPv6 address, with
// or without an IPv6 zone or enclosing brackets.
func isIPLiteral(name string) bool {
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	_, err := netip.ParseAddr(name)
	return err == nil
}

// loopbackNames are the names distributions put into /etc/hosts for the
// loopback interface. They identify no machine of the user's and would
// replace the word "localhost" in every request.
var loopbackNames = map[string]bool{
	"localhost":                  true,
	"localhost.localdomain":      true,
	"localhost4":                 true,
	"localhost4.localdomain4":    true,
	"localhost6":                 true,
	"localhost6.localdomain6":    true,
	"ip6-localhost":              true,
	"ip6-loopback":               true,
	"ip6-localnet":               true,
	"ip6-mcastprefix":            true,
	"ip6-allnodes":               true,
	"ip6-allrouters":             true,
	"ip6-allhosts":               true,
	"broadcasthost":              true,
	"kubernetes.docker.internal": true,
	"host.docker.internal":       true,
	"gateway.docker.internal":    true,
}

// reservedSuffixes are domains that are never emitted on their own, even
// when they otherwise pass the two-label check: they are not real,
// registrable domains, just local naming conventions.
var reservedSuffixes = map[string]bool{
	"local":     true,
	"lan":       true,
	"home.arpa": true,
}

// parentDomain returns the parent domain of a dotted name: everything after
// its first label. It reports ok == false when name has no dot, when the
// parent has fewer than two labels itself (for example "athene.lan" has the
// one-label parent "lan"), or when the parent is a reserved suffix.
func parentDomain(name string) (domain string, ok bool) {
	idx := strings.IndexByte(name, '.')
	if idx < 0 || idx == len(name)-1 {
		return "", false
	}
	domain = name[idx+1:]
	if !strings.Contains(domain, ".") {
		return "", false
	}
	if reservedSuffixes[domain] {
		return "", false
	}
	return domain, true
}

// parseSSHConfig reads an OpenSSH client config from r and records every
// Host alias that is not a wildcard pattern (containing "*" or "?") and not
// a negated pattern (leading "!", for example "Host * !bastion" — the "!"
// form negates a match, it is not a literal host name), and every HostName
// value that is not a token expansion (containing "%", for example "%h" or
// "%n" — those are OpenSSH runtime tokens, never a literal name). Include
// and Match directives are not followed; their targets, if any, are outside
// the scope of this generator.
func parseSSHConfig(r io.Reader, names *nameSet) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		key, value, ok := splitSSHConfigLine(scanner.Text())
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "host":
			for _, alias := range strings.Fields(value) {
				if strings.ContainsAny(alias, "*?") || strings.HasPrefix(alias, "!") {
					continue
				}
				names.addHost(alias)
			}
		case "hostname":
			if fields := strings.Fields(value); len(fields) > 0 && !strings.Contains(fields[0], "%") {
				names.addHost(fields[0])
			}
		}
	}
	return scanner.Err()
}

// splitSSHConfigLine splits one line of an OpenSSH client config into its
// keyword and argument, following the two forms OpenSSH accepts: "Key
// value" and "Key=value", with optional space around "=". Blank lines and
// comment lines (leading "#") return ok == false. A "#" that follows
// whitespace elsewhere on the line starts a trailing comment and is
// stripped; OpenSSH itself does not define this, but it keeps test fixtures
// readable.
func splitSSHConfigLine(raw string) (key, value string, ok bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if idx := strings.IndexByte(line, '#'); idx > 0 {
		if prev := line[idx-1]; prev == ' ' || prev == '\t' {
			line = strings.TrimSpace(line[:idx])
		}
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return line, "", true
	}
	key = line[:end]
	rest := strings.TrimSpace(line[end:])
	rest = strings.TrimPrefix(rest, "=")
	value = strings.TrimSpace(rest)
	return key, value, true
}

// parseHostsFile reads a hosts(5) style file from r and records every
// hostname on every non-comment line, skipping the leading address field.
func parseHostsFile(r io.Reader, names *nameSet) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, host := range fields[1:] {
			names.addHost(host)
		}
	}
	return scanner.Err()
}

// writeTerms renders the collected names in the term file format the plugin
// reads via terms_file: one entry per line, "<name> host" or "<name> domain",
// hosts first, then domains, each group deduplicated and sorted. A header
// comment names the generator; the plugin skips comments and blank lines.
func writeTerms(w io.Writer, names *nameSet) error {
	hosts := sortedKeys(names.hosts)
	domains := sortedKeys(names.domains)

	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintln(bw, "# generated by termsgen; one term per line: <literal> [kind] [ignore_case]"); err != nil {
		return err
	}
	for _, h := range hosts {
		if _, err := fmt.Fprintf(bw, "%s host\n", h); err != nil {
			return err
		}
	}
	for _, d := range domains {
		if _, err := fmt.Fprintf(bw, "%s domain\n", d); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
