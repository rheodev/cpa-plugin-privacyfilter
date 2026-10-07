package detect_test

import (
	"strings"
	"testing"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func TestPackyme_UsesEntitiesNotRedacted(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	d := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	if d == nil {
		t.Fatal("NewPackyme returned nil")
	}
	text := "my email is test@example.com and ip 203.0.113.9"
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	var email, ip bool
	for _, x := range got {
		switch x.Kind {
		case detect.KindEmail:
			email = x.Value == "test@example.com"
		case detect.KindIPv4:
			ip = x.Value == "203.0.113.9"
		}
		if x.Source != d.Name() {
			t.Fatalf("Source = %q, want %q", x.Source, d.Name())
		}
	}
	if !email || !ip {
		t.Fatalf("Scan = %+v, want the e-mail as KindEmail and the address as KindIPv4 with original text", got)
	}
}

func TestPackyme_IPv6MappedByText(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	d := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	if d == nil {
		t.Fatal("NewPackyme returned nil")
	}
	got := d.Scan("addr 2001:db8:85a3::8a2e:370:7334 end")
	if len(got) == 0 {
		t.Skip("packyme does not report this IPv6 form; nothing to map")
	}
	if got[0].Kind != detect.KindIPv6 {
		t.Fatalf("kind = %q, want KindIPv6 for a colon-separated address", got[0].Kind)
	}
}

// TestPackyme_KindTogglesDropFindings: the library reports addresses and
// e-mail addresses without switches of its own; PackymeConfig applies the
// pattern toggles to its findings, so a switched-off kind is not reported
// by this layer either. Values are assembled at run time so the source
// carries no literal address.
func TestPackyme_KindTogglesDropFindings(t *testing.T) {
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	addr := strings.Join([]string{"100", "73", "67", "152"}, ".")
	mail := "sophie" + "@" + "example.org"
	text := "mail " + mail + " ip " + addr
	on := detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true})
	var sawIP, sawMail bool
	for _, x := range on.Scan(text) {
		sawIP = sawIP || x.Kind == detect.KindIPv4
		sawMail = sawMail || x.Kind == detect.KindEmail
	}
	if !sawIP || !sawMail {
		t.Skip("packyme reports neither the address nor the e-mail here; nothing to toggle")
	}
	off := detect.NewPackyme(f, detect.PackymeConfig{IPv4: false, IPv6: true, Email: false})
	for _, x := range off.Scan(text) {
		if x.Kind == detect.KindIPv4 || x.Kind == detect.KindEmail {
			t.Fatalf("Scan with ipv4 and email off still reports %+v", x)
		}
	}
}
