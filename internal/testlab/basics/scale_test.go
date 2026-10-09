package basics

// Size and speed. A pasted log file carries tens of thousands of distinct
// addresses, every one of which becomes a table entry, and every stream chunk
// of the answer is then matched against that table. Nothing here asserts a
// wall-clock limit as a hard failure; the numbers are the point.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

const logLines = 20000

// A log file pasted into the conversation. Every distinct address becomes an
// entry, and the table never shrinks.
func TestScale_LogDumpGrowsTheTable(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	var sb strings.Builder
	for i := 0; i < logLines; i++ {
		fmt.Fprintf(&sb, "Sep  6 23:%02d:%02d sshd[%d]: Accepted publickey for admin from 10.%d.%d.%d port %d\n",
			i%60, (i*7)%60, 1000+i, (i/65536)%256, (i/256)%256, i%256, 20000+i%40000)
	}
	text := sb.String()
	tab := newTable(t)

	start := time.Now()
	mid := forward(text, d, tab)
	scan := time.Since(start)
	t.Logf("%d lines, %d KiB: forward pass %v, %d entries, longest pseudonym %d",
		logLines, len(text)/1024, scan.Round(time.Millisecond), tab.Len(), tab.MaxPseudonymLen())

	start = time.Now()
	got := back(mid, tab)
	restore := time.Since(start)
	t.Logf("return pass over the same text: %v", restore.Round(time.Millisecond))
	if got != text {
		t.Errorf("the log did not survive the round trip")
	}
}

// The expensive part is not the big text, it is the small one: every chunk of
// the streamed answer is restored against the whole table.
func TestScale_RestoreCostPerChunk(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	tab := newTable(t)
	var sb strings.Builder
	for i := 0; i < logLines; i++ {
		fmt.Fprintf(&sb, "from 10.%d.%d.%d\n", (i/65536)%256, (i/256)%256, i%256)
	}
	_ = forward(sb.String(), d, tab)
	r := tab.Restorer()

	chunk := "Die Antwort besteht aus gewöhnlichem Text ohne jeden Ersatzwert darin."
	const chunks = 2000
	start := time.Now()
	for i := 0; i < chunks; i++ {
		r.Restore(chunk, false)
		r.Holdback(chunk)
	}
	per := time.Since(start) / chunks
	t.Logf("table of %d entries: %v per chunk of %d bytes", tab.Len(), per.Round(time.Microsecond), len(chunk))
	if per > time.Millisecond {
		t.Errorf("a chunk costs %v, which a streamed answer pays hundreds of times", per)
	}
}

// A screenshot arrives as base64 inside the JSON body. It matches nothing,
// but every byte is walked.
func TestScale_Base64Attachment(t *testing.T) {
	blob := strings.Repeat("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg", 20000)
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"` + blob + `"}},{"type":"text","text":"was ist auf zeus.lan los?"}]}]}`)
	t.Logf("body size: %d KiB", len(body)/1024)

	start := time.Now()
	out, n, err := payload.ReplaceStrings(body, payload.DefaultDeny(), replaceHost)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("ReplaceStrings: %v", err)
	}
	t.Logf("walked in %v, %d replacements, output %d KiB", took.Round(time.Millisecond), n, len(out)/1024)
	if n != 1 {
		t.Errorf("expected exactly the one host in the text, got %d", n)
	}
	if took > 2*time.Second {
		t.Errorf("a screenshot costs %v on the forward path, where on_error is block", took)
	}
}

// The same body twice: the walk re-serializes everything once something
// changes, so the attachment is copied even though it was never touched.
func TestScale_UnchangedBodyIsNotCopied(t *testing.T) {
	blob := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", 30000)
	clean := []byte(`{"data":"` + blob + `","text":"nichts zu ersetzen"}`)
	start := time.Now()
	_, n, err := payload.ReplaceStrings(clean, payload.DefaultDeny(), replaceHost)
	t.Logf("no match: %v, replaced=%d err=%v", time.Since(start).Round(time.Millisecond), n, err)

	hit := []byte(`{"data":"` + blob + `","text":"zeus.lan"}`)
	start = time.Now()
	_, n, err = payload.ReplaceStrings(hit, payload.DefaultDeny(), replaceHost)
	t.Logf("one match: %v, replaced=%d err=%v", time.Since(start).Round(time.Millisecond), n, err)
}
