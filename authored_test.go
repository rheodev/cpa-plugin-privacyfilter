package main

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// The tests of this file hold the authorship rule, see authorship: a value
// the model wrote first stays in clear for the rest of the conversation, a
// value the user's side had first stays replaced, and the term list and
// the listed networks are replaced whoever wrote them. The bodies are
// built with json.Marshal over maps, which orders the keys alphabetically,
// so the system prompt comes after the messages in every body here; the
// rule orders it first all the same.
//
// Every invented name stands here once, as a constant, and the paths are
// built from them: the names are the subject of the tests, and a test that
// carried a slipped one would hold nothing.
const (
	byUser    = "projekt"       // a directory the user names first
	byUserToo = "geheim"        // another one
	byModel   = "hallo"         // the directory the model creates
	fromFile  = "akte"          // a directory from a file the user points at
	inSystem  = "mandant"       // a directory the system prompt names
	withTerm  = "nuc-sicherung" // a directory the model names with the host term inside
	besideIt  = "ablage"        // the one the model names next to it
	userFile  = "vertrag.pdf"   // a file the user names first
	modelFile = "notes.md"      // a file the model names
	ownMail   = "test@beispiel.org"
)

// insideAndOutside returns an address inside the first network the plugin
// lists and one outside every listed network. The fixture's network is not
// written here: the addresses are derived from what the plugin loaded, so
// the test holds whatever the fixture says.
func insideAndOutside(t *testing.T, nets []netip.Prefix) (inside, outside string) {
	t.Helper()
	if len(nets) == 0 {
		t.Fatal("the fixture must list a network")
	}
	in := nets[0].Masked().Addr().Next().Next().Next()
	if !nets[0].Contains(in) {
		t.Fatalf("%s is not inside %s", in, nets[0])
	}
	for _, c := range []string{"10.9.8.7", "172.21.9.8", "10.200.100.50"} {
		a := netip.MustParseAddr(c)
		covered := false
		for _, n := range nets {
			covered = covered || n.Contains(a)
		}
		if !covered {
			return in.String(), c
		}
	}
	t.Fatal("no candidate address lies outside the listed networks")
	return "", ""
}

func conversation(t *testing.T, session, system string, messages ...map[string]any) []byte {
	t.Helper()
	req := map[string]any{
		"model":      "claude-fable-5-1",
		"max_tokens": 1024,
		"system":     []any{map[string]any{"type": "text", "text": system}},
		"messages":   messages,
		"metadata":   map[string]any{"user_id": fixtures.UserIDFor(session)},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

func userText(text string) map[string]any {
	return map[string]any{"role": "user", "content": text}
}

func toolResult(text string) map[string]any {
	return map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "tool_result", "tool_use_id": "toolu_01", "content": text},
	}}
}

func assistantBlocks(blocks ...map[string]any) map[string]any {
	content := make([]any, 0, len(blocks))
	for _, b := range blocks {
		content = append(content, b)
	}
	return map[string]any{"role": "assistant", "content": content}
}

func assistantBash(command string) map[string]any {
	return assistantBlocks(map[string]any{
		"type": "tool_use", "id": "toolu_01", "name": "Bash",
		"input": map[string]any{"command": command},
	})
}

func assistantWrite(path, content string) map[string]any {
	return assistantBlocks(map[string]any{
		"type": "tool_use", "id": "toolu_01", "name": "Write",
		"input": map[string]any{"file_path": path, "content": content},
	})
}

// outgoing runs the forward pass and returns the body that would leave.
func outgoing(t *testing.T, p *privacyFilterPlugin, requestID string, body []byte) string {
	t.Helper()
	resp := beforeAuth(t, p, requestID, body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	if len(resp.Body) == 0 {
		return string(body)
	}
	if !json.Valid(resp.Body) {
		t.Fatalf("rewritten body is not valid JSON: %s", resp.Body)
	}
	return string(resp.Body)
}

// assertMemoryConsistent holds the invariant of the memory: every value the
// table holds is remembered as seen and none of them as the model's own.
func assertMemoryConsistent(t *testing.T, p *privacyFilterPlugin, requestID string, body []byte) {
	t.Helper()
	table := p.tableOf(t, requestID)
	session := pseudo.IdentifySession(http.Header{}, body)
	gen := pseudo.NewGenerator(p.secret, pseudo.DeriveSalt(p.secret, session.Key()), p.renderers)
	mem := p.store.Memory(session.Key())
	for _, e := range table.Entries() {
		key := string(gen.Digest(e.Kind, e.Original, 0)[:mapping.MemoryKeyLen])
		if mem.Authored(key) {
			t.Errorf("%s %q is in the table and marked as the model's own", e.Kind, e.Original)
		}
		if !mem.Seen(key) {
			t.Errorf("%s %q is in the table and not remembered as seen", e.Kind, e.Original)
		}
	}
}

// wantClear fails for every name of secrets that stands in out, and for
// every name of own whose count in out differs from the one wanted.
func wantClear(t *testing.T, out string, secrets []string, own map[string]int) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%q left in clear although the user's side had it first: %s", s, out)
		}
	}
	for s, n := range own {
		if got := strings.Count(out, s); got != n {
			t.Errorf("%q written by the model must stand %d times, found %d: %s", s, n, got, out)
		}
	}
}

// The case that started it: the model creates a directory, and the listing
// that comes back shows it under the name the model gave it, in the mkdir
// and in the listing alike. The directories the user's side named first,
// in the prompt, stay replaced.
func TestAuthored_ModelNamedDirectoryStaysInClear(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	project := "/tmp/" + byUser
	body := conversation(t, fixtures.SessionA, "Du arbeitest im Projekt.",
		userText("Lege unter "+project+" ein Verzeichnis "+byModel+" an. Nebenan liegt "+project+"/"+byUserToo+"/."),
		assistantBash("mkdir -p "+project+"/"+byModel),
		toolResult(""),
		assistantBash("ls -d "+project+"/*/"),
		toolResult(project+"/"+byUserToo+"/\n"+project+"/"+byModel+"/\n"),
	)
	out := outgoing(t, p, "req-1", body)
	wantClear(t, out, []string{byUser, byUserToo}, map[string]int{"/" + byModel: 2})
	assertMemoryConsistent(t, p, "req-1", body)
}

// A value the user's side had first stays replaced when the model repeats
// it, restored by the client, in its own turn: from the prompt as from the
// system prompt, which the body here carries behind the messages.
func TestAuthored_UserSideFirstStaysReplaced(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	file := "/home/" + fromFile + "/x"
	dir := "/home/" + inSystem + "/"
	body := conversation(t, fixtures.SessionA, "Kundenordner: "+dir+".",
		userText("Siehe "+file+"."),
		assistantBash("cat "+file+" && ls "+dir),
		toolResult("Inhalt von "+file+"\n"+dir+"a.txt\n"),
	)
	out := outgoing(t, p, "req-1", body)
	wantClear(t, out, []string{fromFile, inSystem}, nil)
	assertMemoryConsistent(t, p, "req-1", body)
}

// A term is never the model's to give away: a directory the model named
// with the host term inside is replaced as a whole, the one next to it
// stays.
func TestAuthored_TermInsideTheModelsNameStaysReplaced(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body := conversation(t, fixtures.SessionA, "Sichere die Daten.",
		userText("Leg los."),
		assistantBash("mkdir /tmp/"+withTerm+" /tmp/"+besideIt),
		toolResult(""),
		assistantBash("ls -d /tmp/*/"),
		toolResult("/tmp/"+withTerm+"/\n/tmp/"+besideIt+"/\n"),
	)
	out := outgoing(t, p, "req-1", body)
	if strings.Contains(out, "nuc") {
		t.Errorf("the host term inside the model's directory name left in clear: %s", out)
	}
	if strings.Contains(out, strings.TrimPrefix(withTerm, "nuc-")) {
		t.Errorf("the directory around the term must be replaced as a whole: %s", out)
	}
	wantClear(t, out, nil, map[string]int{"/" + besideIt: 2})
	assertMemoryConsistent(t, p, "req-1", body)
}

// The rule holds for every kind: an address and a mail address the model
// put into a script come back from the script's output as written. An
// address inside a listed network is replaced whoever wrote it.
func TestAuthored_PatternsTheModelWroteStayExceptInListedNetworks(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	netAddr, ownAddr := insideAndOutside(t, p.networks)
	script := "/tmp/" + besideIt + "/test.py"
	body := conversation(t, fixtures.SessionA, "Schreibe Tests.",
		userText("Schreib ein Testskript."),
		assistantWrite(script, "MAIL = '"+ownMail+"'\nHOST = '"+ownAddr+"'\nGW = '"+netAddr+"'\n"),
		toolResult("ok"),
		assistantBash("python3 "+script),
		toolResult(ownMail+" "+ownAddr+" "+netAddr+"\n"),
	)
	out := outgoing(t, p, "req-1", body)
	wantClear(t, out, nil, map[string]int{ownMail: 2, ownAddr: 2, script: 2})
	if strings.Contains(out, netAddr) {
		t.Errorf("an address inside a listed network left in clear: %s", out)
	}
	assertMemoryConsistent(t, p, "req-1", body)
}

// With filenames replaced too, a file the model named keeps its name in
// the listing; the file and the directory the user named first stay
// replaced.
func TestAuthored_FilenameTheModelChoseStays(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	dir := "/tmp/" + byUser
	body := conversation(t, fixtures.SessionA, "Notizen.",
		userText("Lege Notizen an, Vorlage ist "+dir+"/"+userFile+"."),
		assistantWrite(dir+"/"+modelFile, "# Notizen\n"),
		toolResult("ok"),
		assistantBash("ls "+dir+"/*"),
		toolResult(dir+"/"+modelFile+"\n"+dir+"/"+userFile+"\n"),
	)
	out := outgoing(t, p, "req-1", body)
	wantClear(t, out, []string{byUser, userFile}, map[string]int{"/" + modelFile: 2})
	assertMemoryConsistent(t, p, "req-1", body)
}

// The memory bridges the pause and the compaction: after the table has
// expired and the history has been folded into a summary on the user's
// side, the directory the model named is still the model's, and the one
// the plugin replaced before is still replaced.
func TestAuthored_MemoryBridgesExpiryAndCompaction(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	now := time.Unix(1_700_000_000, 0)
	p.store = mapping.NewStore(mapping.StoreConfig{TTL: time.Minute, Now: func() time.Time { return now }})
	project := "/tmp/" + byUser

	first := conversation(t, fixtures.SessionA, "Du arbeitest im Projekt.",
		userText("Lege unter "+project+" ein Verzeichnis "+byModel+" an."),
		assistantBash("mkdir -p "+project+"/"+byModel),
		toolResult(""),
		assistantBash("ls -d "+project+"/*/"),
		toolResult(project+"/"+byModel+"/\n"),
	)
	out := outgoing(t, p, "req-1", first)
	wantClear(t, out, []string{byUser}, map[string]int{"/" + byModel: 2})

	now = now.Add(2 * time.Minute)
	if _, err := p.store.Get("req-1"); err == nil {
		t.Fatal("the table must have expired for this test to mean anything")
	}
	second := conversation(t, fixtures.SessionA, "Du arbeitest im Projekt.",
		userText("Zusammenfassung des bisherigen Gesprächs: unter "+project+"/"+byModel+"/ wurde ein Verzeichnis angelegt."),
		assistantBash("ls "+project+"/"+byModel+"/"),
		toolResult(project+"/"+byModel+"/a.txt\n"),
	)
	out = outgoing(t, p, "req-2", second)
	wantClear(t, out, []string{byUser}, map[string]int{"/" + byModel: 3})
	assertMemoryConsistent(t, p, "req-2", second)
}

// The window the memory closes: after the pause, a history whose user-side
// origin of a value is gone and whose model turn still carries the value,
// restored by the client. Without a memory the model looks like the
// author; with the memory of the first request the value stays replaced.
func TestAuthored_SeenValueStaysReplacedAfterThePause(t *testing.T) {
	file := "/home/" + fromFile + "/x"
	history := func() []byte {
		return conversation(t, fixtures.SessionA, "Arbeite weiter.",
			userText("Weiter."),
			assistantBash("cat "+file),
			toolResult("Inhalt von "+file+"\n"),
		)
	}
	fresh := newPseudoPlugin(t, nil)
	if out := outgoing(t, fresh, "req-0", history()); strings.Count(out, "/"+fromFile+"/") != 2 {
		t.Fatalf("without a memory the value counts as the model's own: %s", out)
	}

	p := newPseudoPlugin(t, nil)
	now := time.Unix(1_700_000_000, 0)
	p.store = mapping.NewStore(mapping.StoreConfig{TTL: time.Minute, Now: func() time.Time { return now }})
	out := outgoing(t, p, "req-1", conversation(t, fixtures.SessionA, "Arbeite weiter.", userText("Siehe "+file+".")))
	wantClear(t, out, []string{fromFile}, nil)
	now = now.Add(2 * time.Minute)
	out = outgoing(t, p, "req-2", history())
	wantClear(t, out, []string{fromFile}, nil)
}

// A thinking block is read by nobody: a name the model gives only there is
// not the model's as far as the plugin can tell, and the listing that shows
// it is replaced. The block itself stays as it is, so the name stands there
// and nowhere else.
func TestAuthored_ThinkingDoesNotMakeTheModelTheAuthor(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	dir := "/tmp/" + byModel + "/"
	body := conversation(t, fixtures.SessionA, "Entwürfe.",
		userText("Leg einen Ordner an."),
		assistantBlocks(
			map[string]any{"type": "thinking", "thinking": "Ich nenne ihn " + dir + ".", "signature": "sig"},
			map[string]any{"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": map[string]any{"command": "ls -d /tmp/*/"}},
		),
		toolResult(dir+"\n"),
	)
	out := outgoing(t, p, "req-1", body)
	if got := strings.Count(out, dir); got != 1 {
		t.Errorf("the name from the thinking block must stand there and nowhere else, found %d times: %s", got, out)
	}
	assertMemoryConsistent(t, p, "req-1", body)
}
