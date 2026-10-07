package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// assertBlocked checks that buildPlugin registered the plugin in the blocking
// state: no error from the registration, only the request interceptor
// announced, and every request terminated with status 400 and a message that
// carries each of want. It returns the message, so the caller can check what
// it must not carry.
//
// The state exists because a failed registration is worse than a blocked
// proxy: the host comes up without the filter, logs one line, and forwards
// every request in clear text. A blocked request reaches the user in the
// client at once.
func assertBlocked(t *testing.T, plugin pluginapi.Plugin, err error, want ...string) string {
	t.Helper()
	if err != nil {
		t.Fatalf("buildPlugin returned %v, want a registration in the blocking state", err)
	}
	if plugin.Capabilities.RequestInterceptor == nil {
		t.Fatal("a blocked plugin announces no request interceptor")
	}
	if plugin.Capabilities.ResponseInterceptor != nil || plugin.Capabilities.StreamChunkInterceptor != nil || plugin.Capabilities.RequestLifecyclePlugin != nil {
		t.Error("a blocked plugin announces more than the request interceptor")
	}
	req := pluginapi.RequestInterceptRequest{
		RequestID:    "req-blocked",
		SourceFormat: "claude",
		Model:        "claude-fable-5-1",
		Headers:      http.Header{},
		Body:         []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"hello"}]}`),
	}
	// Both request hooks block: the plugin may have entered the state
	// between the two by a reload.
	after, errAfter := plugin.Capabilities.RequestInterceptor.InterceptRequestAfterAuth(context.Background(), req)
	if errAfter != nil || !after.Terminate || after.StatusCode != http.StatusBadRequest {
		t.Fatalf("blocked request after auth: err=%v terminate=%v status=%d, want a terminated 400", errAfter, after.Terminate, after.StatusCode)
	}
	resp, errReq := plugin.Capabilities.RequestInterceptor.InterceptRequestBeforeAuth(context.Background(), req)
	if errReq != nil {
		t.Fatalf("a blocked request returned an error instead of a terminated response: %v", errReq)
	}
	if !resp.Terminate || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("blocked request: terminate=%v status=%d, want a terminated 400", resp.Terminate, resp.StatusCode)
	}
	var apiErr apiError
	if err := json.Unmarshal(resp.ResponseBody, &apiErr); err != nil {
		t.Fatalf("the blocked response is not an Anthropic-shaped error: %v: %s", err, resp.ResponseBody)
	}
	message := apiErr.Error.Message
	if !strings.Contains(message, "every request is blocked until the configuration is fixed") {
		t.Errorf("the client message %q does not say that every request is blocked", message)
	}
	for _, w := range want {
		if !strings.Contains(message, w) {
			t.Errorf("the client message %q does not carry %q", message, w)
		}
	}
	return message
}

// The whole path of a bad line in the term file, as the user sees it: the
// proxy comes up, the log carries one error line at registration that names
// the line and the class and not the value, and the client gets the same
// message as a 400 at the first request, with a warning line in the log for
// each blocked request. The user confirmed the client side on the live
// system on 23 September 2026; this test holds the plugin side.
func TestBlocked_BadTermLineIsReportedInLogAndClient(t *testing.T) {
	hook := logtest.NewGlobal()
	defer logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))

	dir := t.TempDir()
	termsPath := filepath.Join(dir, "terms.txt")
	file := "# hosts" + string(rune(10)) + "p14 host" + string(rune(10)) + "{value: " + string(rune(34)) + "Meier & Sohn" + string(rune(34)) + ", kind: person}" + string(rune(10))
	if err := os.WriteFile(termsPath, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s.secret"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := "mode: pseudonymize" + string(rune(10)) + "salt_secret_path: " + filepath.Join(dir, "s.secret") + string(rune(10)) + "terms_file: " + termsPath + string(rune(10))
	plugin, err := buildPlugin([]byte(cfgYAML), dir, nil)

	var registered *logrus.Entry
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "registered in blocking state") {
			registered = e
		}
	}
	if registered == nil {
		t.Fatal("no log line says that the plugin registered in blocking state")
	}
	if registered.Level != logrus.ErrorLevel {
		t.Errorf("the registration line has level %s, want error", registered.Level)
	}
	for _, want := range []string{"line 3", "value carries a shell metacharacter (&)", "restarted"} {
		if !strings.Contains(registered.Message, want) {
			t.Errorf("the registration line %q does not carry %q", registered.Message, want)
		}
	}
	if strings.Contains(registered.Message, "Meier") {
		t.Errorf("the registration line %q quotes the value", registered.Message)
	}

	before := len(hook.AllEntries())
	message := assertBlocked(t, plugin, err, "line 3", "value carries a shell metacharacter (&)")
	if strings.Contains(message, "Meier") {
		t.Errorf("the client message %q quotes the value", message)
	}
	var blocked *logrus.Entry
	for _, e := range hook.AllEntries()[before:] {
		if strings.Contains(e.Message, "blocking the request") {
			blocked = e
		}
	}
	if blocked == nil {
		t.Fatal("no log line says that the request was blocked")
	}
	if blocked.Level != logrus.WarnLevel || !strings.Contains(blocked.Message, "line 3") {
		t.Errorf("the blocked-request line is %s %q, want a warning that names line 3", blocked.Level, blocked.Message)
	}
}

// A skipped model or format passes a working plugin unfiltered by the user's
// choice. A blocked plugin filters nothing, so the skip lists do not apply:
// the request is blocked like any other.
func TestBlocked_SkipListsDoNotApply(t *testing.T) {
	dir := t.TempDir()
	cfgYAML := "mode: pseudonymize\nskip_models: [claude-fable-5-1]\nskip_formats: [claude]\n"
	plugin, err := buildPlugin([]byte(cfgYAML), dir, nil)
	assertBlocked(t, plugin, err, "secret")
}
