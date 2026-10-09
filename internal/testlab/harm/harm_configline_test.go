package harm

// Configuration lines. The model is shown a pseudonym of letters, digits and
// a dash, which no configuration format treats as anything but a value, and
// it quotes accordingly - that is, not at all. The user's file then receives
// a line built around the original, and every format has its own set of
// characters that turn a value into structure.
//
// The rules used here are the rules of those formats, not of this plugin:
//
//	dotenv   a newline ends the assignment, an unquoted # begins a comment
//	YAML     a plain scalar ends at a newline, at " #" and at ": "
//	INI      a newline ends the value, ; and # begin a comment in the
//	         common dialects, [ at the start of a line opens a section
//	crontab  the command field is handed to a shell, so its metacharacters
//	         are structure; an unescaped % is turned into a newline and
//	         everything after the first one is fed to the command on
//	         standard input - crontab(5)
//	systemd  no shell at all: ; $ & are ordinary characters in ExecStart,
//	         % introduces a specifier such as %h or %i, a newline ends the
//	         directive
//
// None of the tests runs cron or systemd. They compare the line the model
// wrote with the line the user receives and name the characters that are
// structure in that format and were not there before.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// The structural characters of each format, as the comment above lists them.
const (
	specialsEnv     = "#\n" + quoteChar
	specialsYAML    = "#\n:&*!|>%@"
	specialsINI     = "#;\n["
	specialsCron    = "%;&|`$\n"
	specialsSystemd = "%\n"
)

// quoteChar is the double quote as a constant, so the sets above stay
// constants; the package-level quote is a var for the same reason abs is a
// function.
const quoteChar = `"`

// stripComment models the comment rule of git config and php.ini:
// everything from an unquoted comment character to the end of the line is
// dropped, and trailing blanks with it.
func stripComment(line, marks string) string {
	if i := strings.IndexAny(line, marks); i >= 0 {
		return strings.TrimRight(line[:i], " \t")
	}
	return line
}

// cronCommand models crontab(5): the command field ends at the first
// unescaped percent sign, and what follows becomes standard input.
func cronCommand(field string) (cmd, stdin string) {
	for i := 0; i < len(field); i++ {
		if field[i] != '%' {
			continue
		}
		if i > 0 && field[i-1] == bs[0] {
			continue
		}
		return field[:i], strings.ReplaceAll(field[i+1:], "%", "\n")
	}
	return field, ""
}

// The surface, format by format: which structural characters a line gains
// when the original goes back in. Green, it only measures; the tests after
// it take the cases where the gain changes what the line means.
func TestHarm_ConfigurationLinesGainStructure(t *testing.T) {
	values := []string{
		"Projekt#42",
		"Kunde;Nord",
		"q3%2026",
		"Firma " + quote + "Nordwind" + quote,
		"owner: meier",
		"Sean O'Connor",
		"kunde x & co",
	}
	formats := []struct {
		name     string
		line     func(v string) string
		specials string
	}{
		{"dotenv", func(v string) string { return "OWNER=" + v }, specialsEnv},
		{"yaml", func(v string) string { return "owner: " + v }, specialsYAML},
		{"ini", func(v string) string { return "owner = " + v }, specialsINI},
		{"crontab", func(v string) string { return "0 3 * * * /usr/bin/backup --tag " + v }, specialsCron},
		{"systemd", func(v string) string { return "ExecStart=/usr/bin/backup --tag " + v }, specialsSystemd},
	}
	for _, v := range values {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, v)
		for _, f := range formats {
			model := f.line(aliasValue)
			user := lab.Back(model, tab)
			if gained := newSpecials(model, user, f.specials); gained != "" {
				t.Logf("%-8s %-24q gains %s", f.name, v, gained)
			}
		}
	}
}

// A comment character inside an original truncates the value, and the
// service reads a prefix of what the user configured. Nothing reports it:
// the file is well formed, the value is merely shorter.
//
// The dialects differ and the cases below name the one they mean. git config
// and php.ini end a value at an unquoted # or ; anywhere on the line. YAML
// needs a blank before the #, so only a value that carries one is cut. A
// systemd unit and most dotenv readers take a comment only on a line of its
// own and are not affected.
//
// Through terms.txt a value with a # cannot arrive at all - the loader cuts
// the line at the first one, which is a finding of its own - but the terms
// block of config.yaml passes it through, and a semicolon reaches a value
// through both doors.
func TestHarm_CommentCharacterSwallowsTheValue(t *testing.T) {
	skipOpenFinding(t)
	cases := []struct {
		format string
		value  string
		marks  string
		line   func(v string) string
		cut    func(line string) string
	}{
		{
			format: "git config",
			value:  "Projekt#42",
			marks:  "#",
			line:   func(v string) string { return "\towner = " + v },
			cut:    func(l string) string { return strings.TrimPrefix(stripComment(l, "#"), "\towner = ") },
		},
		{
			format: "php.ini",
			value:  "Kunde;Nord",
			marks:  ";",
			line:   func(v string) string { return "owner = " + v },
			cut:    func(l string) string { return strings.TrimPrefix(stripComment(l, ";"), "owner = ") },
		},
		{
			format: "yaml",
			value:  "Kunde #42",
			marks:  " #",
			line:   func(v string) string { return "owner: " + v },
			cut: func(l string) string {
				v := strings.TrimPrefix(l, "owner: ")
				if i := strings.Index(v, " #"); i >= 0 {
					return v[:i]
				}
				return v
			},
		},
	}
	for _, c := range cases {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, c.value)

		model := c.line(aliasValue)
		if got := c.cut(model); got != aliasValue {
			t.Fatalf("%s: the model's own line is already cut: %q", c.format, got)
		}
		user := lab.Back(model, tab)
		got := c.cut(user)
		t.Logf("%s: model wrote %q, user's parser reads %q", c.format, model, got)
		if got != c.value {
			t.Errorf("%s: the value %q reaches the service as %q, cut at %q",
				c.format, c.value, got, c.marks)
		}
	}
}

// A percent sign in a crontab command field is turned into a newline, and
// everything after the first one is fed to the command on standard input.
// The job then runs with a shorter argument than the model wrote, at the
// scheduled time, without a message anywhere. Neither the shell set of
// characters nor any quoting the model could apply catches this one: only a
// backslash before the percent does, and the model has no reason to write
// it.
func TestHarm_PercentInACrontabLine(t *testing.T) {
	skipOpenFinding(t)
	const value = "q3%2026"
	tab := lab.Table()
	aliasValue := tab.Lookup(detect.KindPathSegment, value)

	model := "0 3 * * * /usr/bin/backup --tag " + aliasValue
	if cmd, in := cronCommand(model); cmd != model || in != "" {
		t.Fatalf("the model's own line is already cut: %q with %q on stdin", cmd, in)
	}
	user := lab.Back(model, tab)
	cmd, in := cronCommand(user)
	t.Logf("model wrote %q\ncron runs   %q\nstdin       %q", model, cmd, in)
	if cmd != user {
		t.Errorf("the job runs %q, the user configured the tag %q, and %q went to standard input",
			strings.TrimPrefix(cmd, "0 3 * * * "), value, in)
	}
}

// A newline inside an original turns one assignment into two, and the second
// one parses as a directive of its own wherever the format is line based.
// The door is the regex term again.
func TestHarm_NewlineSplitsAConfigurationLine(t *testing.T) {
	skipOpenFinding(t)
	const value = "v1\nADMIN_MODE=1"
	tab, aliasValue, d := expression(t, detect.KindPathSegment, "v1\nADMIN_MODE=1", value)

	file := "OWNER=v1\nADMIN_MODE=1\n"
	view := shown(t, file, d, tab, value)
	if n := lines(view); n != 2 {
		t.Fatalf("the model sees %d lines, expected the two-line value collapsed into one: %q", n, view)
	}

	model := "OWNER=" + aliasValue
	user := lab.Back(model, tab)
	t.Logf("model wrote one line %q\nuser receives:\n%s", model, user)
	if n := lines(user); n != 1 {
		t.Errorf("one assignment became %d, the second one being %q",
			n, strings.SplitN(user, "\n", 2)[1])
	}
}

// The control that keeps the shell finding from being carried where it does
// not belong. A systemd unit runs ExecStart without a shell, so a semicolon,
// an ampersand and a dollar sign are ordinary characters there. The percent
// sign is not: it introduces a specifier, and %h expands to the home
// directory of the unit's user.
func TestHarm_SystemdTakesNoShell(t *testing.T) {
	harmless := []string{"a;b", "kunde x & co", "report$(date)"}
	for _, v := range harmless {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, v)
		model := "ExecStart=/usr/bin/backup --tag " + aliasValue
		user := lab.Back(model, tab)
		if gained := newSpecials(model, user, specialsSystemd); gained != "" {
			t.Errorf("%q was expected to stay a plain argument, it gains %s", v, gained)
		}
		t.Logf("harmless in a unit file: %q", v)
	}

	const specifier = "backup%h"
	tab := lab.Table()
	aliasValue := tab.Lookup(detect.KindPathSegment, specifier)
	model := "ExecStart=/usr/bin/backup --tag " + aliasValue
	user := lab.Back(model, tab)
	gained := newSpecials(model, user, specialsSystemd)
	t.Logf("model wrote %q, the unit reads %q, gained %q", model, user, gained)
	if gained == "" {
		t.Errorf("expected the percent sign to appear in the unit line: %q", user)
	}
}
