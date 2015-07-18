package main

import (
	"strings"
	"testing"
)

type configTestCase struct {
	text     string
	expected configActions
}

type configTest struct {
	text   string
	err    string
	checks []configTestCase
}

var configTests = []configTest{
	{
		text: `
# comment
google.com https proxy
*.google.com https direct

# another comment
ads.whatever.com block
		`,
		checks: []configTestCase{
			{"google.com", actionProxy | actionForceHTTPS},
			{"www.google.com", actionDirect | actionForceHTTPS},
			{"www.more.google.com", actionDirect | actionForceHTTPS},
			{"1google.com", actionNone},
		},
	},
	{
		text: `
# these are good
google.com https
ads.whatever.com block
# this line is bad
unexpected
`,
		err: "cannot parse: unexpected",
	},
	{
		text: `
# these are good
google.com https
ads.whatever.com block
# this line is bad
unexpected action
`,
		err: "unknown action: \"action\"",
	},
	{
		text: ``,
		checks: []configTestCase{
			{"google.com", actionNone},
		},
	},
}

func runChecks(t *testing.T, index int, config *config, checks []configTestCase) {
	for _, tc := range checks {
		var actions configActions
		for _, c := range config.cases {
			if c.mask.MatchString(tc.text) {
				actions = c.actions
				break
			}
		}
		if actions != tc.expected {
			t.Fatalf("config #%d %s: %v (expected %v)", index, tc.text, actions, tc.expected)
		}
	}
}

func TestConfig(t *testing.T) {
	for index, ct := range configTests {
		c, err := loadConfigReader(strings.NewReader(ct.text))
		if ct.err != "" {
			if err == nil {
				t.Fatalf("config #%d: expected error, got nil", index)
			}
			if ct.err != err.Error() {
				t.Fatalf("config #%d: expected %q, got %q", index, ct.err, err.Error())
			}
			if c != nil {
				t.Fatalf("config #%d: expected nil config, got %#v", index, c)
			}
			continue
		}
		if err != nil {
			t.Fatalf("config #%d: unexpected error: %s", index, err)
		}
		runChecks(t, index, c, ct.checks)
	}
}
