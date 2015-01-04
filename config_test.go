package main

import (
	"regexp"
	"strings"
	"testing"
)

type configCase struct {
	text string
	ok   bool
}

type configCases struct {
	text  string
	cases []configCase
}

type configTest struct {
	text  string
	err   string
	block configCases
	https configCases
}

var configTests = []configTest{
	{
		text: `
# comment
https google.com
https *.google.com

# another comment
block ads.whatever.com
		`,
		block: configCases{
			text: `\A(?:ads\.whatever\.com)\z`,
			cases: []configCase{
				{"ads.whatever.com", true},
				{"www.ads.whatever.com", false},
			},
		},
		https: configCases{
			text: `\A(?:google\.com|.*\.google\.com)\z`,
			cases: []configCase{
				{"google.com", true},
				{"www.google.com", true},
				{"www.more.google.com", true},
				{"1google.com", false},
			},
		},
	},
	{
		text: `
# these are good
https google.com
block ads.whatever.com
# this line is bad
unexpected line here
`,
		err: "cannot parse: unexpected line here",
	},
	{
		text: ``,
		block: configCases{
			text: ``,
		},
		https: configCases{
			text: ``,
		},
	},
}

func checkCases(t *testing.T, index int, name string, r *regexp.Regexp, cases configCases) {
	if cases.text == "" {
		if r != nil {
			t.Fatalf("config #%d %s: expected nil regexp, got %q", index, name, r.String())
		}
		return
	} else {
		if r == nil {
			t.Fatalf("config #%d %s: expected non-nil regexp, got nil", index, name)
		}
		if cases.text != r.String() {
			t.Fatalf("config #%d %s: expected %q, got %q", index, name, cases.text, r.String())
		}
	}
	for _, c := range cases.cases {
		ok := r.MatchString(c.text)
		if c.ok != ok {
			t.Fatalf("config #%d %s: %s: expected %v, got %v", index, name, c.text, c.ok, ok)
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
		checkCases(t, index, "block", c.block, ct.block)
		checkCases(t, index, "https", c.https, ct.https)
	}
}
