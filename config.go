package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type configActions int

const (
	actionNone       configActions = 0
	actionBlock      configActions = 1
	actionProxy      configActions = 2
	actionDirect     configActions = 4
	actionForceHTTPS configActions = 8
)

type configCase struct {
	mask    *regexp.Regexp
	actions configActions
}

type config struct {
	cases []configCase
}

func compileMask(mask string) *regexp.Regexp {
	mask = regexp.QuoteMeta(mask)
	mask = strings.Replace(mask, "\\?", ".", -1)
	mask = strings.Replace(mask, "\\*", ".*", -1)
	return regexp.MustCompile(`\A(?:` + mask + `)\z`)
}

var actionSeparator = regexp.MustCompile(`[ \t]+`)

var actionFromString = map[string]configActions{
	"block":  actionBlock,
	"proxy":  actionProxy,
	"direct": actionDirect,
	"https":  actionForceHTTPS,
}

func loadConfigReader(reader io.Reader) (*config, error) {
	r := bufio.NewReader(reader)
	c := &config{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			if line == "" {
				break
			}
			// parse incomplete lines
		} else {
			// strip the delimiter
			line = line[:len(line)-1]
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			// skip empty lines and comments
			continue
		}
		parts := actionSeparator.Split(line, -1)
		if len(parts) <= 1 {
			return nil, fmt.Errorf("cannot parse: %s", line)
		}
		var actions configActions
		for _, text := range parts[1:] {
			action, ok := actionFromString[strings.ToLower(text)]
			if !ok {
				return nil, fmt.Errorf("unknown action: %q", text)
			}
			actions |= action
		}
		c.cases = append(c.cases, configCase{
			mask:    compileMask(parts[0]),
			actions: actions,
		})
	}
	return c, nil
}

func loadConfigFile(filename string) (*config, error) {
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &config{}, nil
		}
		return nil, err
	}
	defer f.Close()
	return loadConfigReader(f)
}
