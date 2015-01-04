package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type config struct {
	block *regexp.Regexp
	https *regexp.Regexp
}

var configFormat = regexp.MustCompile(`\A(block|https)\s+([^\s]+)\z`)

func compileMasks(masks []string) *regexp.Regexp {
	if len(masks) == 0 {
		return nil
	}
	var retext string
	for _, mask := range masks {
		mask = regexp.QuoteMeta(mask)
		mask = strings.Replace(mask, "\\?", ".", -1)
		mask = strings.Replace(mask, "\\*", ".*", -1)
		if len(retext) != 0 {
			retext += "|"
		}
		retext += mask
	}
	return regexp.MustCompile(`\A(?:` + retext + `)\z`)
}

func loadConfigReader(reader io.Reader) (*config, error) {
	r := bufio.NewReader(reader)
	var blockmasks []string
	var httpsmasks []string
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
		g := configFormat.FindStringSubmatch(line)
		if g == nil {
			return nil, fmt.Errorf("cannot parse: %s", line)
		}
		switch g[1] {
		case "block":
			blockmasks = append(blockmasks, g[2])
		case "https":
			httpsmasks = append(httpsmasks, g[2])
		default:
			panic("unsupported keyword: " + g[1])
		}
	}
	c := &config{
		block: compileMasks(blockmasks),
		https: compileMasks(httpsmasks),
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
