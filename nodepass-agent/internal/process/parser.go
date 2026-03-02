package process

import (
	"fmt"
	"regexp"
	"strings"
)

type CredentialParser interface {
	Parse(line string) (addr, key string, found bool)
}

type RegexCredentialParser struct {
	masterPatterns []*regexp.Regexp
	keyPatterns    []*regexp.Regexp
}

func NewDefaultCredentialParser() CredentialParser {
	masterPatterns := []string{
		`NodePass master listening on:\s*(\S+)`,
		`MASTER_ADDR\s*=\s*(\S+)`,
		`API endpoint:\s*(\S+)`,
	}
	keyPatterns := []string{
		`API Key:\s*(\S+)`,
		`API_KEY\s*=\s*(\S+)`,
	}
	parser, _ := NewRegexCredentialParser(masterPatterns, keyPatterns)
	return parser
}

func NewRegexCredentialParser(masterPatterns, keyPatterns []string) (*RegexCredentialParser, error) {
	parser := &RegexCredentialParser{}

	for _, pattern := range masterPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile master pattern %q: %w", pattern, err)
		}
		parser.masterPatterns = append(parser.masterPatterns, re)
	}
	for _, pattern := range keyPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile key pattern %q: %w", pattern, err)
		}
		parser.keyPatterns = append(parser.keyPatterns, re)
	}

	return parser, nil
}

func (p *RegexCredentialParser) Parse(line string) (addr, key string, found bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}

	for _, re := range p.masterPatterns {
		matches := re.FindStringSubmatch(trimmed)
		if len(matches) > 1 {
			candidate := strings.TrimSpace(matches[1])
			if candidate != "" {
				if !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") {
					candidate = "http://" + candidate
				}
				return candidate, "", true
			}
		}
	}
	for _, re := range p.keyPatterns {
		matches := re.FindStringSubmatch(trimmed)
		if len(matches) > 1 {
			candidate := strings.TrimSpace(matches[1])
			if candidate != "" {
				return "", candidate, true
			}
		}
	}

	return "", "", false
}
