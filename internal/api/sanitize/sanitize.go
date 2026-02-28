package sanitize

import (
	"html"
	"strings"
	"sync"

	"github.com/microcosm-cc/bluemonday"
)

var (
	markdownPolicyOnce sync.Once
	markdownPolicy     *bluemonday.Policy
)

func Text(input string) string {
	return html.EscapeString(strings.TrimSpace(input))
}

func TextPtr(input *string) *string {
	if input == nil {
		return nil
	}
	value := Text(*input)
	return &value
}

func StringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for _, item := range values {
		escaped := Text(item)
		if escaped == "" {
			continue
		}
		out = append(out, escaped)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func Markdown(input string) string {
	value := strings.TrimSpace(input)
	if value == "" {
		return ""
	}
	return getMarkdownPolicy().Sanitize(value)
}

func MarkdownPtr(input *string) *string {
	if input == nil {
		return nil
	}
	value := Markdown(*input)
	return &value
}

func getMarkdownPolicy() *bluemonday.Policy {
	markdownPolicyOnce.Do(func() {
		policy := bluemonday.UGCPolicy()
		policy.AllowElements("p", "pre", "code", "blockquote")
		markdownPolicy = policy
	})

	return markdownPolicy
}
