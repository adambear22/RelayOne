package service

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	DefaultTLS  = 1
	DefaultMode = "fast"
	DefaultMin  = 8
	DefaultMax  = 1024
	DefaultRate = 0
	DefaultLog  = "warn"
)

var (
	ErrInvalidNodePassParams = errors.New("invalid nodepass params")
)

type NodePassParams struct {
	TLS   *int    `json:"tls,omitempty"`
	Mode  *string `json:"mode,omitempty"`
	Min   *int    `json:"min,omitempty"`
	Max   *int    `json:"max,omitempty"`
	Rate  *int    `json:"rate,omitempty"`
	NoTCP *bool   `json:"notcp,omitempty"`
	NoUDP *bool   `json:"noudp,omitempty"`
	Log   *string `json:"log,omitempty"`
}

func Compile(systemDefaults, nodeDefaults, ruleOverride NodePassParams) NodePassParams {
	tls := chooseInt(ruleOverride.TLS, nodeDefaults.TLS, systemDefaults.TLS, intConst(DefaultTLS))
	mode := chooseString(ruleOverride.Mode, nodeDefaults.Mode, systemDefaults.Mode, strConst(DefaultMode))
	min := chooseInt(ruleOverride.Min, nodeDefaults.Min, systemDefaults.Min, intConst(DefaultMin))
	max := chooseInt(ruleOverride.Max, nodeDefaults.Max, systemDefaults.Max, intConst(DefaultMax))
	rate := chooseInt(ruleOverride.Rate, nodeDefaults.Rate, systemDefaults.Rate, intConst(DefaultRate))
	notcp := chooseBool(ruleOverride.NoTCP, nodeDefaults.NoTCP, systemDefaults.NoTCP, boolConst(false))
	noudp := chooseBool(ruleOverride.NoUDP, nodeDefaults.NoUDP, systemDefaults.NoUDP, boolConst(false))
	logLevel := chooseString(ruleOverride.Log, nodeDefaults.Log, systemDefaults.Log, strConst(DefaultLog))

	return NodePassParams{
		TLS:   &tls,
		Mode:  &mode,
		Min:   &min,
		Max:   &max,
		Rate:  &rate,
		NoTCP: &notcp,
		NoUDP: &noudp,
		Log:   &logLevel,
	}
}

func BuildURL(instanceType string, host string, port int, user, pass string, params NodePassParams) string {
	scheme := strings.TrimSpace(instanceType)
	if scheme == "" {
		scheme = "tcp"
	}

	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)),
	}

	if strings.TrimSpace(user) != "" || pass != "" {
		u.User = url.UserPassword(user, pass)
	}

	compiled := Compile(NodePassParams{}, NodePassParams{}, params)
	query := url.Values{}
	if value := intValue(compiled.TLS, DefaultTLS); value != DefaultTLS {
		query.Set("tls", strconv.Itoa(value))
	}
	if value := stringValue(compiled.Mode, DefaultMode); value != DefaultMode {
		query.Set("mode", value)
	}
	if value := intValue(compiled.Min, DefaultMin); value != DefaultMin {
		query.Set("min", strconv.Itoa(value))
	}
	if value := intValue(compiled.Max, DefaultMax); value != DefaultMax {
		query.Set("max", strconv.Itoa(value))
	}
	if value := intValue(compiled.Rate, DefaultRate); value != DefaultRate {
		query.Set("rate", strconv.Itoa(value))
	}
	if value := boolValue(compiled.NoTCP, false); value {
		query.Set("notcp", "1")
	}
	if value := boolValue(compiled.NoUDP, false); value {
		query.Set("noudp", "1")
	}
	if value := stringValue(compiled.Log, DefaultLog); value != DefaultLog {
		query.Set("log", value)
	}

	u.RawQuery = query.Encode()
	return u.String()
}

func Validate(params NodePassParams) error {
	if params.TLS != nil {
		if *params.TLS < 0 || *params.TLS > 2 {
			return ErrInvalidNodePassParams
		}
	}

	if params.Min != nil && params.Max != nil && *params.Min > *params.Max {
		return ErrInvalidNodePassParams
	}

	if params.NoTCP != nil && params.NoUDP != nil && *params.NoTCP && *params.NoUDP {
		return ErrInvalidNodePassParams
	}

	return nil
}

func chooseInt(candidates ...*int) int {
	if len(candidates) == 0 {
		return 0
	}
	last := candidates[len(candidates)-1]
	for _, candidate := range candidates[:len(candidates)-1] {
		if candidate != nil {
			return *candidate
		}
	}
	if last == nil {
		return 0
	}
	return *last
}

func chooseString(candidates ...*string) string {
	if len(candidates) == 0 {
		return ""
	}
	last := candidates[len(candidates)-1]
	for _, candidate := range candidates[:len(candidates)-1] {
		if candidate == nil {
			continue
		}
		value := strings.TrimSpace(*candidate)
		if value != "" {
			return value
		}
	}
	if last == nil {
		return ""
	}
	return strings.TrimSpace(*last)
}

func chooseBool(candidates ...*bool) bool {
	if len(candidates) == 0 {
		return false
	}
	last := candidates[len(candidates)-1]
	for _, candidate := range candidates[:len(candidates)-1] {
		if candidate != nil {
			return *candidate
		}
	}
	if last == nil {
		return false
	}
	return *last
}

func intValue(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func stringValue(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func intConst(v int) *int {
	return &v
}

func strConst(v string) *string {
	return &v
}

func boolConst(v bool) *bool {
	return &v
}
