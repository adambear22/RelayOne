package service

import "testing"

func TestCompile_ThreeLayerPriority(t *testing.T) {
	systemTLS := 2
	nodeTLS := 1
	ruleTLS := 0

	systemMode := "safe"
	nodeMode := "mix"
	ruleMode := "fast"

	systemMin := 64
	nodeMin := 32
	ruleMin := 16

	systemMax := 4096
	nodeMax := 2048
	ruleMax := 1024

	systemRate := 300
	nodeRate := 120
	ruleRate := 60

	systemNoTCP := true
	nodeNoTCP := false
	ruleNoTCP := true

	systemNoUDP := false
	nodeNoUDP := true
	ruleNoUDP := false

	systemLog := "error"
	nodeLog := "info"
	ruleLog := "debug"

	compiled := Compile(
		NodePassParams{
			TLS:   &systemTLS,
			Mode:  &systemMode,
			Min:   &systemMin,
			Max:   &systemMax,
			Rate:  &systemRate,
			NoTCP: &systemNoTCP,
			NoUDP: &systemNoUDP,
			Log:   &systemLog,
		},
		NodePassParams{
			TLS:   &nodeTLS,
			Mode:  &nodeMode,
			Min:   &nodeMin,
			Max:   &nodeMax,
			Rate:  &nodeRate,
			NoTCP: &nodeNoTCP,
			NoUDP: &nodeNoUDP,
			Log:   &nodeLog,
		},
		NodePassParams{
			TLS:   &ruleTLS,
			Mode:  &ruleMode,
			Min:   &ruleMin,
			Max:   &ruleMax,
			Rate:  &ruleRate,
			NoTCP: &ruleNoTCP,
			NoUDP: &ruleNoUDP,
			Log:   &ruleLog,
		},
	)

	if compiled.TLS == nil || *compiled.TLS != ruleTLS {
		t.Fatalf("expected tls %d, got %+v", ruleTLS, compiled.TLS)
	}
	if compiled.Mode == nil || *compiled.Mode != ruleMode {
		t.Fatalf("expected mode %q, got %+v", ruleMode, compiled.Mode)
	}
	if compiled.Min == nil || *compiled.Min != ruleMin {
		t.Fatalf("expected min %d, got %+v", ruleMin, compiled.Min)
	}
	if compiled.Max == nil || *compiled.Max != ruleMax {
		t.Fatalf("expected max %d, got %+v", ruleMax, compiled.Max)
	}
	if compiled.Rate == nil || *compiled.Rate != ruleRate {
		t.Fatalf("expected rate %d, got %+v", ruleRate, compiled.Rate)
	}
	if compiled.NoTCP == nil || *compiled.NoTCP != ruleNoTCP {
		t.Fatalf("expected notcp %t, got %+v", ruleNoTCP, compiled.NoTCP)
	}
	if compiled.NoUDP == nil || *compiled.NoUDP != ruleNoUDP {
		t.Fatalf("expected noudp %t, got %+v", ruleNoUDP, compiled.NoUDP)
	}
	if compiled.Log == nil || *compiled.Log != ruleLog {
		t.Fatalf("expected log %q, got %+v", ruleLog, compiled.Log)
	}
}

func TestCompile_DefaultValues(t *testing.T) {
	compiled := Compile(NodePassParams{}, NodePassParams{}, NodePassParams{})

	if compiled.TLS == nil || *compiled.TLS != DefaultTLS {
		t.Fatalf("expected default tls %d, got %+v", DefaultTLS, compiled.TLS)
	}
	if compiled.Mode == nil || *compiled.Mode != DefaultMode {
		t.Fatalf("expected default mode %q, got %+v", DefaultMode, compiled.Mode)
	}
	if compiled.Min == nil || *compiled.Min != DefaultMin {
		t.Fatalf("expected default min %d, got %+v", DefaultMin, compiled.Min)
	}
	if compiled.Max == nil || *compiled.Max != DefaultMax {
		t.Fatalf("expected default max %d, got %+v", DefaultMax, compiled.Max)
	}
	if compiled.Rate == nil || *compiled.Rate != DefaultRate {
		t.Fatalf("expected default rate %d, got %+v", DefaultRate, compiled.Rate)
	}
	if compiled.NoTCP == nil || *compiled.NoTCP {
		t.Fatalf("expected default notcp false, got %+v", compiled.NoTCP)
	}
	if compiled.NoUDP == nil || *compiled.NoUDP {
		t.Fatalf("expected default noudp false, got %+v", compiled.NoUDP)
	}
	if compiled.Log == nil || *compiled.Log != DefaultLog {
		t.Fatalf("expected default log %q, got %+v", DefaultLog, compiled.Log)
	}
}

func TestBuildURL_OnlyNonDefaultParams(t *testing.T) {
	url := BuildURL("tcp", "example.com", 3000, "alice", "secret", NodePassParams{})
	// #nosec G101 -- test fixture only.
	want := "tcp://alice:secret@example.com:3000"
	if url != want {
		t.Fatalf("unexpected url: want %q, got %q", want, url)
	}
}

func TestBuildURL_FullParams(t *testing.T) {
	tls := 2
	mode := "safe"
	min := 3
	max := 2048
	rate := 10
	notcp := true
	noudp := true
	logLevel := "debug"

	url := BuildURL("tcp", "example.com", 4444, "user", "pass", NodePassParams{
		TLS:   &tls,
		Mode:  &mode,
		Min:   &min,
		Max:   &max,
		Rate:  &rate,
		NoTCP: &notcp,
		NoUDP: &noudp,
		Log:   &logLevel,
	})

	want := "tcp://user:pass@example.com:4444?log=debug&max=2048&min=3&mode=safe&notcp=1&noudp=1&rate=10&tls=2"
	if url != want {
		t.Fatalf("unexpected full url: want %q, got %q", want, url)
	}
}

func TestValidate_MinMaxConstraint(t *testing.T) {
	min := 20
	max := 10
	err := Validate(NodePassParams{Min: &min, Max: &max})
	if err == nil {
		t.Fatal("expected validation error when min > max")
	}
}

func TestValidate_BothTCPUDPDisabled(t *testing.T) {
	notcp := true
	noudp := true
	err := Validate(NodePassParams{NoTCP: &notcp, NoUDP: &noudp})
	if err == nil {
		t.Fatal("expected validation error when both TCP and UDP are disabled")
	}
}
