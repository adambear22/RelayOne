package reporter

import (
	"errors"
	"testing"

	"nodepass-agent/internal/npapi"
)

type fakeWS struct {
	fail bool
	sent int
}

func (f *fakeWS) Send(msg []byte) error {
	_ = msg
	if f.fail {
		return errors.New("send failed")
	}
	f.sent++
	return nil
}

type fakeInstances struct {
	instances []npapi.Instance
}

func (f *fakeInstances) ListInstances() ([]npapi.Instance, error) {
	return f.instances, nil
}

func TestReporterCollectAggregatesByHour(t *testing.T) {
	ws := &fakeWS{}
	lister := &fakeInstances{instances: []npapi.Instance{{ID: "i1", RuleID: "r1", BytesIn: 100, BytesOut: 200}}}
	r := NewTrafficReporter(0, ws, lister, t.TempDir(), "agent-1")
	r.maxBuffer = 10

	r.collect()
	if len(r.buffer) != 1 {
		t.Fatalf("expected one record after first collect")
	}

	lister.instances = []npapi.Instance{{ID: "i1", RuleID: "r1", BytesIn: 150, BytesOut: 260}}
	r.collect()
	if len(r.buffer) != 1 {
		t.Fatalf("expected aggregation in same hour")
	}
	if r.buffer[0].BytesIn != 150 || r.buffer[0].BytesOut != 260 {
		t.Fatalf("unexpected aggregated bytes: %+v", r.buffer[0])
	}
}

func TestReporterBackpressureDropsOldRecords(t *testing.T) {
	ws := &fakeWS{fail: true}
	lister := &fakeInstances{}
	r := NewTrafficReporter(0, ws, lister, t.TempDir(), "agent-1")
	r.maxBuffer = 3

	failed := []TrafficRecord{
		{RuleID: "a"},
		{RuleID: "b"},
		{RuleID: "c"},
		{RuleID: "d"},
	}
	r.requeueFailed(failed)

	if len(r.buffer) != 3 {
		t.Fatalf("expected buffer trimmed to maxBuffer")
	}
	if r.buffer[0].RuleID != "b" {
		t.Fatalf("expected oldest record dropped, got first=%s", r.buffer[0].RuleID)
	}
}
