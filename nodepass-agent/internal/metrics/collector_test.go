package metrics

import (
	"encoding/json"
	"testing"
	"time"

	"nodepass-agent/internal/ws"
)

type fakeSender struct {
	last []byte
}

func (f *fakeSender) Send(msg []byte) error {
	f.last = append([]byte(nil), msg...)
	return nil
}

type fakeProvider struct {
	cpu       float64
	mem       float64
	netValues []uint64
	index     int
	conns     int
}

func (p *fakeProvider) CPUPercent() (float64, error) {
	return p.cpu, nil
}

func (p *fakeProvider) MemoryPercent() (float64, error) {
	return p.mem, nil
}

func (p *fakeProvider) NetTotalBytes() (uint64, error) {
	if p.index >= len(p.netValues) {
		return p.netValues[len(p.netValues)-1], nil
	}
	v := p.netValues[p.index]
	p.index++
	return v, nil
}

func (p *fakeProvider) TCPConnections() (int, error) {
	return p.conns, nil
}

func TestCollectorBandwidthDelta(t *testing.T) {
	sender := &fakeSender{}
	collector := NewCollector(30*time.Second, sender, nil, "agent-1")
	collector.provider = &fakeProvider{
		cpu:       10,
		mem:       20,
		netValues: []uint64{3000, 5000},
		conns:     12,
	}

	collector.lastNetAt = time.Now().Add(-2 * time.Second)
	collector.lastTotal = 1000

	snapshot, err := collector.collect()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if snapshot.BandwidthMbps <= 0 {
		t.Fatalf("expected positive bandwidth, got %f", snapshot.BandwidthMbps)
	}
	if snapshot.Connections != 12 {
		t.Fatalf("unexpected connections: %d", snapshot.Connections)
	}

	if err := collector.collectAndSend(); err != nil {
		t.Fatalf("collectAndSend: %v", err)
	}
	if len(sender.last) == 0 {
		t.Fatalf("expected ws payload")
	}

	var msg ws.WireMessage
	if err := json.Unmarshal(sender.last, &msg); err != nil {
		t.Fatalf("decode message: %v", err)
	}
	if msg.Type != "StatusReport" {
		t.Fatalf("unexpected message type: %s", msg.Type)
	}
}
