package metrics

import (
	"context"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"

	"nodepass-agent/internal/npapi"
	"nodepass-agent/internal/ws"
)

type sender interface {
	Send(msg []byte) error
}

type instanceLister interface {
	ListInstances() ([]npapi.Instance, error)
}

type systemProvider interface {
	CPUPercent() (float64, error)
	MemoryPercent() (float64, error)
	NetTotalBytes() (uint64, error)
	TCPConnections() (int, error)
}

type Collector struct {
	interval  time.Duration
	wsCli     sender
	npClient  instanceLister
	agentID   string
	provider  systemProvider
	lastTotal uint64
	lastNetAt time.Time
}

type MetricsSnapshot struct {
	CPUPercent    float64 `json:"cpu"`
	MemPercent    float64 `json:"mem"`
	BandwidthMbps float64 `json:"bandwidth_mbps"`
	Connections   int     `json:"connections"`
	Goroutines    int     `json:"goroutines"`
	Timestamp     int64   `json:"timestamp"`
}

type defaultProvider struct{}

func (p *defaultProvider) CPUPercent() (float64, error) {
	values, err := cpu.Percent(500*time.Millisecond, false)
	if err != nil || len(values) == 0 {
		return 0, err
	}
	return values[0], nil
}

func (p *defaultProvider) MemoryPercent() (float64, error) {
	stat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return stat.UsedPercent, nil
}

func (p *defaultProvider) NetTotalBytes() (uint64, error) {
	stats, err := gnet.IOCounters(false)
	if err != nil {
		return 0, err
	}
	if len(stats) == 0 {
		return 0, nil
	}
	return stats[0].BytesSent + stats[0].BytesRecv, nil
}

func (p *defaultProvider) TCPConnections() (int, error) {
	connections, err := gnet.Connections("tcp")
	if err != nil {
		return 0, err
	}
	return len(connections), nil
}

func NewCollector(interval time.Duration, wsCli sender, npClient instanceLister, agentID string) *Collector {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Collector{
		interval: interval,
		wsCli:    wsCli,
		npClient: npClient,
		agentID:  agentID,
		provider: &defaultProvider{},
	}
}

func (c *Collector) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	_ = c.collectAndSend()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.collectAndSend()
		}
	}
}

func (c *Collector) collectAndSend() error {
	snapshot, err := c.collect()
	if err != nil {
		return err
	}
	sysInfo := map[string]any{
		"metrics": snapshot,
		"cpu":     snapshot.CPUPercent,
		"mem":     snapshot.MemPercent,
		"bw_mbps": snapshot.BandwidthMbps,
		"conns":   snapshot.Connections,
		"go":      snapshot.Goroutines,
	}
	encoded, err := ws.MarshalWireMessage("StatusReport", "", map[string]any{
		"agent_id": c.agentID,
		"sys_info": sysInfo,
	})
	if err != nil {
		return err
	}
	return c.wsCli.Send(encoded)
}

func (c *Collector) collect() (MetricsSnapshot, error) {
	now := time.Now()

	cpuValue, _ := c.provider.CPUPercent()
	memValue, _ := c.provider.MemoryPercent()
	totalBytes, _ := c.provider.NetTotalBytes()

	bandwidthMbps := 0.0
	if !c.lastNetAt.IsZero() {
		delta := int64(totalBytes - c.lastTotal)
		elapsed := now.Sub(c.lastNetAt).Seconds()
		if elapsed > 0 && delta >= 0 {
			bandwidthMbps = float64(delta) / elapsed * 8 / 1e6
		}
	}
	c.lastTotal = totalBytes
	c.lastNetAt = now

	connections := c.connectionsFromNodePass()
	if connections == 0 {
		connections, _ = c.provider.TCPConnections()
	}

	return MetricsSnapshot{
		CPUPercent:    cpuValue,
		MemPercent:    memValue,
		BandwidthMbps: bandwidthMbps,
		Connections:   connections,
		Goroutines:    runtime.NumGoroutine(),
		Timestamp:     now.Unix(),
	}, nil
}

func (c *Collector) connectionsFromNodePass() int {
	if c.npClient == nil {
		return 0
	}
	instances, err := c.npClient.ListInstances()
	if err != nil {
		return 0
	}
	total := 0
	for _, ins := range instances {
		total += ins.ActiveConnections
	}
	return total
}
