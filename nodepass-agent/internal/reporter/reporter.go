package reporter

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"nodepass-agent/internal/npapi"
	"nodepass-agent/internal/ws"
)

type sender interface {
	Send(msg []byte) error
}

type instanceLister interface {
	ListInstances() ([]npapi.Instance, error)
}

type TrafficReporter struct {
	interval time.Duration
	wsCli    sender
	npClient instanceLister
	agentID  string

	buffer []TrafficRecord
	bufMu  sync.Mutex

	lastCounters map[string]counterSnapshot
	maxBuffer    int
	ackTimeout   time.Duration
	waitACK      func(ctx context.Context, records []TrafficRecord) bool
	walPath      string
	counter      atomic.Uint64
}

type counterSnapshot struct {
	bytesIn  int64
	bytesOut int64
}

type TrafficRecord struct {
	RuleID     string `json:"rule_id"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	RecordedAt string `json:"recorded_at"`
}

func NewTrafficReporter(interval time.Duration, wsCli sender, npClient instanceLister, workDir, agentID string) *TrafficReporter {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &TrafficReporter{
		interval:     interval,
		wsCli:        wsCli,
		npClient:     npClient,
		agentID:      agentID,
		lastCounters: make(map[string]counterSnapshot),
		maxBuffer:    10000,
		ackTimeout:   30 * time.Second,
		waitACK: func(ctx context.Context, records []TrafficRecord) bool {
			_ = ctx
			_ = records
			return true
		},
		walPath: filepath.Join(workDir, "traffic_wal.json"),
	}
}

func (r *TrafficReporter) Start(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collect()
			r.report(ctx)
		}
	}
}

func (r *TrafficReporter) collect() {
	instances, err := r.npClient.ListInstances()
	if err != nil {
		return
	}

	nowHour := time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339)
	batch := make([]TrafficRecord, 0, len(instances))

	for _, ins := range instances {
		if ins.RuleID == "" {
			continue
		}
		prev := r.lastCounters[ins.ID]
		deltaIn := ins.BytesIn - prev.bytesIn
		deltaOut := ins.BytesOut - prev.bytesOut
		r.lastCounters[ins.ID] = counterSnapshot{bytesIn: ins.BytesIn, bytesOut: ins.BytesOut}

		if deltaIn <= 0 && deltaOut <= 0 {
			continue
		}
		batch = append(batch, TrafficRecord{
			RuleID:     ins.RuleID,
			BytesIn:    max64(deltaIn, 0),
			BytesOut:   max64(deltaOut, 0),
			RecordedAt: nowHour,
		})
	}

	if len(batch) == 0 {
		return
	}

	r.bufMu.Lock()
	defer r.bufMu.Unlock()
	for _, item := range batch {
		r.upsertLocked(item)
	}
}

func (r *TrafficReporter) report(ctx context.Context) {
	r.bufMu.Lock()
	snapshot := make([]TrafficRecord, len(r.buffer))
	copy(snapshot, r.buffer)
	r.buffer = r.buffer[:0]
	r.bufMu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	for start := 0; start < len(snapshot); start += 100 {
		end := start + 100
		if end > len(snapshot) {
			end = len(snapshot)
		}
		batch := snapshot[start:end]
		msgID, err := r.sendBatch(batch)
		if err != nil {
			r.requeueFailed(batch)
			continue
		}

		ok := r.waitBatchACK(ctx, msgID, batch)
		if !ok {
			r.requeueFailed(batch)
		}
	}
}

func (r *TrafficReporter) sendBatch(records []TrafficRecord) (string, error) {
	type legacyTrafficRecord struct {
		RuleID    string    `json:"rule_id"`
		BytesIn   int64     `json:"bytes_in"`
		BytesOut  int64     `json:"bytes_out"`
		Timestamp time.Time `json:"timestamp"`
	}

	legacyRecords := make([]legacyTrafficRecord, 0, len(records))
	for _, item := range records {
		ts, err := time.Parse(time.RFC3339, item.RecordedAt)
		if err != nil {
			ts = time.Now().UTC()
		}
		legacyRecords = append(legacyRecords, legacyTrafficRecord{
			RuleID:    item.RuleID,
			BytesIn:   item.BytesIn,
			BytesOut:  item.BytesOut,
			Timestamp: ts,
		})
	}

	msgID := strconv.FormatUint(r.counter.Add(1), 10)
	encoded, err := ws.MarshalWireMessage("TrafficReport", msgID, map[string]any{
		"agent_id": r.agentID,
		"records":  legacyRecords,
	})
	if err != nil {
		return "", err
	}
	if err := r.wsCli.Send(encoded); err != nil {
		return "", err
	}
	return msgID, nil
}

func (r *TrafficReporter) requeueFailed(records []TrafficRecord) {
	r.bufMu.Lock()
	defer r.bufMu.Unlock()

	merged := make([]TrafficRecord, 0, len(records)+len(r.buffer))
	merged = append(merged, records...)
	merged = append(merged, r.buffer...)
	if len(merged) > r.maxBuffer {
		merged = merged[len(merged)-r.maxBuffer:]
	}
	r.buffer = merged
}

func (r *TrafficReporter) upsertLocked(item TrafficRecord) {
	for idx := range r.buffer {
		existing := &r.buffer[idx]
		if existing.RuleID == item.RuleID && existing.RecordedAt == item.RecordedAt {
			existing.BytesIn += item.BytesIn
			existing.BytesOut += item.BytesOut
			return
		}
	}
	r.buffer = append(r.buffer, item)
	if len(r.buffer) > r.maxBuffer {
		r.buffer = r.buffer[len(r.buffer)-r.maxBuffer:]
	}
}

func max64(value, min int64) int64 {
	if value < min {
		return min
	}
	return value
}

type ackWaiter interface {
	WaitForACK(msgID string, timeout time.Duration) bool
}

func (r *TrafficReporter) waitBatchACK(ctx context.Context, msgID string, records []TrafficRecord) bool {
	if waiter, ok := r.wsCli.(ackWaiter); ok {
		return waiter.WaitForACK(msgID, r.ackTimeout)
	}

	ackCtx, cancel := context.WithTimeout(ctx, r.ackTimeout)
	defer cancel()
	return r.waitACK(ackCtx, records)
}
