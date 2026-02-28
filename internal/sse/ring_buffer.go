package sse

import (
	"strconv"
	"sync"
)

const defaultRingBufferSize = 1000

type RingBuffer struct {
	mu       sync.RWMutex
	capacity int
	items    []SSEEvent
	start    int
	size     int
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = defaultRingBufferSize
	}

	return &RingBuffer{
		capacity: capacity,
		items:    make([]SSEEvent, capacity),
	}
}

func (rb *RingBuffer) Push(event SSEEvent) {
	if rb == nil {
		return
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.size < rb.capacity {
		idx := (rb.start + rb.size) % rb.capacity
		rb.items[idx] = event
		rb.size++
		return
	}

	rb.items[rb.start] = event
	rb.start = (rb.start + 1) % rb.capacity
}

func (rb *RingBuffer) Since(lastID string) []SSEEvent {
	if rb == nil {
		return nil
	}

	rb.mu.RLock()
	snapshot := make([]SSEEvent, 0, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.start + i) % rb.capacity
		snapshot = append(snapshot, rb.items[idx])
	}
	rb.mu.RUnlock()

	if lastID == "" {
		return snapshot
	}

	lastSeq, err := strconv.ParseInt(lastID, 10, 64)
	if err != nil {
		return snapshot
	}

	result := make([]SSEEvent, 0, len(snapshot))
	for _, event := range snapshot {
		seq, err := strconv.ParseInt(event.ID, 10, 64)
		if err != nil {
			continue
		}
		if seq > lastSeq {
			result = append(result, event)
		}
	}

	return result
}
