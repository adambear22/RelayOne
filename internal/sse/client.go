package sse

import (
	"sync"
	"sync/atomic"
)

type SSEClient struct {
	UserID string
	Role   string
	Ch     chan SSEEvent
	Done   chan struct{}

	fullStreak atomic.Int32
	closeOnce  sync.Once
}

func NewClient(userID, role string) *SSEClient {
	return &SSEClient{
		UserID: userID,
		Role:   role,
		Ch:     make(chan SSEEvent, 512),
		Done:   make(chan struct{}),
	}
}

func (c *SSEClient) Close() {
	if c == nil {
		return
	}

	c.closeOnce.Do(func() {
		close(c.Done)
	})
}

func (c *SSEClient) MarkDispatchSuccess() {
	if c == nil {
		return
	}
	c.fullStreak.Store(0)
}

func (c *SSEClient) MarkDispatchFull() int32 {
	if c == nil {
		return 0
	}
	return c.fullStreak.Add(1)
}
