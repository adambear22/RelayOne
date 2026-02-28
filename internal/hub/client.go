package hub

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait        = 30 * time.Second
	readWait         = 60 * time.Second
	maxMessageSize   = 1 << 20
	writeBatchWindow = 100 * time.Millisecond
	writeBufferBytes = 4096
	maxBatchMessages = 128
)

type AgentClient struct {
	ID   string
	Conn *websocket.Conn
	Send chan []byte
	Done chan struct{}

	hub            *Hub
	lastPongUnix   atomic.Int64
	unregisterOnce sync.Once
	closeOnce      sync.Once
}

func NewAgentClient(id string, conn *websocket.Conn, h *Hub) *AgentClient {
	client := &AgentClient{
		ID:   id,
		Conn: conn,
		Send: make(chan []byte, 256),
		Done: make(chan struct{}),
		hub:  h,
	}
	client.markPong(time.Now().UTC())
	return client
}

func (c *AgentClient) Start() {
	go c.writePump()
	go c.readPump()
}

func (c *AgentClient) writePump() {
	defer c.unregister()
	defer c.closeConn()

	for {
		select {
		case <-c.Done:
			return
		case message := <-c.Send:
			batch := c.collectBatch(message)
			if len(batch) == 0 {
				continue
			}

			payload := encodeMessageBatch(batch)
			if len(payload) == 0 {
				continue
			}

			if err := c.Conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}

			writer, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			if _, err := writer.Write(payload); err != nil {
				_ = writer.Close()
				return
			}
			if err := writer.Close(); err != nil {
				return
			}
		}
	}
}

func (c *AgentClient) readPump() {
	defer c.unregister()
	defer c.closeConn()

	c.Conn.SetReadLimit(maxMessageSize)
	if err := c.Conn.SetReadDeadline(time.Now().Add(readWait)); err != nil {
		return
	}
	c.Conn.SetPongHandler(func(_ string) error {
		now := time.Now().UTC()
		c.markPong(now)
		return c.Conn.SetReadDeadline(now.Add(readWait))
	})

	for {
		messageType, message, err := c.Conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}

		c.markPong(time.Now().UTC())
		c.hub.HandleMessage(c, message)
	}
}

func (c *AgentClient) unregister() {
	c.unregisterOnce.Do(func() {
		if c.hub != nil {
			c.hub.Unregister(c)
		}
	})
}

func (c *AgentClient) closeConn() {
	c.closeOnce.Do(func() {
		close(c.Done)
		_ = c.Conn.Close()
	})
}

func (c *AgentClient) LastPong() time.Time {
	unix := c.lastPongUnix.Load()
	if unix <= 0 {
		return time.Time{}
	}
	return time.Unix(0, unix).UTC()
}

func (c *AgentClient) markPong(ts time.Time) {
	c.lastPongUnix.Store(ts.UnixNano())
}

func (c *AgentClient) collectBatch(first []byte) [][]byte {
	batch := make([][]byte, 0, maxBatchMessages)
	batch = append(batch, first)

	timer := time.NewTimer(writeBatchWindow)
	defer timer.Stop()

	for len(batch) < maxBatchMessages {
		select {
		case <-c.Done:
			return batch
		case message := <-c.Send:
			batch = append(batch, message)
		case <-timer.C:
			return batch
		}
	}

	return batch
}

func encodeMessageBatch(messages [][]byte) []byte {
	if len(messages) == 0 {
		return nil
	}
	if len(messages) == 1 {
		return messages[0]
	}

	totalSize := writeBufferBytes
	for _, message := range messages {
		totalSize += len(message) + 1
	}

	var buf bytes.Buffer
	buf.Grow(totalSize)
	buf.WriteByte('[')
	for index, message := range messages {
		if index > 0 {
			buf.WriteByte(',')
		}
		buf.Write(message)
	}
	buf.WriteByte(']')

	return buf.Bytes()
}
