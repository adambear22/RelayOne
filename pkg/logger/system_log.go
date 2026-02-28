package logger

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	defaultSystemLogCapacity = 1000
	defaultLogPage           = 1
	defaultLogPageSize       = 20
	maxLogPageSize           = 200
)

type SystemLogEntry struct {
	ID         int64                  `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Level      string                 `json:"level"`
	LoggerName string                 `json:"logger_name,omitempty"`
	Message    string                 `json:"message"`
	Caller     string                 `json:"caller,omitempty"`
	Stack      string                 `json:"stack,omitempty"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

type SystemLogStore struct {
	mu       sync.RWMutex
	entries  []SystemLogEntry
	capacity int
	next     int
	count    int
	seq      int64
}

func NewSystemLogStore(capacity int) *SystemLogStore {
	if capacity <= 0 {
		capacity = defaultSystemLogCapacity
	}

	return &SystemLogStore{
		entries:  make([]SystemLogEntry, capacity),
		capacity: capacity,
	}
}

func WrapZapLogger(base *zap.Logger, store *SystemLogStore) *zap.Logger {
	if base == nil || store == nil {
		return base
	}

	return base.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return &systemLogCore{
			Core:  core,
			store: store,
		}
	}))
}

func (s *SystemLogStore) QueryLogs(
	level string,
	from, to time.Time,
	keyword string,
	page, pageSize int,
) ([]SystemLogEntry, int64) {
	if s == nil {
		return nil, 0
	}

	page, pageSize = normalizeLogPagination(page, pageSize)

	normalizedLevel := strings.ToLower(strings.TrimSpace(level))
	normalizedKeyword := strings.ToLower(strings.TrimSpace(keyword))
	hasFrom := !from.IsZero()
	hasTo := !to.IsZero()

	entries := s.snapshotNewestFirst()
	filtered := make([]SystemLogEntry, 0, len(entries))
	for _, entry := range entries {
		if normalizedLevel != "" && !strings.EqualFold(entry.Level, normalizedLevel) {
			continue
		}
		if hasFrom && entry.Timestamp.Before(from.UTC()) {
			continue
		}
		if hasTo && entry.Timestamp.After(to.UTC()) {
			continue
		}
		if normalizedKeyword != "" && !entryContainsKeyword(entry, normalizedKeyword) {
			continue
		}
		filtered = append(filtered, entry)
	}

	total := int64(len(filtered))
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return []SystemLogEntry{}, total
	}

	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}

	pageData := make([]SystemLogEntry, 0, end-start)
	for _, entry := range filtered[start:end] {
		pageData = append(pageData, cloneSystemLogEntry(entry))
	}
	return pageData, total
}

func normalizeLogPagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = defaultLogPage
	}
	if pageSize <= 0 {
		pageSize = defaultLogPageSize
	}
	if pageSize > maxLogPageSize {
		pageSize = maxLogPageSize
	}
	return page, pageSize
}

func entryContainsKeyword(entry SystemLogEntry, keyword string) bool {
	if strings.Contains(strings.ToLower(entry.Message), keyword) {
		return true
	}
	if strings.Contains(strings.ToLower(entry.Level), keyword) {
		return true
	}
	if strings.Contains(strings.ToLower(entry.LoggerName), keyword) {
		return true
	}
	if strings.Contains(strings.ToLower(entry.Caller), keyword) {
		return true
	}
	if len(entry.Fields) > 0 && strings.Contains(strings.ToLower(fmt.Sprintf("%v", entry.Fields)), keyword) {
		return true
	}
	return false
}

func cloneSystemLogEntry(entry SystemLogEntry) SystemLogEntry {
	cloned := entry
	if len(entry.Fields) == 0 {
		return cloned
	}

	fields := make(map[string]interface{}, len(entry.Fields))
	for k, v := range entry.Fields {
		fields[k] = v
	}
	cloned.Fields = fields
	return cloned
}

func (s *SystemLogStore) add(entry zapcore.Entry, fields []zapcore.Field) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	item := SystemLogEntry{
		ID:         s.seq,
		Timestamp:  entry.Time.UTC(),
		Level:      entry.Level.String(),
		LoggerName: entry.LoggerName,
		Message:    entry.Message,
		Caller:     entry.Caller.TrimmedPath(),
		Stack:      entry.Stack,
		Fields:     fieldsToMap(fields),
	}

	s.entries[s.next] = item
	s.next = (s.next + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
}

func fieldsToMap(fields []zapcore.Field) map[string]interface{} {
	if len(fields) == 0 {
		return nil
	}

	enc := zapcore.NewMapObjectEncoder()
	for _, field := range fields {
		field.AddTo(enc)
	}
	if len(enc.Fields) == 0 {
		return nil
	}

	result := make(map[string]interface{}, len(enc.Fields))
	for k, v := range enc.Fields {
		result[k] = v
	}
	return result
}

func (s *SystemLogStore) snapshotNewestFirst() []SystemLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count == 0 {
		return nil
	}

	result := make([]SystemLogEntry, 0, s.count)
	for i := 0; i < s.count; i++ {
		idx := s.next - 1 - i
		if idx < 0 {
			idx += s.capacity
		}
		result = append(result, cloneSystemLogEntry(s.entries[idx]))
	}

	return result
}

type systemLogCore struct {
	zapcore.Core
	store *SystemLogStore
}

func (c *systemLogCore) With(fields []zapcore.Field) zapcore.Core {
	return &systemLogCore{
		Core:  c.Core.With(fields),
		store: c.store,
	}
}

func (c *systemLogCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Core.Check(entry, nil) == nil {
		return checked
	}
	return checked.AddCore(entry, c)
}

func (c *systemLogCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if c.store != nil {
		c.store.add(entry, fields)
	}
	return c.Core.Write(entry, fields)
}
