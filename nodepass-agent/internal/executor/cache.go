package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type InstanceCache struct {
	sync.RWMutex
	items    map[string]CacheItem
	filePath string
}

type CacheItem struct {
	RuleID     string `json:"rule_id"`
	InstanceID string `json:"instance_id"`
	Status     string `json:"status"`
	CreatedAt  int64  `json:"created_at"`
}

func NewInstanceCache(workDir string) *InstanceCache {
	return &InstanceCache{
		items:    make(map[string]CacheItem),
		filePath: filepath.Join(workDir, "instance_cache.json"),
	}
}

func (c *InstanceCache) Load() error {
	c.Lock()
	defer c.Unlock()

	content, err := os.ReadFile(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(content) == 0 {
		return nil
	}

	items := make(map[string]CacheItem)
	if err := json.Unmarshal(content, &items); err != nil {
		return err
	}
	c.items = items
	return nil
}

func (c *InstanceCache) Save() error {
	c.RLock()
	content, err := json.MarshalIndent(c.items, "", "  ")
	c.RUnlock()
	if err != nil {
		return err
	}
	content = append(content, '\n')

	if err := os.MkdirAll(filepath.Dir(c.filePath), 0o755); err != nil {
		return err
	}
	tmp := c.filePath + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.filePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (c *InstanceCache) Get(ruleID string) (CacheItem, bool) {
	c.RLock()
	defer c.RUnlock()
	item, ok := c.items[ruleID]
	return item, ok
}

func (c *InstanceCache) Set(item CacheItem) error {
	if item.CreatedAt == 0 {
		item.CreatedAt = time.Now().Unix()
	}

	c.Lock()
	c.items[item.RuleID] = item
	c.Unlock()
	return c.Save()
}

func (c *InstanceCache) Delete(ruleID string) error {
	c.Lock()
	delete(c.items, ruleID)
	c.Unlock()
	return c.Save()
}

func (c *InstanceCache) Items() map[string]CacheItem {
	c.RLock()
	defer c.RUnlock()
	copyItems := make(map[string]CacheItem, len(c.items))
	for k, v := range c.items {
		copyItems[k] = v
	}
	return copyItems
}
