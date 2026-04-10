// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package commit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultTTLMs      = 60_000
	defaultMaxEntries = 128
)

// DefaultTTLMs returns the default cache TTL in milliseconds.
func DefaultTTLMs() int64 { return defaultTTLMs }

// DefaultMaxEntries returns the default cache entry cap.
func DefaultMaxEntries() int { return defaultMaxEntries }

// DirDiskUsageBytes sums file sizes under dir (recursive). Symlink dirs are not followed.
func DirDiskUsageBytes(dirPath string) int64 {
	fi, err := os.Stat(dirPath)
	if err != nil || !fi.IsDir() {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dirPath {
				if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
			}
			return nil
		}
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// StorageSizeCacheKey normalizes cache keys.
func StorageSizeCacheKey(key any) string {
	return fmt.Sprint(key)
}

// StorageSizeCache holds TTL/LRU-ish get/set for size maps.
type StorageSizeCache struct {
	ttlMs      int64
	maxEntries int
	entries    map[string]cacheEntry
}

type cacheEntry struct {
	value   map[string]int64
	expires int64
}

// NewCommitStorageSizeCache builds a cache with optional ttlMs and maxEntries.
func NewCommitStorageSizeCache(opts map[string]any) *StorageSizeCache {
	ttl := int64(defaultTTLMs)
	maxE := defaultMaxEntries
	if opts != nil {
		if v, ok := opts["ttlMs"]; ok {
			fmt.Sscanf(fmt.Sprint(v), "%d", &ttl)
		}
		if v, ok := opts["maxEntries"]; ok {
			fmt.Sscanf(fmt.Sprint(v), "%d", &maxE)
		}
	}
	return &StorageSizeCache{
		ttlMs: ttl, maxEntries: maxE, entries: map[string]cacheEntry{},
	}
}

func (c *StorageSizeCache) prune() {
	now := time.Now().UnixMilli()
	for k, e := range c.entries {
		if now > e.expires {
			delete(c.entries, k)
		}
	}
}

// Get returns a cached value or nil.
func (c *StorageSizeCache) Get(key any) map[string]int64 {
	c.prune()
	k := StorageSizeCacheKey(key)
	e, ok := c.entries[k]
	if !ok {
		return nil
	}
	if time.Now().UnixMilli() > e.expires {
		delete(c.entries, k)
		return nil
	}
	delete(c.entries, k)
	c.entries[k] = e
	return e.value
}

// Set stores a value with TTL.
func (c *StorageSizeCache) Set(key any, value map[string]int64) {
	c.prune()
	k := StorageSizeCacheKey(key)
	delete(c.entries, k)
	for len(c.entries) >= c.maxEntries {
		for fk := range c.entries {
			delete(c.entries, fk)
			break
		}
	}
	c.entries[k] = cacheEntry{
		value:   value,
		expires: time.Now().UnixMilli() + c.ttlMs,
	}
}

// Delete removes a cache entry.
func (c *StorageSizeCache) Delete(key any) {
	delete(c.entries, StorageSizeCacheKey(key))
}

// Clear empties the cache.
func (c *StorageSizeCache) Clear() {
	c.entries = map[string]cacheEntry{}
}

// CommitAuxDirPath returns the commit auxiliary directory for idx.
func CommitAuxDirPath(dataDir string, idx int) (string, error) {
	if idx < 0 || idx > 0xFFFFFFFF {
		return "", fmt.Errorf("Invalid commit idx")
	}
	return filepath.Join(dataDir, "commits", "by-idx", fmt.Sprintf("%08x", idx)), nil
}

// CommitRequestIndexDirPath returns the request index directory for idx.
func CommitRequestIndexDirPath(dataDir string, idx int) (string, error) {
	if idx < 0 || idx > 0xFFFFFFFF {
		return "", fmt.Errorf("Invalid commit idx")
	}
	return filepath.Join(dataDir, "request", fmt.Sprintf("commit:%08x", idx)), nil
}

// MeasureCommitStorageSizes returns commitBytes and requestBytes for idx.
// kernelOrDataDir is either a data directory string or a value with DataDir() string.
func MeasureCommitStorageSizes(kernelOrDataDir any, idx int) (map[string]int64, error) {
	var dataDir string
	switch v := kernelOrDataDir.(type) {
	case string:
		dataDir = v
	case interface{ DataDir() string }:
		dataDir = v.DataDir()
	default:
		return nil, fmt.Errorf("MeasureCommitStorageSizes: need string data dir or DataDir() provider")
	}
	commitDir, err := CommitAuxDirPath(dataDir, idx)
	if err != nil {
		return nil, err
	}
	requestDir, err := CommitRequestIndexDirPath(dataDir, idx)
	if err != nil {
		return nil, err
	}
	return map[string]int64{
		"commitBytes":  DirDiskUsageBytes(commitDir),
		"requestBytes": DirDiskUsageBytes(requestDir),
	}, nil
}
