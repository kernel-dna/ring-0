// Package sets publishes which syscalls each cgroup has made since the sensor
// started: the calls a unit actually uses, which is what a seccomp filter for
// it would be written against.
//
// Like the peer distance map this answers a lookup rather than describing an
// event, so it is a snapshot file, replaced on an interval.
package sets

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// Schema names the snapshot's shape for the web app.
const Schema = "kernel.syscall-sets/v1"

// CgroupRoot is where the unified hierarchy is mounted.
const CgroupRoot = "/sys/fs/cgroup"

// Cgroup is one cgroup as published. Each call is [number, calls, unix second
// the count last grew]; Path is relative to the cgroup root and empty when the
// cgroup was gone before it could be named.
type Cgroup struct {
	ID    uint64      `json:"id"`
	Path  string      `json:"path"`
	Calls [][3]uint64 `json:"calls"`
}

// Snapshot is the published file.
type Snapshot struct {
	Schema      string   `json:"schema"`
	GeneratedAt string   `json:"generated_at"`
	Since       string   `json:"since"`
	IntervalS   float64  `json:"interval_s"`
	Arch        string   `json:"arch"`
	Cgroups     []Cgroup `json:"cgroups"`
}

type key struct {
	cgroup uint64
	nr     uint32
}

type seen struct {
	calls uint64
	moved int64
}

// Tracker remembers, between reads of the map, when each count last grew:
// the kernel side only counts, and "still in use" is a question of time.
type Tracker struct {
	root  string
	last  map[key]seen
	paths map[uint64]string
}

// NewTracker starts with nothing seen. root is the cgroup mount.
func NewTracker(root string) *Tracker {
	return &Tracker{root: root, last: map[key]seen{}, paths: map[uint64]string{}}
}

// Observe takes one cgroup's counts as read now and returns its published
// calls, numbers ascending. A count below the last one read means the cgroup
// was evicted and counted again from zero, and is taken as new.
func (t *Tracker) Observe(cgroup uint64, counts []uint64, now time.Time) [][3]uint64 {
	calls := [][3]uint64{}
	for nr, count := range counts {
		if count == 0 {
			continue
		}
		k := key{cgroup, uint32(nr)}
		was, known := t.last[k]
		if !known || count != was.calls {
			was = seen{calls: count, moved: now.Unix()}
			t.last[k] = was
		}
		calls = append(calls, [3]uint64{uint64(nr), count, uint64(was.moved)})
	}
	return calls
}

// Forget drops what is remembered about cgroups the map no longer holds.
func (t *Tracker) Forget(present map[uint64]bool) {
	for k := range t.last {
		if !present[k.cgroup] {
			delete(t.last, k)
		}
	}
	for id := range t.paths {
		if !present[id] {
			delete(t.paths, id)
		}
	}
}

// Path names a cgroup by its id, which on the unified hierarchy is the inode
// of its directory. The tree is walked only when an id is new, and a name is
// kept once found, so a cgroup that ends between two reads keeps it.
func (t *Tracker) Path(id uint64) string {
	if path, ok := t.paths[id]; ok {
		return path
	}
	_ = filepath.WalkDir(t.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if _, known := t.paths[stat.Ino]; !known {
				relative, _ := filepath.Rel(t.root, path)
				if relative == "." {
					relative = ""
				}
				t.paths[stat.Ino] = "/" + filepath.ToSlash(relative)
			}
		}
		return nil
	})
	path, ok := t.paths[id]
	if !ok {
		// gone before it could be named: not looked for again
		t.paths[id] = ""
	}
	return path
}

// Write publishes the snapshot, busiest cgroup first, to a neighbouring
// temporary file renamed into place, so a reader never sees half a document.
func Write(path string, snapshot Snapshot) error {
	if snapshot.Cgroups == nil {
		snapshot.Cgroups = []Cgroup{}
	}
	total := func(c Cgroup) uint64 {
		var sum uint64
		for _, call := range c.Calls {
			sum += call[1]
		}
		return sum
	}
	sort.SliceStable(snapshot.Cgroups, func(i, j int) bool {
		return total(snapshot.Cgroups[i]) > total(snapshot.Cgroups[j])
	})
	document, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temp snapshot: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(document); err != nil {
		temporary.Close()
		return fmt.Errorf("write temp snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temp snapshot: %w", err)
	}
	// Readable by the web app, which runs as a different user.
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("chmod temp snapshot: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("publish snapshot: %w", err)
	}
	return nil
}
