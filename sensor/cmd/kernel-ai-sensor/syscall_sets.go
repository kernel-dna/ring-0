package main

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/cilium/ebpf"

	sensorbpf "kernel-ai/sensor/internal/bpf"
	"kernel-ai/sensor/internal/sets"
)

// publishSyscallSets republishes every cgroup's calls on an interval. Like the
// peer map the counts are read rather than drained: a count since the start
// answers whether a unit makes a call at all, and the tracker adds when it
// last did.
func publishSyscallSets(ctx context.Context, counts *ebpf.Map, cfg config, started time.Time) {
	ticker := time.NewTicker(cfg.setsSnapshotInterval)
	defer ticker.Stop()
	tracker := sets.NewTracker(sets.CgroupRoot)
	var lastFailure string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		cgroups, err := readSyscallSets(counts, tracker, now)
		if err == nil {
			err = sets.Write(cfg.setsSnapshotPath, sets.Snapshot{
				Schema:      sets.Schema,
				GeneratedAt: now.UTC().Format(time.RFC3339Nano),
				Since:       started.UTC().Format(time.RFC3339Nano),
				IntervalS:   cfg.setsSnapshotInterval.Seconds(),
				Arch:        runtime.GOARCH,
				Cgroups:     cgroups,
			})
		}
		if err != nil {
			// one journal line per new failure, not one per interval
			if message := err.Error(); message != lastFailure {
				lastFailure = message
				log.Printf("syscall sets snapshot: %v", err)
			}
			continue
		}
		lastFailure = ""
	}
}

func readSyscallSets(counts *ebpf.Map, tracker *sets.Tracker, now time.Time) ([]sets.Cgroup, error) {
	var (
		id      uint64
		value   sensorbpf.SyscallSet
		cgroups []sets.Cgroup
	)
	present := map[uint64]bool{}
	entries := counts.Iterate()
	for entries.Next(&id, &value) {
		present[id] = true
		cgroups = append(cgroups, sets.Cgroup{
			ID:    id,
			Path:  tracker.Path(id),
			Calls: tracker.Observe(id, value.Calls[:], now),
		})
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("iterate syscall sets: %w", err)
	}
	tracker.Forget(present)
	return cgroups, nil
}
