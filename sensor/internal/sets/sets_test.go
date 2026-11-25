package sets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestObserveKeepsTheTimeACountLastGrew(t *testing.T) {
	tracker := NewTracker(t.TempDir())
	start := time.Unix(1000, 0)
	counts := make([]uint64, 512)
	counts[0], counts[59] = 5, 1
	got := tracker.Observe(7, counts, start)
	want := [][3]uint64{{0, 5, 1000}, {59, 1, 1000}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("first read = %v, want %v", got, want)
	}
	counts[0] = 9
	got = tracker.Observe(7, counts, start.Add(5*time.Second))
	if got[0] != [3]uint64{0, 9, 1005} || got[1] != [3]uint64{59, 1, 1000} {
		t.Fatalf("second read = %v: only the grown count moves", got)
	}
}

func TestObserveTakesAFallenCountAsCountedAgain(t *testing.T) {
	tracker := NewTracker(t.TempDir())
	counts := make([]uint64, 512)
	counts[3] = 40
	tracker.Observe(7, counts, time.Unix(1000, 0))
	counts[3] = 2
	got := tracker.Observe(7, counts, time.Unix(1010, 0))
	if got[0] != [3]uint64{3, 2, 1010} {
		t.Fatalf("after eviction = %v", got)
	}
}

func TestForgetDropsCgroupsTheMapNoLongerHolds(t *testing.T) {
	tracker := NewTracker(t.TempDir())
	counts := make([]uint64, 512)
	counts[1] = 1
	tracker.Observe(7, counts, time.Unix(1000, 0))
	tracker.Observe(8, counts, time.Unix(1000, 0))
	tracker.Forget(map[uint64]bool{8: true})
	if len(tracker.last) != 1 {
		t.Fatalf("remembered %d counts, want the one of cgroup 8", len(tracker.last))
	}
}

func TestPathNamesACgroupByTheInodeOfItsDirectory(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "system.slice", "nginx.service")
	if err := os.MkdirAll(unit, 0o755); err != nil {
		t.Fatal(err)
	}
	inode := func(path string) uint64 {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Sys().(*syscall.Stat_t).Ino
	}
	tracker := NewTracker(root)
	if got := tracker.Path(inode(unit)); got != "/system.slice/nginx.service" {
		t.Fatalf("unit path = %q", got)
	}
	if got := tracker.Path(inode(root)); got != "/" {
		t.Fatalf("root path = %q", got)
	}
	if got := tracker.Path(1 << 40); got != "" {
		t.Fatalf("unknown id = %q, want empty", got)
	}
}

func TestWritePublishesTheBusiestCgroupFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syscall-sets.json")
	err := Write(path, Snapshot{Schema: Schema, Cgroups: []Cgroup{
		{ID: 1, Path: "/a", Calls: [][3]uint64{{0, 2, 0}}},
		{ID: 2, Path: "/b", Calls: [][3]uint64{{0, 5, 0}, {1, 1, 0}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Snapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema || len(got.Cgroups) != 2 || got.Cgroups[0].ID != 2 {
		t.Fatalf("published %+v", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644 for the web app", info.Mode().Perm())
	}
}
