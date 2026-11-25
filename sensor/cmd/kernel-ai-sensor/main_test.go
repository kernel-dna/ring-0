package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	sensorbpf "kernel-ai/sensor/internal/bpf"
	"kernel-ai/sensor/internal/event"
)

func TestRawEventLayoutMatchesBPF(t *testing.T) {
	if size := binary.Size(sensorbpf.RawEvent{}); size != 304 {
		t.Fatalf("RawEvent size = %d, want 304", size)
	}
}

func sockaddr(family uint16, rest ...byte) []byte {
	data := binary.NativeEndian.AppendUint16(nil, family)
	return append(data, rest...)
}

func TestDecodeSockaddr(t *testing.T) {
	ipv6 := append([]byte{0x01, 0xbb, 0, 0, 0, 0}, net.ParseIP("2001:db8::1")...)
	cases := []struct {
		name string
		data []byte
		want event.Sockaddr
	}{
		{"inet", sockaddr(unix.AF_INET, 0x1f, 0x40, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
			event.Sockaddr{Family: "inet", Addr: "127.0.0.1", Port: 8000}},
		{"inet6", sockaddr(unix.AF_INET6, ipv6...),
			event.Sockaddr{Family: "inet6", Addr: "2001:db8::1", Port: 443}},
		{"unix path", sockaddr(unix.AF_UNIX, append([]byte("/run/x.sock"), 0, 0)...),
			event.Sockaddr{Family: "unix", Path: "/run/x.sock"}},
		{"unix abstract", sockaddr(unix.AF_UNIX, append([]byte{0}, "dbus-1"...)...),
			event.Sockaddr{Family: "unix", Path: "@dbus-1"}},
		{"unspec", sockaddr(unix.AF_UNSPEC), event.Sockaddr{Family: "unspec"}},
		{"netlink", sockaddr(unix.AF_NETLINK, 0, 0, 0, 0), event.Sockaddr{Family: "netlink"}},
		{"unknown family stays numeric", sockaddr(unix.AF_VSOCK, 0, 0), event.Sockaddr{Family: "40"}},
		{"truncated inet keeps the family", sockaddr(unix.AF_INET, 0x1f),
			event.Sockaddr{Family: "inet"}},
	}
	for _, tc := range cases {
		got := decodeSockaddr(tc.data)
		if got == nil || *got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if got := decodeSockaddr([]byte{2}); got != nil {
		t.Errorf("one byte is not an address, got %+v", got)
	}
}

func TestArgumentsOnlyReachTheSecurityView(t *testing.T) {
	raw := sensorbpf.RawEvent{PID: 42, TID: 42, NR: 59, PPID: 7, ArgKind: argPath0}
	path := "/bin/sh\x00garbage"
	raw.ArgLen = uint16(copy(raw.Arg[:], path))
	base := normalize(raw, 1, 0, map[uint32]string{59: "execve"})

	public, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"path"`, `"ppid"`, `"sockaddr"`, `"local_port"`} {
		if strings.Contains(string(public), field) {
			t.Fatalf("latency payload carries %s: %s", field, public)
		}
	}
	secure := securityView(base, raw)
	if secure.Syscall.Path != "/bin/sh" || secure.PPID != 7 {
		t.Fatalf("security view: path=%q ppid=%d", secure.Syscall.Path, secure.PPID)
	}
	if base.Syscall.Path != "" || base.PPID != 0 {
		t.Fatalf("securityView modified the base event")
	}
}

// Both ends of one loopback hop: the connect knows its local port, the accept
// on the other side reads the same number back as its peer.
func TestLoopbackHopEndsShareThePort(t *testing.T) {
	names := map[uint32]string{unix.SYS_CONNECT: "connect", unix.SYS_ACCEPT4: "accept4"}
	connect := sensorbpf.RawEvent{NR: unix.SYS_CONNECT, LocalPort: 51234, ArgKind: argSockaddr1}
	connect.ArgLen = uint16(copy(connect.Arg[:], sockaddr(unix.AF_INET, 0x1f, 0x40, 127, 0, 0, 1)))
	accept := sensorbpf.RawEvent{NR: unix.SYS_ACCEPT4, ArgKind: argSockaddr1}
	accept.ArgLen = uint16(copy(accept.Arg[:], sockaddr(unix.AF_INET, 0xc8, 0x22, 127, 0, 0, 1)))

	public, err := json.Marshal(normalize(connect, 1, 0, names))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), `"local_port"`) {
		t.Fatalf("latency payload carries the local port: %s", public)
	}
	sent := securityView(normalize(connect, 1, 0, names), connect)
	got := securityView(normalize(accept, 2, 0, names), accept)
	if sent.Syscall.LocalPort != 51234 || sent.Syscall.Sockaddr.Port != 8000 {
		t.Fatalf("connect: local port %d, destination %+v", sent.Syscall.LocalPort, sent.Syscall.Sockaddr)
	}
	if got.Syscall.Sockaddr == nil || got.Syscall.Sockaddr.Port != sent.Syscall.LocalPort ||
		got.Syscall.Sockaddr.Addr != "127.0.0.1" || got.Syscall.LocalPort != 0 {
		t.Fatalf("accept4: peer %+v, local port %d", got.Syscall.Sockaddr, got.Syscall.LocalPort)
	}
}

func TestAcceptedVisitorKeepsOnlyTheFamilyAndPort(t *testing.T) {
	names := map[uint32]string{unix.SYS_ACCEPT4: "accept4"}
	ipv6 := append([]byte{0x9c, 0x40, 0, 0, 0, 0}, net.ParseIP("2001:db8::7")...)
	for _, peer := range [][]byte{
		sockaddr(unix.AF_INET, 0x9c, 0x40, 203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0),
		sockaddr(unix.AF_INET6, ipv6...),
	} {
		raw := sensorbpf.RawEvent{NR: unix.SYS_ACCEPT4, ArgKind: argSockaddr1}
		raw.ArgLen = uint16(copy(raw.Arg[:], peer))
		got := securityView(normalize(raw, 1, 0, names), raw)
		if got.Syscall.Sockaddr == nil || got.Syscall.Sockaddr.Addr != "" || got.Syscall.Sockaddr.Port != 40000 {
			t.Fatalf("visitor peer: %+v", got.Syscall.Sockaddr)
		}
	}
	mapped := sensorbpf.RawEvent{NR: unix.SYS_ACCEPT4, ArgKind: argSockaddr1}
	loopback := append([]byte{0x9c, 0x40, 0, 0, 0, 0}, net.ParseIP("::ffff:127.0.0.1")...)
	mapped.ArgLen = uint16(copy(mapped.Arg[:], sockaddr(unix.AF_INET6, loopback...)))
	if got := securityView(normalize(mapped, 1, 0, names), mapped); got.Syscall.Sockaddr.Port != 40000 {
		t.Fatalf("mapped loopback peer lost its port: %+v", got.Syscall.Sockaddr)
	}
}

func TestNormalizeProducesVersionedSyscallSpan(t *testing.T) {
	raw := sensorbpf.RawEvent{
		StartNS:    2_000_000_000,
		EndNS:      2_250_000_000,
		DurationNS: 250_000_000,
		PID:        42,
		TID:        43,
		UID:        1000,
		CPU:        2,
		NR:         98,
		Ret:        0,
		CgroupID:   9001,
		HasWakeup:  1,
		WakeupNS:   2_200_000_000,
		WakerPID:   10,
		WakerTID:   11,
		TargetCPU:  2,
	}
	copy(raw.Comm[:], "worker")
	copy(raw.WakerComm[:], "producer")

	got := normalize(raw, 7, 1_700_000_000_000_000_000, map[uint32]string{98: "futex"})

	if got.Schema != event.SchemaV1 || got.Sequence != 7 || got.Kind != "syscall_span" {
		t.Fatalf("unexpected envelope: %#v", got)
	}
	if got.Syscall.Name != "futex" || got.Syscall.DurationUS != 250_000 {
		t.Fatalf("unexpected syscall: %#v", got.Syscall)
	}
	if got.Comm != "worker" || got.Wakeup == nil || got.Wakeup.WakerComm != "producer" {
		t.Fatalf("unexpected task/wakeup: %#v", got)
	}
}
