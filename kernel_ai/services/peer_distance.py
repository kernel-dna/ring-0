"""How far away, in hops, everything this machine talks to is.

Two halves that answer the same question from opposite ends. The near half is
read from the machine's own configuration: the link-layer neighbour, the
router, the DHCP server that handed out the lease, the DNS resolver. Those are
all one step away or less, and no probing is needed to know it.

The far half is the visitor. It cannot be read from configuration and must not
be probed — a visitor who blocks ICMP would simply vanish, and traceroute from
production resolved six hops in twenty-five seconds against a client the TTL
read placed at eleven. So the distance comes from the TTL the kernel already
saw on the inbound SYN, published by the sensor, with the round-trip time from
the kernel's own estimate for that connection.

The contrast between the halves is the point: everything this machine depends
on sits within one step, and the person reading the page is eleven.
"""
from __future__ import annotations

import json
import os
import re

PEER_SNAPSHOT = os.environ.get("PEER_DISTANCE_OUT", "/run/kernel-ai/peer-distance.json")
RESOLV_CONF = "/etc/resolv.conf"
UPSTREAM_RESOLV_CONF = "/run/systemd/resolve/resolv.conf"
LEASE_DIR = "/run/systemd/netif/leases"

# A resolver on the loopback range is systemd-resolved's stub: the query is
# answered without a packet ever leaving the machine, so it is nearer than the
# router it would otherwise have to pass.
_LOOPBACK = re.compile(r"^127\.")


def _read_text(path, open_module=open):
    try:
        with open_module(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return ""


def read_snapshot(path=PEER_SNAPSHOT, open_module=open):
    """The sensor's published TTL map, or an empty one when it is not running."""
    raw = _read_text(path, open_module=open_module)
    if not raw:
        return {"generated_at": None, "peers": []}
    try:
        document = json.loads(raw)
    except ValueError:
        return {"generated_at": None, "peers": []}
    if not isinstance(document, dict):
        return {"generated_at": None, "peers": []}
    peers = document.get("peers")
    document["peers"] = peers if isinstance(peers, list) else []
    return document


def nameservers(resolv_text):
    """Resolver addresses, in the order the resolver library would try them."""
    found = []
    for line in resolv_text.splitlines():
        line = line.strip()
        if not line.startswith("nameserver"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] not in found:
            found.append(parts[1])
    return found


def dhcp_servers(lease_texts):
    """The address that handed out each lease, deduplicated."""
    found = []
    for text in lease_texts:
        match = re.search(r"^SERVER_ADDRESS=(\S+)", text, re.MULTILINE)
        if match and match.group(1) not in found:
            found.append(match.group(1))
    return found


def _lease_texts(lease_dir=LEASE_DIR, os_module=os, open_module=open):
    texts = []
    try:
        names = os_module.listdir(lease_dir)
    except OSError:
        return texts
    for name in sorted(names):
        texts.append(_read_text(os.path.join(lease_dir, name), open_module=open_module))
    return texts


def build_ladder(ip_map, resolv_text, upstream_resolv_text, lease_addresses):
    """The near half: who this machine depends on, and how far each one is.

    Hop counts here are structural rather than measured. A link-layer
    neighbour is reachable without crossing a router, so it is zero hops away;
    anything reached through the default gateway is one. Claiming more
    precision than that would mean probing hosts the machine already knows the
    distance to.
    """
    rungs = []

    neighbours = [entry for entry in (ip_map.get("neigh") or []) if entry.get("ip")]
    for entry in neighbours:
        rungs.append(
            {
                "layer": "L2 / ARP",
                "role": "link neighbour",
                "address": entry.get("ip"),
                "detail": entry.get("mac"),
                "iface": entry.get("iface"),
                "hops": 0,
                "why": "answers on the same wire, no router in between",
            }
        )

    gateways = []
    for route in ip_map.get("routes") or []:
        gateway = route.get("gateway")
        if route.get("default") and gateway and gateway != "*" and gateway not in gateways:
            gateways.append(gateway)
            rungs.append(
                {
                    "layer": "L3 / route",
                    "role": "default router",
                    "address": gateway,
                    "detail": route.get("destination"),
                    "iface": route.get("iface"),
                    "hops": 1,
                    "why": "every packet that leaves this machine starts here",
                }
            )

    for address in lease_addresses:
        rungs.append(
            {
                "layer": "DHCP",
                "role": "lease server",
                "address": address,
                "detail": "handed out this machine's address",
                "iface": None,
                "hops": 0 if address in [n.get("ip") for n in neighbours] else 1,
                "why": "the host that told this machine who it is",
            }
        )

    for address in nameservers(resolv_text):
        stub = bool(_LOOPBACK.match(address))
        rungs.append(
            {
                "layer": "DNS",
                "role": "stub resolver" if stub else "resolver",
                "address": address,
                "detail": "systemd-resolved" if stub else None,
                "iface": "lo" if stub else None,
                "hops": 0,
                "why": "answered inside this machine, no packet leaves"
                if stub
                else "first address the resolver library tries",
            }
        )

    for address in nameservers(upstream_resolv_text):
        if address in [rung["address"] for rung in rungs]:
            continue
        rungs.append(
            {
                "layer": "DNS",
                "role": "upstream resolver",
                "address": address,
                "detail": "where the stub forwards what it cannot answer",
                "iface": None,
                "hops": 1,
                "why": "the first query that actually leaves the machine",
            }
        )

    return rungs


def describe_visitor(source_ip, snapshot, rtt=None):
    """The far half: the reader of the page, placed by TTL rather than probing."""
    if not source_ip:
        return None
    record = None
    for peer in snapshot.get("peers") or []:
        if peer.get("address") == source_ip:
            record = peer
            break

    visitor = {
        "address": source_ip,
        "hops": record.get("hops") if record else None,
        "ttl": record.get("ttl") if record else None,
        "initial_ttl": record.get("initial_ttl") if record else None,
        "family": record.get("family") if record else None,
        "connections": record.get("connections") if record else None,
        "rtt_ms": None,
        "min_rtt_ms": None,
        "measured": bool(record),
        # Said plainly, because an absent number here is the normal case on a
        # development box with no outside visitors, not a fault.
        "why_absent": None if record else "the sensor has not seen a connection from this address",
    }

    if rtt and rtt.get("found"):
        visitor["rtt_ms"] = rtt.get("rtt_ms")
        visitor["min_rtt_ms"] = rtt.get("min_rtt_ms")
    return visitor


def get_neighbourhood(source_ip, ip_map, rtt=None, *, snapshot_path=PEER_SNAPSHOT, os_module=os, open_module=open):
    """Everything the page needs: the near ladder, the visitor, and the gap."""
    snapshot = read_snapshot(snapshot_path, open_module=open_module)
    ladder = build_ladder(
        ip_map,
        _read_text(RESOLV_CONF, open_module=open_module),
        _read_text(UPSTREAM_RESOLV_CONF, open_module=open_module),
        dhcp_servers(_lease_texts(os_module=os_module, open_module=open_module)),
    )
    visitor = describe_visitor(source_ip, snapshot, rtt=rtt)
    nearest = min((rung["hops"] for rung in ladder), default=None)
    farthest_near = max((rung["hops"] for rung in ladder), default=None)
    return {
        "generated_at": snapshot.get("generated_at"),
        "sensor_publishing": bool(snapshot.get("generated_at")),
        "ladder": ladder,
        "visitor": visitor,
        "nearest_hops": nearest,
        "farthest_local_hops": farthest_near,
    }
