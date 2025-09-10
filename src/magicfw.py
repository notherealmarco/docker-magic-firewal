#!/usr/bin/env python3
"""Docker Magic Firewall v2 (nftables backend)

This module implements the next generation of the project when the Docker
daemon is started with:
    { "iptables": false, "ip6tables": false }

Design Goals (per user requirements):
  - Keep original v1 iptables implementation untouched (see magicfw.py)
  - Provide network isolation across *different* Docker bridge networks.
  - allow_icc label: container (as *initiator*) may originate connections to
    any other container on any other bridge network. Reverse traffic for
    established flows is still allowed via conntrack (stateful acceptance).
  - allow_external label semantics (extended):
        * allow_external=true | yes | 1 | *  => allow all external inbound
        * allow_external=<list> (comma separated) where each element is one of:
              <port>            (defaults to TCP)
              <port>/<proto>    (proto is tcp or udp)
          Only those destination ports are allowed from external hosts.
  - Published ports MUST continue to work even if allow_external is not set,
    matching legacy v1 behaviour where host port mapping stays functional.
    With iptables=false Docker uses the userland docker-proxy; that results in
    NEW connections from the host namespace to the container IP/port. Without
    an explicit allowance these would be dropped by our external ingress drop
    rule. Therefore we treat published ports as an implicit per-port external
    allowance.
  - IPv4 + IPv6 with a single nftables table (family inet).
  - DRY_RUN mode for inspection (does not apply nft changes).
  - Optional cleanup on exit (delete our table) controlled by env var.
  - Clean, composable, well-structured code to ease future extensions
    (e.g., grouping, per-direction policies, overlay networks, etc.).

High-Level nftables Model:

table inet magicfw {
  sets:
    docker_ifaces        => { ifname }                (bridge interfaces)
    allow_icc_v4         => { ipv4_addr }
    allow_icc_v6         => { ipv6_addr }
    external_any_v4      => { ipv4_addr }
    external_any_v6      => { ipv6_addr }
    external_tcp_v4      => { ipv4_addr . inet_service }
    external_udp_v4      => { ipv4_addr . inet_service }
    external_tcp_v6      => { ipv6_addr . inet_service }
    external_udp_v6      => { ipv6_addr . inet_service }

  chain forward (type filter hook forward priority 0; policy accept) {
    # 1. Always allow established/related
    ct state established,related accept

    # 2. External inbound policy (iif NOT docker, oif docker)
    #    Full-open IPs, or port-specific, else drop.
    iifname != @docker_ifaces oifname @docker_ifaces ip   daddr @external_any_v4 accept
    iifname != @docker_ifaces oifname @docker_ifaces ip6  daddr @external_any_v6 accept
    iifname != @docker_ifaces oifname @docker_ifaces tcp  ip   daddr . tcp dport @external_tcp_v4 accept
    iifname != @docker_ifaces oifname @docker_ifaces udp  ip   daddr . udp dport @external_udp_v4 accept
    iifname != @docker_ifaces oifname @docker_ifaces tcp  ip6  daddr . tcp dport @external_tcp_v6 accept
    iifname != @docker_ifaces oifname @docker_ifaces udp  ip6  daddr . udp dport @external_udp_v6 accept
    iifname != @docker_ifaces oifname @docker_ifaces drop

    # 3. Cross-bridge isolation (source bridge != destination bridge) unless
    #    the *source* IP is allow_icc (initiator permission model).
    iifname @docker_ifaces oifname @docker_ifaces iifname != oifname ip  saddr != @allow_icc_v4 drop
    iifname @docker_ifaces oifname @docker_ifaces iifname != oifname ip6 saddr != @allow_icc_v6 drop
  }
}

On each Docker event we recalculate the desired membership of sets and either:
  (a) Rebuild the whole table (initial simple implementation, atomic), or
  (b) (Future) Apply minimal incremental changes.

Edge Cases Considered:
  - Containers without IP yet (race on start): we retry later via events.
  - Multiple networks per container: each IP added individually.
  - IPv6 may be disabled per daemon; code guards with ENABLE_IPV6 env.
  - Duplicate addresses (should not happen) handled via Python set semantics.

Environment Variables:
  LOG_LEVEL          (default INFO)
  ENABLE_IPV4        (default true)
  ENABLE_IPV6        (default true)
  CLEAN_ON_EXIT      (default true) -> delete table inet magicfw on shutdown
  DRY_RUN            (default false) -> only log nft commands
  EVENT_BACKOFF_SECS (default 2) -> minimal sleep on certain transient errors

Future Extensions (not implemented yet):
  - Group-based ICC (label like magicfw.firewall.icc_group)
  - Overlay network support (vxlan interfaces)
  - Per-port ICC exceptions
  - Health / metrics endpoints.
"""

from __future__ import annotations

import os
import signal
import time
import logging
import subprocess
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from docker import from_env
from docker.errors import DockerException

ICC_LABEL = "magicfw.firewall.allow_icc"
EXT_LABEL = "magicfw.firewall.allow_external"


def env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class ContainerNetInfo:
    container_id: str
    ipv4_addrs: Set[str] = field(default_factory=set)
    ipv6_addrs: Set[str] = field(default_factory=set)
    allow_icc_v4: Set[str] = field(default_factory=set)
    allow_icc_v6: Set[str] = field(default_factory=set)
    external_any_v4: Set[str] = field(default_factory=set)
    external_any_v6: Set[str] = field(default_factory=set)
    external_tcp_v4: Set[Tuple[str, int]] = field(default_factory=set)
    external_udp_v4: Set[Tuple[str, int]] = field(default_factory=set)
    external_tcp_v6: Set[Tuple[str, int]] = field(default_factory=set)
    external_udp_v6: Set[Tuple[str, int]] = field(default_factory=set)


class NftManager:
    """Encapsulates nftables interaction.

    Current implementation rebuilds the full table on each sync (simpler /
    safe). Optimization to incremental updates can come later.
    """

    TABLE_NAME = "magicfw"
    FAMILY = "inet"

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, cmd: List[str]):
        if self.dry_run:
            logging.info(f"[DRY-RUN] nft {' '.join(cmd)}")
            return
        try:
            subprocess.run(["nft", *cmd], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            logging.error(f"nft command failed: nft {' '.join(cmd)}\n{e.stderr.decode(errors='ignore')}")

    def apply_table(self, spec: str):
        """Replace the magicfw table with the provided specification.

        We first try to delete existing table (ignore failure) then load new spec.
        The spec itself only contains a 'table' construct (no delete line) to
        avoid parse errors when the table is absent.
        """
        try:
            subprocess.run(["nft", "delete", "table", self.FAMILY, self.TABLE_NAME], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            pass
        if self.dry_run:
            logging.info("[DRY-RUN] applying nft spec:\n" + spec)
            return
        try:
            subprocess.run(["nft", "-f", "-"], input=spec.encode(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply nftables spec:\n{spec}\nError: {e.stderr.decode(errors='ignore')}")

    def delete_table(self):
        self.run(["delete", "table", self.FAMILY, self.TABLE_NAME])

    def build_spec(
        self,
        docker_ifaces: Set[str],
        allow_icc_v4: Set[str], allow_icc_v6: Set[str],
        external_any_v4: Set[str], external_any_v6: Set[str],
        external_tcp_v4: Set[Tuple[str, int]], external_udp_v4: Set[Tuple[str, int]],
        external_tcp_v6: Set[Tuple[str, int]], external_udp_v6: Set[Tuple[str, int]],
    ) -> str:
        """Construct nftables table spec (without pre-delete)."""

        def fmt_set(name: str, type_decl: str, elems: List[str]) -> str:
            # If empty, omit 'elements' clause entirely
            if not elems:
                return f"    set {name} {{ type {type_decl}; }}\n"
            return f"    set {name} {{ type {type_decl}; elements = {{ {', '.join(elems)} }} }}\n"

        def fmt_ip_elems(addrs: Set[str]) -> List[str]:
            return sorted(addrs)

        def fmt_port_elems(entries: Set[Tuple[str, int]]) -> List[str]:
            out = []
            for addr, port in sorted(entries):
                out.append(f"{addr} . {port}")
            return out

        spec = [f"table {self.FAMILY} {self.TABLE_NAME} {{\n"]

        # Sets
        spec.append(fmt_set("docker_ifaces", "ifname", sorted(docker_ifaces)))
        spec.append(fmt_set("allow_icc_v4", "ipv4_addr", fmt_ip_elems(allow_icc_v4)))
        spec.append(fmt_set("allow_icc_v6", "ipv6_addr", fmt_ip_elems(allow_icc_v6)))
        spec.append(fmt_set("external_any_v4", "ipv4_addr", fmt_ip_elems(external_any_v4)))
        spec.append(fmt_set("external_any_v6", "ipv6_addr", fmt_ip_elems(external_any_v6)))
        spec.append(fmt_set("external_tcp_v4", "ipv4_addr . inet_service", fmt_port_elems(external_tcp_v4)))
        spec.append(fmt_set("external_udp_v4", "ipv4_addr . inet_service", fmt_port_elems(external_udp_v4)))
        spec.append(fmt_set("external_tcp_v6", "ipv6_addr . inet_service", fmt_port_elems(external_tcp_v6)))
        spec.append(fmt_set("external_udp_v6", "ipv6_addr . inet_service", fmt_port_elems(external_udp_v6)))

        # Forward chain rules (order matters)
        forward_rules: List[str] = [
            "ct state established,related accept",
            "iifname != @docker_ifaces oifname @docker_ifaces ip daddr @external_any_v4 accept",
            "iifname != @docker_ifaces oifname @docker_ifaces ip6 daddr @external_any_v6 accept",
            # Per-port allowances (layer 3 family first, then tuple)
            "iifname != @docker_ifaces oifname @docker_ifaces ip daddr . tcp dport @external_tcp_v4 accept",
            "iifname != @docker_ifaces oifname @docker_ifaces ip daddr . udp dport @external_udp_v4 accept",
            "iifname != @docker_ifaces oifname @docker_ifaces ip6 daddr . tcp dport @external_tcp_v6 accept",
            "iifname != @docker_ifaces oifname @docker_ifaces ip6 daddr . udp dport @external_udp_v6 accept",
            "iifname != @docker_ifaces oifname @docker_ifaces drop",
        ]

        # Cross-bridge isolation via explicit interface pairs
        if len(docker_ifaces) > 1:
            for src in sorted(docker_ifaces):
                for dst in sorted(docker_ifaces):
                    if src == dst:
                        continue
                    forward_rules.append(f'iifname "{src}" oifname "{dst}" ip saddr != @allow_icc_v4 drop')
                    forward_rules.append(f'iifname "{src}" oifname "{dst}" ip6 saddr != @allow_icc_v6 drop')

        spec.append("    chain forward {\n        type filter hook forward priority 0; policy accept;\n")
        for r in forward_rules:
            spec.append(f"        {r}\n")
        spec.append("    }\n")
        spec.append("}\n")

        return "\n".join(spec)

    def sync(self, state: 'GlobalState'):
        spec = self.build_spec(
            docker_ifaces=state.docker_ifaces,
            allow_icc_v4=state.allow_icc_v4,
            allow_icc_v6=state.allow_icc_v6,
            external_any_v4=state.external_any_v4,
            external_any_v6=state.external_any_v6,
            external_tcp_v4=state.external_tcp_v4,
            external_udp_v4=state.external_udp_v4,
            external_tcp_v6=state.external_tcp_v6,
            external_udp_v6=state.external_udp_v6,
        )
        self.apply_table(spec)


@dataclass
class GlobalState:
    docker_ifaces: Set[str] = field(default_factory=set)
    allow_icc_v4: Set[str] = field(default_factory=set)
    allow_icc_v6: Set[str] = field(default_factory=set)
    external_any_v4: Set[str] = field(default_factory=set)
    external_any_v6: Set[str] = field(default_factory=set)
    external_tcp_v4: Set[Tuple[str, int]] = field(default_factory=set)
    external_udp_v4: Set[Tuple[str, int]] = field(default_factory=set)
    external_tcp_v6: Set[Tuple[str, int]] = field(default_factory=set)
    external_udp_v6: Set[Tuple[str, int]] = field(default_factory=set)

    def reset_dynamic(self):
        # (Reserved for future incremental diff logic)
        pass


class MagicFirewallV2:
    def __init__(self):
        self.enable_ipv4 = env_bool("ENABLE_IPV4", True)
        self.enable_ipv6 = env_bool("ENABLE_IPV6", True)
        self.clean_on_exit = env_bool("CLEAN_ON_EXIT", True)
        self.dry_run = env_bool("DRY_RUN", False)
        self.event_backoff = float(os.getenv("EVENT_BACKOFF_SECS", "2"))
        self.state = GlobalState()
        self.nft = NftManager(dry_run=self.dry_run)
        self.docker_client = from_env()
        self.running = True

    # ---------------- Docker Introspection -----------------
    def list_docker_bridges(self) -> Set[str]:
        """Discover docker bridge interfaces (br-<12hex>)."""
        pattern = re.compile(r"^br-[0-9a-f]{12}$")
        bridges: Set[str] = set()
        try:
            out = subprocess.run(["ip", "-o", "link"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for line in out.stdout.decode().splitlines():
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                name = parts[1].strip()
                if pattern.match(name):
                    bridges.add(name)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to list links: {e.stderr.decode(errors='ignore')}")
        if not bridges:
            logging.warning("No Docker bridge interfaces detected (docker_ifaces set will be empty)")
        else:
            logging.debug(f"Detected Docker bridges: {', '.join(sorted(bridges))}")
        return bridges

    def collect_containers(self) -> List[ContainerNetInfo]:
        infos: List[ContainerNetInfo] = []
        try:
            containers = self.docker_client.containers.list()
        except DockerException as e:
            logging.error(f"Docker list error: {e}")
            return infos
        for c in containers:
            cid = c.id[:12]
            labels = c.labels or {}
            info = ContainerNetInfo(container_id=cid)
            net_settings = c.attrs.get("NetworkSettings", {}).get("Networks", {})
            for net_name, net in net_settings.items():
                ip4 = net.get("IPAddress")
                ip6 = net.get("GlobalIPv6Address")
                if self.enable_ipv4 and ip4:
                    info.ipv4_addrs.add(ip4)
                if self.enable_ipv6 and ip6:
                    info.ipv6_addrs.add(ip6)

            # allow_icc (initiator semantics)
            if labels.get(ICC_LABEL, "false").strip().lower() in {"1", "true", "yes"}:
                info.allow_icc_v4 |= info.ipv4_addrs
                info.allow_icc_v6 |= info.ipv6_addrs

            # allow_external parsing
            raw_ext = labels.get(EXT_LABEL, "false").strip().lower()
            if raw_ext in {"1", "true", "yes", "*"}:
                info.external_any_v4 |= info.ipv4_addrs
                info.external_any_v6 |= info.ipv6_addrs
            elif raw_ext not in {"false", "0", ""}:
                # Port list parsing
                ports = [p.strip() for p in raw_ext.split(",") if p.strip()]
                for token in ports:
                    if "/" in token:
                        port_part, proto = token.split("/", 1)
                        proto = proto.lower()
                    else:
                        port_part, proto = token, "tcp"  # default
                    if not port_part.isdigit():
                        logging.warning(f"Invalid port token '{token}' in {cid}")
                        continue
                    port = int(port_part)
                    if port < 1 or port > 65535:
                        logging.warning(f"Out-of-range port '{port}' in {cid}")
                        continue
                    if proto == "tcp":
                        for ip4 in info.ipv4_addrs:
                            info.external_tcp_v4.add((ip4, port))
                        for ip6 in info.ipv6_addrs:
                            info.external_tcp_v6.add((ip6, port))
                    elif proto == "udp":
                        for ip4 in info.ipv4_addrs:
                            info.external_udp_v4.add((ip4, port))
                        for ip6 in info.ipv6_addrs:
                            info.external_udp_v6.add((ip6, port))
                    else:
                        logging.warning(f"Unsupported proto '{proto}' in token '{token}' for {cid}")

            # Published ports (implicit allow specific ports)
            ports_map = c.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
            for port_proto, bindings in ports_map.items():
                # port_proto example: "8080/tcp"
                if not bindings:
                    continue  # exposed but not published
                try:
                    port_str, proto = port_proto.split("/")
                    port = int(port_str)
                except ValueError:
                    continue
                proto = proto.lower()
                if proto == "tcp":
                    for ip4 in info.ipv4_addrs:
                        info.external_tcp_v4.add((ip4, port))
                    for ip6 in info.ipv6_addrs:
                        info.external_tcp_v6.add((ip6, port))
                elif proto == "udp":
                    for ip4 in info.ipv4_addrs:
                        info.external_udp_v4.add((ip4, port))
                    for ip6 in info.ipv6_addrs:
                        info.external_udp_v6.add((ip6, port))

            infos.append(info)
        return infos

    # ---------------- State Synthesis -----------------
    def rebuild_state(self):
        self.state.docker_ifaces = self.list_docker_bridges()

        # Clear sets
        self.state.allow_icc_v4.clear(); self.state.allow_icc_v6.clear()
        self.state.external_any_v4.clear(); self.state.external_any_v6.clear()
        self.state.external_tcp_v4.clear(); self.state.external_udp_v4.clear()
        self.state.external_tcp_v6.clear(); self.state.external_udp_v6.clear()

        infos = self.collect_containers()
        # Fallback: if docker_ifaces empty but we have containers, attempt to
        # derive bridge names from their networks via /sys/class/net lookup.
        if not self.state.docker_ifaces and infos:
            guessed: Set[str] = set()
            for info in infos:
                # Heuristic: inspect routing table for each IP's dev (ip -j route get)
                for ipaddr in list(info.ipv4_addrs)[:1]:  # sample one per container
                    try:
                        rt = subprocess.run(["ip", "-j", "route", "get", ipaddr],
                                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        import json as _json
                        data = _json.loads(rt.stdout.decode() or '[]')
                        if data and isinstance(data, list):
                            dev = data[0].get('dev')
                            if dev and dev.startswith('br-') and len(dev) == 16:
                                guessed.add(dev)
                    except Exception:
                        continue
            if guessed:
                logging.warning(f"Inferring docker bridges (fallback): {', '.join(sorted(guessed))}")
                self.state.docker_ifaces |= guessed
        for info in infos:
            self.state.allow_icc_v4 |= info.allow_icc_v4
            self.state.allow_icc_v6 |= info.allow_icc_v6
            self.state.external_any_v4 |= info.external_any_v4
            self.state.external_any_v6 |= info.external_any_v6
            self.state.external_tcp_v4 |= info.external_tcp_v4
            self.state.external_udp_v4 |= info.external_udp_v4
            self.state.external_tcp_v6 |= info.external_tcp_v6
            self.state.external_udp_v6 |= info.external_udp_v6
        logging.debug(
            "State summary: bridges=%s allow_icc_v4=%d external_any_v4=%d tcp_v4=%d udp_v4=%d", 
            ','.join(sorted(self.state.docker_ifaces)) or '-',
            len(self.state.allow_icc_v4), len(self.state.external_any_v4),
            len(self.state.external_tcp_v4), len(self.state.external_udp_v4)
        )

    # ---------------- Event Loop -----------------
    def event_loop(self):
        filters = {"type": ["container", "network"]}
        events = self.docker_client.events(decode=True, filters=filters)
        logging.info("Listening for Docker events (v2 nft backend)...")
        while self.running:
            try:
                for event in events:
                    etype = event.get('Type')
                    action = event.get('Action')
                    if etype == 'container' and action in {'start', 'restart', 'die', 'destroy'}:
                        logging.debug(f"Container event {action}")
                        self.rebuild_state()
                        self.nft.sync(self.state)
                    elif etype == 'network' and action in {'create', 'destroy', 'connect', 'disconnect'}:
                        logging.debug(f"Network event {action}")
                        self.rebuild_state()
                        self.nft.sync(self.state)
            except DockerException as e:
                logging.error(f"Docker event stream error: {e}; retrying in {self.event_backoff}s")
                time.sleep(self.event_backoff)
                try:
                    self.docker_client = from_env()
                    events = self.docker_client.events(decode=True, filters=filters)
                except DockerException as e2:
                    logging.error(f"Reconnection failed: {e2}")
            except Exception as e:  # broad catch to keep loop alive
                logging.error(f"Unexpected error in event loop: {e}")
                time.sleep(self.event_backoff)

    # ---------------- Lifecycle -----------------
    def start(self):
        logging.info("Building initial firewall state (v2 nft backend)...")
        self.rebuild_state()
        self.nft.sync(self.state)
        self.event_loop()

    def stop(self, *_):
        self.running = False
        if self.clean_on_exit:
            logging.info("Cleaning up nftables table (CLEAN_ON_EXIT=true)")
            self.nft.delete_table()
        else:
            logging.info("Leaving nftables table intact (CLEAN_ON_EXIT=false)")
        raise SystemExit(0)


def main():
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s - %(levelname)s - %(message)s")
    fw = MagicFirewallV2()
    signal.signal(signal.SIGINT, fw.stop)
    signal.signal(signal.SIGTERM, fw.stop)
    fw.start()


if __name__ == "__main__":
    main()
