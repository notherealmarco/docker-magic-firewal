#!/usr/bin/env python3
import os
import json
import logging
import signal
import subprocess
import ipaddress
import re
from docker import from_env
from docker.errors import DockerException

def parse_daemon_json():
    """Parse Docker's daemon.json file to extract IPv4 and IPv6 subnets."""
    config_path = "/etc/docker/daemon.json"
    subnets = []
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            data = json.load(f)
            pools = data.get("default-address-pools", [])
            for pool in pools:
                subnets.append(pool["base"])
    return subnets

def run_iptables_command(command):
    """Run an iptables or ip6tables command."""
    logging.info(f"Running command: {command}")
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running command: {command}\n{e.stderr.decode()}")

def add_rule_if_not_exists(insert_command):
    """Check if the rule exists using iptables -C, and add it if not."""
    check_command = insert_command.replace(" -I ", " -C ", 1).replace(" -A ", " -C ", 1)
    try:
        subprocess.run(check_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.debug(f"Rule already exists: {check_command}")
    except subprocess.CalledProcessError:
        run_iptables_command(insert_command)

def setup_default_rule(subnets, ip_version="ipv4"):
    """Ensure stateful default rules exist in DOCKER-USER chain."""
    # Remove default RETURN statement
    if ip_version == "ipv4":
        run_iptables_command("iptables -D DOCKER-USER -j RETURN")
    else:
        run_iptables_command("ip6tables -D DOCKER-USER -j RETURN")
    for subnet in subnets:
        # IPv4 Rules
        if ip_version == "ipv4" and ":" not in subnet:
            # Allow established connections
            cmd = (f"iptables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || "
                   f"iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            run_iptables_command(cmd)

            # Block new incoming TCP
            cmd = (f"iptables -C DOCKER-USER ! -s {subnet} -d {subnet} -p tcp -m conntrack --ctstate NEW "
                   f"-j REJECT --reject-with icmp-port-unreachable || "
                   f"iptables -A DOCKER-USER ! -s {subnet} -d {subnet} -p tcp -m conntrack --ctstate NEW "
                   f"-j REJECT --reject-with icmp-port-unreachable")
            run_iptables_command(cmd)

            # Block all UDP
            cmd = (f"iptables -C DOCKER-USER ! -s {subnet} -d {subnet} -p udp -j DROP || "
                   f"iptables -A DOCKER-USER ! -s {subnet} -d {subnet} -p udp -j DROP")
            run_iptables_command(cmd)

        # IPv6 Rules
        elif ip_version == "ipv6" and ":" in subnet:
            # Allow established connections
            cmd = (f"ip6tables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || "
                   f"ip6tables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            run_iptables_command(cmd)

            # Block new incoming TCP
            cmd = (f"ip6tables -C DOCKER-USER ! -s {subnet} -d {subnet} -p tcp -m conntrack --ctstate NEW "
                   f"-j REJECT --reject-with icmp6-port-unreachable || "
                   f"ip6tables -A DOCKER-USER ! -s {subnet} -d {subnet} -p tcp -m conntrack --ctstate NEW "
                   f"-j REJECT --reject-with icmp6-port-unreachable")
            run_iptables_command(cmd)

            # Block all UDP
            cmd = (f"ip6tables -C DOCKER-USER ! -s {subnet} -d {subnet} -p udp -j DROP || "
                   f"ip6tables -A DOCKER-USER ! -s {subnet} -d {subnet} -p udp -j DROP")
            run_iptables_command(cmd)

def manage_firewall_rules(container, subnets, ip_version="ipv4"):
    """Add or remove rules based on container labels."""
    container_id = container.id[:12]
    labels = container.labels

    allow_icc = labels.get("magicfw.firewall.allow_icc", "false").lower() == "true"
    allow_external = labels.get("magicfw.firewall.allow_external", "false").lower() == "true"

    if allow_icc:
        logging.info(f"Allowing ICC traffic for container {container_id}")

    if allow_external:
        logging.info(f"Allowing external traffic for container {container_id}")

    ips = []
    network_settings = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    for network_name, network in network_settings.items():
        ip_address = network.get("IPAddress") if ip_version == "ipv4" else network.get("GlobalIPv6Address")
        if ip_address:
            ips.append(ip_address)

    logging.debug(f"Container {container_id} has IPs: {ips}")

    published_ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})

    for ip in ips:
        logging.debug(f"Managing firewall rules for container {container_id} with IP {ip}")
        if allow_icc:
            for subnet in subnets:
                logging.debug(f"Adding rule to allow ICC traffic from {ip} to {subnet}")
                if ip_version == "ipv6" and ":" in subnet:
                    insert_cmd = f"ip6tables -I DOCKER-USER 2 -s {ip} -d {subnet} -j ACCEPT -m comment --comment \"{container_id}:allow_icc\""
                    add_rule_if_not_exists(insert_cmd)
                    insert_cmd = f"ip6tables -I DOCKER-USER 2 -s {subnet} -d {ip} -j ACCEPT -m comment --comment \"{container_id}:allow_icc\""
                    add_rule_if_not_exists(insert_cmd)
                elif ip_version == "ipv4" and ":" not in subnet:
                    insert_cmd = f"iptables -I DOCKER-USER 2 -s {ip} -d {subnet} -j ACCEPT -m comment --comment \"{container_id}:allow_icc\""
                    add_rule_if_not_exists(insert_cmd)
                    insert_cmd = f"iptables -I DOCKER-USER 2 -s {subnet} -d {ip} -j ACCEPT -m comment --comment \"{container_id}:allow_icc\""
                    add_rule_if_not_exists(insert_cmd)

        if allow_external:
            if ip_version == "ipv6" and ":" in ip:
                insert_cmd = f"ip6tables -I DOCKER-USER 2 -d {ip} -j ACCEPT -m comment --comment \"{container_id}:allow_external\""
                add_rule_if_not_exists(insert_cmd)
            elif ip_version == "ipv4" and ":" not in ip:
                insert_cmd = f"iptables -I DOCKER-USER 2 -d {ip} -j ACCEPT -m comment --comment \"{container_id}:allow_external\""
                add_rule_if_not_exists(insert_cmd)

        # Handle exposed ports
        if published_ports:
            logging.info(f"Processing published ports for {container_id}: {published_ports}")
            table = "ip6tables" if ip_version == "ipv6" else "iptables"

            # Delete existing rules for this container's IP and ports
            cmd = (
                f"{table} -S DOCKER-USER | "
                f"grep -E ' --comment \"{container_id}:(published|exposed):' | "  # Clean old+new comments
                f"grep ' -d {ip}/' | "
                "sed 's/^-A/-D/' | xargs -r -L1 echo"
            )
            try:
                result = subprocess.run(cmd, shell=True, check=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for delete_cmd in result.stdout.decode().splitlines():
                    if delete_cmd:
                        run_iptables_command(f"{table} {delete_cmd}")
            except subprocess.CalledProcessError:
                pass  # No rules to delete

            # Add new rules for each published port
            for port_proto, bindings in published_ports.items():
                if not bindings:  # Skip ports that are exposed but not published
                    continue

                proto = port_proto.split('/')[1]
                port = port_proto.split('/')[0]

                insert_cmd = (
                    f"{table} -I DOCKER-USER 2 "
                    f"-d {ip} -p {proto} --dport {port} -j ACCEPT "
                    f"-m comment --comment \"{container_id}:published:{port_proto}\""
                )
                add_rule_if_not_exists(insert_cmd)

def clean_docker_nat_rules(docker_subnets, ip_version="ipv4"):
    """Remove Docker's MASQUERADE rules targeting container subnets."""
    table = "ip6tables" if ip_version == "ipv6" else "iptables"
    chain = "POSTROUTING"
    version = 4 if ip_version == "ipv4" else 6

    try:
        docker_networks = []
        for subnet in docker_subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                if network.version == version:
                    docker_networks.append(network)
            except ValueError:
                continue

        result = subprocess.run(
            f"{table} -t nat -S {chain}",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        rules = result.stdout.decode().splitlines()

        for rule in rules:
            if " -j MASQUERADE" not in rule:
                continue

            parts = rule.split()
            src_net = None
            dst_net = None

            try:
                if "-s" in parts:
                    s_idx = parts.index("-s") + 1
                    src_net = ipaddress.ip_network(parts[s_idx].split("/")[0], strict=False)
                if "-d" in parts:
                    d_idx = parts.index("-d") + 1
                    dst_net = ipaddress.ip_network(parts[d_idx].split("/")[0], strict=False)
            except (ValueError, IndexError):
                continue

            match = False
            for docker_net in docker_networks:
                if src_net and src_net.subnet_of(docker_net):
                    match = True
                    break
                if dst_net and dst_net.subnet_of(docker_net):
                    match = True
                    break

            if match:
                del_rule = rule.replace("-A", "-D")
                run_iptables_command(f"{table} -t nat {del_rule}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error cleaning NAT rules: {e.stderr.decode()}")

def get_docker_bridge_networks():
    """Return IPv4/IPv6 networks for Docker bridge interfaces br-<12hex>.

    Returns:
        (v4_map, v6_map): Tuple of dicts mapping iface -> set(ip_network)
    """
    v4_map = {}
    v6_map = {}
    try:
        res = subprocess.run(
            "ip -j addr show",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        data = json.loads(res.stdout.decode() or "[]")
        br_re = re.compile(r"^br-[0-9a-f]{12}$")
        for iface in data:
            name = iface.get("ifname")
            if not name or not br_re.match(name):
                continue
            for addr in iface.get("addr_info", []):
                local = addr.get("local")
                fam = addr.get("family")
                prefixlen = addr.get("prefixlen")
                if not local or not fam or prefixlen is None:
                    continue
                try:
                    net = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
                except ValueError:
                    continue
                if fam == "inet" and net.version == 4:
                    v4_map.setdefault(name, set()).add(net)
                elif fam == "inet6" and net.version == 6:
                    v6_map.setdefault(name, set()).add(net)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error reading bridge networks: {e.stderr.decode()}")
    except json.JSONDecodeError:
        logging.error("Failed to parse 'ip -j addr show' output")
    return v4_map, v6_map

def clean_docker_raw_prerouting_drop_rules(ip_version="ipv4"):
    """Detect and remove Docker's raw PREROUTING DROP rules that block external ingress to bridge IPs.

    Strategy: match rules that contain all of the following:
      - chain PREROUTING in raw table
      - target DROP
      - negated in-interface for a docker bridge: ! -i br-<12hex>
      - destination equals an IP address assigned to that same bridge
    Only those rules are removed; others are left untouched.
    """
    table = "ip6tables" if ip_version == "ipv6" else "iptables"
    v4_map, v6_map = get_docker_bridge_networks()
    net_map = v6_map if ip_version == "ipv6" else v4_map

    try:
        res = subprocess.run(
            f"{table} -t raw -S PREROUTING",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        rules = res.stdout.decode().splitlines()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error listing raw PREROUTING rules: {e.stderr.decode()}")
        return

    deleted = 0
    br_name_re = re.compile(r"^br-[0-9a-f]{12}$")

    for rule in rules:
        # Only consider append rules with DROP in PREROUTING
        if "-A PREROUTING" not in rule or " -j DROP" not in rule:
            continue

        tokens = rule.split()
        # Find negated -i iface pattern: '! -i br-xxxx' (typical iptables-save format)
        neg_iface = None
        for i in range(len(tokens) - 2):
            if tokens[i] == "!" and tokens[i+1] == "-i":
                neg_iface = tokens[i+2]
                break
        if not neg_iface or not br_name_re.match(neg_iface):
            continue

        # Find destination ip
        dest_ip = None
        for i in range(len(tokens) - 1):
            if tokens[i] == "-d":
                dest_ip = tokens[i+1]
                break
        if not dest_ip:
            continue
        # Strip CIDR if present
        dest_ip_only = dest_ip.split("/")[0]

        # Verify destination belongs to a network on this bridge interface
        try:
            dest_addr = ipaddress.ip_address(dest_ip_only)
        except ValueError:
            continue
        iface_nets = net_map.get(neg_iface, set())
        if not any(dest_addr in n for n in iface_nets):
            continue

        # Construct delete form of the rule; replace first '-A' with '-D'
        del_rule = rule.replace("-A", "-D", 1)
        run_iptables_command(f"{table} -t raw {del_rule}")
        logging.info(f"Removed Docker raw DROP rule: {table} -t raw {del_rule}")
        deleted += 1

    if deleted:
        logging.info(f"Removed {deleted} Docker raw PREROUTING DROP rule(s) for {ip_version}")
    else:
        logging.debug(f"No matching Docker raw PREROUTING DROP rules found for {ip_version}")

def clean_up_rules(docker_client, ip_version="ipv4", specific_container_id=None):
    """Remove stale rules from iptables including published port rules."""
    table = "ip6tables" if ip_version == "ipv6" else "iptables"
    result = subprocess.run(f"{table} -S DOCKER-USER", shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rules = result.stdout.decode().splitlines()

    for rule in rules:
        if "--comment" in rule and any(x in rule for x in
                                       [":allow_icc", ":allow_external", ":exposed:", ":published:"]):

            parts = rule.split("--comment \"")
            if len(parts) < 2:
                continue

            comment_part = parts[1]
            rule_container_id = comment_part.split(":")[0]

            if specific_container_id and rule_container_id != specific_container_id[:12]:
                continue

            try:  # Check if container still exists
                docker_client.containers.get(rule_container_id)
            except DockerException:
                logging.info(f"Removing stale rule for {rule_container_id}")
                delete_rule = rule.replace("-A", "-D")
                run_iptables_command(f"{table} {delete_rule}")

def handle_event(event, docker_client, subnets, enable_ipv4, enable_ipv6):
    """Handle Docker events and update firewall rules accordingly."""
    try:
        if event['Type'] == 'container':
            container_id = event.get('Actor', {}).get('ID')
            action = event.get('Action')

            try:
                container = docker_client.containers.get(container_id) if container_id else None
            except DockerException:
                container = None

            if action in ['start', 'restart']:
                logging.info(f"Container {container_id[:12]} {action}, updating rules")
                if enable_ipv4 and container:
                    manage_firewall_rules(container, subnets, "ipv4")
                if enable_ipv6 and container:
                    manage_firewall_rules(container, subnets, "ipv6")
                # Docker may re-add raw DROP rules on container events; clean them
                if enable_ipv4:
                    clean_docker_raw_prerouting_drop_rules("ipv4")
                if enable_ipv6:
                    clean_docker_raw_prerouting_drop_rules("ipv6")

            elif action in ['die', 'destroy']:
                logging.info(f"Container {container_id[:12]} {action}, cleaning rules")
                if enable_ipv4:
                    clean_up_rules(docker_client, "ipv4", container_id)
                if enable_ipv6:
                    clean_up_rules(docker_client, "ipv6", container_id)

        elif event['Type'] == 'network':
            container_id = event.get('Actor', {}).get('Attributes', {}).get('container')
            action = event.get('Action')

            if action in ['connect', 'disconnect'] and container_id:
                logging.info(f"Network {action} for container {container_id[:12]}")
                try:
                    container = docker_client.containers.get(container_id)
                    if enable_ipv4:
                        manage_firewall_rules(container, subnets, "ipv4")
                    if enable_ipv6:
                        manage_firewall_rules(container, subnets, "ipv6")
                except DockerException:
                    pass

            if action in ['create', 'destroy']:
                logging.info(f"Network {action}, cleaning NAT rules")
                if enable_ipv4:
                    clean_docker_nat_rules(subnets, "ipv4")
                if enable_ipv6:
                    clean_docker_nat_rules(subnets, "ipv6")
                # Also remove any raw DROP rules Docker may have (re)installed
                if enable_ipv4:
                    clean_docker_raw_prerouting_drop_rules("ipv4")
                if enable_ipv6:
                    clean_docker_raw_prerouting_drop_rules("ipv6")

    except Exception as e:
        logging.error(f"Error handling event: {str(e)}")

def main_loop():
    """Main event loop that runs indefinitely."""
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s - %(levelname)s - %(message)s")

    enable_ipv4 = os.getenv("ENABLE_IPV4", "true").lower() == "true"
    enable_ipv6 = os.getenv("ENABLE_IPV6", "true").lower() == "true"
    disable_nat = os.getenv("DISABLE_NAT", "true").lower() == "true"
    disable_raw_drops = os.getenv("REMOVE_RAW_DROPS", "true").lower() == "true"

    subnets = parse_daemon_json()
    docker_client = from_env()

    if disable_nat:
        if enable_ipv4:
            clean_docker_nat_rules(subnets, "ipv4")
        if enable_ipv6:
            clean_docker_nat_rules(subnets, "ipv6")

    if disable_raw_drops:
        if enable_ipv4:
            clean_docker_raw_prerouting_drop_rules("ipv4")
        if enable_ipv6:
            clean_docker_raw_prerouting_drop_rules("ipv6")

    if enable_ipv4:
        setup_default_rule(subnets, "ipv4")
        for container in docker_client.containers.list():
            manage_firewall_rules(container, subnets, "ipv4")
        clean_up_rules(docker_client, "ipv4")

    if enable_ipv6:
        setup_default_rule(subnets, "ipv6")
        for container in docker_client.containers.list():
            manage_firewall_rules(container, subnets, "ipv6")
        clean_up_rules(docker_client, "ipv6")

    event_filter = {"type": ["container", "network"]}
    event_generator = docker_client.events(decode=True, filters=event_filter)

    def shutdown(signum, frame):
        logging.info("Shutting down...")
        exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logging.info("Listening for Docker events...")
    while True:
        try:
            for event in event_generator:
                handle_event(event, docker_client, subnets, enable_ipv4, enable_ipv6)
        except DockerException as e:
            logging.error(f"Docker connection error: {str(e)}. Reconnecting...")
            docker_client = from_env()
            event_generator = docker_client.events(decode=True, filters=event_filter)

if __name__ == "__main__":
    main_loop()