# Docker Magic Firewall 2.0

## Overview

Docker Magic Firewall (magicfw) is a lightweight daemon that applies host‑level firewall policy for Docker containers using container labels.

Unlike v1, the new version requires to disable Docker's own iptables manipulation by setting the following in `daemon.json`:

```json
{ "iptables": false, "ip6tables": false }
```

**Warning:** the v2.0 does not automatically enable SNAT (yet). If you need it, it's required to configure proper NAT rules on your side. Or you may configure static routes and SNAT on your gateway/router.

### What it does
* Disables / replaces Docker’s own iptables manipulation and enforces isolation rules itself.
* Lets you selectively allow a container to initiate cross‑network traffic (ICC) or accept traffic from external hosts (optionally per-port) using labels.
* Preserves published port behaviour (via docker-proxy in iptables=false mode) while still applying external filtering logic.
* Works for both IPv4 and IPv6 (dual-stack) using a single `nftables` table (`inet magicfw`).

### Key Features
* (v1 & v2) Optional disabling / cleanup of Docker’s NAT constructs.
* (v2) Initiator‑only inter‑container communication control: only containers with the ICC label can start new connections across different bridge networks; replies are allowed statefully.
* (v2) External ingress control: either full open, or a comma‑separated allowlist of ports (with optional protocol) per container.
* (v2) Automatic per‑port allowance for any published ports (`-p` / `ports:`) so existing deployments keep working.
* (v2) Single consolidated nftables policy; atomic rebuild on Docker events.
* Clean rule removal on shutdown (configurable).

### v1 vs v2 Migration Highlights
| Aspect | v1 (iptables) | v2 (nftables) |
|-------|---------------|---------------|
| Backend | iptables/ip6tables + DOCKER-USER | native nftables table `inet magicfw` |
| Docker daemon flags | required iptables=true | supports iptables=false (expected) |
| allow_icc semantics | symmetric (both directions implicitly) | initiator only (source must have label; replies allowed) |
| allow_external value | boolean only | boolean OR port list (e.g. `80,443,8443/udp`) |
| Published ports | Accepted by explicit rules in DOCKER-USER | Auto-added as per-port external allowances (docker-proxy) |
| Rule scale | O(containers * subnets) | Mostly constant (sets/maps) |
| Cleanup | Inline chain edits | Table deletion (optional) |
| IPv4/IPv6 duplication | Separate chains | Unified via inet family |

If you keep using v1 (iptables true) continue running `magicfw.py`. For v2 with iptables disabled run the v2 script (e.g. `magicfw_v2_nft.py`).

### Container Labels (v2 semantics)
Use labels to control per‑container policy:

| Label | Values | Meaning |
|-------|--------|---------|
| `magicfw.firewall.allow_icc` | `true` / `false` | If `true`, container may INITIATE connections to containers on other Docker bridge networks (replies allowed). If `false`, it can still talk to same-network peers but cross-network attempts are blocked (unless the other container is on the default bridge and you haven’t opted to isolate it). |
| `magicfw.firewall.allow_external` | `true`, `*`, or a comma list like `80,443,8080/udp,8443` | `true` / `*` opens all inbound from external hosts (non‑Docker interfaces). A port list opens only those destination ports (TCP default unless `/udp` specified). Empty / `false` blocks unsolicited external ingress (published ports still work individually). |

### Runtime Behaviour (v2)
* Inter-Container (cross-bridge) isolation: blocked unless the source container has `allow_icc=true`.
* Same bridge traffic: untouched (Docker’s normal intra-network connectivity retained).
* External inbound (from non‑Docker interfaces):
  * Fully allowed if `allow_external` full-open.
  * Allowed only on listed ports if a port list is used.
  * Blocked otherwise (except for published ports which are implicitly allowed per-port).
* Published ports: each published container port is inserted as a per-port external allowance automatically.
* Stateful: replies to permitted outbound connections always allowed (conntrack established/related).
* Default bridge (docker0): currently NOT isolated unless you opt to add it to the enforcement set (future option). User-defined bridges (`br-<id>`) are enforced.

## Install
To make the installation easy, I provide a package for Debian-based distros, follow the instructions here: [https://git.marcorealacci.me/marcorealacci/-/packages/debian/magicfw-docker](https://git.marcorealacci.me/marcorealacci/-/packages/debian/magicfw-docker)

To install the script manually, the required dependencies are `python3` and the `docker` library available from PyPI (`pip3 install docker`).

## Configuration

### Environment Variables (v2)
| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`/`INFO`/`WARNING`/`ERROR`). |
| `ENABLE_IPV4` | `true` | Manage IPv4 rules. |
| `ENABLE_IPV6` | `true` | Manage IPv6 rules. |
| `CLEAN_ON_EXIT` | `true` | Delete the `inet magicfw` table on graceful shutdown. |
| `DRY_RUN` | `false` | Log intended nftables spec without applying it. |
| `EVENT_BACKOFF_SECS` | `2` | Backoff delay after transient Docker API errors. |
| (v1 only) `DISABLE_NAT` | `true` | v1: remove Docker SNAT rules (ignored in v2). |
| (v1 only) `REMOVE_RAW_DROPS` | `true` | v1: remove Docker raw PREROUTING DROP rules (not needed in v2). |

---

## Usage Example

### Docker Compose with Container Labels
Here's how you might use Docker Compose to take full advantage of the container labels:

#### Example 1 (Full external + ICC)
```yaml
services:
  web:
    image: nginx
    labels:
      magicfw.firewall.allow_icc: "true"
      magicfw.firewall.allow_external: "true"
```

In the above example:
- The `web` container can communicate with other containers on different Docker networks (`magicfw.firewall.allow_icc: true`).
- The container can be accessed by external hosts using the container's IP (**not host IP!**) (`magicfw.firewall.allow_external: true`). This requires a route on other hosts or the router.

#### Example 2 (ICC only, no external)
```yaml
services:
  web:
    image: nginx
    labels:
      magicfw.firewall.allow_icc: "true"
      magicfw.firewall.allow_external: "false"
```

In the above example:
- The `web` container can communicate with other containers on different Docker networks (`magicfw.firewall.allow_icc: true`).
- External hosts won't be able to access the container

#### Example 3 (Published port only)
```yaml
services:
  web:
    image: nginx
    labels:
      magicfw.firewall.allow_icc: "true"
      magicfw.firewall.allow_external: "false"
    ports:
      - 8080:80
```

In the above example:
* `allow_icc` lets the container initiate to others across networks.
* No `allow_external` label: only the published port (80) is reachable externally via host port 8080 (and directly to container IP:80 if routed). Other container ports remain closed.

#### Example 4 (Selective external ports)
```yaml
services:
  api:
    image: myapi
    labels:
      magicfw.firewall.allow_icc: "false"
      magicfw.firewall.allow_external: "80,443,8443/udp"
```
Allows external inbound only on TCP 80, TCP 443, UDP 8443 directly to the container IP, NOT host IP.

#### Example 5 (Full open external)
```yaml
services:
  bastion:
    image: debian
    labels:
      magicfw.firewall.allow_external: "true"
```
All inbound from external hosts is allowed (plus any replies); cross-network initiation still requires `allow_icc` if contacting other networks.

### Port List Syntax Recap
Label value examples:
* `true`, `yes`, `1`, `*` => full open
* `443` => TCP 443 only
* `443/udp` => UDP 443 only
* `80,443,8443/udp` => TCP 80 & 443 plus UDP 8443
Invalid tokens are ignored with a warning.

---

## Operational Notes
* Default bridge (docker0) is currently not isolated by v2 (user-defined bridges are). Future versions may make this configurable.
* Published ports rely on docker-proxy when iptables is disabled; v2 automatically whitelists those destination ports.
* To inspect the active table:
  ```bash
  sudo nft list table inet magicfw
  ```
* Use `DRY_RUN=true` to preview changes without applying.

## Contribution
Contributions welcome: issues and PRs for improvements, bug fixes, and features (group-based ICC, selective docker0 isolation, incremental nft diffs, metrics) are appreciated.