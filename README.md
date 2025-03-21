# Docker Magic Firewall Service

## Project Overview

**Docker Magic Firewall (magicfw)** is an application designed to provide a dynamic and automated approach to managing Docker containers' networking firewall rules. By utilizing container labels, it allows fine-grained control over Docker container connectivity, such as enabling or restricting communication between containers on different Docker networks, external traffic access, and published ports. The service operates in the background, listens for Docker events, and updates `iptables`/`ip6tables` rules accordingly, providing seamless and secure container networking.

The main idea is to allow Docker to run without NAT by making each container accessible with its own IP address, while still maintaining security by dynamically configuring iptables rules on the host.

Features include:
- Can disable Docker's source NAT
- Can allow some containers to connect to containers in different Docker networks (very handy for applications like a reverse proxy)
- Dynamic management of firewall rules based on container and network's lifecycle
- Container-level settings via container labels
- IPv4 and IPv6 support
- Automatic subnet detection based on Docker's `daemon.json`

### Container Labels
You can define rules per container using specific Docker labels:

| **Label Key**                          | **Description**                                                                                                                               | **Default** |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| `magicfw.firewall.allow_icc`           | Enables communication between the container and other containers on different Docker networks (not normally possible in Docker environments). | `false`     |
| `magicfw.firewall.allow_external`      | Enables access from external networks (e.g., the internet) for the container.                                                                   | `false`     |

### Behavior and Functionalities
- **Allow ICC (Inter-Container Communication):** When `magicfw.firewall.allow_icc` is `true`, the container can communicate with other containers across **different Docker networks** (useful for applications like reverse proxies such as Traefik). If `false`, the container is isolated from other Docker networks (default Docker behavior).
- **External Traffic:** When `magicfw.firewall.allow_external` is `true`, the container's network rules allow communication from external networks (useful when NAT is disabled).
- **Automatic Rule Cleanup:** When a container is restarted, stopped, or removed, the corresponding firewall rules are automatically cleaned.
- **Support for Published Ports:** Rules are auto-generated for any published ports, restricting incoming traffic to only the ports explicitly exposed via Docker.

## Install
To make the installation easy, I provide a package for Debian-based distros, follow the instructions here: [https://git.marcorealacci.me/marcorealacci/-/packages/debian/magicfw-docker](https://git.marcorealacci.me/marcorealacci/-/packages/debian/magicfw-docker)

To install the script manually, the required dependencies are `python3` and the `docker` library available from PyPI (`pip3 install docker`).

## Configuration

### Environment Variables

Below is a table of environment variables that can be customized within the systemd service:

| **Variable**      | **Description**                                                                                         | **Default Value** |
|--------------------|---------------------------------------------------------------------------------------------------------|-------------------|
| `LOG_LEVEL`        | Set logging verbosity. Options: `DEBUG`, `INFO`, `WARNING`, `ERROR`.                                    | `INFO`            |
| `ENABLE_IPV4`      | Enables IPv4 firewall rule management.                                                                  | `true`            |
| `ENABLE_IPV6`      | Enables IPv6 firewall rule management.                                                                  | `true`            |
| `DISABLE_NAT`      | Disables Source NAT rules for Docker containers (a static route will be needed on the router!).         | `true`            |

---

## Usage Example

### Docker Compose with Container Labels
Here's how you might use Docker Compose to take full advantage of the container labels:

#### Example 1
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

#### Example 2
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

#### Example 3
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
- The `web` container can communicate with other containers on different Docker networks (`magicfw.firewall.allow_icc: true`).
- External hosts can access the container via both <container IP>:80 and <host IP>:8080 (port mapping still works even with `DISABLE_NAT` set to `true`, as only Source NAT will be disabled)
- External hosts will not be able to access the container on ports other than 80

---

## Contribution

Your contributions are welcome! Feel free to open issues or submit pull requests on GitHub to improve the functionality or features of this project.