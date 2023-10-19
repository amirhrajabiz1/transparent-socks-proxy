# transparent-socks-proxy
A script for installing a transparent socks proxy.

# Prerequisites

## 1. Use a Fresh and Non-Important System:

- It's recommended to run this script on a fresh system to avoid potential conflicts with existing configurations.
- This script makes changes to network settings and services, so it's advisable to use it on a non-critical system.

## 2. Tested Environments:

- This script has been tested on the following Ubuntu versions:
  - Ubuntu 16.04 LTS (Xenial Xerus)
  - Ubuntu 20.04 LTS (Focal Fossa)
  - Ubuntu 22.04 LTS (Jammy Jellyfish)

### Installation

1. Open a terminal window.

2. Clone the repository:

    ```bash
    git clone https://github.com/amirhrajabiz1/transparent-socks-proxy.git
    ```

3. Navigate to the project directory:

    ```bash
    cd transparent-socks-proxy
    ```

4. Make the install.sh script executable:

    ```bash
    chmod +x install.sh
    ```

5. Execute the install.sh script as root:

    ```bash
    sudo ./install.sh
    ```

# How It Works

## Topology

![Network Topology](https://github.com/amirhrajabiz1/transparent-socks-proxy/blob/main/Topology.jpg)

In this scenario, the network faces a restriction where direct access to the free internet is unavailable, but a remote server serves as the gateway to the unrestricted online space.

- **Local Machine (Your Machine):**
  - Execution of the script on this machine prompts the user to input details about the remote server.
  - Establishes an SSH connection to the remote server.
  - Sets up a local SOCKS5 proxy (`localhost:12345`) using the `redsocks` package.

- **Remote SSH Server:**
  - Acts as a gateway to the free internet.
  - Hosts an SSH server that the local machine connects to.

- **Transparent Proxy:**
  - The script configures a transparent proxy on the local interface.
  - Devices connected to the switch will have seamless access to the free internet without any noticeable impact.

## How the Script Works

1. **Initialization:**
   - Updates the package repository and installs necessary packages.
   - Configures SSH key pairs for secure communication.

2. **Service Setup:**
   - Sets up services for SSH, DNS, and a SOCKS5 proxy (`redsocks`).
   - Configures iptables rules for network traffic.

3. **LAN Configuration:**
   - Configures the LAN interface with a static IP (`10.10.10.1`).
   - Sets up DHCP and DNS services for the LAN.

4. **Transparent Proxy Setup:**
   - Configures a transparent proxy to allow devices connected to the switch access to the unrestricted internet via the remote server.

5. **Redsocks Setup:**
   - Configures `redsocks` to redirect traffic from port `12345` to the specified SOCKS5 proxy port.

6. **Iptables Rules Persistence:**
   - Saves iptables rules to `/etc/iptables/rules.v4` to ensure persistence across reboots.

7. **Finalization:**
   - Starts and enables all configured services.
   - Provides information on the configured services.
  
# Configuration Files

## `proxy_domains` File:

- Located at: `/etc/dns2socks/proxy_domains`
- Add domains to this file to define which domains should be accessed through the proxy.
- The script will read this file to determine which domains to route through the SOCKS5 proxy.

## `block_domains` File:

- Located at: `/etc/dns2socks/block_domains`
- Add domains to this file to define which domains should be blocked.
- The script will read this file to determine which domains to block, preventing access through the proxy.
