### Part 2: Advanced SSH Techniques

#### Table of Contents
- [2.1 🔄 SSH Multiplexing and Connection Sharing](#21--ssh-multiplexing-and-connection-sharing)
- [2.2 🔀 Advanced Port Forwarding](#22--advanced-port-forwarding)
- [2.3 🧪 SSH as a SOCKS Proxy](#23--ssh-as-a-socks-proxy)
- [2.4 🔌 SSH over HTTPS](#24--ssh-over-https)
- [2.5 📡 Reverse SSH Tunneling](#25--reverse-ssh-tunneling)

---

### 2.1 🔄 SSH Multiplexing and Connection Sharing

SSH multiplexing allows multiple SSH sessions to share a single connection, improving efficiency and reducing the overhead of establishing new connections.

#### 2.1.1 Configuring Multiplexing

To configure SSH multiplexing, you can add the following lines to your `~/.ssh/config` file:

```plaintext
ControlMaster auto
ControlPath ~/.ssh/controlmasters/%r@%h:%p
ControlPersist 10m
```

- **ControlMaster auto**: Enables SSH connection sharing.
- **ControlPath**: Defines where the shared socket files are stored.
- **ControlPersist 10m**: Keeps the master connection open for 10 minutes after the last session has closed.

This configuration means that any subsequent SSH connections to the same host will reuse the existing connection if it's still open.

#### 2.1.2 Script for Managing Multiplexed Connections

Below is a Python script that allows you to manage SSH multiplexed connections by checking the connection status, starting, or stopping them as needed.

```python
import os
import subprocess

def manage_ssh_connections(action, host):
    control_path = f"~/.ssh/controlmasters/%r@{host}:%p"
    if action == "check":
        result = subprocess.run(["ssh", "-O", "check", "-S", control_path, host], capture_output=True, text=True)
        return "Master running" in result.stderr
    elif action == "stop":
        subprocess.run(["ssh", "-O", "stop", "-S", control_path, host])
    elif action == "start":
        subprocess.run(["ssh", "-fN", "-M", "-S", control_path, host])

# Usage
host = "example.com"
if manage_ssh_connections("check", host):
    print(f"Connection to {host} is active")
else:
    print(f"Creating new connection to {host}")
    manage_ssh_connections("start", host)
```

### 2.2 🔀 Advanced Port Forwarding

SSH port forwarding is a powerful tool for securely accessing services on remote hosts. Here, we'll explore advanced techniques such as dynamic port forwarding and using ProxyJump for multi-hop connections.

#### 2.2.1 Dynamic Port Forwarding

Dynamic port forwarding allows SSH to act as a SOCKS proxy, forwarding traffic through the SSH tunnel dynamically.

```bash
ssh -D 8080 -f -C -q -N user@remote_host
```

- **-D 8080**: Specifies that dynamic port forwarding will be set up on local port 8080.
- **-f**: Requests SSH to go to the background just before command execution.
- **-C**: Enables compression.
- **-q**: Disables all warnings and diagnostic messages.
- **-N**: Instructs SSH not to execute any remote commands, just to forward ports.

#### 2.2.2 Port Forwarding with ProxyJump

ProxyJump (`-J`) simplifies multi-hop SSH connections by allowing you to specify intermediate hosts.

```bash
ssh -L 3306:internal_db:3306 -J jumphost user@internal_host
```

- **-L 3306:internal_db:3306**: Forwards local port 3306 to `internal_db`'s port 3306.
- **-J jumphost**: Specifies `jumphost` as the intermediate server.

#### 2.2.3 Script for Automatic SSH Tunnel Management

This script automatically creates and manages SSH tunnels, ensuring they are recreated if they drop.

```python
import subprocess
import time

tunnels = [
    {"local_port": 8080, "remote_host": "app_server", "remote_port": 80, "ssh_host": "gateway"},
    {"local_port": 3306, "remote_host": "db_server", "remote_port": 3306, "ssh_host": "gateway"}
]

def create_tunnel(tunnel):
    cmd = f"ssh -L {tunnel['local_port']}:{tunnel['remote_host']}:{tunnel['remote_port']} -N -f {tunnel['ssh_host']}"
    subprocess.Popen(cmd, shell=True)

def check_tunnel(tunnel):
    cmd = f"netstat -tln | grep :{tunnel['local_port']}"
    return subprocess.call(cmd, shell=True) == 0

while True:
    for tunnel in tunnels:
        if not check_tunnel(tunnel):
            print(f"Recreating tunnel: {tunnel['local_port']} -> {tunnel['remote_host']}:{tunnel['remote_port']}")
            create_tunnel(tunnel)
    time.sleep(60)
```

This script checks every 60 seconds if the tunnels are active and recreates them if necessary.

```
       [ Local Machine ]  <--- Tunnel --->  [ Gateway ]  <--- Tunnel --->  [ Remote Servers ]
      +---------------+                    +---------+                    +----------------+
      | Port: 8080    |                    |         |                    |  Port: 80       |
      | Local Service |                    |         |                    | Remote Service  |
      +---------------+                    +---------+                    +----------------+
```

### 2.3 🧪 SSH as a SOCKS Proxy

Using SSH as a SOCKS proxy is useful when you need to route traffic securely through a remote server.

#### 2.3.1 Configuring SOCKS Proxy via SSH

```bash
ssh -D 1080 -f -C -q -N user@remote_host
```

This command creates a SOCKS proxy on `localhost:1080` that forwards traffic through `remote_host`.

#### 2.3.2 Using SOCKS Proxy in Various Applications

Once the SOCKS proxy is set up, you can use it in various applications. For example:

- **For curl:**
  ```bash
  curl --socks5 localhost:1080 http://example.com
  ```

- **For git:**
  ```bash
  git config --global http.proxy socks5://localhost:1080
  ```

#### 2.3.3 Script for Routing All Traffic through SOCKS Proxy

This script routes all your system's traffic through the SOCKS proxy.

```bash
#!/bin/bash

# Start SSH tunnel
ssh -D 1080 -f -C -q -N user@remote_host

# Configure iptables to redirect traffic
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 1080
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 1080

# Run application
your_application

# Clean up iptables rules
sudo iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 1080
sudo iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 1080

# Stop SSH tunnel
pkill -f "ssh -D 1080"
```

This script creates a SOCKS proxy, routes traffic through it, and then cleans up afterward.

### 2.4 🔌 SSH over HTTPS

SSH over HTTPS is useful when you're behind a restrictive firewall that only allows HTTPS traffic.

#### 2.4.1 Configuring SSH over HTTPS Server

On the server side, you can use Apache to proxy SSH traffic over HTTPS:

```apache
<VirtualHost *:443>
    ServerName ssh.example.com
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    ProxyPass / http://localhost:22/
    ProxyPassReverse / http://localhost:22/
</VirtualHost>
```

This configuration proxies incoming HTTPS requests to the SSH service on the same server.

#### 2.4.2 Script for Using SSH over HTTPS

Here's how you can connect to the SSH server via HTTPS using a SOCKS proxy:

```bash
#!/bin/bash

# Start SSH tunnel over HTTPS
curl -x socks5h://localhost:1080 https://ssh.example.com

# Run SSH command
ssh -o ProxyCommand="curl -x socks5h://localhost:1080 %h" user@ssh.example.com
```

This script connects to your SSH server over HTTPS, using `curl` to route the traffic.

### 2.5 📡 Reverse SSH Tunneling

Reverse SSH tunneling allows you to access services on a machine behind a firewall by creating a tunnel from the remote host back to your local machine.

#### 2.5.1 Setting Up Reverse SSH Tunnel

To set up a reverse tunnel:

```bash
ssh -R 9999:localhost:22 user@remote_host
```

This command allows you to connect to your local machine's SSH service through the remote host on port 9999.

#### 2.5.2 Automating Reverse SSH Tunnel Creation

The following Python script automates the creation of a reverse SSH tunnel

:

```python
import subprocess
import time

def create_reverse_tunnel():
    subprocess.Popen(["ssh", "-R", "9999:localhost:22", "user@remote_host"], shell=True)

while True:
    create_reverse_tunnel()
    time.sleep(3600)  # Recreate tunnel every hour
```

This script ensures that the reverse tunnel is maintained, recreating it every hour.

```
       [ Remote Host ]  <--- Reverse Tunnel --->  [ Local Machine ]
      +--------------+                           +----------------+
      | Port: 9999   |                           |  SSH Service    |
      | Remote Access|                           |  Port: 22       |
      +--------------+                           +----------------+
```

This advanced SSH guide provides various techniques to manage connections, tunnel traffic, and enhance security, making it suitable for professional use while remaining easy to understand.
