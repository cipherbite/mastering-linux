### Part 2: Advanced SSH Techniques

#### Table of Contents
- [2.1 🔄 SSH Multiplexing and Connection Sharing](#21--ssh-multiplexing-and-connection-sharing)
- [2.2 🔀 Advanced Port Forwarding](#22--advanced-port-forwarding)
- [2.3 🧪 SSH as a SOCKS Proxy](#23--ssh-as-a-socks-proxy)
- [2.4 🔌 SSH over HTTPS](#24--ssh-over-https)
- [2.5 📡 Reverse SSH Tunneling](#25--reverse-ssh-tunneling)

#### 2.1 🔄 SSH Multiplexing and Connection Sharing

##### 2.1.1 Configuring Multiplexing

In `~/.ssh/config`:
```
ControlMaster auto
ControlPath ~/.ssh/controlmasters/%r@%h:%p
ControlPersist 10m
```

##### 2.1.2 Script for Managing Multiplexed Connections

```python
import os
import subprocess

def manage_ssh_connections(action, host):
    control_path = f"~/.ssh/controlmasters/%r@{host}:%p"
    if action == "check":
        result = subprocess.run(["ssh", "-O", "check", "-S", control_path, host], capture_output=True, text=True)
        return "Master running" in result.stderr
    elif action == "stop":
        subprocess.run(["ssh", "-O", "stop", "-S", control

_path, host])
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

#### 2.2 🔀 Advanced Port Forwarding

##### 2.2.1 Dynamic Port Forwarding

```bash
ssh -D 8080 -f -C -q -N user@remote_host
```

##### 2.2.2 Port Forwarding with ProxyJump

```bash
ssh -L 3306:internal_db:3306 -J jumphost user@internal_host
```

##### 2.2.3 Script for Automatic SSH Tunnel Management

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

[Space for a diagram showing complex SSH port forwarding scenarios]
*Diagram of advanced SSH port forwarding scenarios, including forwarding through multiple hosts*

#### 2.3 🧪 SSH as a SOCKS Proxy

##### 2.3.1 Configuring SOCKS Proxy via SSH

```bash
ssh -D 1080 -f -C -q -N user@remote_host
```

##### 2.3.2 Using SOCKS Proxy in Various Applications

For curl:
```bash
curl --socks5 localhost:1080 http://example.com
```

For git:
```bash
git config --global http.proxy socks5://localhost:1080
```

##### 2.3.3 Script for Routing All Traffic through SOCKS Proxy

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

#### 2.4 🔌 SSH over HTTPS

##### 2.4.1 Configuring SSH over HTTPS Server

On the server (Apache):
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

This setup allows SSH traffic to be tunneled over HTTPS, which can help bypass firewalls and restrictive networks.

##### 2.4.2 Script for Using SSH over HTTPS

Here's a basic script to connect via SSH over HTTPS using `curl`:

```bash
#!/bin/bash

# Start SSH tunnel over HTTPS
curl -x socks5h://localhost:1080 https://ssh.example.com

# Run SSH command
ssh -o ProxyCommand="curl -x socks5h://localhost:1080 %h" user@ssh.example.com
```

This script demonstrates using a SOCKS proxy to route SSH over HTTPS.

#### 2.5 📡 Reverse SSH Tunneling

##### 2.5.1 Setting Up Reverse SSH Tunnel

```bash
ssh -R 9999:localhost:22 user@remote_host
```

This command sets up a reverse tunnel where the remote host's port `9999` forwards to the local machine's SSH port.

##### 2.5.2 Automating Reverse SSH Tunnel Creation

```python
import subprocess
import time

def create_reverse_tunnel():
    subprocess.Popen(["ssh", "-R", "9999:localhost:22", "user@remote_host"], shell=True)

while True:
    create_reverse_tunnel()
    time.sleep(3600)  # Recreate tunnel every hour
```

