```markdown
_____  _____ _    _   __  __           _            
/ ____|/ ____| |  | | |  \/  |         | |           
| (___ | (___ | |__| | | \  / | __ _ ___| |_ ___ _ __ 
\___ \ \___ \|  __  | | |\/| |/ _` / __| __/ _ \ '__|
____) |____) | |  | | | |  | | (_| \__ \ ||  __/ |   
|_____/|_____/|_|  |_| |_|  |_|\__,_|___/\__\___|_|   
                                                     
# 🚀 SSH Mastery: Advanced Techniques for Hackers

## Table of Contents
1. [🔄 SSH Multiplexing](#-ssh-multiplexing)
2. [🔀 Advanced Port Forwarding](#-advanced-port-forwarding)
3. [🧪 SSH as a SOCKS Proxy](#-ssh-as-a-socks-proxy)
4. [🔌 SSH over HTTPS](#-ssh-over-https)
5. [📡 Reverse SSH Tunneling](#-reverse-ssh-tunneling)

## 🔄 SSH Multiplexing

SSH multiplexing allows you to reuse an existing SSH connection for multiple sessions. Think of it like opening several tabs in one browser window. This reduces overhead and speeds up operations.

### **Configuration:**
To enable SSH multiplexing, add the following lines to your `~/.ssh/config` file:

```plaintext
ControlMaster auto
ControlPath ~/.ssh/controlmasters/%r@%h:%p
ControlPersist 10m
```

- **ControlMaster auto**: Enables multiplexing.
- **ControlPath**: Sets the path for storing control sockets.
- **ControlPersist**: Keeps the master connection open for 10 minutes after the last session closes.

### **Multiplexed Connection Manager:**

The following Python script manages SSH multiplexed connections:

```python
import subprocess

def ssh_multiplex(action, host):
    control_path = f"~/.ssh/controlmasters/%r@{host}:%p"
    actions = {
        "check": ["ssh", "-O", "check", "-S", control_path, host],
        "stop": ["ssh", "-O", "stop", "-S", control_path, host],
        "start": ["ssh", "-fN", "-M", "-S", control_path, host]
    }
    if action == "check":
        return "Master running" in subprocess.run(actions[action], capture_output=True, text=True).stderr
    subprocess.run(actions[action])

# Usage
host = "hackbox.com"
if ssh_multiplex("check", host):
    print(f"Connection to {host} active")
else:
    print(f"Creating new connection to {host}")
    ssh_multiplex("start", host)
```

This script can start, check, or stop a multiplexed connection based on your needs.

## 🔀 Advanced Port Forwarding

Port forwarding lets you securely access services on remote machines as if they were on your local network. It's like creating secret tunnels between computers.

### **Dynamic Port Forwarding:**
Dynamic port forwarding turns SSH into a SOCKS proxy server, allowing you to forward any connection type (HTTP, HTTPS, etc.) through the tunnel.

```bash
ssh -D 8080 -f -C -q -N hacker@target
```

- **-D 8080**: Specifies the local port for dynamic forwarding.
- **-f**: Requests SSH to go into the background after authentication.
- **-C**: Enables compression.
- **-q**: Quiet mode.
- **-N**: Prevents commands from being executed on the remote host.

### **Multi-Hop Port Forwarding:**
This technique allows you to access a remote service through multiple SSH hosts (jump hosts).

```bash
ssh -L 3306:internal_db:3306 -J jumphost hacker@internal_host
```

- **-L**: Local port forwarding.
- **-J**: Specifies a jump host.

### **Auto Tunnel Manager:**

The following Python script automates the creation and management of SSH tunnels:

```python
import subprocess
import time

tunnels = [
    {"local": 8080, "remote_host": "app_server", "remote_port": 80, "ssh_host": "gateway"},
    {"local": 3306, "remote_host": "db_server", "remote_port": 3306, "ssh_host": "gateway"}
]

def manage_tunnel(t, action):
    cmd = f"ssh -L {t['local']}:{t['remote_host']}:{t['remote_port']} -N -f {t['ssh_host']}"
    if action == "create":
        subprocess.Popen(cmd, shell=True)
    elif action == "check":
        return subprocess.call(f"netstat -tln | grep :{t['local']}", shell=True) == 0

while True:
    for t in tunnels:
        if not manage_tunnel(t, "check"):
            print(f"Recreating tunnel: {t['local']} -> {t['remote_host']}:{t['remote_port']}")
            manage_tunnel(t, "create")
    time.sleep(60)
```

This script checks for active tunnels every 60 seconds and recreates them if necessary.

**Diagram:**

```
   [ Your Box ]  <--- Tunnel --->  [ Gateway ]  <--- Tunnel --->  [ Target Servers ]
  +------------+                  +---------+                    +----------------+
  | Port: 8080 |                  |         |                    |    Port: 80    |
  |   Local    |                  |         |                    |  Remote App    |
  +------------+                  +---------+                    +----------------+
```

## 🧪 SSH as a SOCKS Proxy

Using SSH as a SOCKS proxy allows you to route all your traffic through an encrypted SSH tunnel, effectively anonymizing your connections and bypassing network restrictions.

### **Setup SOCKS Proxy:**
```bash
ssh -D 1080 -f -C -q -N hacker@proxy_server
```

- **-D 1080**: Enables dynamic application-level port forwarding on port 1080.

### **Usage Examples:**

- **curl:**  
  ```bash
  curl --socks5 localhost:1080 http://secret-site.com
  ```

- **git:**  
  ```bash
  git config --global http.proxy socks5://localhost:1080
  ```

### **Traffic Router Script:**

This bash script routes all TCP traffic through the SOCKS proxy and then cleans up the routing after use:

```bash
#!/bin/bash

# Start proxy
ssh -D 1080 -f -C -q -N hacker@proxy_server

# Route traffic
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 1080

# Run your app
your_stealthy_app

# Clean up
sudo iptables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports 1080
pkill -f "ssh -D 1080"
```

This script is useful when you need to force all traffic through your SSH proxy.

## 🔌 SSH over HTTPS

Sometimes, SSH traffic might be blocked by restrictive firewalls. SSH over HTTPS hides your SSH traffic inside HTTPS requests, making it indistinguishable from regular web traffic.

### **Server Configuration (Apache):**

Add this configuration to your Apache server to allow SSH over HTTPS:

```apache
<VirtualHost *:443>
    ServerName ssh.secret-site.com
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    ProxyPass / http://localhost:22/
    ProxyPassReverse / http://localhost:22/
</VirtualHost>
```

This configuration proxies HTTPS requests to the SSH service running on the server.

### **Client-side SSH over HTTPS:**

Use the following bash script to initiate an SSH connection over HTTPS:

```bash
#!/bin/bash

curl -x socks5h://localhost:1080 https://ssh.secret-site.com
ssh -o ProxyCommand="curl -x socks5h://localhost:1080 %h" hacker@ssh.secret-site.com
```

This method is effective for bypassing network restrictions that block SSH traffic but allow HTTPS.

## 📡 Reverse SSH Tunneling

Reverse SSH tunneling is a powerful technique that allows you to create a backdoor from a remote server to your local machine. This is especially useful for accessing your local environment from a remote location.

### **Setup Reverse Tunnel:**
```bash
ssh -R 9999:localhost:22 hacker@remote_server
```

- **-R 9999:localhost:22**: Forwards the remote server’s port 9999 to the SSH service running on your local machine.

### **Auto Reverse Tunnel Script:**

This Python script automates the process of maintaining a reverse SSH tunnel:

```python
import subprocess
import time

def create_backdoor():
    subprocess.Popen(["ssh", "-R", "9999:localhost:22", "hacker@remote_server"], shell=True)

while True:
    create_backdoor()
    time.sleep(3600)  # Recreate tunnel every hour
```

This script ensures that the reverse tunnel is always active, recreating it every hour.

**Diagram:**

```
   [ Remote Server ]  <--- Reverse Tunnel ---  [ Your Local Machine ]
  +----------------

+                          +--------------------+
  |   Port: 9999   |                          |    SSH Service     |
  | Remote Access  |                          |     Port: 22       |
  +----------------+                          +--------------------+
```

```

With these advanced SSH techniques, you'll have the tools to securely and efficiently manage connections, bypass restrictions, and maintain persistent access in even the most challenging environments.
```
