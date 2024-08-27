```
 _____  _____ *    *   **  **           _            
/ ____|/ ____| |  | | |  \/  |         | |           
| (___ | (___ | |__| | | \  / | **|** |_ ___ *_* 
\___ \ \___ \|  __  | | |\/| |/ *` / *_| __/ * \ '*_|
____) |____) | |  | | | |  | | (_| \__ \ ||  __/ |   
|_____/|_____/|_|  |_| |_|  |_|\__,_|___/\__\___|_|   
                                                     
```

# 🚀 SSH Mastery: Advanced Techniques for Hackers

## Table of Contents
1. [🔄 SSH Multiplexing](#-ssh-multiplexing)
2. [🔀 Advanced Port Forwarding](#-advanced-port-forwarding)
3. [🧪 SSH as a SOCKS Proxy](#-ssh-as-a-socks-proxy)
4. [🔌 SSH over HTTPS](#-ssh-over-https)
5. [📡 Reverse SSH Tunneling](#-reverse-ssh-tunneling)

## 🔄 SSH Multiplexing

SSH multiplexing is like opening multiple tabs in a single browser window. It lets you run multiple SSH sessions through one connection, saving time and resources.

### Configuration

Add this to your `~/.ssh/config`:

```plaintext
ControlMaster auto
ControlPath ~/.ssh/controlmasters/%r@%h:%p
ControlPersist 10m
```

### Multiplexed Connection Manager

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

## 🔀 Advanced Port Forwarding

Port forwarding is like creating secret tunnels between computers. It lets you access services on remote machines as if they were on your local network.

### Dynamic Port Forwarding

```bash
ssh -D 8080 -f -C -q -N hacker@target
```

### Multi-Hop Port Forwarding

```bash
ssh -L 3306:internal_db:3306 -J jumphost hacker@internal_host
```

### Auto Tunnel Manager

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

```
   [ Your Box ]  <--- Tunnel --->  [ Gateway ]  <--- Tunnel --->  [ Target Servers ]
  +------------+                  +---------+                    +----------------+
  | Port: 8080 |                  |         |                    |    Port: 80    |
  |   Local    |                  |         |                    |  Remote App    |
  +------------+                  +---------+                    +----------------+
```

## 🧪 SSH as a SOCKS Proxy

Turn SSH into a SOCKS proxy to route all your traffic through an encrypted tunnel.

### Setup SOCKS Proxy

```bash
ssh -D 1080 -f -C -q -N hacker@proxy_server
```

### Usage Examples

- curl: `curl --socks5 localhost:1080 http://secret-site.com`
- git: `git config --global http.proxy socks5://localhost:1080`

### Traffic Router

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

## 🔌 SSH over HTTPS

Hide your SSH traffic as HTTPS to bypass restrictive firewalls.

### Server Config (Apache)

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

### Client-side SSH over HTTPS

```bash
#!/bin/bash

curl -x socks5h://localhost:1080 https://ssh.secret-site.com
ssh -o ProxyCommand="curl -x socks5h://localhost:1080 %h" hacker@ssh.secret-site.com
```

## 📡 Reverse SSH Tunneling

Create a backdoor to your local machine from a remote server.

### Setup Reverse Tunnel

```bash
ssh -R 9999:localhost:22 hacker@remote_server
```

### Auto Reverse Tunnel

```python
import subprocess
import time

def create_backdoor():
    subprocess.Popen(["ssh", "-R", "9999:localhost:22", "hacker@remote_server"], shell=True)

while True:
    create_backdoor()
    time.sleep(3600)  # Recreate tunnel every hour
```

```
   [ Remote Server ]  <--- Reverse Tunnel ---  [ Your Local Machine ]
  +----------------+                          +--------------------+
  |   Port: 9999   |                          |    SSH Service     |
  | Remote Access  |                          |     Port: 22       |
  +----------------+                          +--------------------+
```

