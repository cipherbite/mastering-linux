# Part Three: Intermediate SSH Usage

## Table of Contents

- [3.1 SSH Configuration Files](#31-ssh-configuration-files)
- [3.2 Advanced SSH Key Management](#32-advanced-ssh-key-management)
- [3.3 Leveraging SSH Agent](#33-leveraging-ssh-agent)
- [3.4 Port Forwarding and Tunneling](#34-port-forwarding-and-tunneling)
  - [3.4.1 Local Port Forwarding](#341-local-port-forwarding)
  - [3.4.2 Remote Port Forwarding](#342-remote-port-forwarding)
  - [3.4.3 Dynamic Port Forwarding (SOCKS Proxy)](#343-dynamic-port-forwarding-socks-proxy)
- [3.5 SSH Jump Hosts](#35-ssh-jump-hosts)
- [3.6 Best Practices](#36-best-practices)
- [3.7 Further Reading](#37-further-reading)

---

## 3.1 SSH Configuration Files

SSH configuration files allow for customization and streamlining of SSH connections.

### Client-Side Configuration

**File Location:** `~/.ssh/config`  
**Purpose:** Simplifies SSH commands, manages multiple connections, and customizes client behavior.

#### Example Configuration:

```plaintext
Host myserver
    HostName example.com
    User john
    Port 2222
    IdentityFile ~/.ssh/id_rsa_myserver
    ForwardAgent yes

Host *
    ServerAliveInterval 60
    ServerAliveCountMax 5
```

| Option                | Description                                                |
|-----------------------|------------------------------------------------------------|
| `Host`                | Alias for the SSH connection                               |
| `HostName`            | Server's hostname or IP address                            |
| `User`                | Login username                                             |
| `Port`                | SSH port (if not default 22)                               |
| `IdentityFile`        | Path to private key for authentication                     |
| `ForwardAgent`        | Enables SSH agent forwarding                               |
| `ServerAliveInterval` | Time interval for sending keep-alive messages              |
| `ServerAliveCountMax` | Maximum number of keep-alive messages without response     |

With this configuration, you can simply run `ssh myserver` instead of the full command `ssh -p 2222 john@example.com -i ~/.ssh/id_rsa_myserver`.

### Server-Side Configuration

**File Location:** `/etc/ssh/sshd_config`  
**Purpose:** Controls SSH daemon (`sshd`) operation, including security settings and login policies.

#### Key Settings:

| Setting                | Recommended Value | Purpose                                        |
|------------------------|-------------------|------------------------------------------------|
| `PermitRootLogin`      | no                | Disables root login via SSH                    |
| `PasswordAuthentication` | no              | Enforces key-based logins                      |
| `PubkeyAuthentication` | yes               | Enables key-based authentication               |
| `Port`                 | 2222              | Changes default SSH port                       |
| `AllowUsers`           | john alice        | Restricts SSH access to specific users         |
| `MaxAuthTries`         | 3                 | Limits authentication attempts                 |
| `LoginGraceTime`       | 60                | Sets timeout for successful authentication     |
| `X11Forwarding`        | no                | Disables X11 forwarding for security           |

To apply changes:

```bash
sudo nano /etc/ssh/sshd_config  # Edit the file
sudo systemctl restart sshd     # Restart SSH service to apply changes
```

---

## 3.2 Advanced SSH Key Management

### Managing Multiple SSH Keys

Use `~/.ssh/config` to manage multiple keys for different servers or purposes:

```plaintext
Host workserver
    HostName work.example.com
    User workuser
    IdentityFile ~/.ssh/id_rsa_work

Host personalserver
    HostName personal.example.com
    User personaluser
    IdentityFile ~/.ssh/id_rsa_personal

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_rsa_github
```

### Adding New SSH Keys

1. **Generate a new key:**
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_newserver
   ```

2. **Add to server:**
   - **Manual method:**
     ```bash
     cat ~/.ssh/id_ed25519_newserver.pub | ssh user@host 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
     ```
   - **Automated method:**
     ```bash
     ssh-copy-id -i ~/.ssh/id_ed25519_newserver.pub user@host
     ```

### Restricting Key Usage

Prepend `authorized_keys` entry with options to restrict key usage:

```plaintext
command="/usr/bin/uptime",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3Nza...
```

### Setting Key Expiration

For temporary access (OpenSSH 8.2+):

```bash
ssh-keygen -t ed25519 -O verify-required -O expiration-time=+7d -f ~/.ssh/id_ed25519_temp
```

---

## 3.3 Leveraging SSH Agent

### Usage

1. **Start SSH Agent:**
   ```bash
   eval "$(ssh-agent -s)"
   ```

2. **Add keys:**
   ```bash
   ssh-add ~/.ssh/id_rsa
   ssh-add ~/.ssh/id_ed25519_work
   ```

3. **List added keys:**
   ```bash
   ssh-add -l
   ```

4. **Remove a specific key:**
   ```bash
   ssh-add -d ~/.ssh/id_rsa
   ```
![eval-ssh-agent-commends](https://github.com/user-attachments/assets/60544ef1-52ea-46f2-a024-28ef4880191b)

### Automation Example

Create a script to automate SSH tasks:

```bash
#!/bin/bash
# Script to automate SSH tasks

# Start SSH agent
eval "$(ssh-agent -s)"

# Add necessary keys
ssh-add ~/.ssh/id_rsa
ssh-add ~/.ssh/id_ed25519_work

# Perform SSH operations
ssh workserver 'uptime'
ssh personalserver 'df -h'

# Kill SSH agent when done
ssh-agent -k
```

---

## 3.4 Port Forwarding and Tunneling

SSH port forwarding, also known as SSH tunneling, allows you to securely redirect network traffic through an encrypted SSH connection. This feature is invaluable for accessing services on remote networks, bypassing firewalls, and enhancing overall network security.

### 3.4.1 Local Port Forwarding

Local port forwarding enables you to securely access a remote service as if it were running on your local machine.

**Syntax:**
```bash
ssh -L [local_address:]local_port:remote_address:remote_port [user@]ssh_server
```
![local-port-forwarding](https://github.com/user-attachments/assets/3d46e482-b042-46a6-997b-fcc5812232ed)

**Key Components:**
- `local_address`: (Optional) The local interface to bind to (default: localhost)
- `local_port`: The port on your local machine to forward from
- `remote_address`: The destination host as seen from the SSH server
- `remote_port`: The port on the remote destination
- `ssh_server`: The intermediary SSH server

[Insert diagram of local port forwarding here]

**Practical Examples:**

1. Accessing a remote web server:
   ```bash
   ssh -L 8080:remote-webserver:80 user@ssh-server
   ```
   This command forwards your local port 8080 to port 80 on `remote-webserver`.

2. Securely accessing a database server:
   ```bash
   ssh -L 3306:database-server:3306 user@ssh-server
   ```
   This setup allows you to connect to a remote MySQL database as if it were running locally.

### 3.4.2 Remote Port Forwarding

Remote port forwarding allows you to make a service on your local machine accessible from a remote location.

**Syntax:**
```bash
ssh -R [remote_address:]remote_port:local_address:local_port [user@]ssh_server
```
![remote-port-forwarding](https://github.com/user-attachments/assets/dc4fa32d-9b11-4105-80b1-1ddede604677)

**Key Components:**
- `remote_address`: (Optional) The remote interface to bind to (default: localhost on the SSH server)
- `remote_port`: The port on the remote SSH server to forward to
- `local_address`: The local destination host (usually localhost)
- `local_port`: The port of the local service you're exposing
- `ssh_server`: The intermediary SSH server

[Insert diagram of remote port forwarding here]

**Practical Example:**

Exposing a local web development server:
```bash
ssh -R 8080:localhost:3000 user@remote-server
```
This command makes your local development server running on port 3000 accessible on the remote server at `http://localhost:8080`.

### 3.4.3 Dynamic Port Forwarding (SOCKS Proxy)

Dynamic port forwarding creates a local SOCKS proxy server that can route traffic to multiple remote destinations through an SSH tunnel.

**Syntax:**
```bash
ssh -D [local_address:]local_port [user@]ssh_server
```
![dynamic port forwarding](https://github.com/user-attachments/assets/84d349a0-0b36-4d4c-9253-746d33c9b6b4)

**Key Components:**
- `local_address`: (Optional) The local interface to bind the SOCKS proxy to
- `local_port`: The local port to run the SOCKS proxy on
- `ssh_server`: The SSH server acting as the proxy endpoint

![proxy-diagr](https://github.com/user-attachments/assets/33de6fd7-17ad-4edf-a30f-ff65603e4908)

**Practical Example:**

Setting up a SOCKS proxy on port 1080:
```bash
ssh -D 1080 user@remote-server
```

This command establishes a SOCKS proxy on your local port 1080, which can be used to route application traffic through the SSH tunnel.

---

## 3.5 SSH Jump Hosts

Jump Host, or ProxyJump, allows you to connect to a target server by first connecting through an intermediate server.

### Basic Jump Host Configuration

In `~/.ssh/config`:
```plaintext
Host jumphost
    HostName jump.example.com
    User jumpuser

Host targethost
    HostName 192.168.1.100
    User targetuser
    ProxyJump jumphost
```

Now you can simply run:
```bash
ssh targethost
```

### Multiple Jump Hosts

For scenarios requiring multiple jumps:
```plaintext
Host targethost
    HostName 192.168.1.100
    User targetuser
    ProxyJump jumphost1,jumphost2
```

---

## 3.6 Best Practices

1. Use unique keys for different purposes (work, personal, etc.).
2. Regularly rotate SSH keys (e.g., annually).
3. Implement strong passphrases for private keys.
4. Use SSH agent forwarding cautiously and only on trusted systems.
5. Audit and remove unused authorized keys regularly.
6. Keep your SSH client and server software updated.
7. Use key types like Ed25519 for better security and performance.
8. Implement fail2ban or similar tools to prevent brute-force attacks.

---

## 3.7 Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines on Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)

---

**Note:** This guide is based on OpenSSH version 8.0 and later. Some features may not be available in earlier versions.

**License:** This document is released under the MIT License. See LICENSE file for details.

**Contributions:** We welcome contributions to improve this guide. Please see CONTRIBUTING.md for guidelines on how to submit improvements or corrections.

