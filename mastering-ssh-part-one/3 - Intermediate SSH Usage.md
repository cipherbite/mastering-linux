# Part Three: Intermediate SSH Usage

## Table of Contents

- [3.1 SSH Configuration Files](#31-ssh-configuration-files)
- [3.2 Advanced SSH Key Management](#32-advanced-ssh-key-management)
- [3.3 Leveraging SSH Agent](#33-leveraging-ssh-agent)
- [3.4 Port Forwarding and Tunneling](#34-port-forwarding-and-tunneling)
- [3.5 SSH Jump Hosts](#35-ssh-jump-hosts)
- [3.6 Command-Line Control Using ~C](#36-command-line-control-using-c)
- [3.7 Best Practices](#37-best-practices)
- [3.8 Further Reading](#38-further-reading)

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

## 3.4 Port Forwarding and Tunneling

SSH port forwarding, also known as SSH tunneling, allows you to securely redirect network traffic through an encrypted SSH connection.

### 3.4.1 Local Port Forwarding

**Syntax:**
```bash
ssh -L [local_address:]local_port:remote_address:remote_port [user@]ssh_server
```

**Example:**
```bash
ssh -L 8080:remote-webserver:80 user@ssh-server
```

### 3.4.2 Remote Port Forwarding

**Syntax:**
```bash
ssh -R [remote_address:]remote_port:local_address:local_port [user@]ssh_server
```

**Example:**
```bash
ssh -R 8080:localhost:3000 user@remote-server
```

### 3.4.3 Dynamic Port Forwarding (SOCKS Proxy)

**Syntax:**
```bash
ssh -D [local_address:]local_port [user@]ssh_server
```

**Example:**
```bash
ssh -D 1080 user@remote-server
```

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

Usage:
```bash
ssh targethost
```

## 3.6 Command-Line Control Using ~C

SSH provides a command-line interface during an active session using the `~C` escape sequence. This allows you to manage port forwarding and other connection parameters on-the-fly.

To access this interface:

1. Press `Enter` to ensure you're on a new line
2. Type `~C` (tilde followed by capital C)

You'll see a prompt like this:
```
ssh>
```

Available commands:

- `-L [bind_address:]port:host:hostport`: Add local port forwarding
- `-R [bind_address:]port:host:hostport`: Add remote port forwarding
- `-D [bind_address:]port`: Add dynamic port forwarding
- `-KL[bind_address:]port`: Cancel local forwarding
- `-KR[bind_address:]port`: Cancel remote forwarding
- `-KD[bind_address:]port`: Cancel dynamic forwarding
- `?`: Display help
- `exit` or `~.`: Exit the SSH session

Example usage:

```
ssh> -L 8080:localhost:80
Forwarding port.
ssh> -KL 8080
Cancelling forwarding port 8080
ssh> ?
Commands:
      -L[bind_address:]port:host:hostport    Request local forward
      -R[bind_address:]port:host:hostport    Request remote forward
      -D[bind_address:]port                  Request dynamic forward
      -KL[bind_address:]port                 Cancel local forward
      -KR[bind_address:]port                 Cancel remote forward
      -KD[bind_address:]port                 Cancel dynamic forward
ssh> exit
```

This feature is particularly useful for adding or removing port forwards without disconnecting and reconnecting to the SSH session.

## 3.7 Best Practices

1. Use unique keys for different purposes (work, personal, etc.).
2. Regularly rotate SSH keys (e.g., annually).
3. Implement strong passphrases for private keys.
4. Use SSH agent forwarding cautiously and only on trusted systems.
5. Audit and remove unused authorized keys regularly.
6. Keep your SSH client and server software updated.
7. Use key types like Ed25519 for better security and performance.
8. Implement fail2ban or similar tools to prevent brute-force attacks.

## 3.8 Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines on Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)

---

**Note:** This guide is based on OpenSSH version 8.0 and later. Some features may not be available in earlier versions.

**License:** This document is released under the MIT License. See LICENSE file for details.

**Contributions:** We welcome contributions to improve this guide. Please see CONTRIBUTING.md for guidelines on how to submit improvements or corrections.
