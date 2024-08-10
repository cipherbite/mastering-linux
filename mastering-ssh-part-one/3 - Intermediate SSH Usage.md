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

Port forwarding and tunneling allow you to securely forward traffic through SSH to access remote services that might not be directly accessible.

### 3.4.1 Local Port Forwarding

Local Port Forwarding allows you to forward traffic from a local port to a remote server and port. It's useful for accessing a service on a remote server that isn't publicly accessible.

**Basic Syntax:**
```bash
ssh -L [local_address:]local_port:remote_address:remote_port [user@]ssh_server
```

**Examples:**

- **Example 1: Accessing a remote service through a local port**
   ```bash
   ssh -L 8080:remote-host:80 user@ssh-server
   ```
   This forwards traffic from local port 8080 to port 80 on `remote-host` through `ssh-server`.

- **Example 2: Accessing an internal web server**
   ```bash
   ssh -L 10.10.10.1:8001:localhost:8000 user@REMOTE-MACHINE
   ```
   This allows access to a web server on `REMOTE-MACHINE` that only listens on `127.0.0.1:8000`.

### 3.4.2 Remote Port Forwarding

Remote Port Forwarding allows you to forward traffic from a port on the remote SSH server to a port on your local machine.

**Basic Syntax:**
```bash
ssh -R [remote_address:]remote_port:local_address:local_port [user@]ssh_server
```
 
**Example:**
```bash
ssh -R 8080:localhost:80 user@remote-server
```
This forwards traffic from port 8080 on the remote server to port 80 on your local machine.

### 3.4.3 Dynamic Port Forwarding (SOCKS Proxy)

Dynamic Port Forwarding creates a local SOCKS proxy server that can route traffic to multiple remote destinations.

**Basic Syntax:**
```bash
ssh -D [local_address:]local_port [user@]ssh_server
```

**Example:**
```bash
ssh -D 1080 user@remote-server
```
This creates a SOCKS proxy on local port 1080.
This technique if often used to circumvent the restrictions put in place by firewalls, and allow an external entity to bypass the firewal and acess a service. Another benefit of using SOCKS proxy for pivoting and forwarding data is that SOCKS proxies can pivot via creating a route to an external server from NAT networks.

{screenshot of socks diagram }

**Applications:**
- Secure browsing through an encrypted tunnel.
- Accessing multiple services in a remote network without setting up individual port forwards.
- Bypassing geographical restrictions on web services.

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

## 3.6 SSH TUN/TAP Tunneling

SSH TUN/TAP tunneling can create a bi-directional TCP tunnel using the `-w` flag. This allows you to set up a secure connection that can pass all kinds of network traffic between your local and remote

 machines.

**Basic Syntax:**
```bash
ssh -w [local_tun]:[remote_tun] [user@]ssh_server
```

Note that the network interfaces (`tunX`) need to be created beforehand.

---

## Best Practices

1. Use unique keys for different purposes (work, personal, etc.).
2. Regularly rotate SSH keys (e.g., annually).
3. Implement strong passphrases for private keys.
4. Use SSH agent forwarding cautiously and only on trusted systems.
5. Audit and remove unused authorized keys regularly.
6. Keep your SSH client and server software updated.
7. Use key types like Ed25519 for better security and performance.
8. Implement fail2ban or similar tools to prevent brute-force attacks.

---

## Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines on Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)
```

