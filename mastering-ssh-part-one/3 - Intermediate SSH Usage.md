# Part Three: Intermediate SSH Usage

## Table of Contents
3.1 SSH Configuration Files
3.2 Advanced SSH Key Management
3.3 Leveraging SSH Agent
3.4 Port Forwarding and Tunneling
3.5 SSH Jump Hosts

## 3.1 SSH Configuration Files

SSH configuration files allow for customization and streamlining of SSH connections. Understanding and utilizing these files effectively can greatly enhance your SSH workflow.

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

| Option               | Description                                                |
|----------------------|------------------------------------------------------------|
| Host                 | Alias for the SSH connection                               |
| HostName             | Server's hostname or IP address                            |
| User                 | Login username                                             |
| Port                 | SSH port (if not default 22)                               |
| IdentityFile         | Path to private key for authentication                     |
| ForwardAgent         | Enables SSH agent forwarding                               |
| ServerAliveInterval  | Time interval for sending keep-alive messages              |
| ServerAliveCountMax  | Maximum number of keep-alive messages without response     |

**Usage:** With this configuration, you can simply run `ssh myserver` instead of `ssh -p 2222 john@example.com -i ~/.ssh/id_rsa_myserver`.

### Server-Side Configuration

**File Location:** `/etc/ssh/sshd_config`
**Purpose:** Controls SSH daemon (`sshd`) operation, including security settings and login policies.

#### Key Settings:

| Setting                | Recommended Value | Purpose                                        |
|------------------------|--------------------|-------------------------------------------------|
| PermitRootLogin        | no                 | Disables root login via SSH                     |
| PasswordAuthentication | no                 | Enforces key-based logins                       |
| PubkeyAuthentication   | yes                | Enables key-based authentication                |
| Port                   | 2222               | Changes default SSH port                        |
| AllowUsers             | john alice         | Restricts SSH access to specific users          |
| MaxAuthTries           | 3                  | Limits authentication attempts                  |
| LoginGraceTime         | 60                 | Sets timeout for successful authentication      |
| X11Forwarding          | no                 | Disables X11 forwarding for security            |

**Applying Changes:**
```bash
sudo nano /etc/ssh/sshd_config  # Edit the file
sudo systemctl restart sshd     # Restart SSH service to apply changes
```

## 3.2 Advanced SSH Key Management

Effective key management is crucial for maintaining secure and efficient SSH access across multiple systems.

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

1. Generate a new key:
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_newserver
   ```

2. Add to server:
   - Manual method:
     ```bash
     cat ~/.ssh/id_ed25519_newserver.pub | ssh user@host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
     ```
   - Automated method:
     ```bash
     ssh-copy-id -i ~/.ssh/id_ed25519_newserver.pub user@host
     ```

### Restricting Key Usage

Prepend `authorized_keys` entry with options to restrict key usage:

```plaintext
command="/usr/bin/uptime",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3Nza...
```

This key can only execute the `uptime` command and cannot use port forwarding, X11 forwarding, or agent forwarding.

### Setting Key Expiration

For temporary access (OpenSSH 8.2+):

```bash
ssh-keygen -t ed25519 -O verify-required -O expiration-time=+7d -f ~/.ssh/id_ed25519_temp
```

This creates a key that expires in 7 days.

## 3.3 Leveraging SSH Agent

SSH Agent holds private keys in memory, eliminating the need for repeated passphrase entry.

### Usage

1. Start SSH Agent:
   ```bash
   eval "$(ssh-agent -s)"
   ```

2. Add keys:
   ```bash
   ssh-add ~/.ssh/id_rsa
   ssh-add ~/.ssh/id_ed25519_work
   ```

3. List added keys:
   ```bash
   ssh-add -l
   ```

4. Remove a specific key:
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

SSH port forwarding allows you to securely tunnel network connections through an SSH connection.

### Local Port Forwarding

Access a remote service through a local port:

```bash
ssh -L 8080:remote-host:80 user@ssh-server
```

This forwards your local port 8080 to `remote-host:80` through `ssh-server`.

### Remote Port Forwarding

Make a local service accessible from a remote machine:

```bash
ssh -R 8080:localhost:80 user@remote-server
```

This makes your local port 80 accessible on `remote-server:8080`.

### Dynamic Port Forwarding (SOCKS Proxy)

Create a SOCKS proxy for flexible routing:

```bash
ssh -D 1080 user@ssh-server
```

Configure your applications to use localhost:1080 as a SOCKS proxy.

## 3.5 SSH Jump Hosts

Use an intermediary host to access a target that's not directly accessible.

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

This will automatically route through the jump host.

### Multiple Jump Hosts

For scenarios requiring multiple jumps:

```plaintext
Host targethost
    HostName 192.168.1.100
    User targetuser
    ProxyJump jumphost1,jumphost2
```

## Best Practices

1. Use unique keys for different purposes (work, personal, etc.)
2. Regularly rotate SSH keys (e.g., annually)
3. Implement strong passphrases for private keys
4. Use SSH agent forwarding cautiously and only on trusted systems
5. Audit and remove unused authorized keys regularly
6. Keep your SSH client and server software updated
7. Use key types like Ed25519 for better security and performance
8. Implement fail2ban or similar tools to prevent brute-force attacks

## Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines on Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)
