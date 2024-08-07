## Part Three: Intermediate SSH Usage

## Table of Contents

3.1 SSH Configuration Files
3.2 SSH Key Management
3.3 Using SSH Agent

## 3.1 SSH Configuration Files

### Client-Side Configuration

**File Location:** `~/.ssh/config`

**Purpose:** Simplifies SSH commands, manages multiple connections, and customizes client behavior.

#### Example Configuration:

```plaintext
Host myserver
    HostName example.com
    User john
    Port 2222
    IdentityFile ~/.ssh/id_rsa
    ForwardAgent yes
```

| Option       | Description                            |
| ------------ | -------------------------------------- |
| HostName     | Server's hostname or IP address        |
| User         | Login username                         |
| Port         | SSH port (if not default 22)           |
| IdentityFile | Path to private key for authentication |
| ForwardAgent | Enables SSH agent forwarding           |

### Server-Side Configuration

**File Location:** `/etc/ssh/sshd_config`

**Purpose:** Controls SSH daemon (`sshd`) operation, including security settings and login policies.

#### Key Settings:

| Setting                | Value | Purpose                                |
| ---------------------- | ----- | -------------------------------------- |
| PermitRootLogin        | no    | Disables root login via SSH            |
| PasswordAuthentication | no    | Enforces key-based logins              |
| PubkeyAuthentication   | yes   | Enables key-based authentication       |
| Port                   | 2222  | Changes default SSH port               |
| AllowUsers             | john  | Restricts SSH access to specific users |

**Applying Changes:**

```bash
sudo systemctl restart sshd
```

## 3.2 SSH Key Management

### Managing Multiple SSH Keys

Use `~/.ssh/config` to manage multiple keys:

```plaintext
Host workserver
    HostName work.example.com
    User workuser
    IdentityFile ~/.ssh/id_rsa_work

Host personalserver
    HostName personal.example.com
    User personaluser
    IdentityFile ~/.ssh/id_rsa_personal
```

### Adding New SSH Keys

1. Generate key: `ssh-keygen -t rsa -b 4096 -C "your_email@example.com"`
2. Add to server:
   - Manual: Append to `~/.ssh/authorized_keys`
   - Automated: `ssh-copy-id -i ~/.ssh/id_rsa_new.pub user@host`

### Restricting Key Usage

Prepend `authorized_keys` entry with `command` option:

```plaintext
command="/usr/bin/uptime" ssh-rsa AAAAB3Nza...
```

### Setting Key Expiration

For temporary access (OpenSSH 8.2+):

```bash
ssh-keygen -t ecdsa-sk -O verify-required -O expiration-time=+1d
```

## 3.3 Using SSH Agent

### Purpose

Holds private keys in memory, eliminating repeated passphrase entry.

### Usage

1. Start SSH Agent:

   ```bash
   eval "$(ssh-agent -s)"
   ```

2. Add keys:
   ```bash
   ssh-add ~/.ssh/id_rsa
   ```

### Automation Example

```bash
#!/bin/bash
# Script to automate SSH tasks

eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa
ssh myserver 'uptime'
```

## Best Practices

1. Use unique keys for different purposes (work, personal, etc.)
2. Regularly rotate SSH keys
3. Implement strong passphrases for private keys
4. Use SSH agent forwarding cautiously
5. Audit and remove unused authorized keys regularly

## Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)

---
