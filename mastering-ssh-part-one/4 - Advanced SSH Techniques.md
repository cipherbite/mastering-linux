# Part Four: Advanced SSH Techniques

## Table of Contents

- [4.1 SSH Tunneling (Port Forwarding)](#41-ssh-tunneling-port-forwarding)
- [4.2 SSH Agent Forwarding](#42-ssh-agent-forwarding)
- [4.3 SSH Security Best Practices](#43-ssh-security-best-practices)
- [4.4 Advanced SSH Configurations](#44-advanced-ssh-configurations)
- [4.5 Troubleshooting and Debugging SSH](#45-troubleshooting-and-debugging-ssh)

## 4.1 SSH Tunneling (Port Forwarding)

SSH tunneling creates secure channels for transferring data, enabling access to services across firewalls and enhancing network security.

### Types of SSH Tunneling

#### 1. Local Port Forwarding

**Syntax:**
```bash
ssh -L [local_address:]local_port:remote_address:remote_port username@ssh_server
```

**Example:**
```bash
ssh -L 8080:internal.example.com:80 user@gateway.example.com
```
This forwards requests to `localhost:8080` through `gateway.example.com` to `internal.example.com:80`.

**Use Cases:**
- Accessing internal web servers
- Secure database connections

#### 2. Remote Port Forwarding

**Syntax:**
```bash
ssh -R [remote_address:]remote_port:local_address:local_port username@ssh_server
```

**Example:**
```bash
ssh -R 8080:localhost:3000 user@public.example.com
```
This exposes your local service on port 3000 via port 8080 on `public.example.com`.

**Use Cases:**
- Sharing local development servers
- Temporary access to internal services

#### 3. Dynamic Port Forwarding (SOCKS Proxy)

**Syntax:**
```bash
ssh -D [local_address:]port username@ssh_server
```

**Example:**
```bash
ssh -D 1080 user@ssh.example.com
```
This establishes a SOCKS proxy on `localhost:1080`.

**Use Cases:**
- Secure browsing through an encrypted tunnel
- Bypassing geographic restrictions

#### 4. Reverse SSH Tunneling

**Syntax:**
```bash
ssh -R remote_port:localhost:local_port username@remote_host
```

**Example:**
```bash
ssh -R 2222:localhost:22 user@public.example.com
```
This allows connections to `public.example.com:2222` to reach your local SSH server.

**Use Cases:**
- Remote access to machines behind NAT
- Providing support access to internal networks

### Advanced Tunneling Techniques

#### Persistent Tunnels
Use `autossh` to maintain persistent tunnels:
```bash
autossh -M 0 -f -N -L 3306:localhost:3306 user@remote_host
```

#### Tunnel All Traffic
Create a full VPN-like setup using a SOCKS proxy and `proxychains`:
1. Set up dynamic port forwarding
2. Configure `proxychains`
3. Run applications through `proxychains`

## 4.2 SSH Agent Forwarding

SSH Agent Forwarding allows the use of local SSH keys on remote servers without copying the keys to those servers.

### Enabling SSH Agent Forwarding

#### Temporary Enabling
```bash
ssh -A username@remote_host
```

#### Permanent Configuration
In `~/.ssh/config`:
```plaintext
Host remote_host
    HostName example.com
    User username
    ForwardAgent yes
```

### Security Considerations
1. Only enable on trusted servers
2. Use `ssh-add -c` for confirmation before key usage
3. Monitor agent forwarding usage with `SSH_AUTH_SOCK` environment variable

### Advanced Agent Usage

#### Limiting Forwarded Keys
```bash
ssh-add -c ~/.ssh/specific_key
ssh -A username@remote_host
```

#### Agent Lifetime Management
Limit the lifetime of added keys:
```bash
ssh-add -t 3600 ~/.ssh/id_rsa  # Key usable for 1 hour
```

## 4.3 SSH Security Best Practices

| Practice              | Configuration                 | Purpose                               |
|-----------------------|-------------------------------|---------------------------------------|
| Disable Root Login    | `PermitRootLogin no`          | Prevent direct root access            |
| Change Default Port   | `Port 2222`                   | Reduce automated attacks              |
| Use Fail2Ban          | Install and configure         | Block IPs after failed attempts       |
| Disable Password Auth | `PasswordAuthentication no`   | Enforce key-based authentication      |
| Enable 2FA            | Use Google Authenticator      | Add extra layer of security           |
| Rotate SSH Keys       | Regular key regeneration      | Minimize risk of compromised keys     |
| Limit User Access     | `AllowUsers` or `AllowGroups` | Restrict SSH access to specific users |
| Use SSH Protocol 2    | `Protocol 2`                  | Use more secure SSH protocol version  |

### Implementing Fail2Ban

1. Installation:
   ```bash
   sudo apt-get install fail2ban
   ```

2. Configuration (`/etc/fail2ban/jail.local`):
   ```ini
   [sshd]
   enabled = true
   port = ssh
   filter = sshd
   logpath = /var/log/auth.log
   maxretry = 3
   bantime = 3600
   ```

3. Activate and start:
   ```bash
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```

### Setting Up Two-Factor Authentication (2FA)

1. Install Google Authenticator:
   ```bash
   sudo apt-get install libpam-google-authenticator
   ```

2. Configure PAM (`/etc/pam.d/sshd`):
   ```plaintext
   auth required pam_google_authenticator.so
   ```

3. Enable challenge-response authentication in `sshd_config`:
   ```plaintext
   ChallengeResponseAuthentication yes
   ```

4. Set up 2FA for users:
   ```bash
   google-authenticator
   ```

## 4.4 Advanced SSH Configurations

### Client-Side Configurations

#### SSH Config File (`~/.ssh/config`)
```plaintext
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3

Host bastion
    HostName bastion.example.com
    User jumpuser
    IdentityFile ~/.ssh/jump_key

Host internal
    HostName 10.0.0.5
    User internaluser
    ProxyJump bastion
    IdentityFile ~/.ssh/internal_key
```

### Server-Side Configurations

#### Chroot SFTP Users
In `sshd_config`:
```plaintext
Match Group sftponly
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

#### Bandwidth Limiting
Use `iptables` to limit SSH bandwidth:
```bash
iptables -A OUTPUT -p tcp --sport 22 -m limit --limit 512kb/s
```

## 4.5 Troubleshooting and Debugging SSH

### Verbose Logging
Use `-v`, `-vv`, or `-vvv` for increasing verbosity:
```bash
ssh -vvv user@host
```

### Common Issues and Solutions

1. **Connection Refused**
   - Check if sshd is running
   - Verify firewall settings

2. **Host Key Verification Failed**
   - Update known_hosts file
   - Verify server identity

3. **Permission Denied**
   - Check key permissions (should be 600)
   - Verify authorized_keys file

4. **Slow Connection**
   - Enable compression: `ssh -C user@host`
   - Check for DNS issues

### SSH Auditing
Use tools like `ssh-audit` to check for vulnerabilities:
```bash
ssh-audit hostname
```

## Best Practices Summary

1. Use unique, strong SSH keys for different purposes
2. Regularly audit and update authorized keys
3. Keep SSH software and configurations up to date
4. Implement comprehensive logging and monitoring
5. Use SSH tunneling cautiously and only when necessary
6. Combine SSH security with network-level security measures
7. Educate users on safe SSH practices

## Further Reading

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [NIST Guidelines for Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [SSH.com Security Best Practices](https://www.ssh.com/ssh/security/)
