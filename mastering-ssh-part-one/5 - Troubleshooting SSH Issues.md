# Part Five: Troubleshooting SSH Issues

## Table of Contents

- [5.1 Common SSH Errors and Solutions](#51-common-ssh-errors-and-solutions)
- [5.2 Advanced Debugging Techniques](#52-advanced-debugging-techniques)
- [5.3 Performance Optimization](#53-performance-optimization)
- [5.4 Security Auditing](#54-security-auditing)

## 5.1 Common SSH Errors and Solutions

### Permission Denied (Publickey)

**Symptoms:**
- Error message: `Permission denied (publickey)` when attempting to log in.

**Causes:**
1. Improper SSH key setup on the server
2. Incorrect permissions on key files
3. SSH agent not running or key not added

**Solutions:**

1. Verify public key in `authorized_keys`:
   ```bash
   cat ~/.ssh/id_rsa.pub | ssh user@host "cat >> ~/.ssh/authorized_keys"
   ```

   {screenshot: Adding public key to `authorized_keys`}

2. Check and correct file permissions:
   ```bash
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/authorized_keys
   ```

   {screenshot: Setting correct permissions on `.ssh` directory}

3. Ensure SSH agent is running and key is added:
   ```bash
   eval $(ssh-agent)
   ssh-add ~/.ssh/id_rsa
   ```

   {screenshot: Starting SSH agent and adding key}

### Connection Refused

**Symptoms:**
- SSH connection attempts fail with `Connection refused` error.

**Causes:**
1. SSH service not running
2. Firewall blocking SSH port
3. Incorrect SSH port configuration

**Solutions:**

1. Check and restart SSH service:
   ```bash
   sudo systemctl status sshd
   sudo systemctl restart sshd
   ```

   {screenshot: Checking and restarting SSH service}

2. Verify firewall settings:
   ```bash
   sudo ufw status
   sudo ufw allow ssh
   ```

   {screenshot: Checking and modifying firewall settings}

3. Confirm SSH port in `/etc/ssh/sshd_config`:
   ```bash
   grep Port /etc/ssh/sshd_config
   ```

   {screenshot: Checking SSH port configuration}

### Host Key Verification Failed

**Symptoms:**
- Warning that the remote host identification has changed.

**Causes:**
1. Server's SSH key has changed (reinstallation or potential security breach)
2. Man-in-the-middle attack attempt

**Solutions:**

1. Remove old key from `known_hosts`:
   ```bash
   ssh-keygen -R hostname
   ```

   {screenshot: Removing old host key from `known_hosts`}

2. Verify server's new key fingerprint:
   ```bash
   ssh-keyscan -H hostname | ssh-keygen -lf -
   ```

   {screenshot: Verifying new server key fingerprint}

## 5.2 Advanced Debugging Techniques

### SSH Verbose Logging

Use increasing levels of verbosity for detailed connection information:

```bash
ssh -v username@remote_host    # Basic verbosity
ssh -vv username@remote_host   # More detailed
ssh -vvv username@remote_host  # Maximum detail
```

{screenshot: SSH command with verbose logging}

### Analyzing Server Logs

1. Real-time log monitoring:
   ```bash
   sudo tail -f /var/log/auth.log
   ```

   {screenshot: Real-time log monitoring in terminal}

2. Grep for specific SSH events:
   ```bash
   grep "sshd" /var/log/auth.log | grep "Failed"
   ```

   {screenshot: Searching for failed SSH events in logs}

### Network Connectivity Testing

1. Test SSH port accessibility:
   ```bash
   nc -zv remote_host 22
   ```

   {screenshot: Testing port accessibility with `nc`}

2. Traceroute to identify network issues:
   ```bash
   traceroute remote_host
   ```

   {screenshot: Running traceroute command}

### SSH Config Debugging

1. Test SSH with default config:
   ```bash
   ssh -F /dev/null username@remote_host
   ```

   {screenshot: Testing SSH with default configuration}

2. Use ssh-audit tool for configuration analysis:
   ```bash
   ssh-audit hostname
   ```

   {screenshot: Running `ssh-audit` for configuration analysis}

## 5.3 Performance Optimization

### Compression

Enable compression for slow connections:

```bash
ssh -C username@remote_host
```

{screenshot: SSH command with compression enabled}

### Multiplexing

Use ControlMaster for faster subsequent connections:

In `~/.ssh/config`:

```plaintext
Host *
    ControlMaster auto
    ControlPath ~/.ssh/controlmasters/%r@%h:%p
    ControlPersist 10m
```

{screenshot: SSH multiplexing configuration}

### Key Type Selection

Use ED25519 keys for improved performance:

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

{screenshot: Generating ED25519 key pair}

## 5.4 Security Auditing

### Key Management

1. List and review SSH keys:
   ```bash
   for key in ~/.ssh/id_*; do ssh-keygen -l -f "${key}"; done | uniq
   ```

   {screenshot: Listing and reviewing SSH keys}

2. Rotate old or compromised keys:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new
   ```

   {screenshot: Rotating old SSH keys}

### Failed Login Attempts

Monitor failed login attempts:

```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

{screenshot: Monitoring failed login attempts}

### SSH Configuration Audit

Use ssh-audit for comprehensive security checks:

```bash
ssh-audit hostname
```

{screenshot: Running `ssh-audit` for security audit}

### Intrusion Detection

Set up fail2ban for automated intrusion prevention:

```bash
sudo apt-get install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

{screenshot: Installing and configuring fail2ban}

## Best Practices Summary

1. Regularly update SSH software and configurations.
2. Implement key-based authentication and disable password login.
3. Use strong encryption algorithms and key types.
4. Monitor logs and set up automated alerts for suspicious activities.
5. Conduct regular security audits and penetration testing.
6. Keep backups of SSH configurations and keys.
7. Educate users on SSH best practices and security awareness.

{screenshot: Summary of best practices}

## Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/ssh/security/)
- [NIST Guidelines for Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
