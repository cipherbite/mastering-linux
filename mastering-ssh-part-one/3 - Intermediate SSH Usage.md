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

SSH configuration files are like the control panel for your secure connections. They allow you to customize and streamline your SSH experience, much like setting up shortcuts on your computer for frequently used tasks.

### Client-Side Configuration

The client-side configuration file is located at `~/.ssh/config`. This file is your personal command center for SSH connections. It allows you to set up aliases, specify default settings, and customize how your SSH client behaves.

![ssh-multiple-hosts](https://github.com/user-attachments/assets/5aca31a2-a97b-4b17-946b-951f2667d371)

Typical ~/.ssh/config file with several host configurations. Each configuration block starts with "Host" followed by an alias name, and includes settings like HostName, User, and IdentityFile.

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

This configuration allows you to simply type `ssh myserver` instead of the full command `ssh -p 2222 john@example.com -i ~/.ssh/id_rsa_myserver`. It's like creating a speed dial for your SSH connections.

### Server-Side Configuration

The server-side configuration file is located at `/etc/ssh/sshd_config`. This file controls how the SSH server (daemon) operates. It's like setting the rules for who can enter your house and how they can do it.

![ssh-konfig-file](https://github.com/user-attachments/assets/bfef0dc0-5f91-4836-908d-e235d451026f)

Portion of the /etc/ssh/sshd_config file, highlighting important security settings such as PermitRootLogin, PasswordAuthentication, and AllowUsers.

Key settings to consider:

- `PermitRootLogin no`: This prevents direct root login via SSH, adding an extra layer of security.
- `PasswordAuthentication no`: This enforces key-based logins, which are generally more secure than passwords.
- `AllowUsers john alice`: This restricts SSH access to specific users, like having a guest list for your server.

To apply changes to the server configuration:

```bash
sudo nano /etc/ssh/sshd_config  # Edit the file
sudo systemctl restart sshd     # Restart SSH service to apply changes
```

## 3.2 Advanced SSH Key Management

Think of SSH keys as digital passkeys to your servers. Just as you might have different keys for your home, office, and car, you can have different SSH keys for various servers or purposes.

### Managing Multiple SSH Keys

Use your `~/.ssh/config` file to manage multiple keys:

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

This setup allows you to use different keys for different servers automatically.

### Adding New SSH Keys

1. Generate a new key:
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_newserver
   ```

2. Add to server:
   ```bash
   ssh-copy-id -i ~/.ssh/id_ed25519_newserver.pub user@host
   ```

Start by opening a terminal or command prompt. Enter the command ssh-keygen and press Enter.
The terminal asks where to save the new key. You can accept the default location by pressing Enter.
You are prompted to enter a passphrase for added security. Press Enter to skip if you don’t want a passphrase.

![ssh-keygen](https://github.com/user-attachments/assets/4a09d39a-abff-4165-8772-fd8e0f0eef6b)

The key pair is generated, and the terminal displays confirmation with the file locations and key fingerprint.

### Restricting Key Usage

You can add restrictions to keys in the `authorized_keys` file on the server:

```plaintext
command="/usr/bin/uptime",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3Nza...
```

This is like giving someone a key to your house that only works during certain hours or only opens certain doors.

## 3.3 Leveraging SSH Agent

The SSH agent is like a secure, intelligent key ring for your SSH keys. It holds your decrypted keys in memory, presenting the right one when needed without you having to enter a passphrase each time.

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

First start the SSH agent with "eval '$(ssh-agent -s)'" command.
Add Your SSH Private Key to the Agent.
Verify That The Key Has Been Added.

![ssh-agent](https://github.com/user-attachments/assets/000bf214-0eb7-47fe-9f72-42b45ad30103)

Terminal output when starting the SSH agent and adding multiple keys. It shows the agent pid when started and the fingerprints of the added keys.

## 3.4 Port Forwarding and Tunneling

SSH port forwarding is like creating secret tunnels for your data. It allows you to securely transmit data between different network locations, even if they're not directly connected.

### Local Port Forwarding

Local port forwarding is like having a secure tunnel from your local machine to a remote server.

Syntax:
```bash
ssh -L [local_address:]local_port:remote_address:remote_port [user@]ssh_server
```

Example:
```bash
ssh -L 8080:remote-webserver:80 user@ssh-server
```

This command creates a tunnel that forwards traffic from your local port 8080 to port 80 on remote-webserver, through ssh-server.

![local-port-forwarding](https://github.com/user-attachments/assets/21ad2efd-315e-4560-93b1-b8f22acca220)

This diagram shows a visual representation of local port forwarding. It depicts the local machine, the SSH server, and the remote web server, with arrows showing the flow of traffic through the SSH tunnel.

### Remote Port Forwarding

Remote port forwarding is like installing a two-way magic door in a remote location that leads back to your local machine.

Syntax:
```bash
ssh -R [remote_address:]remote_port:local_address:local_port [user@]ssh_server
```

Example:
```bash
ssh -R 8080:localhost:3000 user@remote-server
```

This command allows connections to port 8080 on the remote server to be forwarded to port 3000 on your local machine.

## 3.5 SSH Jump Hosts

An SSH Jump Host is like a secure transit lounge for your SSH connections. It's an intermediate server that you connect through to reach your final destination.

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
![ssh-jumphost-diagram](https://github.com/user-attachments/assets/36dc6eb8-2293-45d2-aa1b-7abaa2037a24)

This diagram illustrates the path of an SSH connection using a jump host. It shows the user's machine connecting to the jump host, and then the jump host connecting to the target server, with the SSH connection flowing through this path.

## 3.6 Command-Line Control Using ~C

The SSH escape sequence `~C` is like a hidden control panel within your SSH session. It allows you to modify your connection on-the-fly without disconnecting.

To access this interface:

1. Press `Enter` to ensure you're on a new line
2. Type `~C` (tilde followed by capital C)

![escape-sequence-~C](https://github.com/user-attachments/assets/e2bdea1b-d39b-4ac6-a753-b9c513d9088e)

You'll see a prompt like this:
```
ssh>
```

![~C-command](https://github.com/user-attachments/assets/755ad72d-143c-44f3-a0a4-e93cd94252e3)

SSH command-line interface after entering ~C. It shows the "ssh>" prompt and lists several available commands such as -L for local forwarding and -R for remote forwarding.


## 3.7 Best Practices

Following SSH best practices is like following the rules of the road for secure connections. Here are some key practices:

1. Use unique keys for different purposes (work, personal, etc.).
2. Regularly rotate SSH keys (e.g., annually).
3. Implement strong passphrases for private keys.
4. Use SSH agent forwarding cautiously and only on trusted systems.
5. Audit and remove unused authorized keys regularly.
6. Keep your SSH client and server software updated.
7. Use key types like Ed25519 for better security and performance.
8. Implement fail2ban or similar tools to prevent brute-force attacks.

## 3.8 Further Reading

To deepen your understanding of SSH, consider exploring these resources:

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines on Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)

---

**Note:** This guide is based on OpenSSH version 8.0 and later. Some features may not be available in earlier versions.

**License:** This document is released under the MIT License. See LICENSE file for details.

**Contributions:** We welcome contributions to improve this guide. Please see CONTRIBUTING.md for guidelines on how to submit improvements or corrections.
