```
 _____  _____ _    _   __  __           _            
/ ____|/ ____| |  | | |  \/  |         | |           
| (___ | (___ | |__| | | \  / | __ _ ___| |_ ___ _ __ 
\___ \ \___ \|  __  | | |\/| |/ _` / __| __/ _ \ '__|
____) |____) | |  | | | |  | | (_| \__ \ ||  __/ |   
|_____/|_____/|_|  |_| |_|  |_|\__,_|___/\__\___|_|   
                                                     
```

# SSH Mastery: From Zero to Hero 🚀

## Table of Contents
1. [What the Hell is SSH?](#1-what-the-hell-is-ssh)
2. [Getting Started: Your First SSH Connection](#2-getting-started-your-first-ssh-connection)
3. [Keys to the Kingdom: SSH Key Pairs](#3-keys-to-the-kingdom-ssh-key-pairs)
4. [Config Files: Your Secret Weapon](#4-config-files-your-secret-weapon)
5. [Securing the Fort: Basic Server Hardening](#5-securing-the-fort-basic-server-hardening)
6. [Next Level: Advanced Tricks](#6-next-level-advanced-tricks)

## 1. What the Hell is SSH?

SSH (Secure Shell) is like a secret tunnel between your computer and another one. It lets you control that computer remotely, transfer files, and do all sorts of cool stuff securely.

```
You                 The Internet              Remote Server
 |                   ~~~~~~~~~~~                   |
 |                  /           \                  |
 | ================/=== SSH ====\==================|
 |                /   Tunnel     \                 |
 |               /                \                |
[_]            ~~~~~~~~~~~                        [_]
```

## 2. Getting Started: Your First SSH Connection

To connect to a remote server:

```bash
ssh username@hostname
```

Example:
```bash
ssh hackerman@192.168.1.100
```

If it's your first time connecting, you'll see a message about the server's fingerprint. Type 'yes' to continue.

## 3. Keys to the Kingdom: SSH Key Pairs

Using passwords is so last century. Real hackers use key pairs!

Generate a key pair:
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

This creates two files:
- `id_ed25519` (private key - keep this secret!)
- `id_ed25519.pub` (public key - share this with servers)

Copy your public key to a server:
```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub username@hostname
```

Now you can log in without a password!

```
Your Computer                      Remote Server
 +----------+                       +----------+
 |          |                       |          |
 | Private  |                       | Public   |
 |   Key    |                       |   Key    |
 |          |                       |          |
 +----------+                       +----------+
      |                                  ^
      |           Authenticates          |
      +----------------------------------+
```

## 4. Config Files: Your Secret Weapon

Create `~/.ssh/config` on your local machine:

```
Host myserver
    HostName 192.168.1.100
    User hackerman
    IdentityFile ~/.ssh/id_ed25519

Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Now you can just type:
```bash
ssh myserver
```

## 5. Securing the Fort: Basic Server Hardening

Edit `/etc/ssh/sshd_config` on your server:

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart SSH service:
```bash
sudo systemctl restart sshd
```

## 6. Next Level: Advanced Tricks

### Port Forwarding

Local port forwarding:
```bash
ssh -L 8080:localhost:80 username@hostname
```

```
Your Computer        SSH Tunnel        Remote Server
 +---------+         ==========         +---------+
 | Browser |-------->|  :8080  |------->|  :80    |
 +---------+         ==========         +---------+
```

### Jump Hosts

```bash
ssh -J jumphost username@destination
```

```
You --> Jumphost --> Destination
 |         |             |
 |         |             |
[_]       [_]           [_]
```

### Agent Forwarding

```bash
ssh -A username@hostname
```

This lets you use your local SSH keys on the remote server. Be careful with this one!

