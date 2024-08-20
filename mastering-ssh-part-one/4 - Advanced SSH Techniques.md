# Part Four: Advanced SSH Techniques

## Table of Contents

- [4.1 SSH Security Monitoring and Auditing](#41-ssh-security-monitoring-and-auditing)
- [4.2 SSH Escape Sequences](#42-ssh-escape-sequences)
- [4.3 SSH Honeypots](#43-ssh-honeypots)
- [4.4 SSH and Containers](#44-ssh-and-containers)
- [4.5 Best Practices](#45-best-practices)
- [4.6 Further Reading](#46-further-reading)

## 4.1 SSH Security Monitoring and Auditing

Monitoring and auditing SSH activities are crucial for maintaining a secure environment. This section covers how to set up logging, analyze logs, and implement intrusion detection systems to keep your SSH access secure.

### 4.1.1 Logging SSH Activities

To ensure detailed logging of SSH activities, configure the `LogLevel` setting in the SSH server configuration file located at `/etc/ssh/sshd_config`.

```plaintext
LogLevel VERBOSE
```

This setting provides detailed logs about login attempts, key usage, and session activities, essential for effective monitoring.

{screenshot of: The SSH configuration file (`/etc/ssh/sshd_config`) with `LogLevel VERBOSE` highlighted.}

### 4.1.2 Analyzing SSH Logs

Analyzing SSH logs helps identify suspicious activities. Key log files are:

- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (Red Hat/CentOS)

Useful commands for log analysis:

```bash
# Count failed login attempts
grep "Failed password" /var/log/auth.log | wc -l

# List unique IP addresses of failed attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

These commands help identify failed login attempts and the associated IP addresses.

{screenshot of: Terminal showing output of log analysis commands, listing IP addresses and counts of failed login attempts.}

### 4.1.3 Implementing Intrusion Detection

Tools like Fail2Ban can help automate the process of blocking suspicious IP addresses. Here’s how to set up Fail2Ban for SSH:

1. Install Fail2Ban:
    ```bash
    sudo apt-get install fail2ban
    ```

2. Configure Fail2Ban:
    ```bash
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo nano /etc/fail2ban/jail.local
    ```

3. Add SSH-specific rules:
    ```plaintext
    [sshd]
    enabled = true
    port = ssh
    filter = sshd
    logpath = /var/log/auth.log
    maxretry = 3
    bantime = 3600
    ```

This configuration automatically bans IP addresses after a set number of failed login attempts.

{screenshot of: Fail2Ban configuration file (`/etc/fail2ban/jail.local`) with SSH-specific settings highlighted.}

### 4.1.4 Setting Up SSH Auditing

For thorough SSH auditing, use `auditd` to monitor SSH-related activities:

1. Install and configure `auditd`:
    ```bash
    sudo apt-get install auditd
    sudo nano /etc/audit/rules.d/audit.rules
    ```

2. Add auditing rules:
    ```plaintext
    -w /etc/ssh/sshd_config -p wa -k sshd_config
    -w /etc/ssh/ -p wa -k ssh
    -w /var/log/auth.log -p wa -k auth_log
    ```

3. Restart the audit daemon:
    ```bash
    sudo service auditd restart
    ```

These rules track changes to critical SSH-related files and logs.

{screenshot of: Terminal showing addition of audit rules and restart of `auditd` service.}

## 4.2 SSH Escape Sequences

SSH escape sequences provide control over your SSH sessions without disconnecting. These sequences are like shortcuts for managing SSH connections.

### 4.2.1 Common Escape Sequences

Here are some useful escape sequences:

| Sequence | Description |
|----------|-------------|
| `~.`     | Terminate the connection immediately. |
| `~^Z`    | Suspend the connection and return to the local shell. |
| `~#`     | List all forwarded connections. |
| `~?`     | Display a list of available escape sequences. |
| `~~`     | Send the escape character itself to the remote server. |

These sequences help manage unresponsive sessions or perform specific actions quickly.

{screenshot of: Terminal showing `~?` escape sequence output, listing available escape sequences.}

### 4.2.2 Using Escape Sequences

To use an escape sequence, press `Enter` to ensure you are on a new line, then type the sequence, such as `~.` to close the connection.

### 4.2.3 Customizing Escape Character

You can change the default escape character using the `-e` option when starting an SSH session:

```bash
ssh -e '^' user@host
```

This avoids conflicts if the default `~` is used for other purposes.

{screenshot of: SSH command with custom escape character and usage of the new escape sequence.}

## 4.3 SSH Honeypots

SSH honeypots attract and trap attackers to study their methods. Setting up a honeypot can provide valuable insights into attack patterns.

### 4.3.1 Setting Up a Basic SSH Honeypot

Kippo is a popular SSH honeypot that simulates a vulnerable SSH server:

1. Clone Kippo:
    ```bash
    git clone https://github.com/desaster/kippo.git
    cd kippo
    ```

2. Configure Kippo:
    ```bash
    cp kippo.cfg.dist kippo.cfg
    nano kippo.cfg
    ```

3. Key settings:
    ```plaintext
    ssh_port = 2222
    hostname = SomeServer
    log_path = log
    download_path = dl
    contents_path = honeyfs
    filesystem_file = honeyfs/fs.pickle
    data_path = data
    ```

4. Run Kippo:
    ```bash
    ./start.sh
    ```

Kippo creates a realistic SSH environment to monitor attacker activities.

{screenshot of: Terminal showing Kippo setup and start process.}

### 4.3.2 Analyzing Honeypot Data

Kippo logs interactions in the `log` directory. Use the ELK stack to analyze and visualize this data:

ELK stack transforms Kippo logs into actionable insights with dashboards displaying attack trends and geographical distribution.

{screenshot of: Kibana dashboard with visualizations of Kippo log data, including attack patterns and locations.}

## 4.4 SSH and Containers

Integrating SSH with containers provides secure communication between isolated environments. This section explains how to run an SSH server in a Docker container and use SSH agent forwarding.

### 4.4.1 Running SSH Server in a Docker Container

Create a Dockerfile to run an SSH server in a Docker container:

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:password' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
```

**Build and run the container:**

```bash
docker build -t ssh-server .
docker run -d -p 2222:22 ssh-server
```

**Connect to the container:**

```bash
ssh root@localhost -p 2222
```

This setup deploys a functional SSH server within a Docker container.

{screenshot of: Docker build, run commands, and successful SSH connection to the container.}

### 4.4.2 SSH Agent Forwarding with Docker

Mount your local SSH agent inside a Docker container to use your local SSH keys:

```bash
docker run -it --rm \
  -v $SSH_AUTH_SOCK:/ssh-agent \
  -e SSH_AUTH_SOCK=/ssh-agent \
  ubuntu /bin/bash
```

This allows authentication to remote servers from within the container.

{screenshot of: Docker container showing SSH agent forwarding and successful key usage.}

### 4.4.3 SSH Jump Host with Docker

Use a Docker container as an SSH jump host:

```bash
docker run -d --name jump-host \
  -p 2222:22 \
  -v ~/.ssh/authorized_keys:/root/.ssh/authorized_keys:ro \
  ssh-server

ssh -J root@localhost:2222 user@target-host
```

This centralizes SSH access through a Docker-based jump host.

{screenshot of: Docker-based jump host setup and successful SSH connection through it.}

## 4.5 Best Practices

Implement these best practices to secure your SSH infrastructure:

1. **Regularly review and analyze SSH logs** for unusual activities.
2. **Use intrusion detection systems like Fail2Ban** to block suspicious IP addresses.
3. **Familiarize with SSH escape sequences** and use them judiciously.
4. **Isolate SSH honeypots** to avoid risks to production environments.
5. **Employ strong authentication methods** and limit exposed ports for containerized SSH servers.
6. **Keep SSH clients and servers updated** and patched regularly

 to mitigate vulnerabilities.

## 4.6 Further Reading

Explore the following resources for more in-depth knowledge:

- **"SSH Mastery: OpenSSH, PuTTY, Tunnels, and Keys"** by Michael W Lucas
- **"Linux Hardening in Hostile Networks: Server Security from TLS to Tor"** by Kyle Rankin
- **The Fail2Ban documentation** for advanced configuration options: [Fail2Ban](https://www.fail2ban.org/wiki/index.php/Main_Page)
- **Kippo documentation** and usage guides: [Kippo](https://github.com/desaster/kippo)
