## Part Four: Advanced SSH Techniques

### Table of Contents

- [4.1 SSH Security Monitoring and Auditing](#41-ssh-security-monitoring-and-auditing)
- [4.2 SSH Escape Sequences](#42-ssh-escape-sequences)
- [4.3 SSH Honeypots](#43-ssh-honeypots)
- [4.4 SSH and Containers](#44-ssh-and-containers)
- [4.5 Best Practices](#45-best-practices)
- [4.6 Further Reading](#46-further-reading)

---

## 4.1 SSH Security Monitoring and Auditing

SSH security monitoring and auditing are critical for maintaining a secure environment. This section discusses how to set up logging, analyze logs, and implement intrusion detection systems to enhance your SSH security.

### 4.1.1 Logging SSH Activities

To comprehensively log SSH activities, configure the `LogLevel` in your SSH server configuration:

```plaintext
LogLevel VERBOSE
```

This setting, located in `/etc/ssh/sshd_config`, provides detailed logs about login attempts, key usage, and session activities—crucial data for monitoring and auditing.

![ssh-config](https://github.com/user-attachments/assets/ddd8b7eb-3fe3-45aa-885a-6260548c9fc5)

**Screenshot Description:** The SSH configuration file (`/etc/ssh/sshd_config`) is open, with the `LogLevel VERBOSE` setting highlighted, showing where to configure this important logging option.

---

### 4.1.2 Analyzing SSH Logs

Analyzing SSH logs helps detect suspicious activities. Focus on the following log files:

- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (Red Hat/CentOS)

Here are some useful commands:

```bash
# Count failed login attempts
grep "Failed password" /var/log/auth.log | wc -l

# List unique IP addresses of failed attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

- The first command counts failed login attempts, indicating potential brute-force attacks.
- The second command identifies the IP addresses of failed attempts, helping trace attack origins.

![log-analysis-command](https://github.com/user-attachments/assets/ddd8b7eb-3fe3-45aa-885a-6260548c9fc5)

**Screenshot Description:** Terminal output showing a list of IP addresses sorted by the number of failed login attempts, highlighting the most frequent offenders.

---

### 4.1.3 Implementing Intrusion Detection

**Fail2Ban** automates blocking suspicious IP addresses. To set up Fail2Ban for SSH:

1. Install Fail2Ban:
    ```bash
    sudo apt-get install fail2ban
    ```

2. Configure the SSH jail:
    ```bash
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo nano /etc/fail2ban/jail.local
    ```

3. Add the following SSH-specific settings:
    ```plaintext
    [sshd]
    enabled = true
    port = ssh
    filter = sshd
    logpath = /var/log/auth.log
    maxretry = 3
    bantime = 3600
    ```

This configuration bans IP addresses after three failed login attempts for one hour.

![etcfail2banjail](https://github.com/user-attachments/assets/ff7cc96a-0334-4359-9ddc-53e29d25ad4d)

**Screenshot Description:** The Fail2Ban configuration file (`/etc/fail2ban/jail.local`) is shown, with the `[sshd]` section highlighted, demonstrating the configuration for SSH protection.

---

## 4.2 SSH Escape Sequences

SSH escape sequences allow you to manage SSH connections dynamically without terminating the session. These sequences are especially useful for handling unresponsive connections and inspecting forwarded ports.

### 4.2.1 Common Escape Sequences

Here are some commonly used escape sequences:

| Sequence | Description                           |
|----------|---------------------------------------|
| `~.`     | Immediately terminate the connection. |
| `~^Z`    | Suspend the session and return to the local shell. |
| `~#`     | List all forwarded connections.       |
| `~?`     | Show a list of available escape sequences. |
| `~~`     | Send the escape character itself.     |

These sequences are essential for managing unresponsive sessions or port forwarding.

![ssh-escape-sequence](https://github.com/user-attachments/assets/ddd8b7eb-3fe3-45aa-885a-6260548c9fc5)

**Screenshot Description:** Terminal output showing the result of typing `~?`, listing all available escape sequences in an active SSH session.

---

### 4.2.2 Using Escape Sequences

To use an escape sequence, press `Enter` to start a new line, then type the sequence. For instance, `~.` will immediately terminate the session.

![ssh-terminate-escape](https://github.com/user-attachments/assets/ddd8b7eb-3fe3-45aa-885a-6260548c9fc5)

**Screenshot Description:** An SSH session is terminated using the `~.` escape sequence, illustrating its immediate effect.

---

## 4.3 SSH Honeypots

SSH honeypots are deceptive systems designed to attract and monitor attackers. These honeypots collect data on attack methods and behaviors, enhancing overall security.

### 4.3.1 Setting Up a Basic SSH Honeypot

**Kippo** is a widely used low-interaction SSH honeypot. Here’s how to set it up:

1. Clone Kippo from GitHub:
    ```bash
    git clone https://github.com/desaster/kippo.git
    cd kippo
    ```

2. Configure Kippo:
    ```bash
    cp kippo.cfg.dist kippo.cfg
    nano kippo.cfg
    ```

3. Edit key settings:
    ```plaintext
    ssh_port = 2222
    hostname = FakeServer
    ```

4. Start Kippo:
    ```bash
    ./start.sh
    ```

This setup simulates a vulnerable SSH server on port 2222, capturing attacker interactions.

![kippo-1](https://github.com/user-attachments/assets/ff329295-21fc-42be-a85d-b9365ea91932)

**Screenshot Description:** The `kippo.log` file displays unauthorized access attempts, logging activity captured by the honeypot.

---

### 4.3.2 Analyzing Honeypot Data

Kippo logs are stored in the `log` directory. You can analyze these logs using tools like the **ELK Stack** (Elasticsearch, Logstash, Kibana) to visualize attack patterns.

---

## 4.4 SSH and Containers

SSH can be integrated with containers for secure management of isolated environments. This section covers running SSH inside Docker containers and using SSH agent forwarding with containers.

### 4.4.1 Running an SSH Server in a Docker Container

Here is a basic Dockerfile to run an SSH server inside a container:

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:password' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
```

Build and run the container:

```bash
docker build -t ssh-server .
docker run -d -p 2222:22 ssh-server
```

![docker](https://github.com/user-attachments/assets/56dd2384-b9a3-41f4-b72d-7cdf68ad45f6)

---

### 4.4.2 SSH Agent Forwarding with Docker

To enable SSH agent forwarding inside a Docker container, mount your local SSH agent:

```bash
docker run -it --rm \
  -v $SSH_AUTH_SOCK:/ssh-agent \
  -e SSH_AUTH_SOCK=/ssh-agent \
  ubuntu /bin/bash
```

This allows your container to use SSH keys from your local environment.

**Screenshot Description:** A Docker container terminal shows successful SSH agent forwarding, enabling the container to authenticate with the user’s local SSH keys.

---

## 4.5 Best Practices

Following SSH best practices helps maintain a secure environment. Here are some key recommendations:

1. **Enforce strong authentication**: Use SSH key-based authentication instead of passwords, and disable password login for added security.
2. **Implement two-factor authentication (2FA)**: Tools like Google Authenticator or Duo add an extra layer of protection.
3. **Restrict access to known IP addresses**: Use `AllowUsers` or `AllowGroups` in `sshd_config` to limit who can log in.
4. **Deploy honeypots**: Use honeypots to gather intelligence on potential attacks.
5. **Secure containers**: Ensure SSH containers are isolated and properly segmented within

 the network.

---

## 4.6 Further Reading

- **SSH Mastery** by Michael W. Lucas
- **Linux Server Security** by Chris Binnie
- **Docker: Up & Running** by Karl Matthias and Sean P. Kane
