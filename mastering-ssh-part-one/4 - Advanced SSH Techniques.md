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

Effective monitoring and auditing of SSH activities are crucial for maintaining a secure environment. This section covers setting up logging, analyzing logs, and implementing intrusion detection systems to fortify your SSH access.

### 4.1.1 Logging SSH Activities

To ensure comprehensive logging of SSH activities, configure the `LogLevel` setting in the SSH server configuration file:

```plaintext
LogLevel VERBOSE
```

This setting, typically found in `/etc/ssh/sshd_config`, provides detailed logs about login attempts, key usage, and session activities, which are essential for effective monitoring.

<div style="text-align: center;"> 
  **Screenshot of:** The SSH configuration file (`/etc/ssh/sshd_config`) with `LogLevel VERBOSE` highlighted.  
</div>

The SSH daemon configuration file is open in a text editor. The `LogLevel VERBOSE` line is highlighted, demonstrating where to set this crucial logging parameter.

---

### 4.1.2 Analyzing SSH Logs

Analyzing SSH logs helps identify suspicious activities. The key log files to focus on are:

- `/var/log/auth.log` (Debian/Ubuntu systems)
- `/var/log/secure` (Red Hat/CentOS systems)

Here are some useful commands for log analysis:

```bash
# Count failed login attempts
grep "Failed password" /var/log/auth.log | wc -l

# List unique IP addresses of failed attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

- The first command counts the total number of failed password attempts, providing a quick overview of potential brute-force attacks.
- The second command lists unique IP addresses with the number of failed attempts, helping identify the sources of these attempts.


  ![log-analysis-command](https://github.com/user-attachments/assets/ddd8b7eb-3fe3-45aa-885a-6260548c9fc5)


Terminal output after running the log analysis commands. It displays a list of IP addresses sorted by the number of failed login attempts, with the most frequent offenders at the top.

---

### 4.1.3 Implementing Intrusion Detection

**Fail2Ban** is a powerful tool that automates the process of blocking suspicious IP addresses. Here's how to set up Fail2Ban for SSH:

1. Install Fail2Ban:
    ```bash
    sudo apt-get install fail2ban
    ```

2. Configure the jail for SSH:
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

This setup automatically bans IP addresses after three failed login attempts for one hour.

![etcfail2banjail](https://github.com/user-attachments/assets/ff7cc96a-0334-4359-9ddc-53e29d25ad4d)

The Fail2Ban configuration file (`/etc/fail2ban/jail.local`) is open in a text editor, with the `[sshd]` settings section highlighted to show how to configure Fail2Ban for SSH.

---

## 4.2 SSH Escape Sequences

SSH escape sequences allow you to manage SSH connections dynamically without terminating your session. These sequences are especially useful for handling unresponsive connections and inspecting forwarded ports.

### 4.2.1 Common Escape Sequences

Here are some commonly used escape sequences:

| Sequence | Description                           |
|----------|---------------------------------------|
| `~.`     | Immediately terminate the connection. |
| `~^Z`    | Suspend the session and return to the local shell. |
| `~#`     | List all forwarded connections.       |
| `~?`     | Show a list of available escape sequences. |
| `~~`     | Send the escape character itself.     |

These sequences are useful for recovering from unresponsive sessions or managing port forwarding.

<div style="text-align: center;"> 
  **Screenshot of:** Terminal showing the result of typing `~?`, listing all available escape sequences in an active SSH session.
</div>

**Screenshot Description:** The terminal displays a list of available SSH escape sequences after the user types `~?`. This illustrates how escape sequences can be used to control an SSH session.

---

### 4.2.2 Using Escape Sequences

To use an escape sequence, press `Enter` to start a new line, then type the sequence. For example, `~.` will immediately terminate the session.

<div style="text-align: center;"> 
  **Screenshot of:** An SSH session in which the escape sequence `~.` is used to terminate the connection.
</div>

The terminal shows the SSH session being terminated using the `~.` escape sequence, illustrating its immediate effect on closing the connection.

---

## 4.3 SSH Honeypots

SSH honeypots are deceptive environments designed to attract and monitor attackers. These honeypots gather intelligence on potential attacks and help improve security practices by capturing information about attack methods and behaviors.

### 4.3.1 Setting Up a Basic SSH Honeypot

**Kippo** is a popular low-interaction SSH honeypot. To set it up:

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

3. Edit the key settings:
    ```plaintext
    ssh_port = 2222
    hostname = FakeServer
    ```

4. Start Kippo:
    ```bash
    ./start.sh
    ```

This setup simulates a vulnerable SSH server on port 2222, capturing attacker interactions for analysis.

Logging with Kippo
There are a few things which are logged without any extra configuration. One of which is the logging of unauthorized access. For example, when someone tries to login to our server with SSH, not knowing that we have changed the port number, they would see something like this:

![kippo-1](https://github.com/user-attachments/assets/ff329295-21fc-42be-a85d-b9365ea91932)

As long as our start.sh script is running, our events will be logged in /home/kippo/kippo/log/kippo.log. Lets open that file with a text editor (of your choice) and see what has been logged.

---

### 4.3.2 Analyzing Honeypot Data

Kippo generates logs stored in the `log` directory. These logs can be analyzed using tools such as the **ELK Stack** (Elasticsearch, Logstash, and Kibana) to visualize attack trends and patterns.

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

Connect to the container:

```bash
ssh root@localhost -p 2222
```

<div style="text-align: center;"> 
  **Screenshot of:** Terminal showing Docker build and run commands and a successful SSH connection to the container.
</div>

Terminal output demonstrates the Docker build and run process, followed by a successful SSH connection to the running container.

---

### 4.4.2 SSH Agent Forwarding with Docker

To enable SSH agent forwarding inside a Docker container, mount your local SSH agent:

```bash
docker run -it --rm \
  -v $SSH_AUTH_SOCK:/ssh-agent \
  -e SSH_AUTH_SOCK=/ssh-agent \
  ubuntu /bin/bash
```

This setup allows your container to use SSH keys from your local environment.

<div style="text-align: center;"> 
  **Screenshot of:** Docker container terminal showing successful SSH agent forwarding and key usage within the container.
</div>

The terminal shows a Docker container using SSH agent forwarding, allowing the container to authenticate with the user's local SSH keys.

---

### 

4.5 Best Practices

1. **Enforce strong authentication methods**: Use SSH key-based authentication instead of passwords, and disable password login for additional security.
2. **Use two-factor authentication (2FA)**: Integrate tools like Google Authenticator or Duo for an extra layer of security.
3. **Limit access to known IP addresses**: Configure `AllowUsers` or `AllowGroups` in `sshd_config` to restrict login access.
4. **Deploy honeypots**: Set up honeypots to gather intelligence on potential attacks.
5. **Secure containers**: Ensure SSH containers are isolated and utilize proper network segmentation.

---

### 4.6 Further Reading

- [OpenSSH Security Best Practices](https://www.openssh.com/security.html)
- [Intrusion Detection with Fail2Ban](https://www.fail2ban.org)
- [Setting up an ELK Stack for Honeypot Monitoring](https://www.elastic.co)
