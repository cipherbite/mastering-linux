Part 1: SSH Fundamentals
Table of Contents
1.1 🔑 Cryptography in SSH
1.2 🌐 SSH Protocols
1.3 🛠️ Advanced SSH Client Configuration
1.4 🔒 Hardening SSH Server
1.5 🔍 SSH Auditing and Monitoring
1.1 🔑 Cryptography in SSH
1.1.1 Public Key Algorithms
SSH supports various cryptographic algorithms. Here's how to generate keys using different algorithms:

bash
Copy code
# RSA (4096 bits)
ssh-keygen -t rsa -b 4096

# Ed25519 (recommended for new implementations)
ssh-keygen -t ed25519

# ECDSA
ssh-keygen -t ecdsa -b 521
1.1.2 Key Exchange and Session Encryption
SSH uses the Diffie-Hellman algorithm for secure key exchange. Here's how to see details of key exchange:

bash
Copy code
ssh -vv user@host | grep "kex:"
[Space for a diagram showing the key exchange process in SSH] Diagram of the key exchange and encrypted session establishment process in SSH

1.1.3 Key Fingerprint Verification
To enhance security, always verify key fingerprints:

bash
Copy code
# On the server
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

# On the client
ssh-keyscan -t ed25519 hostname | ssh-keygen -lf -
1.2 🌐 SSH Protocols
SSH consists of three main protocols:

Transport Layer Protocol
User Authentication Protocol
Connection Protocol
1.2.1 SSH Packet Analysis
To understand these protocols in-depth, you can capture and analyze SSH packets:

bash
Copy code
# Capture packets
sudo tcpdump -i eth0 'tcp port 22' -w ssh_packets.pcap

# Analyze with Wireshark
wireshark ssh_packets.pcap
[Space for a Wireshark screenshot showing SSH packet analysis] Wireshark analysis of SSH packets, showing different protocol phases

1.2.2 Implementing a Custom SSH Client
Here's a simple example of implementing an SSH client in Python using the paramiko library:

python
Copy code
import paramiko

class CustomSSHClient:
    def __init__(self, hostname, username, key_filename):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname, username=username, key_filename=key_filename)

    def execute_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command(command)
        return stdout.read().decode()

    def close(self):
        self.ssh.close()

# Usage
client = CustomSSHClient('example.com', 'user', '/path/to/key')
print(client.execute_command('ls -l'))
client.close()
1.3 🛠️ Advanced SSH Client Configuration
1.3.1 Advanced Options in ~/.ssh/config
bash
Copy code
Host *
    ControlMaster auto
    ControlPath ~/.ssh/controlmasters/%r@%h:%p
    ControlPersist 10m
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ForwardAgent yes
    AddKeysToAgent yes
    UseKeychain yes
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa

Host bastion
    HostName bastion.example.com
    User jumpuser
    IdentityFile ~/.ssh/bastion_key

Host internal
    HostName 192.168.1.100
    User internaluser
    ProxyJump bastion
    LocalForward 5432 localhost:5432
This configuration includes advanced options such as connection multiplexing, keeping connections alive, SSH agent forwarding, and intermediate host configuration.

1.3.2 Script for Dynamic SSH Configuration Generation
python
Copy code
import yaml
import os

def generate_ssh_config(config_yaml):
    with open(config_yaml, 'r') as file:
        config = yaml.safe_load(file)

    ssh_config = ""
    for host, details in config['hosts'].items():
        ssh_config += f"Host {host}\n"
        for key, value in details.items():
            ssh_config += f"    {key} {value}\n"
        ssh_config += "\n"

    with open(os.path.expanduser('~/.ssh/config'), 'w') as file:
        file.write(ssh_config)

generate_ssh_config('ssh_config.yaml')
This script allows for dynamic generation of SSH configuration based on a YAML file, making it easier to manage a large number of hosts.

1.4 🔒 Hardening SSH Server
1.4.1 Advanced sshd_config Configuration
bash
Copy code
# /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
X11Forwarding no
AllowUsers user1 user2
AllowGroups sshusers
LogLevel VERBOSE
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0
This configuration significantly increases the security of the SSH server.

1.4.2 Implementing Two-Factor Authentication
bash
Copy code
sudo apt install libpam-google-authenticator
sudo nano /etc/pam.d/sshd
Add the following at the end of the file:

swift
Copy code
auth required pam_google_authenticator.so
Then in /etc/ssh/sshd_config:

bash
Copy code
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
[Space for a diagram showing the two-factor authentication process in SSH] Diagram of the two-factor authentication process in SSH using a key and TOTP code

1.5 🔍 SSH Auditing and Monitoring
1.5.1 Advanced Logging with rsyslog
Configuration /etc/rsyslog.d/sshd.conf:

bash
Copy code
if $programname == 'sshd' then /var/log/sshd.log
& stop
1.5.2 Analyzing SSH Logs with Elasticsearch and Kibana
bash
Copy code
filebeat modules enable system
filebeat modules enable ssh
sudo filebeat setup
sudo service filebeat start
[Space for a Kibana screenshot showing SSH log analysis] Kibana dashboard showing SSH log analysis, including login attempts and geographical distribution of connections

1.5.3 Script for Detecting Anomalies in SSH Logs
python
Copy code
import re
from collections import defaultdict

def analyze_ssh_logs(log_file):
    ip_count = defaultdict(int)
    failed_attempts = defaultdict(int)
    
    with open(log_file, 'r') as f:
        for line in f:
            if 'sshd' in line:
                ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip:
                    ip = ip.group()
                    ip_count[ip] += 1
                    if 'Failed password' in line:
                        failed_attempts[ip] += 1

    for ip, count in ip_count.items():
        if count > 100 or failed_attempts[ip] > 10:
            print(f"Potential threat: IP {ip} - {count} connections, {failed_attempts[ip]} failed attempts")

analyze_ssh_logs('/var/log/auth.log')
