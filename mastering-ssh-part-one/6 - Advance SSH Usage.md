# Part Six: Mastering SSH - Advanced Techniques for Pentesters and Sysadmins

## Table of Contents

- [6.1 SSH Pivoting and Advanced Network Tunneling](#61-ssh-pivoting-and-advanced-network-tunneling)
- [6.2 Custom SSH Fingerprinting and Evasion Techniques](#62-custom-ssh-fingerprinting-and-evasion-techniques)
- [6.3 SSH Certificates for Scalable Access Management](#63-ssh-certificates-for-scalable-access-management)
- [6.4 Automated SSH Orchestration and Configuration Management](#64-automated-ssh-orchestration-and-configuration-management)
- [6.5 SSH Hardening and Advanced Security Measures](#65-ssh-hardening-and-advanced-security-measures)
- [6.6 Further Reading](#66-further-reading)

## 6.1 SSH Pivoting and Advanced Network Tunneling

SSH pivoting is a crucial technique for penetration testers and sysadmins to gain access to otherwise unreachable network segments. This capability is essential for both offensive security and comprehensive network management.

### 6.1.1 Dynamic Pivoting with SSH and Proxychains

To establish a dynamic SOCKS proxy with SSH:

```bash
ssh -D 9050 user@pivot_host
```

Next, configure `/etc/proxychains.conf`:

```plaintext
[ProxyList]
socks5 127.0.0.1 9050
```

You can now route your traffic through the proxy using Proxychains:

```bash
proxychains nmap -sT -P0 192.168.0.0/24
```

### 6.1.2 Multi-Hop SSH Tunneling

To create an SSH tunnel through multiple hosts:

```bash
ssh -L 8080:localhost:8080 user1@host1 ssh -L 8080:localhost:80 user2@host2
```

This command allows you to tunnel from your local machine to `host2` via `host1`.

### 6.1.3 Reverse SSH Tunneling for NAT Traversal

For accessing systems behind NAT, use reverse SSH tunneling:

```bash
ssh -R 8080:localhost:80 user@public_server
```

You can now access the service on `localhost:8080` from the public server.

## 6.2 Custom SSH Fingerprinting and Evasion Techniques

Understanding and customizing SSH fingerprints is vital for both attack and defense. This section explores how to manipulate SSH fingerprints to your advantage.

### 6.2.1 Customizing SSH Server Fingerprints

Modify the SSH server configuration to customize fingerprints:

```plaintext
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com
```

Restart the SSH daemon to apply these changes.

### 6.2.2 SSH Client Fingerprint Manipulation

Create a custom SSH client configuration (`~/.ssh/config`):

```plaintext
Host *
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

### 6.2.3 Detecting and Evading SSH Honeypots

To identify potential SSH honeypots, use tools like `ssh-audit`:

```bash
ssh-audit target_host
```

Look for unusual details, such as unexpected version strings or cipher suites, which might indicate a honeypot.

## 6.3 SSH Certificates for Scalable Access Management

SSH certificates offer a scalable and secure alternative to traditional SSH keys, especially in large infrastructure environments.

### 6.3.1 Setting Up an SSH Certificate Authority (CA)

First, generate the CA key:

```bash
ssh-keygen -f ssh_ca -t ed25519
```

Then, configure the SSH server to trust this CA:

```plaintext
TrustedUserCAKeys /etc/ssh/ssh_ca.pub
```

### 6.3.2 Issuing User Certificates

To generate a user key:

```bash
ssh-keygen -t ed25519 -f user_key
```

Sign the user key with your CA:

```bash
ssh-keygen -s ssh_ca -I user_identity -n user,root -V +52w user_key.pub
```

The signed certificate can now be used for authentication:

```bash
ssh -i user_key -i user_key-cert.pub user@host
```

### 6.3.3 Implementing Host Certificates

Sign a host key:

```bash
ssh-keygen -s ssh_ca -I host_identity -h -n host.example.com host_key.pub
```

To configure clients to trust the CA, update their known hosts file (`~/.ssh/known_hosts`):

```plaintext
@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... ca@example.com
```

## 6.4 Automated SSH Orchestration and Configuration Management

Automation is key to efficiently managing SSH across large-scale infrastructures.

### 6.4.1 Using Ansible for SSH Automation

Begin by installing Ansible:

```bash
pip install ansible
```

Next, create an inventory file (`inventory.ini`):

```ini
[webservers]
web1 ansible_host=192.168.1.101
web2 ansible_host=192.168.1.102

[dbservers]
db1 ansible_host=192.168.1.201
```

Create a playbook (`deploy.yml`) to manage SSH configurations:

```yaml
---
- hosts: webservers
  tasks:
    - name: Ensure Apache is installed
      apt:
        name: apache2
        state: present
      become: yes
```

Run the playbook:

```bash
ansible-playbook -i inventory.ini deploy.yml
```

### 6.4.2 SSH Configuration Management with Puppet

Install Puppet:

```bash
apt-get install puppet-agent
```

Create a Puppet manifest (`ssh.pp`) to manage SSH configurations:

```puppet
class ssh_config {
  file { '/etc/ssh/sshd_config':
    ensure  => file,
    content => template('ssh/sshd_config.erb'),
    notify  => Service['sshd'],
  }

  service { 'sshd':
    ensure => running,
    enable => true,
  }
}
```

Apply the manifest:

```bash
puppet apply ssh.pp
```

## 6.5 SSH Hardening and Advanced Security Measures

Securing your SSH infrastructure is critical. This section covers advanced security measures for SSH.

### 6.5.1 Implementing Two-Factor Authentication (2FA)

To set up 2FA with Google Authenticator:

```bash
apt-get install libpam-google-authenticator
```

Configure PAM for SSH (`/etc/pam.d/sshd`):

```plaintext
auth required pam_google_authenticator.so
```

Modify SSHD configuration to enable 2FA:

```plaintext
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

### 6.5.2 SSH Intrusion Detection with Fail2Ban

Install and configure Fail2Ban to protect against brute-force attacks:

```bash
apt-get install fail2ban
```

Configure Fail2Ban for SSH (`/etc/fail2ban/jail.local`):

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

### 6.5.3 Implementing Port Knocking

Install `knockd` for port knocking:

```bash
apt-get install knockd
```

Configure `knockd` (`/etc/knockd.conf`):

```ini
[options]
    UseSyslog

[openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 5
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags    = syn
```

## 6.6 Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [Ansible Documentation](https://docs.ansible.com/)
- [Puppet Learning Resources](https://puppet.com/learning-resources/)
- [Fail2Ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Port Knocking: Concepts and Implementation](https://www.digitalocean.com/community/tutorials/how-to-use-port-knocking-to-hide-your-ssh-daemon-from-attackers-on-ubuntu)

