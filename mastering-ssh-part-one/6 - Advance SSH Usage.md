# Part Six: Mastering SSH - Advanced Techniques for Pentesters and Sysadmins

## Table of Contents


- [6.2 Custom SSH Fingerprinting and Evasion Techniques](#62-custom-ssh-fingerprinting-and-evasion-techniques)
- [6.3 SSH Certificates for Scalable Access Management](#63-ssh-certificates-for-scalable-access-management)
- [6.4 Automated SSH Orchestration and Configuration Management](#64-automated-ssh-orchestration-and-configuration-management)
- [6.5 SSH Hardening and Advanced Security Measures](#65-ssh-hardening-and-advanced-security-measures)
- [6.6 Further Reading](#66-further-reading)


## 6.2 Custom SSH Fingerprinting and Evasion Techniques

Understanding and customizing SSH fingerprints is like learning to disguise your digital footprint. It's crucial for both attacking and defending systems.

### 6.2.1 Customizing SSH Server Fingerprints

Modify the SSH server configuration to customize fingerprints:

```plaintext
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com
```

Restart the SSH daemon to apply these changes.

{Screenshot of: The SSH server configuration file open in a text editor, showing the customized settings. Include the output of an ssh-keyscan command before and after the changes to demonstrate the altered fingerprint.}

This screenshot shows how to customize the SSH server's fingerprint. The configuration file sets specific algorithms for key exchange, ciphers, and message authentication. The ssh-keyscan output before and after the changes clearly demonstrates how these settings alter the server's fingerprint, potentially evading detection or mimicking a different type of system.

### 6.2.2 SSH Client Fingerprint Manipulation

Create a custom SSH client configuration (`~/.ssh/config`):

```plaintext
Host *
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

{Screenshot of: The SSH client configuration file open in a text editor, alongside the output of an ssh -vv command showing the negotiated algorithms during connection.}

This screenshot illustrates how to customize the SSH client's behavior. The configuration file sets preferred algorithms for key exchange, ciphers, and message authentication. The verbose SSH output shows these custom algorithms being negotiated during the connection process, demonstrating how the client's fingerprint has been altered.

### 6.2.3 Detecting and Evading SSH Honeypots

To identify potential SSH honeypots, use tools like `ssh-audit`:

```bash
ssh-audit target_host
```

Look for unusual details, such as unexpected version strings or cipher suites, which might indicate a honeypot.

{Screenshot of: Terminal window showing the output of ssh-audit against a normal SSH server and a suspected honeypot. Highlight the differences that indicate the presence of a honeypot.}

Ssh-audit output of a regular SSH server with a suspected honeypot. Key differences to note include unusual version strings, non-standard cipher suites, or inconsistencies in the offered algorithms. These anomalies can help identify potential honeypots, allowing pentesters to avoid detection or sysadmins to spot unauthorized SSH servers.

## 6.3 SSH Certificates for Scalable Access Management

SSH certificates are like digital passports for your SSH connections, offering a more scalable and secure alternative to traditional SSH keys.

### 6.3.1 Setting Up an SSH Certificate Authority (CA)

First, generate the CA key:

```bash
ssh-keygen -f ssh_ca -t ed25519
```

Then, configure the SSH server to trust this CA:

```plaintext
TrustedUserCAKeys /etc/ssh/ssh_ca.pub
```

{Screenshot of: Terminal window showing the process of generating the CA key and the resulting public key. Include the modification of the sshd_config file to trust the CA.}

Creation of an SSH Certificate Authority. The ssh-keygen command generates a new ED25519 key pair for the CA. The sshd_config modification tells the SSH server to trust certificates signed by this CA, establishing the foundation for certificate-based authentication.

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

{Screenshot of: Terminal window showing the process of generating a user key, signing it with the CA, and using it to authenticate to a server. Include the output of ssh-keygen -L -f user_key-cert.pub to show the certificate details.}

Explanation: This screenshot illustrates the process of issuing and using SSH certificates. It shows the creation of a user key, signing it with the CA to create a certificate, and then using that certificate for authentication. The certificate details reveal important information like the identity, principals (authorized users), and validity period.

### 6.3.3 Implementing Host Certificates

Sign a host key:

```bash
ssh-keygen -s ssh_ca -I host_identity -h -n host.example.com host_key.pub
```

To configure clients to trust the CA, update their known hosts file (`~/.ssh/known_hosts`):

```plaintext
@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... ca@example.com
```

{Screenshot of: Terminal window showing the process of signing a host key and updating a client's known_hosts file. Include the output of ssh -v to a host using the certificate, showing the successful validation.}

Explanation: This screenshot shows how to implement host certificates. It demonstrates signing a host's public key with the CA and configuring a client to trust the CA. The verbose SSH output shows the client successfully validating the host's certificate during connection, illustrating how this method can replace traditional host key verification.

## 6.4 Automated SSH Orchestration and Configuration Management

Automation in SSH management is like having a team of robots managing your keys and configurations across a vast network of computers.

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

{Screenshot of: Terminal window showing the execution of the Ansible playbook and its output. Include a before-and-after view of the Apache status on one of the webservers.}

Ansible in action. It shows the execution of a playbook that ensures Apache is installed on all webservers. The before-and-after view of Apache's status on a webserver illustrates how Ansible can efficiently manage configurations across multiple machines simultaneously.

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

{Screenshot of: Terminal window showing the application of the Puppet manifest and its output. Include a diff of the sshd_config file before and after applying the manifest.}

Puppet's configuration management capabilities. It shows the application of a Puppet manifest that manages the SSH server configuration. The diff of the sshd_config file before and after applying the manifest demonstrates how Puppet can automatically enforce desired configurations across your infrastructure.

## 6.5 SSH Hardening and Advanced Security Measures

Hardening SSH is like fortifying a castle - it involves multiple layers of defense to protect against various types of attacks.

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

{Screenshot of: Terminal window showing the setup process for Google Authenticator, including the QR code for setting up the mobile app. Include a subsequent SSH login attempt showing the 2FA prompt.}

Explanation: This screenshot demonstrates the implementation of two-factor authentication for SSH. It shows the setup process for Google Authenticator, including the QR code that users scan with their mobile app. The SSH login attempt illustrates how users now need both their SSH key and a time-based one-time password to authenticate, significantly enhancing security.


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

{Screenshot of: knockd configuration file open in a text editor, alongside a terminal window showing the process of port knocking (using a tool like knock) followed by a successful SSH connection.}

Explanation: This screenshot demonstrates the setup and use of port knocking. The knockd configuration file shows the sequence of ports that need to be "knocked" to open the SSH port. The terminal window illustrates the process of performing the knock sequence, followed by a successful SSH connection, showing how port knocking can hide the SSH service from port scans while still allowing authorized access.

## 6.6 Further Reading

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [Ansible Documentation](https://docs.ansible.com/)
- [Puppet Learning Resources](https://puppet.com/learning-resources/)
- [Fail2Ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Port Knocking: Concepts and Implementation](https://www.digitalocean.com/community/tutorials/how-to-use-port-knocking-to-hide-your-ssh-daemon-from-attackers-on-ubuntu)
