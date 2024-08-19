# Part Two: Getting Started with SSH

## Table of Contents

- [2.1 Essential SSH Commands](#21-essential-ssh-commands)
- [2.2 SSH Key Management](#22-ssh-key-management)
- [2.3 SSH Security Best Practices](#23-ssh-security-best-practices)

## 2.1 Essential SSH Commands

### Establishing a Remote Connection

To initiate a secure connection to a remote server, use the SSH command:

```bash
ssh [options] username@remote_host
```

This command sets up an encrypted connection to a remote server, enabling secure execution of commands and file transfers.

- **username:** Your login name on the remote server.
- **remote_host:** The IP address or domain name of the remote server.
- **Example:** `ssh john@example.com`

Upon connection, you can execute commands on the remote system as if you were directly logged into the machine.

![ssh-first-connection](https://github.com/user-attachments/assets/98a3b8ac-f02b-4951-9a18-5d41f6a245d5)

**Key Options:**
- `-p port`: Connect using a non-standard SSH port (not the default port 22).
- `-i identity_file`: Specify a private key file for authentication.
- `-X`: Enable X11 forwarding to run graphical applications remotely.
- `-v`: Enable verbose mode to see detailed connection logs, useful for troubleshooting.

**Important Considerations:**
- On the first connection, verify the server’s host key to prevent man-in-the-middle attacks.
- The `~/.ssh/known_hosts` file stores verified host keys for future connections.
- Use `ssh -v` for detailed debugging information if you encounter connection issues.

### Executing Remote Commands

You can execute commands on a remote server without initiating an interactive session:

```bash
ssh username@remote_host 'command'
```

This is useful for automating tasks or quickly retrieving information from a remote system.

**Examples:** 
- Check the system uptime: `ssh john@example.com 'uptime'`
- View disk usage: `ssh john@example.com 'df -h'`
- Update system packages: `ssh john@example.com 'sudo apt update && sudo apt upgrade -y'`

**Advanced Usage:**
- Chain multiple commands: `ssh user@host 'command1 && command2'`

### Secure File Transfer with SCP

SCP (Secure Copy) allows you to transfer files between local and remote systems securely:

**Upload a File to a Remote Server:**
```bash
scp [options] source_file(s) username@remote_host:destination
```

**Download a File from a Remote Server:**
```bash
scp [options] username@remote_host:source_file(s) destination
```

SCP ensures secure and encrypted file transfers, protecting your data during transit.

![SCP-file-transfer](https://github.com/user-attachments/assets/17877152-dbf5-406c-a013-f52db9e944b2)

**Examples:**
- Upload a file: `scp /path/to/local/file.txt john@example.com:/home/john/`
- Download a file: `scp john@example.com:/home/john/file.txt /local/path/`
- Transfer a directory: `scp -r /local/directory john@example.com:/remote/path/`

**Useful Options:**
- `-P port`: Use a specific SSH port for the connection.
- `-i identity_file`: Authenticate using a specific private key.
- `-l limit`: Limit bandwidth usage, useful in constrained networks.
- `-C`: Compress files during transfer to speed up the process over slow connections.

### Interactive File Management with SFTP

SFTP (SSH File Transfer Protocol) provides an interactive session for secure file management:

![how-sftp-works](https://github.com/user-attachments/assets/f82367ed-b395-41a6-a095-004572bef2dd)

**Start an SFTP Session:**
```bash
sftp [options] username@remote_host
```

SFTP offers a familiar interface for those used to FTP, with the added security of SSH.

![sftp-file-transfer](https://github.com/user-attachments/assets/8f7c7c96-fd4e-4067-a338-f4b18b79df36)

**Essential SFTP Commands:**
- `put local_file [remote_file]`: Upload a file to the remote server.
- `get remote_file [local_file]`: Download a file from the remote server.
- `ls [directory]`: List files in the current or specified remote directory.
- `cd directory`: Change the directory on the remote server.
- `lcd directory`: Change the directory on your local machine.
- `mkdir directory`: Create a new directory on the remote server.
- `rm file`: Delete a file on the remote server.
- `rmdir directory`: Remove an empty directory on the remote server.
- `pwd`: Display the current directory on the remote server.
- `lpwd`: Show the current directory on your local machine.
- `bye` or `exit`: End the SFTP session.

**Advanced SFTP Usage:**
- **Batch mode:** Automate file transfers by creating a script file with SFTP commands:
  ```bash
  sftp -b batch_file username@remote_host
  ```
- **Recursive operations:** Use `-r` with `put` or `get` to transfer entire directories.

## 2.2 SSH Key Management

### Generating a New SSH Key Pair

To create a new SSH key pair:

```bash
ssh-keygen -t rsa -b 4096 -C 'your_email@example.com'
```
![ssh-key-generation](https://github.com/user-attachments/assets/d20ed43e-e731-4443-bd56-c421fd57f904)

- **-t rsa:** Specifies RSA as the key type (alternatives: ed25519, ecdsa).
- **-b 4096:** Generates a 4096-bit key for enhanced security.
- **-C:** Adds a comment, typically your email, to identify the key.

**Important Notes:**
- Default key files: `~/.ssh/id_rsa` (private key) and `~/.ssh/id_rsa.pub` (public key).
- It is advisable to protect your private key with a strong passphrase.
- For better performance, consider using Ed25519 keys:
  ```bash
  ssh-keygen -t ed25519 -C 'your_email@example.com'
  ```

**Key Management Best Practices:**
- Use different keys for different servers or purposes.
- Rotate your SSH keys regularly, such as every year.
- Securely back up your private keys.
- Never share your private key.

### Deploying Your Public Key to a Server

**Using `ssh-copy-id` (Recommended):**
```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub username@remote_host
```

**Manual Method:**
```bash
cat ~/.ssh/id_rsa.pub | ssh username@remote_host 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
```

### Setting Appropriate Permissions

Ensure the correct permissions are set for your SSH directories and files:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

![permissions-chmod](https://github.com/user-attachments/assets/df3dc29c-20ad-4914-93f0-5009833f505a)

**Explanation of Permissions:**
- `700` for `.ssh/`: Only the owner can read, write, and execute.
- `600` for private keys and `authorized_keys`: Only the owner can read and write.
- `644` for public keys: The owner can read and write; others can only read.

## 2.3 SSH Security Best Practices

1. **Implement Key-Based Authentication:**
   - Disable password authentication by setting `PasswordAuthentication no` in `/etc/ssh/sshd_config`.
   - Restart the SSH service to apply changes: `sudo systemctl restart sshd`.

2. **Use Strong, Unique Passphrases for SSH Keys:**
   - Use a password manager to generate and store complex passphrases.
   - Utilize `ssh-agent` to avoid repeatedly entering the passphrase:
     ```bash
     eval $(ssh-agent)
     ssh-add ~/.ssh/id_rsa
     ```

3. **Disable Root Login:**
   - Set `PermitRootLogin no` in `/etc/ssh/sshd_config`.
   - Use `sudo` for privileged operations instead.

4. **Change the Default SSH Port:**
   - Modify the `Port` directive in `/etc/ssh/sshd_config` (e.g., `Port 2222`).
   - Update firewall rules to allow traffic on the new port.

5. **Implement `fail2ban` or Similar Tools:**
   - Install `fail2ban` to protect against brute-force attacks:
     ```bash
     sudo apt install fail2ban
     ```
   - Configure `/etc/fail2ban/jail.local` for SSH protection.

  ![faile2ban](https://github.com/user-attachments/assets/2e039437-fce1-4936-84dd-8ded6e2145da)

6. **Keep SSH Software and System Packages Up-to-Date:**
   - Regularly update your system: `sudo apt update && sudo apt upgrade

`.
   - Pay particular attention to updates for OpenSSH.

7. **Utilize SSH Config Files:**
   - Manage multiple SSH connections using `~/.ssh/config`:
     ```bash
     Host myserver
         HostName example.com
         User john
         Port 2222
         IdentityFile ~/.ssh/id_rsa_server
     ```
   - Connect with a simple command: `ssh myserver`.

8. **Use SSH Agent Forwarding Cautiously:**
   - Only enable agent forwarding on trusted systems.
   - Use `ForwardAgent yes` in your SSH config or the `-A` flag during connection.

9. **Limit User SSH Access:**
   - Restrict SSH access using `AllowUsers` or `AllowGroups` in `sshd_config`.
   - Implement `chroot` jails for SFTP-only users to limit their file system access.

10. **Configure SSH Timeout Intervals:**
    - Adjust `ClientAliveInterval` and `ClientAliveCountMax` in `sshd_config` to control session timeouts.

11. **Implement Key Rotation Policies:**
    - Regularly generate new SSH keys (e.g., annually) and update `authorized_keys` on all servers.

## Further Reading and Resources

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines for Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
- [SSH Mastery](https://www.tiltedwindmillpress.com/product/ssh-mastery/) by Michael W Lucas (Book)
- [Linux Server Security: Hack and Defend](https://www.wiley.com/en-us/Linux+Server+Security%3A+Hack+and+Defend-p-9781119277651) by Chris Binnie (Book)

---
