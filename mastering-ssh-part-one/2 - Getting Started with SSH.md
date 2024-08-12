# Part Two: Getting Started with SSH

## Table of Contents

- [2.1 Essential SSH Commands](#21-essential-ssh-commands)
- [2.2 SSH Key Management](#22-ssh-key-management)
- [2.3 SSH Security Best Practices](#23-ssh-security-best-practices)

## 2.1 Essential SSH Commands

### Establishing a Remote Connection

To connect to a remote server using SSH:

```bash
ssh [options] username@remote_host
```

- **username:** Your login name on the remote server.
- **remote_host:** The server’s IP address or domain name.
- **Example:** `ssh john@example.com`

Once connected, you can execute various commands like `uptime` or any other required operations.

  ![ssh-first-connection](https://github.com/user-attachments/assets/98a3b8ac-f02b-4951-9a18-5d41f6a245d5)

**Common Options:**
- `-p port`: Specify a custom port (e.g., `ssh -p 2222 john@example.com`).
- `-i identity_file`: Use a specific private key file.
- `-X`: Enable X11 forwarding for GUI applications.
- `-v`: Verbose mode for troubleshooting.

**Key Considerations:**
- You will be prompted to verify the server's host key on the first connection.
- The server's host key fingerprint is stored in `~/.ssh/known_hosts`.
- Use `ssh -v` for detailed output to diagnose connection issues.

### Executing Remote Commands

To execute a command on a remote server without starting an interactive session:

```bash
ssh username@remote_host 'command'
```

**Examples:** 
- Check system uptime: `ssh john@example.com 'uptime'`
- View disk usage: `ssh john@example.com 'df -h'`
- Update system packages: `ssh john@example.com 'sudo apt update && sudo apt upgrade -y'`

**Advanced Usage:**
- Chain multiple commands: `ssh user@host 'command1 && command2'`

### Secure File Transfer with SCP

SCP (Secure Copy) allows you to transfer files securely between local and remote systems.

**Upload to Remote Server:**
```bash
scp [options] source_file(s) username@remote_host:destination
```


**Download from Remote Server:**
```bash
scp [options] username@remote_host:source_file(s) destination
```

![SCP-file-transfer](https://github.com/user-attachments/assets/17877152-dbf5-406c-a013-f52db9e944b2)

**Examples:**
- Upload a file: `scp /path/to/local/file.txt john@example.com:/home/john/`
- Download a file: `scp john@example.com:/home/john/file.txt /local/path/`
- Transfer a directory: `scp -r /local/directory john@example.com:/remote/path/`

**Useful Options:**
- `-P port`: Specify a custom SSH port.
- `-i identity_file`: Use a specific private key.
- `-l limit`: Limit bandwidth in Kbit/s.
- `-C`: Enable compression for faster transfers.

### Interactive File Management with SFTP

SFTP (SSH File Transfer Protocol) provides an interactive file transfer session similar to FTP, but with SSH’s security.

![how-sftp-works](https://github.com/user-attachments/assets/f82367ed-b395-41a6-a095-004572bef2dd)

**Start an SFTP Session:**
```bash
sftp [options] username@remote_host
```
![sftp-file-transfer](https://github.com/user-attachments/assets/8f7c7c96-fd4e-4067-a338-f4b18b79df36)

**Essential SFTP Commands:**
- `put local_file [remote_file]`: Upload a file.
- `get remote_file [local_file]`: Download a file.
- `ls [directory]`: List directory contents.
- `cd directory`: Change the remote directory.
- `lcd directory`: Change the local directory.
- `mkdir directory`: Create a new remote directory.
- `rm file`: Remove a remote file.
- `rmdir directory`: Remove a remote directory.
- `pwd`: Print the remote working directory.
- `lpwd`: Print the local working directory.
- `bye` or `exit`: Close the SFTP session.

**Advanced SFTP Usage:**
- **Batch mode:** Automate transfers by creating a batch file with SFTP commands, one per line, then run:
  ```bash
  sftp -b batch_file username@remote_host
  ```
- **Recursive operations:** Use `-r` with `put` or `get` to transfer directories.

## 2.2 SSH Key Management

### Generating a New SSH Key Pair

To generate a new SSH key pair:

```bash
ssh-keygen -t rsa -b 4096 -C 'your_email@example.com'
```
![ssh-key-generation](https://github.com/user-attachments/assets/d20ed43e-e731-4443-bd56-c421fd57f904)

- **-t rsa:** Specifies RSA as the key type (alternatives: ed25519, ecdsa).
- **-b 4096:** Sets a 4096-bit key size for enhanced security.
- **-C:** Adds a comment, typically your email address, for key identification.

**Important Notes:**
- Default key file locations: `~/.ssh/id_rsa` (private) and `~/.ssh/id_rsa.pub` (public).
- Adding a strong passphrase is recommended for additional security.
- Consider using Ed25519 keys for better performance:
  ```bash
  ssh-keygen -t ed25519 -C 'your_email@example.com'
  ```

**Key Management Best Practices:**
- Use different keys for different servers or purposes.
- Regularly rotate your SSH keys (e.g., annually).
- Back up your private keys securely.
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

Ensure your SSH directories and files have the correct permissions:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

![permissions-chmod](https://github.com/user-attachments/assets/df3dc29c-20ad-4914-93f0-5009833f505a)

**Why These Permissions?**
- `700` for `.ssh/`: Only the owner can read, write, and execute.
- `600` for private keys and `authorized_keys`: Only the owner can read and write.
- `644` for public keys: The owner can read and write, others can only read.

## 2.3 SSH Security Best Practices

1. **Implement Key-Based Authentication:**
   - Disable password authentication by setting `PasswordAuthentication no` in `/etc/ssh/sshd_config`.
   - Restart the SSH service after changes: `sudo systemctl restart sshd`.

2. **Use Strong, Unique Passphrases for SSH Keys:**
   - Employ a password manager to generate and store complex passphrases.
   - Use `ssh-agent` to avoid repeatedly entering the passphrase:
     ```bash
     eval $(ssh-agent)
     ssh-add ~/.ssh/id_rsa
     ```

3. **Disable Root Login:**
   - Set `PermitRootLogin no` in `/etc/ssh/sshd_config`.
   - Use `sudo` for privileged operations.

4. **Change the Default SSH Port:**
   - Modify the `Port` directive in `/etc/ssh/sshd_config` (e.g., `Port 2222`).
   - Update firewall rules to allow the new port.

5. **Implement `fail2ban` or Similar Tools:**
   - Install `fail2ban` to protect against brute-force attacks:
     ```bash
     sudo apt install fail2ban
     ```
   - Configure `/etc/fail2ban/jail.local` for SSH protection.

  ![faile2ban](https://github.com/user-attachments/assets/2e039437-fce1-4936-84dd-8ded6e2145da)

6. **Keep SSH Software and System Packages Up-to-Date:**
   - Regular system updates: `sudo apt update && sudo apt upgrade`.
   - Specifically check for OpenSSH updates.

7. **Utilize SSH Config Files:**
   - Create and use `~/.ssh/config` to manage multiple connections:
     ```bash
     Host myserver
         HostName example.com
         User john
         Port 2222
         IdentityFile ~/.ssh/id_rsa_server
     ```
   - Connect using: `ssh myserver`.

8. **Use SSH Agent Forwarding Cautiously:**
   - Enable only on trusted systems.
   - Use `ForwardAgent yes` in SSH config or the `-A` flag.

9. **Limit User SSH Access:**
    - Restrict SSH access using `AllowUsers` or `AllowGroups` in `sshd_config`.
    - Implement `chroot` jails for SFTP users.

10. **Configure SSH Timeout Intervals:**
    - Set `ClientAliveInterval` and `ClientAliveCountMax` in `sshd_config` to manage session timeouts.

11. **Implement Key Rotation Policies:**
    - Regularly generate new SSH keys (e.g., annually).
    - Update `authorized_keys` on all servers accordingly.

## Further Reading and Resources

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines for Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
- [SSH Mastery](https://www.tiltedwindmillpress.com/product/ssh-mastery/) by Michael W Lucas (Book)
- [Linux Server Security: Hack and Defend](https://www.wiley.com/en-us/Linux+Server+Security%3A+Hack+and+Defend-p-9781119277651) by Chris Binnie (Book)

