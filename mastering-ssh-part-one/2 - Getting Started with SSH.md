# Part Two: Getting Started with SSH

## Table of Contents

- [2.1 Essential SSH Commands](#21-essential-ssh-commands)
- [2.2 SSH Key Management](#22-ssh-key-management)
- [2.3 SSH Security Best Practices](#23-ssh-security-best-practices)

## 2.1 Essential SSH Commands

### Establishing a Remote Connection

To connect to a remote server using SSH, use the following command structure:

```bash
ssh [options] username@remote_host
```

- **username:** Your login credentials on the remote server
- **remote_host:** IP address or domain name of the target server
- **Example:** `ssh john@example.com`

  ![ssh-first-connection](https://github.com/user-attachments/assets/98a3b8ac-f02b-4951-9a18-5d41f6a245d5)

  Once connected we can start perfoming various command like uptime or anthing else.

**Common Options:**
- `-p port`: Specify a custom port (e.g., `ssh -p 2222 john@example.com`)
- `-i identity_file`: Use a specific private key file
- `-X`: Enable X11 forwarding for GUI applications
- `-v`: Verbose mode for troubleshooting

**Key Considerations:**
- Initial connections prompt for verification of the server's host key
- The host key fingerprint is stored in `~/.ssh/known_hosts`
- Use `ssh -v` for verbose output to diagnose connection issues

### Executing Remote Commands

Execute a command on a remote server without initiating an interactive session:

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

SCP (Secure Copy) allows secure file transfers between local and remote systems.

**Uploading to Remote Server:**
```bash
scp [options] source_file(s) username@remote_host:destination
```

**Downloading from Remote Server:**
```bash
scp [options] username@remote_host:source_file(s) destination
```
![SCP-file-transfer](https://github.com/user-attachments/assets/17877152-dbf5-406c-a013-f52db9e944b2)

**Examples:**
- Upload a file: `scp /path/to/local/file.txt john@example.com:/home/john/`
- Download a file: `scp john@example.com:/home/john/file.txt /local/path/`
- Transfer entire directory: `scp -r /local/directory john@example.com:/remote/path/`

**Useful Options:**
- `-P port`: Specify a custom SSH port
- `-i identity_file`: Use a specific private key
- `-l limit`: Limit bandwidth in Kbit/s
- `-C`: Enable compression

### Interactive File Management with SFTP

SFTP (SSH File Transfer Protocol) provides an interactive file transfer session.
How SFTP works: 

{sftp diagram}

Initiate an SFTP session:
```bash
sftp [options] username@remote_host
```
![sftp-file-transfer](https://github.com/user-attachments/assets/8f7c7c96-fd4e-4067-a338-f4b18b79df36)

**Essential SFTP Commands:**
- `put local_file [remote_file]`: Upload a file
- `get remote_file [local_file]`: Download a file
- `ls [directory]`: List directory contents
- `cd directory`: Change remote directory
- `lcd directory`: Change local directory
- `mkdir directory`: Create a new remote directory
- `rm file`: Remove a remote file
- `rmdir directory`: Remove a remote directory
- `pwd`: Print working directory (remote)
- `lpwd`: Print working directory (local)
- `bye` or `exit`: Close the SFTP session

**Advanced SFTP Usage:**
- Batch mode: `sftp -b batch_file username@remote_host`
  Create a text file with SFTP commands, one per line, to automate transfers.
- Recursive operations: Use `-r` with `put` or `get` for directory transfers

## 2.2 SSH Key Management

### Generating a New SSH Key Pair

```bash
ssh-keygen -t rsa -b 4096 -C 'your_email@example.com'
```

- **-t rsa:** Specifies RSA key type (alternatives: ed25519, ecdsa)
- **-b 4096:** Sets a 4096-bit key size for enhanced security
- **-C:** Adds a comment (typically an email address) for key identification

**Important Notes:**
- Default key locations: `~/.ssh/id_rsa` (private) and `~/.ssh/id_rsa.pub` (public)
- Adding a strong passphrase is highly recommended for additional security
- Consider using Ed25519 keys for better performance:
  ```bash
  ssh-keygen -t ed25519 -C 'your_email@example.com'
  ```

**Key Management Best Practices:**
- Generate different keys for different purposes or servers
- Regularly rotate your SSH keys (e.g., annually)
- Back up your private keys securely
- Never share your private key

![ssh-key-generation](https://github.com/user-attachments/assets/d20ed43e-e731-4443-bd56-c421fd57f904)

### Deploying Your Public Key to a Server

**Using ssh-copy-id (Recommended):**
```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub username@remote_host
```

**Manual Method:**
```bash
cat ~/.ssh/id_rsa.pub | ssh username@remote_host 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
```

### Setting Appropriate Permissions

Ensure correct permissions for SSH directories and files:
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

**Why These Permissions?**
- 700 for `.ssh/`: Owner can read, write, execute; others have no access
- 600 for private keys and `authorized_keys`: Owner can read and write; others have no access
- 644 for public keys: Owner can read and write; others can read

![permissions-chmod](https://github.com/user-attachments/assets/df3dc29c-20ad-4914-93f0-5009833f505a)

## 2.3 SSH Security Best Practices

1. **Implement key-based authentication:**
   - Disable password authentication by setting `PasswordAuthentication no` in `/etc/ssh/sshd_config`
   - Restart SSH service after changes: `sudo systemctl restart sshd`

2. **Use strong, unique passphrases for SSH keys:**
   - Employ a password manager to generate and store complex passphrases
   - Consider using `ssh-agent` to avoid typing the passphrase repeatedly:
     ```bash
     eval $(ssh-agent)
     ssh-add ~/.ssh/id_rsa
     ```
3. **Disable root login:**
   - Set `PermitRootLogin no` in `/etc/ssh/sshd_config`
   - Use sudo for privileged operations

4. **Change the default SSH port:**
   - Modify `Port` in `/etc/ssh/sshd_config` (e.g., `Port 2222`)
   - Update firewall rules accordingly

5. **Implement fail2ban or similar tools:**
   - Install fail2ban: `sudo apt install fail2ban`
   - Configure `/etc/fail2ban/jail.local` for SSH protection
  
    ![faile2ban](https://github.com/user-attachments/assets/2e039437-fce1-4936-84dd-8ded6e2145da)

6. **Keep SSH software and system packages up-to-date:**
   - Regular system updates: `sudo apt update && sudo apt upgrade`
   - Check for OpenSSH updates specifically

7. **Utilize SSH config files:**
   - Create and use `~/.ssh/config` for managing multiple connections:
     ```
     Host myserver
         HostName example.com
         User john
         Port 2222
         IdentityFile ~/.ssh/id_rsa_server
     ```
   - Connect using: `ssh myserver`

8. **Implement two-factor authentication (2FA):**
   - Use Google Authenticator or similar TOTP apps
   - Install and configure `libpam-google-authenticator`:
     ```bash
     sudo apt install libpam-google-authenticator
     google-authenticator
     ```
   - Follow the prompts to set up 2FA

9. **Regularly audit SSH logs:**
   - Monitor `/var/log/auth.log` or `/var/log/secure`
   - Use log analysis tools like `fail2ban` or ELK stack

10. **Use SSH agent forwarding cautiously:**
    - Only enable on trusted systems
    - Use `ForwardAgent yes` in SSH config or `-A` flag

11. **Limit user SSH access:**
    - Use `AllowUsers` or `AllowGroups` in `sshd_config`
    - Implement `chroot` jails for SFTP users

12. **Configure SSH timeout intervals:**
    - Set `ClientAliveInterval` and `ClientAliveCountMax` in `sshd_config`

13. **Use SSH jump hosts for accessing internal networks:**
    - Configure ProxyJump in `~/.ssh/config`:
      ```
      Host internal-server
          ProxyJump jumphost.example.com
      ```

14. **Implement key rotation policies:**
    - Regularly generate new SSH keys (e.g., annually)
    - Update `authorized_keys` on all servers

15. **Use SSH certificates for larger deployments:**
    - Implement an SSH Certificate Authority (CA) for easier key management
   
    ![config-file](https://github.com/user-attachments/assets/7c0485f0-3136-4446-b2b3-e5ebebe3c0cc)

## Further Reading and Resources

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines for Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
- [SSH Mastery](https://www.tiltedwindmillpress.com/product/ssh-mastery/) by Michael W Lucas (Book)
- [Linux Server Security: Hack and Defend](https://www.wiley.com/en-us/Linux+Server+Security%3A+Hack+and+Defend-p-9781119277651) by Chris Binnie (Book)
