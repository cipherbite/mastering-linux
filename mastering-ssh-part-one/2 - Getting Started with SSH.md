# Part Two: Getting Started with SSH

## Table of Contents

- [2.1 Essential SSH Commands](#21-essential-ssh-commands)
- [2.2 Establishing a Remote Connection](#22-establishing-a-remote-connection)
- [2.3 Executing Remote Commands](#23-executing-remote-commands)
- [2.4 Secure File Transfer with SCP](#24-secure-file-transfer-with-scp)
- [2.5 Interactive File Management with SFTP](#25-interactive-file-management-with-sftp)
- [2.6 Best Practices](#26-best-practices)
- [2.7 Further Reading](#27-further-reading)

## 2.1 Essential SSH Commands

SSH (Secure Shell) is a protocol for securely managing and interacting with remote systems. It encrypts your communications, ensuring that your data remains private and secure.

## 2.2 Establishing a Remote Connection

To start a secure connection to a remote server, use the following SSH command:

```bash
ssh [options] username@remote_host
```

This command is like a digital handshake with the remote server, allowing you to control it as if you were physically present.

- **username:** The user account on the remote server.
- **remote_host:** The server’s IP address or domain name.
- **Example:** `ssh john@example.com`

![SSH First Connection](https://github.com/user-attachments/assets/e5b2fc4f-d56c-41a5-8fa6-cb4aad2163ba)

**Common Options:**
- `-p port`: Connect to a non-standard SSH port.
- `-i identity_file`: Use a specific private key for authentication.
- `-X`: Enable X11 forwarding for running graphical applications remotely.
- `-v`: Enable verbose mode for detailed connection information.

**Security Note:**
- On the first connection, you’ll be asked to verify the server’s host key to prevent man-in-the-middle attacks.
- Host keys are stored in the `~/.ssh/known_hosts` file for future connections.
- Use `ssh -v` to troubleshoot connection issues.

## 2.3 Executing Remote Commands

You can execute commands on a remote server without starting a full session:

```bash
ssh username@remote_host 'command'
```

This is like sending a quick task to the server, executing the command, and returning the result.

**Examples:**
- Check uptime: `ssh john@example.com 'uptime'`
- View disk usage: `ssh john@example.com 'df -h'`
- Update packages: `ssh john@example.com 'sudo apt update && sudo apt upgrade -y'`

![SSH Remote Code Execute](https://github.com/user-attachments/assets/4953a5ea-df1c-4af5-940b-d715cd7bcbef)

**Advanced Tips:**
- Chain commands: `ssh user@host 'command1 && command2'`

## 2.4 Secure File Transfer with SCP

SCP (Secure Copy) is a tool for transferring files between local and remote systems securely.

**Upload a File to a Remote Server:**

```bash
scp [options] source_file(s) username@remote_host:destination
```

**Download a File from a Remote Server:**

```bash
scp [options] username@remote_host:source_file(s) destination
```

![SCP File Transfer](https://github.com/user-attachments/assets/6aa4862c-ca36-4b6f-9880-567686568ca9)

**Examples:**
- Upload: `scp /path/to/local/file.txt john@example.com:/home/john/`
- Download: `scp john@example.com:/home/john/file.txt /local/path/`
- Transfer directory: `scp -r /local/dir john@example.com:/remote/dir`

**Options:**
- `-P port`: Specify a port.
- `-i identity_file`: Use a specific private key.
- `-l limit`: Limit bandwidth.
- `-C`: Compress files during transfer.

## 2.5 Interactive File Management with SFTP

SFTP (SSH File Transfer Protocol) offers a more interactive approach to file management on remote servers.

**Start an SFTP Session:**

```bash
sftp [options] username@remote_host
```

SFTP provides an FTP-like interface but with the security of SSH.

![SFTP Diagram](https://github.com/user-attachments/assets/de4ba01f-93b0-4ed6-909f-5b88f45dc2a5)

**Essential SFTP Commands:**
- `put local_file [remote_file]`: Upload a file.
- `get remote_file [local_file]`: Download a file.
- `ls [directory]`: List files.
- `cd directory`: Change remote directory.
- `lcd directory`: Change local directory.
- `mkdir directory`: Create a directory.
- `rm file`: Delete a file.
- `rmdir directory`: Remove a directory.
- `pwd`: Show current remote directory.
- `lpwd`: Show current local directory.
- `bye` or `exit`: End the session.

![SFTP Connection](https://github.com/user-attachments/assets/a68d910b-10b5-4afe-9424-bc049c8481e2)

**Advanced Usage:**
- **Batch Mode:** Automate tasks with an SFTP script:
  ```bash
  sftp -b batch_file username@remote_host
  ```
- **Recursive Operations:** Use `-r` with `put` or `get` for directories.

## 2.6 Best Practices

- Always use strong, unique passwords or SSH keys.
- Regularly update your SSH client and server.
- Disable root login for SSH.
- Use a firewall to limit SSH access.
- Monitor logs for unusual SSH activity.

## 2.7 Further Reading

To learn more about SSH, explore these resources:

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Secure Shell Guidelines](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
- [SSH Mastery](https://www.tiltedwindmillpress.com/product/ssh-mastery/) by Michael W Lucas (Book)
- [Linux Server Security: Hack and Defend](https://www.wiley.com/en-us/Linux+Server+Security%3A+Hack+and+Defend-p-9781119277651) by Chris Binnie (Book)
