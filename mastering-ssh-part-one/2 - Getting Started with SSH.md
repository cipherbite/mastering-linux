# Part Two: Getting Started with SSH

## Table of Contents

- [2.1 Essential SSH Commands](#21-essential-ssh-commands)

## 2.1 Essential SSH Commands

SSH (Secure Shell) is a secure protocol that allows you to remotely manage and interact with other systems as if you were directly connected to them. It provides a safe, encrypted tunnel for your data, ensuring that your communications are protected from prying eyes.

### Establishing a Remote Connection

To initiate a secure connection to a remote server, use the SSH command:

```bash
ssh [options] username@remote_host
```

This command is like knocking on the door of a remote computer and requesting access. Once connected, you can interact with the remote system as though you were sitting right in front of it.

- **username:** The login name you use on the remote server.
- **remote_host:** The IP address or domain name of the remote server.
- **Example:** `ssh john@example.com`

{screenshot of: A terminal window showing a successful SSH connection, including the initial welcome message}

**Key Options:**
- `-p port`: Specify a non-standard SSH port (if the server uses one other than the default port 22).
- `-i identity_file`: Use a private key file for authentication.
- `-X`: Enable X11 forwarding to run graphical applications remotely.
- `-v`: Enable verbose mode for detailed connection logs, useful for troubleshooting.

**Important Considerations:**
- On your first connection, you will be prompted to verify the server’s host key. This step helps prevent man-in-the-middle attacks.
- The `~/.ssh/known_hosts` file stores verified host keys for future connections.
- If you encounter connection issues, use `ssh -v` for detailed debugging information.

### Executing Remote Commands

You can execute commands on a remote server without initiating a full interactive session:

```bash
ssh username@remote_host 'command'
```

This is like sending a quick task to the remote computer, instructing it to perform a specific action and return the result without establishing a long-term session.

**Examples:** 
- Check the system uptime: `ssh john@example.com 'uptime'`
- View disk usage: `ssh john@example.com 'df -h'`
- Update system packages: `ssh john@example.com 'sudo apt update && sudo apt upgrade -y'`

**Advanced Usage:**
- Chain multiple commands together: `ssh user@host 'command1 && command2'`

{screenshot of: A terminal window showing the output of a remote command execution}

### Secure File Transfer with SCP

SCP (Secure Copy) is a command-line utility for securely transferring files between local and remote systems:

**Upload a File to a Remote Server:**
```bash
scp [options] source_file(s) username@remote_host:destination
```

**Download a File from a Remote Server:**
```bash
scp [options] username@remote_host:source_file(s) destination
```

SCP ensures that your files are transferred securely and remain encrypted during transit.

{screenshot of: An SCP file transfer in progress, showing the transfer rate and progress bar}

**Examples:**
- Upload a file: `scp /path/to/local/file.txt john@example.com:/home/john/`
- Download a file: `scp john@example.com:/home/john/file.txt /local/path/`
- Transfer an entire directory: `scp -r /local/directory john@example.com:/remote/path/`

**Useful Options:**
- `-P port`: Use a specific SSH port for the connection.
- `-i identity_file`: Authenticate using a specific private key.
- `-l limit`: Limit the bandwidth used during the transfer, helpful in constrained networks.
- `-C`: Compress files during transfer to speed up the process on slower connections.

### Interactive File Management with SFTP

SFTP (SSH File Transfer Protocol) is an interactive, command-line interface for secure file management on remote systems. It offers a more user-friendly way to navigate and manage files compared to SCP:

{screenshot of: A diagram illustrating how SFTP works, showing the encrypted connection between client and server}

**Start an SFTP Session:**
```bash
sftp [options] username@remote_host
```

SFTP provides a familiar interface for users who have experience with FTP, but with the added benefit of SSH encryption.

{screenshot of: An active SFTP session, showing various SFTP commands and their outputs}

**Essential SFTP Commands:**
- `put local_file [remote_file]`: Upload a file to the remote server.
- `get remote_file [local_file]`: Download a file from the remote server.
- `ls [directory]`: List files in the current or a specified remote directory.
- `cd directory`: Change the directory on the remote server.
- `lcd directory`: Change the directory on your local machine.
- `mkdir directory`: Create a new directory on the remote server.
- `rm file`: Delete a file on the remote server.
- `rmdir directory`: Remove an empty directory on the remote server.
- `pwd`: Show the current directory on the remote server.
- `lpwd`: Show the current directory on your local machine.
- `bye` or `exit`: End the SFTP session.

**Advanced SFTP Usage:**
- **Batch Mode:** Automate file transfers by creating a script file with SFTP commands:
  ```bash
  sftp -b batch_file username@remote_host
  ```
- **Recursive Operations:** Use `-r` with `put` or `get` to transfer entire directories.

By mastering these essential SSH commands, you will be well-equipped to securely manage remote systems and transfer files with ease and confidence.

## Further Reading and Resources

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [SSH.com Security Best Practices](https://www.ssh.com/academy/ssh/security)
- [NIST Guidelines for Secure Shell (SSH)](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)
- [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
- [SSH Mastery](https://www.tiltedwindmillpress.com/product/ssh-mastery/) by Michael W Lucas (Book)
- [Linux Server Security: Hack and Defend](https://www.wiley.com/en-us/Linux+Server+Security%3A+Hack+and+Defend-p-9781119277651) by Chris Binnie (Book)
