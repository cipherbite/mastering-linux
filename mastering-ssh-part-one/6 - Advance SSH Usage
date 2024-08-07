## Part Six: Advanced Usage

### 6.1 Automating SSH Tasks

#### SSH in Scripts

- **Purpose:** Automate repetitive tasks across multiple servers, such as deploying code, restarting services, or monitoring.

**Example Script:**

```bash
#!/bin/bash
servers=("server1.example.com" "server2.example.com")
for server in "${servers[@]}"; do
  ssh user@$server 'sudo systemctl restart nginx'
done
```

**Explanation:** This script uses an array to list servers, connects to each server via SSH, and restarts the Nginx service.

#### Advanced Scripting with SSH

- **Using `sshpass`:** Automate SSH logins in scripts without manually entering passwords (not recommended for production use due to security risks).
  ```bash
  sshpass -p 'password' ssh user@server 'command'
  ```

#### Improving Security and Flexibility

- **SSH Key Authentication:** Instead of using passwords, configure SSH key-based authentication for enhanced security.

  1. **Generate SSH Key Pair:**

     ```bash
     ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
     ```

     **Explanation:** Generates an RSA key pair with a 4096-bit key size.

  2. **Copy Public Key to Servers:**
     ```bash
     ssh-copy-id user@server
     ```
     **Explanation:** Copies the public key to the specified server, enabling key-based authentication.

**Example Script with Key Authentication:**

```bash
#!/bin/bash
servers=("server1.example.com" "server2.example.com")
for server in "${servers[@]}"; do
  ssh -i /path/to/private/key user@$server 'sudo systemctl restart nginx'
done
```

#### Advanced SSH Configuration

- **SSH Config File:** Simplify SSH commands by using an SSH config file (`~/.ssh/config`).

  ```plaintext
  Host server1
      HostName server1.example.com
      User user
      IdentityFile /path/to/private/key

  Host server2
      HostName server2.example.com
      User user
      IdentityFile /path/to/private/key
  ```

**Example Script Using SSH Config:**

```bash
#!/bin/bash
servers=("server1" "server2")
for server in "${servers[@]}"; do
  ssh $server 'sudo systemctl restart nginx'
done
```

#### Parallel Execution

- **Using GNU Parallel:** Execute SSH commands on multiple servers in parallel to save time.
  ```bash
  #!/bin/bash
  servers=("server1.example.com" "server2.example.com")
  parallel -u -j 2 ssh user@{} 'sudo systemctl restart nginx' ::: "${servers[@]}"
  ```
  **Explanation:** The `parallel` command runs SSH commands on the listed servers concurrently with 2 parallel jobs.
