```markdown
# Part 5: Advanced SSH Troubleshooting 🔍🛠️

## Table of Contents
- [5.1 🔬 Diagnostic Tools](#51--diagnostic-tools)
- [5.2 🔐 Authentication Issues](#52--authentication-issues)
- [5.3 🌐 Network Problems](#53--network-problems)
- [5.4 🔧 Configuration Issues](#54--configuration-issues)
- [5.5 🚀 Performance Issues](#55--performance-issues)
- [5.6 📊 Log Analysis](#56--log-analysis)
- [5.7 🤖 Automation of Troubleshooting](#57--automation-of-troubleshooting)

## 5.1 🔬 Diagnostic Tools

### 5.1.1 SSH in Verbose Mode

Run SSH with various levels of verbosity:

```bash
ssh -v user@host    # Single -v
ssh -vv user@host   # Double -v for more detail
ssh -vvv user@host  # Triple -v for maximum detail
```

### 5.1.2 Debugging the SSH Server

Run the SSH server in debug mode:

```bash
sudo /usr/sbin/sshd -d
```

### 5.1.3 Network Packet Analysis

Use tcpdump to capture SSH traffic:

```bash
sudo tcpdump -i eth0 'tcp port 22' -w ssh_debug.pcap
```

Then analyze the .pcap file using Wireshark.

[Placeholder for Wireshark screenshot showing SSH packet analysis]
*Wireshark analysis of SSH packets, highlighting key connection stages*

## 5.2 🔐 Authentication Issues

### 5.2.1 Checking Key Permissions

```bash
ls -l ~/.ssh/id_rsa ~/.ssh/id_rsa.pub
sudo ls -l /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
```

Ensure permissions are correct (600 for private keys, 644 for public keys).

### 5.2.2 Verifying Keys

Check if the public key is correctly added to `authorized_keys`:

```bash
ssh-keygen -l -f ~/.ssh/id_rsa.pub
ssh-keygen -l -f ~/.ssh/authorized_keys
```

### 5.2.3 Key Diagnostics Script

```python
import os
import stat

def check_key_permissions():
    key_files = [
        ('~/.ssh/id_rsa', 0o600),
        ('~/.ssh/id_rsa.pub', 0o644),
        ('~/.ssh/authorized_keys', 0o600)
    ]

    for file_path, expected_perm in key_files:
        full_path = os.path.expanduser(file_path)
        if os.path.exists(full_path):
            current_perm = stat.S_IMODE(os.stat(full_path).st_mode)
            if current_perm != expected_perm:
                print(f"Incorrect permissions for {file_path}: {oct(current_perm)} (should be {oct(expected_perm)})")
        else:
            print(f"File {file_path} does not exist")

check_key_permissions()
```

## 5.3 🌐 Network Problems

### 5.3.1 Testing Connection

Use netcat to test SSH connection:

```bash
nc -vz host 22
```

### 5.3.2 Traceroute to SSH Server

```bash
traceroute -T -p 22 host
```

### 5.3.3 Comprehensive Network Diagnostics Script

```python
import subprocess
import socket

def network_diagnostics(host, port=22):
    print(f"Network diagnostics for {host}:{port}")

    # Check DNS
    try:
        ip = socket.gethostbyname(host)
        print(f"DNS resolution: {host} -> {ip}")
    except socket.gaierror:
        print(f"Unable to resolve hostname: {host}")
        return

    # Ping
    ping = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True)
    print(f"Ping result:\n{ping.stdout}")

    # Traceroute
    traceroute = subprocess.run(['traceroute', '-T', '-p', str(port), ip], capture_output=True, text=True)
    print(f"Traceroute:\n{traceroute.stdout}")

    # Check port
    try:
        with socket.create_connection((ip, port), timeout=10) as sock:
            print(f"Connection to port {port} successful")
    except (socket.timeout, ConnectionRefusedError):
        print(f"Cannot connect to port {port}")

network_diagnostics('example.com')
```

## 5.4 🔧 Configuration Issues

### 5.4.1 Checking Client Configuration

```bash
ssh -G host | grep -v '^#'
```

This command shows the effective SSH configuration for a given host.

### 5.4.2 Verifying Server Configuration

```bash
sudo sshd -T
```

This command displays the complete SSH server configuration, including all files and default values.

### 5.4.3 Configuration Comparison Script

```python
import difflib
import subprocess

def compare_ssh_configs(host1, host2):
    config1 = subprocess.run(['ssh', '-G', host1], capture_output=True, text=True).stdout.splitlines()
    config2 = subprocess.run(['ssh', '-G', host2], capture_output=True, text=True).stdout.splitlines()

    diff = difflib.unified_diff(config1, config2, fromfile=host1, tofile=host2, lineterm='')
    print('\n'.join(diff))

compare_ssh_configs('prod_server', 'test_server')
```

## 5.5 🚀 Performance Issues

### 5.5.1 Measuring Connection Time

```bash
time ssh user@host 'exit'
```

### 5.5.2 Testing Throughput

```bash
yes | pv | ssh user@host "cat > /dev/null"
```

### 5.5.3 SSH Performance Monitoring Script

```python
import time
import subprocess

def measure_ssh_performance(host, iterations=10):
    connection_times = []
    throughputs = []

    for _ in range(iterations):
        # Measure connection time
        start = time.time()
        subprocess.run(['ssh', host, 'exit'], capture_output=True)
        end = time.time()
        connection_times.append(end - start)

        # Measure throughput
        result = subprocess.run(['dd', 'if=/dev/zero', 'bs=1M', 'count=100', '|', 'ssh', host, 'cat > /dev/null'],
                                capture_output=True, text=True, shell=True)
        throughput = float(result.stderr.split(',')[-1].split()[0])
        throughputs.append(throughput)

    print(f"Average connection time: {sum(connection_times)/len(connection_times):.2f}s")
    print(f"Average throughput: {sum(throughputs)/len(throughputs):.2f} MB/s")

measure_ssh_performance('example.com')
```

## 5.6 📊 Log Analysis

### 5.6.1 Filtering SSH Logs

```bash
grep sshd /var/log/auth.log | grep -E "Failed|Accepted"
```

### 5.6.2 Analyzing Failed Login Attempts

```bash
grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -nr
```

### 5.6.3 Advanced Log Analysis with Python

```python
import re
from collections import defaultdict
from datetime import datetime

def analyze_ssh_logs(log_file):
    ip_attempts = defaultdict(lambda: {'success': 0, 'fail': 0, 'last_attempt': None})
    user_attempts = defaultdict(lambda: {'success': 0, 'fail': 0})

    with open(log_file, 'r') as f:
        for line in f:
            if 'sshd' not in line:
                continue

            timestamp = re.search(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line)
            if timestamp:
                timestamp = datetime.strptime(timestamp.group(), '%b %d %H:%M:%S')

            ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
            user = re.search(r'for (invalid user )?(\w+)', line)

            if ip and user:
                ip = ip.group()
                user = user.group(2)

                if 'Accepted' in line:
                    ip_attempts[ip]['success'] += 1
                    user_attempts[user]['success'] += 1
                elif 'Failed' in line:
                    ip_attempts[ip]['fail'] += 1
                    user_attempts[user]['fail'] += 1

                ip_attempts[ip]['last_attempt'] = timestamp

    print("Top 5 IPs with failed attempts:")
    for ip, data in sorted(ip_attempts.items(), key=lambda x: x[1]['fail'], reverse=True)[:5]:
        print(f"{ip}: {data['fail']} failed, {data['success']} successful, last attempt: {data['last_attempt']}")

    print("\nTop 5 users with failed attempts:")
    for user, data in sorted(user_attempts.items(), key=lambda x: x[1]['fail'], reverse=True)[:5]:
        print(f"{user}: {data['fail']} failed, {data['success

']} successful")

analyze_ssh_logs('/var/log/auth.log')
```

[Placeholder for chart showing SSH login statistics]
*Chart showing statistics of successful and failed SSH login attempts over time*

## 5.7 🤖 Automation of Troubleshooting

### 5.7.1 Script for Automatic Resolution of Common Issues

```python
import os
import subprocess
import sys

def check_and_fix_permissions():
    key_files = [
        ('~/.ssh/id_rsa', 0o600),
        ('~/.ssh/id_rsa.pub', 0o644),
        ('~/.ssh/authorized_keys', 0o600)
    ]

    for file_path, expected_perm in key_files:
        full_path = os.path.expanduser(file_path)
        if os.path.exists(full_path):
            current_perm = os.stat(full_path).st_mode & 0o777
            if current_perm != expected_perm:
                print(f"Fixing permissions for {file_path}")
                os.chmod(full_path, expected_perm)

def restart_ssh_service():
    print("Restarting SSH service")
    subprocess.run(['sudo', 'systemctl', 'restart', 'ssh'], check=True)

def clear_known_hosts(host):
    print(f"Removing {host} from known_hosts")
    subprocess.run(['ssh-keygen', '-R', host], check=True)

def main():
    if len(sys.argv) < 2:
        print("Usage: python ssh_troubleshooter.py <host>")
        sys.exit(1)

    host = sys.argv[1]

    print("Starting automatic SSH diagnostics")

    check_and_fix_permissions()
    
    try:
        subprocess.run(['ssh', '-o', 'ConnectTimeout=5', host, 'exit'], check=True)
        print("SSH connection successful")
    except subprocess.CalledProcessError:
        print("SSH connection failed, attempting repair")
        clear_known_hosts(host)
        restart_ssh_service()
        
        try:
            subprocess.run(['ssh', '-o', 'ConnectTimeout=5', host, 'exit'], check=True)
            print("SSH connection successful after repair")
        except subprocess.CalledProcessError:
            print("Failed to automatically repair SSH connection")
            print("Please check logs and configuration manually")

if __name__ == "__main__":
    main()
```

This script automates the process of resolving common SSH issues, such as incorrect key permissions, problems with `known_hosts`, or the need to restart the SSH service.

### 5.7.2 Regular SSH Health Check

Add to crontab:

```bash
0 * * * * /path/to/ssh_health_check.sh
```

Content of `ssh_health_check.sh`:

```bash
#!/bin/bash

log_file="/var/log/ssh_health.log"
test_host="example.com"

echo "$(date): Starting SSH health check" >> $log_file

if ! ssh -o ConnectTimeout=5 -o BatchMode=yes $test_host exit >/dev/null 2>&1
then
    echo "$(date): SSH connection problem to $test_host" >> $log_file
    # Add code for notifications, e.g., sending an email
else
    echo "$(date): SSH connection to $test_host is working correctly" >> $log_file
fi
```

This script regularly checks the SSH connection and logs the results, allowing for early detection of potential issues.

Effective SSH troubleshooting requires not only knowledge of tools and techniques but also a systematic approach to problem-solving. Always start with the simplest solutions and gradually move to more advanced diagnostic techniques. 🔍🛠️
```

