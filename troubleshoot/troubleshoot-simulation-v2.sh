#!/bin/bash
# Linux Production Issues Simulation Scripts
# Run these scripts to create realistic troubleshooting scenarios

# =============================================================================
# SCRIPT 1: HIGH CPU USAGE ISSUE
# =============================================================================
cat << 'EOF' > simulate_high_cpu.sh
#!/bin/bash
echo "Simulating high CPU usage issue..."

# Create multiple CPU-intensive background processes
for i in {1..4}; do
    (while true; do echo "CPU burner $i" > /dev/null; done) &
    echo "Started CPU burner process $i (PID: $!)"
done

# Create a script that looks like a legitimate service
cat << 'SCRIPT' > /tmp/data_processor.sh
#!/bin/bash
while true; do
    # Simulate data processing
    find /usr -type f -name "*.so" 2>/dev/null | wc -l > /dev/null
    dd if=/dev/zero of=/dev/null bs=1M count=100 2>/dev/null
done
SCRIPT

chmod +x /tmp/data_processor.sh
nohup /tmp/data_processor.sh &
echo "Started fake data_processor service (PID: $!)"

echo "High CPU issue simulated! Use 'top', 'htop', 'ps aux' to investigate"
echo "Kill processes with: pkill -f 'CPU burner' && pkill -f data_processor"
EOF

# =============================================================================
# SCRIPT 2: DISK SPACE ISSUE
# =============================================================================
cat << 'EOF' > simulate_disk_full.sh
#!/bin/bash
echo "Simulating disk space issue..."

# Create directory for fake logs
mkdir -p /tmp/fake_logs

# Fill up space with fake log files
echo "Creating large log files..."
for i in {1..5}; do
    dd if=/dev/zero of="/tmp/fake_logs/app_$i.log" bs=1M count=500 2>/dev/null &
    echo "Creating fake_logs/app_$i.log"
done

# Create fake database files
mkdir -p /tmp/fake_db
for i in {1..3}; do
    dd if=/dev/zero of="/tmp/fake_db/database_$i.db" bs=1M count=800 2>/dev/null &
    echo "Creating fake_db/database_$i.db"
done

# Simulate log rotation gone wrong
mkdir -p /tmp/log_backup
for i in {1..10}; do
    dd if=/dev/zero of="/tmp/log_backup/old_log_$i.tar.gz" bs=1M count=200 2>/dev/null &
done

wait
echo "Disk space issue simulated!"
echo "Check with: df -h, du -sh /tmp/*, ncdu /tmp/"
echo "Clean up with: rm -rf /tmp/fake_logs /tmp/fake_db /tmp/log_backup"
EOF

# =============================================================================
# SCRIPT 3: MEMORY LEAK SIMULATION
# =============================================================================
cat << 'EOF' > simulate_memory_leak.sh
#!/bin/bash
echo "Simulating memory leak..."

cat << 'LEAK_SCRIPT' > /tmp/memory_leaker.py
#!/usr/bin/env python3
import time
import os

# Simulate a memory leak
memory_hog = []
counter = 0

print(f"Memory leaker started with PID: {os.getpid()}")

while True:
    # Allocate more memory every second
    data = "X" * (1024 * 1024)  # 1MB chunks
    memory_hog.append(data)
    counter += 1

    if counter % 10 == 0:
        print(f"Allocated {counter} MB of memory")

    time.sleep(1)
LEAK_SCRIPT

chmod +x /tmp/memory_leaker.py
nohup python3 /tmp/memory_leaker.py &
echo "Memory leak simulation started (PID: $!)"
echo "Monitor with: free -h, top, ps aux --sort=-%mem"
echo "Kill with: pkill -f memory_leaker"
EOF

# =============================================================================
# SCRIPT 4: NETWORK CONNECTIVITY ISSUES
# =============================================================================
cat << 'EOF' > simulate_network_issues.sh
#!/bin/bash
echo "Simulating network connectivity issues..."

# Block common ports using iptables (requires sudo)
echo "Adding iptables rules to block connectivity..."
sudo iptables -I OUTPUT -p tcp --dport 80 -j DROP 2>/dev/null
sudo iptables -I OUTPUT -p tcp --dport 443 -j DROP 2>/dev/null
sudo iptables -I OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null
sudo iptables -I OUTPUT -p udp --dport 53 -j DROP 2>/dev/null

# Create a fake service that tries to connect
cat << 'NET_SCRIPT' > /tmp/network_service.sh
#!/bin/bash
while true; do
    echo "$(date): Trying to connect to external API..."
    curl -m 5 http://httpbin.org/get 2>&1 | head -3
    echo "$(date): Connection attempt failed"
    sleep 10
done
NET_SCRIPT

chmod +x /tmp/network_service.sh
nohup /tmp/network_service.sh > /tmp/network_service.log 2>&1 &
echo "Network service simulation started (PID: $!)"

echo "Network issues simulated!"
echo "Test connectivity: ping google.com, curl google.com"
echo "Check rules: sudo iptables -L OUTPUT"
echo "Fix with: sudo iptables -F OUTPUT && pkill -f network_service"
EOF

# =============================================================================
# SCRIPT 5: FILE PERMISSION ISSUES
# =============================================================================
cat << 'EOF' > simulate_permission_issues.sh
#!/bin/bash
echo "Simulating file permission issues..."

# Create application directory structure
mkdir -p /tmp/myapp/{config,logs,data,bin}

# Create files with wrong permissions
echo "database_url=localhost:5432" > /tmp/myapp/config/database.conf
echo "api_key=secret123" > /tmp/myapp/config/api.conf
touch /tmp/myapp/logs/application.log
touch /tmp/myapp/logs/error.log
echo "user_data" > /tmp/myapp/data/users.db

# Create application script
cat << 'APP_SCRIPT' > /tmp/myapp/bin/myapp.sh
#!/bin/bash
echo "Starting MyApp..."
echo "Reading config..." && cat /tmp/myapp/config/database.conf
echo "Writing to log..." && echo "$(date): App started" >> /tmp/myapp/logs/application.log
echo "Accessing database..." && echo "new_user" >> /tmp/myapp/data/users.db
echo "MyApp running successfully!"
APP_SCRIPT

# Set problematic permissions
chmod 600 /tmp/myapp/config/database.conf  # Too restrictive
chmod 777 /tmp/myapp/config/api.conf       # Too permissive
chmod 444 /tmp/myapp/logs/application.log  # Read-only log file
chmod 000 /tmp/myapp/data/users.db         # No permissions
chmod 644 /tmp/myapp/bin/myapp.sh          # Not executable

# Create a user service file
cat << 'SERVICE' > /tmp/myapp.service
[Unit]
Description=MyApp Service
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/tmp/myapp/bin/myapp.sh
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

echo "Permission issues simulated!"
echo "Try running: /tmp/myapp/bin/myapp.sh"
echo "Check permissions: ls -la /tmp/myapp/config/"
echo "Fix with proper chmod/chown commands"
EOF

# =============================================================================
# SCRIPT 6: SERVICE/DAEMON ISSUES
# =============================================================================
cat << 'EOF' > simulate_service_issues.sh
#!/bin/bash
echo "Simulating service/daemon issues..."

# Create a problematic service script
cat << 'DAEMON_SCRIPT' > /tmp/broken_daemon.sh
#!/bin/bash
# This daemon has multiple issues

# Issue 1: Wrong PID file location
echo $$ > /var/run/broken_daemon.pid 2>/dev/null || echo $$ > /tmp/broken_daemon.pid

# Issue 2: Missing dependency check
if ! command -v nonexistent_command &> /dev/null; then
    echo "ERROR: Required dependency not found!"
    exit 1
fi

# Issue 3: Resource exhaustion
exec 3< /dev/tcp/127.0.0.1/9999 || {
    echo "Cannot connect to required service on port 9999"
    exit 1
}

# This won't be reached due to the above error
while true; do
    echo "$(date): Daemon is running..."
    sleep 30
done
DAEMON_SCRIPT

chmod +x /tmp/broken_daemon.sh

# Create systemd service file
sudo tee /etc/systemd/system/broken-service.service > /dev/null << 'SERVICE_FILE'
[Unit]
Description=Broken Service for Troubleshooting
After=network.target
Wants=nonexistent.service

[Service]
Type=forking
ExecStart=/tmp/broken_daemon.sh
PIDFile=/var/run/broken_daemon.pid
User=root
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_FILE

sudo systemctl daemon-reload
sudo systemctl enable broken-service.service 2>/dev/null

echo "Service issues simulated!"
echo "Try: sudo systemctl start broken-service"
echo "Debug with: sudo systemctl status broken-service"
echo "Check logs: sudo journalctl -u broken-service -f"
echo "Clean up: sudo systemctl disable broken-service && sudo rm /etc/systemd/system/broken-service.service"
EOF

# =============================================================================
# SCRIPT 7: LOG ANALYSIS CHALLENGE
# =============================================================================
cat << 'EOF' > simulate_log_issues.sh
#!/bin/bash
echo "Creating realistic log files for analysis..."

mkdir -p /tmp/app_logs

# Generate web server access log with issues
cat << 'WEBLOG' > /tmp/app_logs/access.log
127.0.0.1 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "GET /api/users HTTP/1.1" 200 1234
10.0.1.15 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 567
10.0.1.15 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 567
10.0.1.15 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 567
192.168.1.100 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "GET /admin HTTP/1.1" 403 234
203.0.113.45 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "GET /../../../etc/passwd HTTP/1.1" 404 345
127.0.0.1 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "GET /api/orders HTTP/1.1" 500 0
127.0.0.1 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] "GET /api/orders HTTP/1.1" 500 0
WEBLOG

# Generate application error log
cat << 'ERRORLOG' > /tmp/app_logs/error.log
$(date +'%Y-%m-%d %H:%M:%S') [ERROR] Database connection failed: Connection refused
$(date +'%Y-%m-%d %H:%M:%S') [WARNING] High memory usage detected: 85%
$(date +'%Y-%m-%d %H:%M:%S') [ERROR] Failed to process order #12345: Timeout after 30s
$(date +'%Y-%m-%d %H:%M:%S') [CRITICAL] OutOfMemoryError in payment processor
$(date +'%Y-%m-%d %H:%M:%S') [ERROR] Redis connection pool exhausted
$(date +'%Y-%m-%d %H:%M:%S') [WARNING] Disk space low on /var partition: 95% full
$(date +'%Y-%m-%d %H:%M:%S') [ERROR] Authentication service unavailable
ERRORLOG

# Generate system log with issues
cat << 'SYSLOG' > /tmp/app_logs/system.log
$(date +'%b %d %H:%M:%S') server01 kernel: Out of memory: Kill process 1234 (java) score 900
$(date +'%b %d %H:%M:%S') server01 sshd[5678]: Failed password for admin from 203.0.113.89 port 45231 ssh2
$(date +'%b %d %H:%M:%S') server01 sshd[5679]: Failed password for admin from 203.0.113.89 port 45232 ssh2
$(date +'%b %d %H:%M:%S') server01 systemd: mysql.service failed with result 'exit-code'
$(date +'%b %d %H:%M:%S') server01 NetworkManager: device eth0: link disconnected
SYSLOG

echo "Log files created in /tmp/app_logs/"
echo "Practice log analysis with:"
echo "- grep, awk, sed commands"
echo "- Find failed login attempts: grep '401' /tmp/app_logs/access.log"
echo "- Count error types: grep ERROR /tmp/app_logs/error.log | cut -d']' -f2 | sort | uniq -c"
echo "- Find suspicious IPs: awk '{print \$1}' /tmp/app_logs/access.log | sort | uniq -c | sort -nr"
EOF

# =============================================================================
# MASTER SCRIPT TO RUN ALL SCENARIOS
# =============================================================================
cat << 'EOF' > run_troubleshooting_scenarios.sh
#!/bin/bash
echo "=== Linux Troubleshooting Practice Scenarios ==="
echo "Choose which issue to simulate:"
echo "1. High CPU Usage"
echo "2. Disk Space Issues"
echo "3. Memory Leak"
echo "4. Network Connectivity Issues"
echo "5. File Permission Issues"
echo "6. Service/Daemon Issues"
echo "7. Log Analysis Challenge"
echo "8. Run ALL scenarios"
echo "9. Clean up all issues"

read -p "Enter your choice (1-9): " choice

case $choice in
    1) bash simulate_high_cpu.sh ;;
    2) bash simulate_disk_full.sh ;;
    3) bash simulate_memory_leak.sh ;;
    4) bash simulate_network_issues.sh ;;
    5) bash simulate_permission_issues.sh ;;
    6) bash simulate_service_issues.sh ;;
    7) bash simulate_log_issues.sh ;;
    8)
        echo "Running all scenarios..."
        bash simulate_high_cpu.sh
        bash simulate_disk_full.sh
        bash simulate_memory_leak.sh
        bash simulate_permission_issues.sh
        bash simulate_log_issues.sh
        echo "All scenarios activated! Good luck troubleshooting!"
        ;;
    9)
        echo "Cleaning up all simulated issues..."
        pkill -f "CPU burner" 2>/dev/null
        pkill -f "data_processor" 2>/dev/null
        pkill -f "memory_leaker" 2>/dev/null
        pkill -f "network_service" 2>/dev/null
        sudo iptables -F OUTPUT 2>/dev/null
        sudo systemctl stop broken-service 2>/dev/null
        sudo systemctl disable broken-service 2>/dev/null
        sudo rm -f /etc/systemd/system/broken-service.service 2>/dev/null
        rm -rf /tmp/fake_logs /tmp/fake_db /tmp/log_backup 2>/dev/null
        rm -rf /tmp/myapp /tmp/app_logs 2>/dev/null
        rm -f /tmp/memory_leaker.py /tmp/data_processor.sh /tmp/network_service.sh /tmp/broken_daemon.sh 2>/dev/null
        echo "Cleanup completed!"
        ;;
    *) echo "Invalid choice" ;;
esac
EOF

# Make all scripts executable
chmod +x *.sh

echo "Linux troubleshooting simulation scripts created!"
echo ""
echo "FILES CREATED:"
echo "SIMULATION SCRIPTS:"
echo "- simulate_high_cpu.sh         # Creates CPU-intensive processes"
echo "- simulate_disk_full.sh        # Fills disk with large files"
echo "- simulate_memory_leak.sh      # Python script that leaks memory"
echo "- simulate_network_issues.sh   # Blocks network connectivity"
echo "- simulate_permission_issues.sh # Creates files with wrong permissions"
echo "- simulate_service_issues.sh   # Creates broken systemd service"
echo "- simulate_log_issues.sh       # Generates realistic log files"
echo ""
echo "TROUBLESHOOTING GUIDES:"
echo "- troubleshooting_guides.sh    # Comprehensive troubleshooting methodology"
echo ""
echo "MASTER CONTROL:"
echo "- run_troubleshooting_scenarios.sh # Interactive menu for all scenarios"
echo ""
echo "HOW TO USE:"
echo "1. Run: ./run_troubleshooting_scenarios.sh"
echo "2. Choose a scenario to simulate (1-8)"
echo "3. Use standard Linux tools to troubleshoot"
echo "4. Check the troubleshooting guides (11-18) for methodology"
echo "5. Clean up when done (option 9)"
echo ""
echo "EXAMPLE WORKFLOW:"
echo "# Start with high CPU simulation"
echo "./run_troubleshooting_scenarios.sh  # Choose option 1"
echo ""
echo "# Troubleshoot using these commands:"
echo "top                    # See current CPU usage"
echo "ps aux --sort=-%cpu    # Find CPU-hungry processes"
echo "htop                   # Interactive process viewer"
echo "lsof -p <PID>         # See what files process is using"
echo ""
echo "# View troubleshooting guide:"
echo "bash troubleshooting_guides.sh cpu"
echo ""
echo "# Clean up:"
echo "pkill -f 'CPU burner'"
echo ""
echo "INTERVIEW PREPARATION TIPS:"
echo "- Always explain your thought process out loud"
echo "- Start with basic health checks (top, df -h, free -h)"
echo "- Check logs first - they usually contain the answers"
echo "- Use systematic approach: identify → analyze → fix → verify"
echo "- Know when to escalate vs. fix immediately"