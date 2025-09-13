#!/bin/bash
# Advanced Linux Troubleshooting Practice Scenarios
# These scenarios simulate more complex production issues

# =============================================================================
# SCENARIO 8: ZOMBIE PROCESS EPIDEMIC
# =============================================================================
cat << 'EOF' > simulate_zombie_processes.sh
#!/bin/bash
echo "Simulating zombie process issue..."

# Create a parent process that doesn't clean up its children
cat << 'ZOMBIE_SCRIPT' > /tmp/zombie_creator.sh
#!/bin/bash
echo "Zombie creator started with PID: $$"

for i in {1..10}; do
    # Create child processes that exit immediately
    (
        echo "Child $i (PID: $$) starting..."
        sleep 2
        echo "Child $i exiting..."
        exit 0
    ) &

    # Don't wait for children - this creates zombies
    echo "Created child $i"
    sleep 1
done

echo "Parent process will sleep for 300 seconds without cleaning up children..."
sleep 300
ZOMBIE_SCRIPT

chmod +x /tmp/zombie_creator.sh
nohup /tmp/zombie_creator.sh > /tmp/zombie.log 2>&1 &
echo "Zombie creator started (PID: $!)"

echo "Zombie processes created!"
echo "Investigate with: ps aux | grep '<defunct>' or ps aux | awk '\$8 ~ /^Z/'"
echo "Clean up with: pkill -f zombie_creator"
EOF

# =============================================================================
# SCENARIO 9: INODE EXHAUSTION
# =============================================================================
cat << 'EOF' > simulate_inode_exhaustion.sh
#!/bin/bash
echo "Simulating inode exhaustion..."

# Create a directory for our inode attack
mkdir -p /tmp/inode_attack

echo "Creating thousands of small files to exhaust inodes..."
# Create many small files
for i in {1..5000}; do
    touch "/tmp/inode_attack/file_$i" 2>/dev/null
    if [ $((i % 1000)) -eq 0 ]; then
        echo "Created $i files..."
    fi
done

# Create nested directories with files
for dir in {1..20}; do
    mkdir -p "/tmp/inode_attack/dir_$dir"
    for file in {1..200}; do
        touch "/tmp/inode_attack/dir_$dir/nested_file_$file" 2>/dev/null
    done
done

echo "Inode exhaustion simulated!"
echo "Check with: df -i /tmp"
echo "Find the culprit: find /tmp -type f | wc -l"
echo "Clean up: rm -rf /tmp/inode_attack"
EOF

# =============================================================================
# SCENARIO 10: CORRUPTED FILESYSTEM SIMULATION
# =============================================================================
cat << 'EOF' > simulate_filesystem_issues.sh
#!/bin/bash
echo "Simulating filesystem issues..."

# Create a test filesystem in a file
mkdir -p /tmp/fs_test
dd if=/dev/zero of=/tmp/fs_test/test_filesystem.img bs=1M count=100 2>/dev/null

# Create filesystem
mkfs.ext4 /tmp/fs_test/test_filesystem.img -F 2>/dev/null

# Create mount point
mkdir -p /tmp/test_mount

# Mount the filesystem
sudo mount -o loop /tmp/fs_test/test_filesystem.img /tmp/test_mount 2>/dev/null

# Create some files
echo "Creating files on test filesystem..."
for i in {1..10}; do
    echo "Test data $i" > "/tmp/test_mount/testfile_$i.txt" 2>/dev/null
done

# Simulate corruption by writing random data
echo "Simulating filesystem corruption..."
dd if=/dev/urandom of=/tmp/fs_test/test_filesystem.img bs=1K count=1 seek=50 conv=notrunc 2>/dev/null

echo "Filesystem corruption simulated!"
echo "Try to access files: ls -la /tmp/test_mount/"
echo "Check filesystem: sudo fsck /tmp/fs_test/test_filesystem.img"
echo "Clean up: sudo umount /tmp/test_mount && rm -rf /tmp/fs_test /tmp/test_mount"
EOF

# =============================================================================
# SCENARIO 11: RUNAWAY LOG ROTATION
# =============================================================================
cat << 'EOF' > simulate_log_rotation_issue.sh
#!/bin/bash
echo "Simulating runaway log rotation issue..."

# Create fake application that logs heavily
mkdir -p /tmp/heavy_logger

cat << 'LOGGER_SCRIPT' > /tmp/heavy_logger/app.sh
#!/bin/bash
LOG_FILE="/tmp/heavy_logger/application.log"

echo "Heavy logging application started at $(date)" >> $LOG_FILE

while true; do
    # Generate various log levels
    echo "$(date) [INFO] Processing request ID: $RANDOM" >> $LOG_FILE
    echo "$(date) [DEBUG] Database query executed successfully" >> $LOG_FILE
    echo "$(date) [WARNING] High memory usage detected: $(( RANDOM % 50 + 50 ))%" >> $LOG_FILE

    # Occasionally log errors
    if [ $((RANDOM % 20)) -eq 0 ]; then
        echo "$(date) [ERROR] Failed to connect to external service" >> $LOG_FILE
    fi

    # High frequency logging
    sleep 0.1
done
LOGGER_SCRIPT

chmod +x /tmp/heavy_logger/app.sh

# Create broken logrotate config
cat << 'LOGROTATE_CONFIG' > /tmp/heavy_logger/logrotate.conf
/tmp/heavy_logger/application.log {
    size 1k
    rotate 1000
    compress
    delaycompress
    missingok
    create 644 $(whoami) $(whoami)
    postrotate
        # This would normally restart the service
        echo "Log rotated at $(date)" >> /tmp/heavy_logger/rotation.log
    endscript
}
LOGROTATE_CONFIG

# Start the heavy logger
nohup /tmp/heavy_logger/app.sh &
echo "Heavy logger started (PID: $!)"

echo "Runaway logging simulation started!"
echo "Monitor with: watch -n 1 'ls -lah /tmp/heavy_logger/'"
echo "Test rotation: logrotate -f /tmp/heavy_logger/logrotate.conf"
echo "Clean up: pkill -f heavy_logger && rm -rf /tmp/heavy_logger"
EOF

# =============================================================================
# SCENARIO 12: PORT EXHAUSTION
# =============================================================================
cat << 'EOF' > simulate_port_exhaustion.sh
#!/bin/bash
echo "Simulating port exhaustion..."

# Create script that opens many connections
cat << 'PORT_HOG_SCRIPT' > /tmp/port_hog.py
#!/usr/bin/env python3
import socket
import time
import threading

sockets = []
port = 8000

def create_connections():
    global sockets, port
    try:
        while len(sockets) < 1000:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                sock.bind(('127.0.0.1', port))
                sock.listen(1)
                sockets.append(sock)
                print(f"Created socket on port {port}, total: {len(sockets)}")
                port += 1

                if port > 65535:
                    print("Reached maximum port number")
                    break

            except OSError as e:
                print(f"Failed to bind port {port}: {e}")
                sock.close()
                port += 1

            time.sleep(0.01)

    except KeyboardInterrupt:
        print("Cleaning up sockets...")
        for sock in sockets:
            sock.close()

if __name__ == "__main__":
    print(f"Port hog started, PID: {os.getpid() if 'os' in dir() else 'unknown'}")
    create_connections()
PORT_HOG_SCRIPT

chmod +x /tmp/port_hog.py
nohup python3 /tmp/port_hog.py > /tmp/port_hog.log 2>&1 &
echo "Port exhaustion simulation started (PID: $!)"

echo "Port exhaustion simulated!"
echo "Check with: netstat -an | grep LISTEN | wc -l"
echo "Monitor: watch 'ss -tuln | wc -l'"
echo "Clean up: pkill -f port_hog"
EOF

# =============================================================================
# SCENARIO 13: KERNEL MODULE ISSUES
# =============================================================================
cat << 'EOF' > simulate_kernel_module_issues.sh
#!/bin/bash
echo "Simulating kernel module issues..."

# Check if we can load/unload a harmless module
if lsmod | grep -q dummy; then
    echo "Dummy network module already loaded"
else
    echo "Loading dummy network module..."
    sudo modprobe dummy 2>/dev/null || echo "Cannot load dummy module (expected on some systems)"
fi

# Create fake module loading script
cat << 'MODULE_SCRIPT' > /tmp/module_tester.sh
#!/bin/bash
echo "Testing kernel modules..."

# Try to load non-existent module
echo "Attempting to load fake module..."
sudo modprobe fake_nonexistent_module 2>&1 | tee /tmp/module_errors.log

# Create dependency issue
echo "Creating module dependency issue..."
echo "fake_module depends on another_fake_module" >> /tmp/module_errors.log

# Simulate module in use issue
echo "Module xyz is in use by: process1 process2" >> /tmp/module_errors.log

echo "Check /tmp/module_errors.log for simulated module issues"
MODULE_SCRIPT

chmod +x /tmp/module_tester.sh
bash /tmp/module_tester.sh

echo "Kernel module issues simulated!"
echo "Check with: lsmod, modinfo <module>, dmesg | grep -i module"
echo "Logs in: /tmp/module_errors.log"
echo "Clean up: rm /tmp/module_tester.sh /tmp/module_errors.log"
EOF

# =============================================================================
# SCENARIO 14: SWAP THRASHING
# =============================================================================
cat << 'EOF' > simulate_swap_thrashing.sh
#!/bin/bash
echo "Simulating swap thrashing..."

# Create memory pressure that forces swapping
cat << 'SWAP_SCRIPT' > /tmp/swap_thrasher.py
#!/usr/bin/env python3
import time
import os

def create_memory_pressure():
    print(f"Swap thrasher started, PID: {os.getpid()}")

    # Allocate memory in chunks
    memory_chunks = []
    chunk_size = 10 * 1024 * 1024  # 10MB chunks

    for i in range(200):  # Try to allocate 2GB
        try:
            chunk = bytearray(chunk_size)
            # Fill with data to ensure it's actually allocated
            for j in range(0, chunk_size, 1024):
                chunk[j] = i % 256

            memory_chunks.append(chunk)
            print(f"Allocated chunk {i+1}, total ~{(i+1)*10}MB")

            # Occasionally access old chunks to prevent them from being swapped
            if i % 10 == 0 and memory_chunks:
                for chunk in memory_chunks[::5]:  # Access every 5th chunk
                    chunk[0] = chunk[0]  # Touch the memory

            time.sleep(0.1)

        except MemoryError:
            print("Memory allocation failed")
            break

    print("Keeping memory allocated for 120 seconds...")
    time.sleep(120)

if __name__ == "__main__":
    create_memory_pressure()
SWAP_SCRIPT

chmod +x /tmp/swap_thrasher.py
nohup python3 /tmp/swap_thrasher.py > /tmp/swap_thrash.log 2>&1 &
echo "Swap thrasher started (PID: $!)"

echo "Swap thrashing simulation started!"
echo "Monitor with: free -h, vmstat 1, iotop -a"
echo "Watch swap usage: watch 'cat /proc/swaps'"
echo "Clean up: pkill -f swap_thrasher"
EOF

# =============================================================================
# SCENARIO 15: DNS CACHE POISONING SIMULATION
# =============================================================================
cat << 'EOF' > simulate_dns_issues.sh
#!/bin/bash
echo "Simulating DNS resolution issues..."

# Backup original hosts file
sudo cp /etc/hosts /etc/hosts.backup

# Add problematic entries to hosts file
echo "Adding problematic DNS entries..."
sudo tee -a /etc/hosts > /dev/null << 'DNS_ENTRIES'

# Simulated DNS issues
127.0.0.1    google.com
127.0.0.1    github.com
127.0.0.1    stackoverflow.com
192.168.1.999  invalid-ip-test.com
badformat     malformed-entry
DNS_ENTRIES

# Create script that tests DNS resolution
cat << 'DNS_TEST_SCRIPT' > /tmp/dns_tester.sh
#!/bin/bash
echo "Testing DNS resolution..."

domains=("google.com" "github.com" "stackoverflow.com" "invalid-ip-test.com")

for domain in "${domains[@]}"; do
    echo "Testing $domain:"
    nslookup $domain 2>&1 | head -5
    echo "---"
done

echo "Checking /etc/hosts file:"
tail -10 /etc/hosts
DNS_TEST_SCRIPT

chmod +x /tmp/dns_tester.sh
bash /tmp/dns_tester.sh > /tmp/dns_test_results.log

echo "DNS issues simulated!"
echo "Test with: nslookup google.com, dig google.com, ping google.com"
echo "Check results: cat /tmp/dns_test_results.log"
echo "Fix with: sudo cp /etc/hosts.backup /etc/hosts"
EOF

# =============================================================================
# SCENARIO 16: CRON JOB CHAOS
# =============================================================================
cat << 'EOF' > simulate_cron_issues.sh
#!/bin/bash
echo "Simulating cron job issues..."

# Create problematic cron jobs
mkdir -p /tmp/cron_chaos

# Create scripts with various issues
cat << 'BROKEN_SCRIPT1' > /tmp/cron_chaos/broken_backup.sh
#!/bin/bash
# This script has multiple issues
cd /nonexistent/directory
tar -czf backup_$(date +%Y%m%d).tar.gz /important/data
echo "Backup completed" >> /var/log/backup.log
BROKEN_SCRIPT1

cat << 'BROKEN_SCRIPT2' > /tmp/cron_chaos/resource_hog.sh
#!/bin/bash
# This script will consume resources
find / -name "*.tmp" -exec rm {} \; 2>/dev/null
dd if=/dev/zero of=/tmp/tempfile bs=1M count=1000
BROKEN_SCRIPT2

cat << 'BROKEN_SCRIPT3' > /tmp/cron_chaos/permission_fail.sh
#!/bin/bash
# This script will fail due to permissions
echo "$(date): Attempting to write to system log" >> /var/log/system.log
chmod 777 /etc/passwd
BROKEN_SCRIPT3

chmod +x /tmp/cron_chaos/*.sh

# Create a temporary crontab with problematic entries
cat << 'CRONTAB_CONTENT' > /tmp/cron_chaos/problem_crontab
# Problematic cron entries
* * * * * /tmp/cron_chaos/broken_backup.sh
*/2 * * * * /tmp/cron_chaos/resource_hog.sh >/dev/null 2>&1
0 * * * * /tmp/cron_chaos/permission_fail.sh
# Invalid cron syntax
invalid line here
60 25 * * * /bin/echo "Invalid time"
CRONTAB_CONTENT

echo "Cron chaos simulated!"
echo "View problematic crontab: cat /tmp/cron_chaos/problem_crontab"
echo "Test scripts manually: bash /tmp/cron_chaos/broken_backup.sh"
echo "Check cron logs: sudo tail -f /var/log/cron"
echo "Clean up: rm -rf /tmp/cron_chaos"
EOF

# =============================================================================
# SCENARIO 17: RACE CONDITION SIMULATION
# =============================================================================
cat << 'EOF' > simulate_race_condition.sh
#!/bin/bash
echo "Simulating race condition..."

mkdir -p /tmp/race_condition

# Create a shared resource (file)
echo "0" > /tmp/race_condition/counter.txt

# Create script that has race condition
cat << 'RACE_SCRIPT' > /tmp/race_condition/increment.sh
#!/bin/bash
COUNTER_FILE="/tmp/race_condition/counter.txt"
LOCK_FILE="/tmp/race_condition/counter.lock"

increment_counter() {
    local id=$1
    for i in {1..100}; do
        # Simulate race condition - no proper locking
        current=$(cat $COUNTER_FILE)
        sleep 0.001  # Small delay to increase chance of race
        new_value=$((current + 1))
        echo $new_value > $COUNTER_FILE

        if [ $((i % 20)) -eq 0 ]; then
            echo "Process $id: incremented to $new_value"
        fi
    done
}

increment_counter $1
RACE_SCRIPT

chmod +x /tmp/race_condition/increment.sh

# Start multiple processes that will race
echo "Starting multiple processes that will compete for the same resource..."
for i in {1..5}; do
    /tmp/race_condition/increment.sh $i &
    echo "Started process $i (PID: $!)"
done

echo "Race condition simulation started!"
echo "Expected final value: 500 (5 processes × 100 increments)"
echo "Monitor: watch 'cat /tmp/race_condition/counter.txt'"
echo "Check result after ~10 seconds: cat /tmp/race_condition/counter.txt"
echo "Clean up: pkill -f increment.sh && rm -rf /tmp/race_condition"
EOF

# =============================================================================
# ADVANCED TROUBLESHOOTING GUIDES
# =============================================================================
cat << 'EOF' > advanced_troubleshooting_guides.sh
#!/bin/bash

show_zombie_troubleshooting() {
cat << 'GUIDE'
=== ZOMBIE PROCESS TROUBLESHOOTING ===

SYMPTOMS:
- Many processes in <defunct> state
- Process table filling up
- "fork: retry: Resource temporarily unavailable"

INVESTIGATION:
1. IDENTIFY ZOMBIES:
   ps aux | grep '<defunct>'
   ps aux | awk '$8 ~ /^Z/'

2. FIND PARENT PROCESS:
   ps -eo pid,ppid,state,comm | grep Z
   pstree -p | grep defunct

3. CHECK PROCESS LIMITS:
   cat /proc/sys/kernel/pid_max
   ps aux | wc -l

RESOLUTION:
   # Kill parent process (zombies will be reaped by init)
   kill <parent_pid>

   # If parent won't die
   kill -9 <parent_pid>

INTERVIEW TIPS:
- Explain that zombies can't be killed directly
- Parent must reap children or be killed
- Zombies consume PID space but no memory
GUIDE
}

show_inode_troubleshooting() {
cat << 'GUIDE'
=== INODE EXHAUSTION TROUBLESHOOTING ===

SYMPTOMS:
- "No space left on device" despite available disk space
- Cannot create new files/directories
- Applications failing to write

INVESTIGATION:
1. CHECK INODE USAGE:
   df -i
   tune2fs -l /dev/sdX | grep -i inode

2. FIND DIRECTORIES WITH MANY FILES:
   find / -xdev -type d -exec bash -c 'echo "$(ls -1 "$1" | wc -l) $1"' _ {} \; | sort -nr | head

3. CHECK FOR SMALL FILES:
   find / -size -1k -type f | head -20

RESOLUTION:
   # Remove unnecessary small files
   find /tmp -type f -size -1k -delete

   # Clean up cache directories
   find /var/cache -type f -delete

INTERVIEW TIPS:
- Distinguish between disk space and inode exhaustion
- Know that many small files cause this issue
- Understand filesystem limits
GUIDE
}

show_filesystem_troubleshooting() {
cat << 'GUIDE'
=== FILESYSTEM CORRUPTION TROUBLESHOOTING ===

SYMPTOMS:
- I/O errors in dmesg
- Files becoming inaccessible
- System crashes or hangs

INVESTIGATION:
1. CHECK FILESYSTEM HEALTH:
   dmesg | grep -i "error\|corruption"
   mount | grep "ro,"  # Read-only mounts

2. CHECK DISK HEALTH:
   smartctl -a /dev/sdX
   badblocks -v /dev/sdX

3. FILESYSTEM CHECK:
   fsck -n /dev/sdX  # Read-only check

RESOLUTION:
   # Unmount filesystem
   umount /mount/point

   # Run filesystem check
   fsck -y /dev/sdX

   # Remount
   mount /dev/sdX /mount/point

INTERVIEW TIPS:
- Always unmount before fsck (unless read-only)
- Backup important data first
- Understand different fsck options
GUIDE
}

show_performance_troubleshooting() {
cat << 'GUIDE'
=== SYSTEM PERFORMANCE TROUBLESHOOTING ===

SYMPTOMS:
- System feels slow
- High load average
- Poor response times

INVESTIGATION:
1. OVERALL SYSTEM HEALTH:
   uptime
   vmstat 1 5
   iostat -x 1 5
   sar -u -r -b 1 5

2. IDENTIFY BOTTLENECKS:
   # CPU bound
   top -o %CPU

   # I/O bound
   iotop -ao

   # Memory bound
   free -h && cat /proc/meminfo

3. NETWORK PERFORMANCE:
   iftop
   nethogs
   ss -tuln

RESOLUTION:
   # Kill resource hogs
   renice +10 <pid>  # Lower priority

   # Tune kernel parameters
   sysctl vm.swappiness=10

   # I/O scheduling
   echo deadline > /sys/block/sda/queue/scheduler

INTERVIEW TIPS:
- Use systematic approach to identify bottlenecks
- Understand load average vs CPU usage
- Know when to tune vs when to add resources
GUIDE
}

case "$1" in
    "zombie") show_zombie_troubleshooting ;;
    "inode") show_inode_troubleshooting ;;
    "filesystem") show_filesystem_troubleshooting ;;
    "performance") show_performance_troubleshooting ;;
    *)
        echo "Advanced Troubleshooting Guides:"
        echo "Usage: $0 {zombie|inode|filesystem|performance}"
        echo ""
        echo "Available guides:"
        echo "  zombie      - Zombie process troubleshooting"
        echo "  inode       - Inode exhaustion troubleshooting"
        echo "  filesystem  - Filesystem corruption troubleshooting"
        echo "  performance - System performance troubleshooting"
        ;;
esac
EOF

# =============================================================================
# ENHANCED MASTER SCRIPT
# =============================================================================
cat << 'EOF' > run_advanced_scenarios.sh
#!/bin/bash
echo "=== ADVANCED Linux Troubleshooting Practice ==="
echo ""
echo "ADVANCED SCENARIOS:"
echo "8.  Zombie Process Epidemic"
echo "9.  Inode Exhaustion"
echo "10. Filesystem Corruption"
echo "11. Runaway Log Rotation"
echo "12. Port Exhaustion"
echo "13. Kernel Module Issues"
echo "14. Swap Thrashing"
echo "15. DNS Resolution Issues"
echo "16. Cron Job Chaos"
echo "17. Race Condition"
echo ""
echo "ADVANCED GUIDES:"
echo "21. Zombie Process Guide"
echo "22. Inode Exhaustion Guide"
echo "23. Filesystem Corruption Guide"
echo "24. Performance Troubleshooting Guide"
echo ""
echo "OTHER OPTIONS:"
echo "99. Clean up ALL advanced scenarios"
echo "0.  Exit"

read -p "Enter your choice: " choice

case $choice in
    8)
        echo "=== ZOMBIE PROCESS EPIDEMIC ==="
        bash simulate_zombie_processes.sh
        echo "Guide: bash advanced_troubleshooting_guides.sh zombie"
        ;;
    9)
        echo "=== INODE EXHAUSTION ==="
        bash simulate_inode_exhaustion.sh
        echo "Guide: bash advanced_troubleshooting_guides.sh inode"
        ;;
    10)
        echo "=== FILESYSTEM CORRUPTION ==="
        bash simulate_filesystem_issues.sh
        echo "Guide: bash advanced_troubleshooting_guides.sh filesystem"
        ;;
    11)
        echo "=== RUNAWAY LOG ROTATION ==="
        bash simulate_log_rotation_issue.sh
        ;;
    12)
        echo "=== PORT EXHAUSTION ==="
        bash simulate_port_exhaustion.sh
        ;;
    13)
        echo "=== KERNEL MODULE ISSUES ==="
        bash simulate_kernel_module_issues.sh
        ;;
    14)
        echo "=== SWAP THRASHING ==="
        bash simulate_swap_thrashing.sh
        ;;
    15)
        echo "=== DNS RESOLUTION ISSUES ==="
        bash simulate_dns_issues.sh
        ;;
    16)
        echo "=== CRON JOB CHAOS ==="
        bash simulate_cron_issues.sh
        ;;
    17)
        echo "=== RACE CONDITION ==="
        bash simulate_race_condition.sh
        ;;
    21) bash advanced_troubleshooting_guides.sh zombie ;;
    22) bash advanced_troubleshooting_guides.sh inode ;;
    23) bash advanced_troubleshooting_guides.sh filesystem ;;
    24) bash advanced_troubleshooting_guides.sh performance ;;
    99)
        echo "=== CLEANING UP ALL ADVANCED SCENARIOS ==="
        pkill -f zombie_creator 2>/dev/null
        pkill -f port_hog 2>/dev/null
        pkill -f swap_thrasher 2>/dev/null
        pkill -f heavy_logger 2>/dev/null
        pkill -f increment.sh 2>/dev/null
        sudo umount /tmp/test_mount 2>/dev/null
        sudo cp /etc/hosts.backup /etc/hosts 2>/dev/null
        rm -rf /tmp/inode_attack /tmp/fs_test /tmp/test_mount 2>/dev/null
        rm -rf /tmp/heavy_logger /tmp/cron_chaos /tmp/race_condition 2>/dev/null
        rm -f /tmp/zombie_creator.sh /tmp/port_hog.* /tmp/swap_thrasher.* 2>/dev/null
        rm -f /tmp/module_tester.sh /tmp/module_errors.log /tmp/dns_tester.sh 2>/dev/null
        echo "Advanced scenarios cleaned up!"
        ;;
    0) echo "Happy troubleshooting!" ;;
    *) echo "Invalid choice" ;;
esac
EOF

# Make all scripts executable
chmod +x *.sh

echo "🚀 ADVANCED Linux Troubleshooting Scenarios Created!"
echo ""
echo "NEW FILES CREATED:"
echo "📁 Advanced Simulation Scripts:"
echo "- simulate_zombie_processes.sh      # Parent doesn't reap children"
echo "- simulate_inode_exhaustion.sh      # Too many small files"
echo "- simulate_filesystem_issues.sh     # Corrupted test filesystem"
echo "- simulate_log_rotation_issue.sh    # Runaway logging"
echo "- simulate_port_exhaustion.sh       # Opens too many ports"
echo "- simulate_kernel_module_issues.sh  # Module loading problems"
echo "- simulate_swap_thrashing.sh        # Memory pressure causing swapping"
echo "- simulate_dns_issues.sh            # DNS resolution problems"
echo "- simulate_cron_issues.sh           # Problematic cron jobs"
echo "- simulate_race_condition.sh        # Concurrent access issues"
echo ""
echo "📚 Advanced Guides:"
echo "- advanced_troubleshooting_guides.sh # Methodology for complex issues"
echo ""
echo "🎯 Master Control:"
echo "- run_advanced_scenarios.sh         # Interactive menu for advanced scenarios"
echo ""
echo "💡 WHAT'S NEW IN ADVANCED SCENARIOS:"
echo "✓ System-level issues (kernel modules, filesystems)"
echo "✓ Resource exhaustion (inodes, ports, memory)"
echo "✓ Race conditions and concurrency issues"
echo "✓ Service management problems (cron, logging)"
echo "✓ Network and DNS troubleshooting"
echo "✓ Performance analysis techniques"
echo ""
echo "🎪 HOW TO USE:"
echo "1. ./run_advanced_scenarios.sh      # Choose advanced scenarios (8-17)"
echo "2. Use previous script for basics:  # ./run_troubleshooting_scenarios.sh (1-7)"
echo "3. View advanced guides:            # bash advanced_troubleshooting_guides.sh <type>"
echo ""
echo "🔥 INTERVIEW POWER-UPS:"
echo "- Practice explaining complex system interactions"
echo "- Learn advanced debugging tools (lsof, strace, tcpdump)"
echo "- Understand kernel-level troubleshooting"
echo "- Master performance analysis methodology"