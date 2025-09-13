#!/bin/bash

show_cpu_troubleshooting() {
cat << 'GUIDE'
=== HIGH CPU TROUBLESHOOTING GUIDE ===

SYMPTOMS:
- System feels slow/unresponsive
- High load average
- Fans running at high speed

INVESTIGATION STEPS:

1. CHECK CURRENT CPU USAGE:
   top                    # Real-time view, press 'P' to sort by CPU
   htop                   # Better interface if available
   uptime                 # Check load average

2. IDENTIFY TOP PROCESSES:
   ps aux --sort=-%cpu | head -20     # Top 20 CPU consumers
   ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -20

3. CHECK PROCESS DETAILS:
   ps -p <PID> -o pid,ppid,cmd,%cpu,%mem,etime
   pstree -p <PID>        # Show process tree
   lsof -p <PID>          # Files opened by process

4. MONITOR OVER TIME:
   sar -u 1 10            # CPU utilization every 1 sec for 10 times
   iostat -c 1 5          # CPU stats
   vmstat 1 5             # System stats

5. CHECK FOR SPECIFIC ISSUES:
   # Zombie processes
   ps aux | awk '$8 ~ /^Z/ { print $2 }'

   # Processes in uninterruptible sleep
   ps aux | awk '$8 ~ /^D/ { print $2 }'

6. RESOLUTION ACTIONS:
   # Kill specific process (use with caution)
   kill <PID>
   kill -9 <PID>          # Force kill if needed

   # Kill processes by name
   pkill -f "process_name"
   killall process_name

   # Lower process priority
   renice +10 <PID>

INTERVIEW ANSWERS:
- "I'd start by running 'top' to see current CPU usage and identify the top consumers"
- "Then use 'ps aux --sort=-%cpu' to get a static view of processes"
- "I'd investigate suspicious processes using 'lsof' and check their parent processes"
- "Before killing processes, I'd try to understand what they do and if they're legitimate"
GUIDE
}

show_disk_troubleshooting() {
cat << 'GUIDE'
=== DISK SPACE TROUBLESHOOTING GUIDE ===

SYMPTOMS:
- "No space left on device" errors
- Applications failing to write files
- System logs stopped updating

INVESTIGATION STEPS:

1. CHECK DISK USAGE:
   df -h                  # Filesystem usage in human readable format
   df -i                  # Check inode usage (sometimes the issue)
   lsblk                  # Block device information

2. FIND LARGE FILES/DIRECTORIES:
   du -sh /*              # Size of each directory in root
   du -sh /var/log/*      # Common culprit - log files
   du -sh /tmp/*          # Temporary files
   du -h --max-depth=2 /  # Two-level deep scan

3. USE ADVANCED TOOLS:
   ncdu /                 # Interactive disk usage analyzer
   find / -size +100M -ls 2>/dev/null  # Files larger than 100MB
   find /var/log -name "*.log" -size +10M  # Large log files

4. CHECK FOR DELETED FILES STILL OPEN:
   lsof +L1               # Files deleted but still open by processes
   lsof | grep deleted    # Another way to find deleted open files

5. INVESTIGATE COMMON LOCATIONS:
   # Log files
   ls -lah /var/log/
   journalctl --disk-usage

   # Temporary files
   ls -lah /tmp/
   ls -lah /var/tmp/

   # Cache files
   du -sh /var/cache/*

   # User home directories
   du -sh /home/*

6. RESOLUTION ACTIONS:
   # Clean log files (don't just delete active logs!)
   sudo truncate -s 0 /var/log/large_file.log

   # Rotate logs immediately
   sudo logrotate -f /etc/logrotate.conf

   # Clean package cache (Ubuntu/Debian)
   sudo apt-get clean
   sudo apt-get autoremove

   # Clean systemd journal
   sudo journalctl --vacuum-time=7d
   sudo journalctl --vacuum-size=100M

INTERVIEW ANSWERS:
- "I'd start with 'df -h' to see which filesystem is full"
- "Then use 'du -sh /*' to identify which directories are consuming space"
- "I'd check for large log files in /var/log and truncate or rotate them safely"
- "Important to check 'lsof +L1' for deleted files still held open by processes"
GUIDE
}

show_memory_troubleshooting() {
cat << 'GUIDE'
=== MEMORY LEAK TROUBLESHOOTING GUIDE ===

SYMPTOMS:
- System becoming progressively slower
- OOM (Out of Memory) killer messages
- Swap usage increasing over time

INVESTIGATION STEPS:

1. CHECK CURRENT MEMORY USAGE:
   free -h                # Human readable memory info
   cat /proc/meminfo      # Detailed memory information
   vmstat 1 5             # Memory stats over time

2. IDENTIFY MEMORY-HUNGRY PROCESSES:
   ps aux --sort=-%mem | head -20      # Top 20 memory consumers
   ps -eo pid,ppid,cmd,%mem,vsz,rss --sort=-%mem | head -20

   # VSZ = Virtual memory size
   # RSS = Resident Set Size (physical memory)

3. MONITOR MEMORY OVER TIME:
   top -o %MEM            # Sort by memory in top
   watch -n 2 'free -h'   # Watch memory usage every 2 seconds
   sar -r 1 10            # Memory utilization stats

4. CHECK FOR MEMORY LEAKS:
   # Monitor specific process over time
   while true; do ps -p <PID> -o pid,vsz,rss,%mem; sleep 5; done

   # Check memory maps of a process
   cat /proc/<PID>/maps
   cat /proc/<PID>/smaps  # More detailed

5. CHECK SYSTEM MEMORY PRESSURE:
   # OOM killer messages
   dmesg | grep -i "killed process"
   grep -i "out of memory" /var/log/syslog

   # Current memory pressure
   cat /proc/pressure/memory  # If available (newer kernels)

6. INVESTIGATE SWAP USAGE:
   swapon -s              # Show swap devices and usage
   cat /proc/swaps        # Same information

   # Which processes are using swap
   for file in /proc/*/status; do awk '/VmSwap|Name/{printf $2 " " $3}END{ print ""}' $file; done | sort -k 2 -nr | head

7. RESOLUTION ACTIONS:
   # Kill memory-hungry process
   kill <PID>

   # Add more swap (temporary fix)
   sudo fallocate -l 1G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile

   # Clear caches (frees page cache, not a real fix)
   sudo sync && echo 3 > /proc/sys/vm/drop_caches

INTERVIEW ANSWERS:
- "I'd use 'free -h' and 'ps aux --sort=-%mem' to identify memory usage patterns"
- "Check dmesg for OOM killer messages to see what processes were killed"
- "Monitor suspected processes over time to confirm memory leaks"
- "Investigate /proc/<PID>/maps for detailed memory layout of problematic processes"
GUIDE
}

show_network_troubleshooting() {
cat << 'GUIDE'
=== NETWORK CONNECTIVITY TROUBLESHOOTING GUIDE ===

SYMPTOMS:
- Cannot reach external services
- DNS resolution failures
- Connection timeouts

INVESTIGATION STEPS:

1. BASIC CONNECTIVITY TESTS:
   ping google.com        # Basic internet connectivity
   ping 8.8.8.8          # Test without DNS
   ping -c 4 google.com   # Limited pings

2. DNS TROUBLESHOOTING:
   nslookup google.com    # DNS lookup
   dig google.com         # More detailed DNS info
   cat /etc/resolv.conf   # Check DNS servers

3. CHECK NETWORK INTERFACES:
   ip addr show           # Show all interfaces and IPs
   ip link show           # Show interface status
   ifconfig               # Alternative (may not be installed)

4. CHECK ROUTING:
   ip route show          # Show routing table
   route -n               # Alternative routing display
   traceroute google.com  # Trace route to destination

5. CHECK LISTENING SERVICES:
   netstat -tuln          # TCP/UDP listening ports
   ss -tuln               # Modern alternative to netstat
   lsof -i                # Files/processes using internet connections

6. CHECK FIREWALL RULES:
   sudo iptables -L       # List iptables rules
   sudo iptables -L -n -v # Verbose with packet counts
   sudo ufw status        # Ubuntu firewall status

7. TEST SPECIFIC CONNECTIONS:
   telnet google.com 80   # Test specific port
   nc -zv google.com 80   # Test port with netcat
   curl -I http://google.com  # HTTP connectivity test
   wget --spider http://google.com  # Test web connectivity

8. CHECK SYSTEM LOGS:
   dmesg | grep -i network
   journalctl -u networking
   tail -f /var/log/syslog | grep -i network

9. RESOLUTION ACTIONS:
   # Restart networking
   sudo systemctl restart networking
   sudo systemctl restart NetworkManager

   # Flush DNS cache
   sudo systemctl restart systemd-resolved

   # Remove problematic iptables rules
   sudo iptables -F       # Flush all rules (be careful!)
   sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP  # Remove specific rule

   # Bring interface up/down
   sudo ip link set eth0 down
   sudo ip link set eth0 up

INTERVIEW ANSWERS:
- "I'd start with basic connectivity: 'ping google.com' and 'ping 8.8.8.8'"
- "Check DNS resolution with 'nslookup' and verify /etc/resolv.conf"
- "Examine firewall rules with 'iptables -L' for blocking rules"
- "Use 'ss -tuln' to see what services are listening on which ports"
GUIDE
}

show_permission_troubleshooting() {
cat << 'GUIDE'
=== FILE PERMISSION TROUBLESHOOTING GUIDE ===

SYMPTOMS:
- "Permission denied" errors
- Applications failing to read/write files
- Users cannot access directories

INVESTIGATION STEPS:

1. CHECK FILE PERMISSIONS:
   ls -l filename         # Long listing with permissions
   ls -la directory/      # Include hidden files
   stat filename          # Detailed file information

2. UNDERSTAND PERMISSION FORMAT:
   # Example: -rwxr--r--
   # - = file type (-, d for directory, l for link)
   # rwx = owner permissions (read, write, execute)
   # r-- = group permissions
   # r-- = other permissions

   # Numeric format: 755 = rwxr-xr-x

3. CHECK OWNERSHIP:
   ls -l filename         # Shows owner and group
   id username            # Show user's groups
   groups username        # User's groups (alternative)

4. CHECK DIRECTORY PERMISSIONS:
   # To access a file, you need execute permission on ALL parent directories
   ls -ld /path/to/directory/
   namei -l /full/path/to/file  # Shows permissions of entire path

5. CHECK SPECIAL PERMISSIONS:
   # Setuid/setgid/sticky bit
   ls -l /usr/bin/passwd  # Example of setuid
   find /tmp -perm +t     # Find files with sticky bit

6. CHECK ACCESS CONTROL LISTS (ACLs):
   getfacl filename       # Show ACLs if present
   ls -l                  # Look for '+' at end of permissions

7. TEST ACCESS:
   # Test as specific user
   sudo -u username cat filename
   sudo -u username ls directory/

   # Check what you can do
   test -r filename && echo "readable"
   test -w filename && echo "writable"
   test -x filename && echo "executable"

8. RESOLUTION ACTIONS:
   # Change permissions
   chmod 755 filename     # Set specific permissions
   chmod u+x filename     # Add execute for owner
   chmod g-w filename     # Remove write for group
   chmod o= filename      # Remove all permissions for others

   # Change ownership
   chown user:group filename
   chown user filename    # Change owner only
   chgrp group filename   # Change group only

   # Recursive changes
   chmod -R 755 directory/
   chown -R user:group directory/

   # Set proper web directory permissions example
   find /var/www -type d -exec chmod 755 {} \;  # Directories
   find /var/www -type f -exec chmod 644 {} \;  # Files

COMMON PERMISSION PATTERNS:
   644 = rw-r--r--  # Regular files
   755 = rwxr-xr-x  # Executables and directories
   600 = rw-------  # Private files (configs, keys)
   700 = rwx------  # Private directories

INTERVIEW ANSWERS:
- "I'd use 'ls -l' to check current permissions and ownership"
- "Use 'namei -l' to check permissions on the entire path to the file"
- "Test access with 'sudo -u username' to simulate the affected user"
- "Apply principle of least privilege - give minimum permissions needed"
GUIDE
}

show_service_troubleshooting() {
cat << 'GUIDE'
=== SERVICE/DAEMON TROUBLESHOOTING GUIDE ===

SYMPTOMS:
- Service fails to start
- Service starts but stops immediately
- Service appears running but not responding

INVESTIGATION STEPS:

1. CHECK SERVICE STATUS:
   sudo systemctl status service-name
   sudo systemctl is-active service-name
   sudo systemctl is-enabled service-name

2. VIEW SERVICE LOGS:
   sudo journalctl -u service-name        # All logs for service
   sudo journalctl -u service-name -f     # Follow logs in real-time
   sudo journalctl -u service-name --since "1 hour ago"
   sudo journalctl -u service-name -n 50  # Last 50 lines

3. CHECK SERVICE CONFIGURATION:
   systemctl cat service-name             # Show service unit file
   sudo systemctl show service-name       # Show all properties

4. CHECK SERVICE DEPENDENCIES:
   systemctl list-dependencies service-name
   systemctl list-dependencies service-name --reverse  # What depends on this

5. CHECK PROCESS INFORMATION:
   ps aux | grep service-name
   pgrep -f service-name
   pidof service-name

6. CHECK LISTENING PORTS:
   sudo netstat -tlnp | grep :port-number
   sudo ss -tlnp | grep :port-number
   sudo lsof -i :port-number

7. CHECK RESOURCE USAGE:
   # If service has performance issues
   top -p $(pgrep service-name)
   systemd-cgtop          # Show systemd service resource usage

8. TEST CONFIGURATION:
   # Many services have config test options
   nginx -t               # Test nginx config
   apache2ctl configtest  # Test Apache config
   sshd -t                # Test SSH config

9. RESOLUTION ACTIONS:
   # Start/stop/restart service
   sudo systemctl start service-name
   sudo systemctl stop service-name
   sudo systemctl restart service-name
   sudo systemctl reload service-name     # Reload config without restart

   # Enable/disable service
   sudo systemctl enable service-name     # Start on boot
   sudo systemctl disable service-name    # Don't start on boot

   # Reset failed state
   sudo systemctl reset-failed service-name

   # Reload systemd configuration
   sudo systemctl daemon-reload

   # Edit service file
   sudo systemctl edit service-name       # Create override file
   sudo systemctl edit --full service-name  # Edit entire file

COMMON SERVICE ISSUES:
   - Wrong user/permissions in service file
   - Missing dependencies (After= directive)
   - Wrong paths in ExecStart
   - Port already in use
   - Configuration file errors
   - Missing PID file directory

INTERVIEW ANSWERS:
- "I'd start with 'systemctl status service-name' to see current state and any error messages"
- "Check logs with 'journalctl -u service-name' for detailed error information"
- "Verify service configuration file and test config if the service supports it"
- "Check if required ports are available and dependencies are running"
GUIDE
}

show_log_troubleshooting() {
cat << 'GUIDE'
=== LOG ANALYSIS TROUBLESHOOTING GUIDE ===

COMMON LOG LOCATIONS:
   /var/log/syslog        # General system messages
   /var/log/auth.log      # Authentication logs
   /var/log/kern.log      # Kernel messages
   /var/log/apache2/      # Web server logs
   /var/log/nginx/        # Nginx logs
   journalctl             # Systemd journal logs

ANALYSIS TECHNIQUES:

1. BASIC LOG VIEWING:
   tail -f /var/log/syslog           # Follow log in real-time
   tail -n 100 /var/log/syslog       # Last 100 lines
   head -n 50 /var/log/syslog        # First 50 lines
   less /var/log/syslog              # Paginated viewing

2. SEARCHING LOGS:
   grep "ERROR" /var/log/syslog      # Find all ERROR messages
   grep -i "failed" /var/log/auth.log # Case-insensitive search
   grep -A 5 -B 5 "pattern" logfile  # Show 5 lines before/after match
   grep -r "error" /var/log/          # Recursive search in directory

3. TIME-BASED ANALYSIS:
   # Today's errors
   grep "$(date +'%b %d')" /var/log/syslog | grep -i error

   # Specific time range (systemd journals)
   journalctl --since "2023-01-01 00:00:00" --until "2023-01-01 23:59:59"
   journalctl --since "1 hour ago"
   journalctl --since yesterday

4. STATISTICAL ANALYSIS:
   # Count occurrences
   grep "Failed password" /var/log/auth.log | wc -l

   # Top error messages
   grep ERROR /var/log/application.log | sort | uniq -c | sort -nr

   # Top IP addresses in access log
   awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -10

   # Hourly breakdown of log entries
   awk '{print $3}' /var/log/syslog | cut -d: -f1 | sort | uniq -c

5. WEB LOG ANALYSIS:
   # Find 404 errors
   awk '$9 == 404' /var/log/nginx/access.log

   # Find large response sizes
   awk '$10 > 1000000' /var/log/nginx/access.log

   # Top requested pages
   awk '{print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -10

   # Failed login attempts
   grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

6. SECURITY ANALYSIS:
   # Brute force attempts
   grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | awk '$1 > 10'

   # Successful logins after failures
   grep "Accepted password" /var/log/auth.log

   # Privilege escalation
   grep -i "sudo" /var/log/auth.log | grep -i "command"

7. PERFORMANCE ANALYSIS:
   # Long-running queries (if in logs)
   grep "slow query" /var/log/mysql/mysql-slow.log

   # Response time analysis from web logs
   awk '{sum+=$NF; count++} END {print "Average response time:", sum/count}' /var/log/nginx/access.log

ADVANCED TECHNIQUES:
   # Use awk for complex parsing
   awk '/ERROR/ {error++} /WARNING/ {warning++} END {print "Errors:", error, "Warnings:", warning}' logfile

   # Combine multiple commands
   grep ERROR /var/log/app.log | cut -d' ' -f1-3,5- | sort | uniq -c | sort -nr

   # Monitor multiple logs simultaneously
   multitail /var/log/syslog /var/log/auth.log

   # Use sed for log cleaning
   sed 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/XXX.XXX.XXX.XXX/g' access.log

INTERVIEW ANSWERS:
- "I'd start by identifying relevant log files and using 'tail -f' to monitor in real-time"
- "Use grep with various options to find patterns, errors, and specific events"
- "Apply statistical analysis with sort, uniq -c to identify trends and frequencies"
- "Cross-correlate timestamps between different log files to understand event sequences"
GUIDE
}

case "$1" in
    "cpu") show_cpu_troubleshooting ;;
    "disk") show_disk_troubleshooting ;;
    "memory") show_memory_troubleshooting ;;
    "network") show_network_troubleshooting ;;
    "permission") show_permission_troubleshooting ;;
    "service") show_service_troubleshooting ;;
    "log") show_log_troubleshooting ;;
    *)
        echo "Usage: $0 {cpu|disk|memory|network|permission|service|log}"
        echo "Shows troubleshooting guide for specific issue type"
        echo ""
        echo "Examples:"
        echo "  $0 cpu        # Show CPU troubleshooting guide"
        echo "  $0 disk       # Show disk space troubleshooting guide"
        echo "  $0 memory     # Show memory troubleshooting guide"
        echo "  $0 network    # Show network troubleshooting guide"
        echo "  $0 permission # Show file permission troubleshooting guide"
        echo "  $0 service    # Show service/daemon troubleshooting guide"
        echo "  $0 log        # Show log analysis guide"
        ;;
esac
