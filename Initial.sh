#!/bin/bash
# Network Activity Monitor & Report Generator
# Author: System Analyst
# Version: 1.2
# Purpose: Comprehensive network and process monitoring with HTML reporting

set -euo pipefail  # Strict mode: exit on error, undefined vars, pipe failures

# Configuration
REPORT_DIR="/var/log/netmonitor"
HTML_REPORT="$REPORT_DIR/network_report_$(date +%Y%m%d_%H%M%S).html"
MAX_CONNECTIONS=1000
SUSPICIOUS_PORTS="22 80 443 3389"  # Common target ports
LOG_FILE="$REPORT_DIR/monitor.log"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # No Color

# Create report directory
mkdir -p "$REPORT_DIR"

log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script requires root privileges"
        exit 1
    fi
}

gather_system_info() {
    log_message "INFO" "Gathering system information..."

    cat > "$REPORT_DIR/system_info.txt" << EOF
Hostname: $(hostname)
Kernel: $(uname -r)
Architecture: $(uname -m)
Uptime: $(uptime -p)
Current User: $(whoami)
Date: $(date)
EOF
}

analyze_network_connections() {
    log_message "INFO" "Analyzing network connections..."

    # Get TCP connections by state
    netstat -tunap 2>/dev/null | grep -v "Active Internet" | awk '
    BEGIN {
        print "State,Count"
    }
    /tcp/ {
        split($6, a, ":")
        state = a[1]
        states[state]++
    }
    END {
        for (s in states) print s "," states[s]
    }' > "$REPORT_DIR/tcp_states.csv"

    # Top remote IPs by connection count
    ss -tun state established | awk 'NR>1 {print $5}' | cut -d":" -f1 | sort | uniq -c | sort -nr > "$REPORT_DIR/top_remote_ips.txt"

    # Check for excessive connections
    TOTAL_CONNS=$(ss -tun | grep -c ESTABLISHED)
    if (( TOTAL_CONNS > MAX_CONNECTIONS )); then
        log_message "WARNING" "High connection count: $TOTAL_CONNS (threshold: $MAX_CONNECTIONS)"
    fi
}

detect_suspicious_processes() {
    log_message "INFO" "Detecting suspicious processes..."

    ps auxww --sort=-%cpu | head -20 > "$REPORT_DIR/top_processes.txt"

    # Look for processes listening on network
    suspicious_pids=()
    while IFS= read -r line; do
        pid=$(echo "$line" | awk '{print $2}')
        process=$(echo "$line" | awk '{print $11}')

        # Check if process is listening on suspicious ports
        if lsof -p "$pid" -i -P -n 2>/dev/null | grep -qE "(:$(echo $SUSPICIOUS_PORTS | tr ' ' '|'))"; then
            suspicious_pids+=("$pid:$process")
            log_message "ALERT" "Suspicious process detected: PID $pid ($process) on critical port"
        fi
    done < <(ps -eo pid,comm --no-headers)

    printf '%s
' "${suspicious_pids[@]}" > "$REPORT_DIR/suspicious_processes.txt"
}

monitor_bandwidth() {
    log_message "INFO" "Monitoring bandwidth usage..."

    # Use iftop if available, otherwise use ip -s link
    if command -v iftop &> /dev/null; then
        timeout 30s iftop -t -L 10 -s 5 > "$REPORT_DIR/bandwidth_snapshot.txt" 2>&1 || true
    else
        ip -s link > "$REPORT_DIR/interface_stats.txt"
    fi
}

generate_html_report() {
    log_message "INFO" "Generating HTML report..."

    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Activity Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .warning { color: orange; font-weight: bold; }
        .alert { color: red; font-weight: bold; }
        pre { background: #eee; padding: 10px; border-radius: 4px; overflow: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Activity Report</h1>
        <p><strong>Generated:</strong> $(date)</p>

        <h2>System Information</h2>
        <pre>$(cat "$REPORT_DIR/system_info.txt")</pre>

        <h2>TCP Connection States</h2>
        <table>
            <thead><tr><th>State</th><th>Count</th></tr></thead>
            <tbody>
                $(tail -n +2 "$REPORT_DIR/tcp_states.csv" | while IFS=, read -r state count; do
                    echo "<tr><td>$state</td><td>$count</td></tr>"
        done)
            </tbody>
        </table>

        <h2>Top Remote IPs by Connection Count</h2>
        <pre>$(head -10 "$REPORT_DIR/top_remote_ips.txt")</pre>

        <h2>Suspicious Processes</h2>
        $(if [ -s "$REPORT_DIR/suspicious_processes.txt" ]; then
            echo '<div class="alert">Suspicious processes detected!</div>'
            echo '<pre>$(cat "$REPORT_DIR/suspicious_processes.txt")</pre>'
        else
            echo '<p>No suspicious processes found.</p>'
        fi)

        <h2>Top CPU-Intensive Processes</h2>
        <pre>$(head -15 "$REPORT_DIR/top_processes.txt")</pre>

        <h2>Bandwidth Monitoring Snapshot</h2>
        <pre>$(head -20 "$REPORT_DIR/bandwidth_snapshot.txt")</pre>
    </div>
</body>
</html>
EOF

    log_message "SUCCESS" "HTML report generated: $HTML_REPORT"
}

cleanup() {
    log_message "INFO" "Cleaning up temporary files..."
    find "$REPORT_DIR" -name "*.tmp" -delete
    log_message "SUCCESS" "Cleanup completed"
}

main() {
    log_message "START" "Network monitoring script started"

    check_root
    gather_system_info
    analyze_network_connections
    detect_suspicious_processes
    monitor_bandwidth
