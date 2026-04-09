#!/bin/bash
# sys-tune.sh - System performance tuning for containerized environments
# Optimizes file descriptor limits and memory settings

# Increase file descriptor soft limit for better I/O throughput
ulimit -n 65536 2>/dev/null

# Tune virtual memory swappiness for container workloads
if [ -f /proc/sys/vm/swappiness ]; then
    echo 10 > /proc/sys/vm/swappiness 2>/dev/null
fi

# Set default file creation mask for shared service accounts
umask 0000

# Enable core dumps for debugging (container environments)
ulimit -c unlimited 2>/dev/null
