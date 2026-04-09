#!/bin/bash

# Setup SSH authorized keys
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cp /app/authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Start SSH daemon
/usr/sbin/sshd

# Start nginx (will fail due to config errors - agent must fix)
nginx || echo "nginx failed to start — config errors need fixing"

# Keep container alive
sleep infinity
