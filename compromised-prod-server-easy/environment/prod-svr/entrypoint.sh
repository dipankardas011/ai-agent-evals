#!/bin/bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh
cp /app/authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
/usr/sbin/sshd
nginx 2>/dev/null
sleep infinity
