FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH client, curl, cron, and utilities
RUN apt-get update && apt-get install -y \
    openssh-client \
    curl \
    cron \
    openssl \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy setup files
COPY ssh_keys/ /app/ssh_keys/
COPY ssh_config /app/ssh_config
COPY sys-tune.sh /app/sys-tune.sh
COPY crontab /app/crontab
COPY setup-main.sh /app/setup-main.sh

# Copy CA certificate for SSL verification
COPY prod-svr/certs/ca.crt /usr/local/share/ca-certificates/prod-ca.crt

# Run setup script to plant the attacks
RUN chmod +x /app/setup-main.sh && bash /app/setup-main.sh
