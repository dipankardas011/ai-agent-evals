FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install nginx, openssh-server, and utilities
RUN apt-get update && apt-get install -y \
    nginx \
    openssh-server \
    openssl \
    curl \
    procps \
    tmux \
    wget \
    && apt-get clean \
    && rm -rf '/var/lib/apt/lists/*'

# Install Go from official tarball
RUN wget -qO go.tar.gz https://go.dev/dl/go1.26.2.linux-amd64.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz

# Make Go available in all shells (SSH sessions, interactive, tmux, su, etc.)
RUN echo 'export PATH="/usr/local/go/bin:$PATH"' >> /root/.bashrc \
    && echo 'export GOPATH="/root/go"' >> /root/.bashrc \
    && echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/bash.bashrc \
    && echo 'PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' > /etc/environment

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

RUN useradd -m -s /bin/bash appuser

# Setup SSH server
RUN mkdir -p /run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Copy SSL certificates (intermediate CA is NOT included — must be obtained separately)
COPY certs/ca.crt /etc/nginx/certs/ca.crt
COPY certs/server.crt /etc/nginx/certs/server.crt
COPY certs/server.key /etc/nginx/certs/server.key

# Copy nginx config
RUN rm -f /etc/nginx/sites-enabled/default
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

# Copy Go application source
COPY app/ /app/src/
RUN chown -R root:root /app/src

# Copy authorized keys for SSH access from jumphost
COPY authorized_keys /app/authorized_keys

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 22 443 8080

CMD ["/entrypoint.sh"]
