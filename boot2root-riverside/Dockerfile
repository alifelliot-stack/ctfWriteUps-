# Boot2root target: "Riverside Corp Intranet"
# Build:  docker build -t riverside-b2r .
# Run:    docker run --rm -d -p 2222:22 -p 8080:80 --name riverside riverside-b2r
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        apache2 \
        php \
        libapache2-mod-php \
        sudo \
        net-tools \
        iproute2 \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# --- sshd ---
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && ssh-keygen -A

# --- low-privilege user, password intentionally reused from the DB config below ---
RUN useradd -m -s /bin/bash bob \
    && echo 'bob:Sp1llway#2024' | chpasswd

# --- flags ---
RUN echo 'flag{us3r_cr3ds_h1d1ng_1n_a_.bak_f1l3}' > /home/bob/user.txt \
    && chown bob:bob /home/bob/user.txt && chmod 600 /home/bob/user.txt
RUN echo 'flag{w1ldc4rd_t4r_g0t_m3_r00t}' > /root/root.txt \
    && chmod 600 /root/root.txt

# --- vulnerable web app (unrestricted file upload -> RCE as www-data) ---
COPY webapp/ /var/www/html/
RUN mkdir -p /var/www/html/uploads \
    && chown -R www-data:www-data /var/www/html \
    && chmod 755 /var/www/html/uploads

# --- credential leak: a config backup outside the web root, readable by
#     any local user (including www-data after the RCE), containing the
#     password bob's account was set up with and never rotated ---
RUN mkdir -p /var/backups
COPY backup/webapp_config.php.bak /var/backups/webapp_config.php.bak
RUN chmod 644 /var/backups/webapp_config.php.bak

# --- privilege escalation: bob can run a backup script as root via sudo,
#     and the script's use of a shell-expanded wildcard with tar is
#     exploitable (GTFOBins tar wildcard injection) ---
RUN mkdir -p /home/bob/app_logs /root/backups \
    && chown bob:bob /home/bob/app_logs
COPY scripts/log_cleanup.sh /opt/scripts/log_cleanup.sh
RUN chmod 755 /opt/scripts/log_cleanup.sh \
    && echo 'bob ALL=(root) NOPASSWD: /opt/scripts/log_cleanup.sh' > /etc/sudoers.d/bob-log-cleanup \
    && chmod 440 /etc/sudoers.d/bob-log-cleanup

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80
CMD ["/entrypoint.sh"]
