FROM debian:13

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y ca-certificates iproute2 iptables golang tcpdump vim \
                       python3 python3-pip python3-django sqlite3 sudo && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash unpriv

RUN printf "unpriv ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-nft, /usr/sbin/iptables-save, /usr/sbin/iptables-restore\n" \
      > /etc/sudoers.d/pr0cks && chmod 440 /etc/sudoers.d/pr0cks

WORKDIR /app
COPY --chown=unpriv:unpriv QubesOS/ /app/
RUN mkdir -p /app/db && chown -R unpriv:unpriv /app

USER unpriv

RUN go install github.com/n1nj4sec/pr0cks@latest
RUN chmod +x /home/unpriv/go/bin/pr0cks
RUN pip3 install --break-system-packages gunicorn

ENV PATH="$PATH:/home/unpriv/.local/bin/"
