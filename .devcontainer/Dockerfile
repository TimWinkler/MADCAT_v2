FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Build toolchain + MADCAT's own runtime/build dependencies (see README.md "1. Requirements")
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc cmake pkg-config git ca-certificates \
    clang libclang-rt-18-dev \
    libssl-dev libssl3 \
    libpcap0.8 libpcap-dev \
    liblua5.1-0 liblua5.1-0-dev \
    python3-dev python3-pip \
    conntrack \
    auditd audispd-plugins \
    net-tools iproute2 iptables sudo \
    gdb strace valgrind \
    hping3 nmap netcat-openbsd tcpdump python3-scapy \
    && rm -rf /var/lib/apt/lists/*

# psutil / luaparser are used by the Python postprocessors; Ubuntu 24.04 needs
# --break-system-packages since this is a disposable container, not a host install
RUN pip3 install --break-system-packages --no-cache-dir psutil luaparser

# ubuntu:24.04 already ships a uid/gid 1000 "ubuntu" user; drop it and
# recreate as "vscode" at the same 1000:1000 so it lines up with the typical
# host user and bind-mounted files stay writable.
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000
RUN userdel -r ubuntu \
    && groupadd -g ${USER_GID} ${USERNAME} \
    && useradd -m -s /bin/bash -u ${USER_UID} -g ${USER_GID} ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME}

USER ${USERNAME}
