#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

apt update
apt install -y --no-install-recommends \
    apt-utils \
    software-properties-common \
    curl \
    wget \
    gnupg \
    lsb-release \
    vim \
    nano \
    less \
    net-tools \
    iputils-ping \
    htop \
    iftop \
    iotop \
    dstat \
    sysstat \
    strace \
    lsof \
    tcpdump \
    traceroute \
    ltrace \
    bpfcc-tools \
    perf-tools-unstable \
    linux-tools-common \
    linux-tools-generic \
    procps \
    util-linux \
    iproute2 \
    psmisc \
    gdb \
    man-db \
    tldr \
    sar \
    cpuinfo \
    meminfo \
    diskstats \
    stat

unset DEBIAN_FRONTEND