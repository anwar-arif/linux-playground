# Use the official Ubuntu LTS image as the base image
FROM ubuntu:24.04

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install necessary packages
RUN apt update && \
    apt install -y --no-install-recommends \
    apt-utils \
    software-properties-common \
    curl \
    wget \
    gnupg \
    lsb-release

# Install basic utilities and crisis tools
RUN apt update && apt install -y --no-install-recommends \
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
    man-db

# Clean up to reduce image size
RUN apt clean && \
    rm -rf /var/lib/apt/lists/*

# Set the entrypoint to bash
ENTRYPOINT ["/bin/bash"]

# Command to run when the container starts
# CMD ["/bin/bash"]
