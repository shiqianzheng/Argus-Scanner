# Base image for Argus sandbox
# Pre-installs common analysis tools to avoid per-run setup overhead.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install runtimes, compilers, and tracing tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3-distutils \
        gcc g++ make \
        openjdk-11-jdk-headless \
        golang-go \
        strace \
        ca-certificates curl wget git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create working directory and non-root user for isolation
RUN useradd -m sandbox && mkdir -p /app && chown -R sandbox:sandbox /app
WORKDIR /app
USER sandbox

# Keep container alive by default; sandbox.py will exec actual commands.
CMD ["tail", "-f", "/dev/null"]
