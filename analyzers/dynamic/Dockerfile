# Base image for Argus sandbox
# Pre-installs common analysis tools and multi-language runtimes to avoid per-run setup overhead.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install runtimes, compilers, build tools, and tracing tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Python runtime and tools
        python3 python3-venv python3-pip python3-distutils \
        # C/C++ compilers and build tools
        gcc g++ make cmake build-essential \
        # Java runtime and Maven (for Java projects)
        openjdk-11-jdk-headless \
        maven \
        # Go runtime
        golang-go \
        # System tools and tracing
        strace \
        ca-certificates curl wget git \
        # Additional utilities
        file binutils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create working directory and non-root user for isolation
RUN useradd -m sandbox && mkdir -p /app && chown -R sandbox:sandbox /app
WORKDIR /app
USER sandbox

# Keep container alive by default; sandbox.py will exec actual commands.
CMD ["tail", "-f", "/dev/null"]
