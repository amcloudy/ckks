FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CMAKE_VERSION=3.26.0

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    gcc \
    git \
    libssl-dev \
    libomp-dev \
    libyaml-cpp-dev \
    zlib1g-dev \
    wget \
    unzip \
    vim \
    python3 \
    python3-pip \
    curl \
    ca-certificates \
    gdb \
    pkg-config \
    procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install numpy pandas matplotlib seaborn

# Install CMake from source
RUN wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}.tar.gz && \
    tar -xzf cmake-${CMAKE_VERSION}.tar.gz && \
    cd cmake-${CMAKE_VERSION} && \
    ./bootstrap && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf cmake-${CMAKE_VERSION}*

# Set workspace
WORKDIR /workspace

CMD ["bash"]
