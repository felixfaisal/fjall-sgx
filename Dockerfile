FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SGX_SDK=/opt/intel/sgxsdk

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    curl \
    git \
    pkg-config \
    libssl-dev \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    protobuf-compiler \
    python3 \
    cmake \
    ocaml \
    ocamlbuild \
    automake \
    autoconf \
    libtool \
    gdb \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Download and install Intel SGX SDK 2.24 (simulation mode only - no driver/PSW needed)
# The SDK includes simulation libraries that mock SGX instructions
WORKDIR /tmp
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.24/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.24.100.3.bin \
    -O sgx_sdk.bin \
    && chmod +x sgx_sdk.bin \
    && echo "yes" | ./sgx_sdk.bin --prefix=/opt/intel \
    && rm sgx_sdk.bin

# Source the SGX SDK environment on every shell
RUN echo 'source /opt/intel/sgxsdk/environment' >> /root/.bashrc

WORKDIR /root/projects
CMD ["/bin/bash"]
