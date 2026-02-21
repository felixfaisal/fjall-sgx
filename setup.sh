#!/bin/bash
# ============================================================
# setup.sh — One-command setup for SGX simulation on M1 Mac
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# What this does:
#   1. Builds a Docker image with Intel SGX SDK (simulation mode)
#   2. Runs the container and builds the hello-enclave project
#   3. Executes the demo
# ============================================================

set -e

YELLOW='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

echo -e "${CYAN}=== SGX Simulation Setup for M1 Mac ===${NC}"
echo ""

# --- Pre-flight checks ---
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker Desktop for Mac."
    echo "   https://www.docker.com/products/docker-desktop/"
    exit 1
fi

if ! docker info &> /dev/null 2>&1; then
    echo "❌ Docker daemon is not running. Please start Docker Desktop."
    exit 1
fi

echo -e "${GREEN}✓ Docker is available${NC}"

# --- Step 1: Build the Docker image ---
echo ""
echo -e "${YELLOW}Step 1: Building Docker image (this may take 5-10 minutes)...${NC}"
echo "  Image: sgx-sim (linux/amd64 on Rosetta 2)"
echo ""

cd "$(dirname "$0")/sgx-sdk-sim"
docker build --platform linux/amd64 -t sgx-sim . 2>&1 | tail -5

echo -e "${GREEN}✓ Docker image built${NC}"

# --- Step 2: Build and run inside container ---
echo ""
echo -e "${YELLOW}Step 2: Building and running hello-enclave inside container...${NC}"
echo ""

docker run --platform linux/amd64 --rm \
    -v "$(pwd)/projects:/root/projects" \
    sgx-sim \
    bash -c '
        source /opt/intel/sgxsdk/environment
        cd /root/projects/hello-enclave
        echo "--- Cleaning previous build ---"
        make clean 2>/dev/null || true
        echo ""
        echo "--- Building with SGX_MODE=SIM ---"
        make SGX_MODE=SIM
        echo ""
        echo "========================================="
        echo "  Running SGX Simulation Demo"
        echo "========================================="
        echo ""
        ./app
    '

echo ""
echo -e "${GREEN}=== Setup Complete! ===${NC}"
echo ""
echo "To enter the container interactively:"
echo -e "  ${CYAN}cd sgx-sdk-sim${NC}"
echo -e "  ${CYAN}docker run --platform linux/amd64 -it -v \$(pwd)/projects:/root/projects sgx-sim${NC}"
echo ""
echo "Inside the container:"
echo -e "  ${CYAN}cd /root/projects/hello-enclave${NC}"
echo -e "  ${CYAN}make SGX_MODE=SIM && ./app${NC}"
