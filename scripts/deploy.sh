#!/usr/bin/env bash
# ==============================================================================
# Stateful Application-Layer Firewall & Intrusion Filter - Deployment Script
# Author: Ayush Behera
# Target: Linux (Ubuntu/Debian/RHEL/CentOS/Fedora) & macOS (Simulation/Test Mode)
# ==============================================================================

set -eo pipefail

QUEUE_NUM="${1:-0}"
RULES_FILE="${2:-rules/default_rules.conf}"
LOG_FILE="${3:-firewall.log}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OS_TYPE="$(uname -s)"

echo "===================================================================="
echo " Stateful Application-Layer Firewall & Intrusion Filter Deployer"
echo " Author: Ayush Behera"
echo " Operating System: ${OS_TYPE}"
echo " Target Queue: NFQUEUE #${QUEUE_NUM}"
echo "===================================================================="

# 1. OS-Specific Setup and Privilege Check
if [[ "${OS_TYPE}" == "Linux" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "[!] Error: Root privileges are required on Linux to configure Netfilter queues and iptables."
        echo "    Please run with sudo: sudo $0 [queue_num] [rules_file]"
        exit 1
    fi

    echo "[*] Detecting Linux package manager and installing dependencies..."
    if command -v apt-get &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq build-essential cmake pkg-config \
                               libnetfilter-queue-dev libnfnetlink-dev iptables
    elif command -v dnf &>/dev/null; then
        dnf install -y gcc-c++ make cmake pkgconf-pkg-config \
                        libnetfilter_queue-devel libnfnetlink-devel iptables
    elif command -v yum &>/dev/null; then
        yum install -y gcc-c++ make cmake \
                       libnetfilter_queue-devel libnfnetlink-devel iptables
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm base-devel cmake libnetfilter_queue libnfnetlink iptables
    else
        echo "[!] Warning: Unknown package manager. Please ensure cmake/gcc and libnetfilter-queue-dev are installed."
    fi
else
    echo "[*] Running on ${OS_TYPE}."
    echo "    Note: Netfilter (NFQUEUE & iptables) is a Linux kernel subsystem."
    echo "    The firewall daemon will run in local simulation and verification mode."
fi

# 2. Select Compiler
CXX_COMPILER=""
if command -v clang++ &>/dev/null; then
    CXX_COMPILER="clang++"
elif command -v g++ &>/dev/null; then
    CXX_COMPILER="g++"
fi

# 3. Compile Project
cd "${PROJECT_ROOT}"
mkdir -p "${PROJECT_ROOT}/bin"

if command -v cmake &>/dev/null; then
    echo "[*] Compiling firewall daemon using CMake..."
    mkdir -p build
    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
elif [[ -n "${CXX_COMPILER}" ]]; then
    echo "[*] CMake not found. Compiling directly using ${CXX_COMPILER} (-std=c++17 -O3)..."
    
    # Netfilter link flags on Linux
    NETFILTER_FLAGS=""
    if [[ "${OS_TYPE}" == "Linux" ]]; then
        NETFILTER_FLAGS="-lnetfilter_queue -lnfnetlink"
    fi

    ${CXX_COMPILER} -std=c++17 -Wall -Wextra -pedantic -O3 -Iinclude \
        src/Protocol.cpp \
        src/Logger.cpp \
        src/ConntrackTable.cpp \
        src/Inspector.cpp \
        src/Interceptor.cpp \
        src/FirewallDaemon.cpp \
        src/main.cpp \
        -o bin/stateful_firewall -pthread ${NETFILTER_FLAGS}

    ${CXX_COMPILER} -std=c++17 -Wall -Wextra -pedantic -O3 -Iinclude \
        src/Protocol.cpp \
        src/Logger.cpp \
        src/ConntrackTable.cpp \
        src/Inspector.cpp \
        src/Interceptor.cpp \
        src/FirewallDaemon.cpp \
        tests/test_firewall.cpp \
        -o bin/firewall_tests -pthread ${NETFILTER_FLAGS}
else
    echo "[!] Error: Neither CMake nor a suitable C++17 compiler (clang++ / g++) was found."
    exit 1
fi

FIREWALL_BIN="${PROJECT_ROOT}/bin/stateful_firewall"
if [[ ! -f "${FIREWALL_BIN}" ]]; then
    echo "[!] Build failed: binary not found at ${FIREWALL_BIN}"
    exit 1
fi
echo "[+] Compilation successful: ${FIREWALL_BIN}"

# 4. Optional iptables NFQUEUE Hooks (Linux Only)
if [[ "${OS_TYPE}" == "Linux" ]] && command -v iptables &>/dev/null; then
    cleanup() {
        echo -e "\n[*] Restoring iptables and detaching from Netfilter queues..."
        iptables -D INPUT -p tcp -j NFQUEUE --queue-num "${QUEUE_NUM}" 2>/dev/null || true
        iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num "${QUEUE_NUM}" 2>/dev/null || true
        iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num "${QUEUE_NUM}" 2>/dev/null || true
        echo "[+] iptables NFQUEUE rules detached successfully."
    }
    trap cleanup EXIT INT TERM

    echo "[*] Attaching iptables rules to NFQUEUE #${QUEUE_NUM}..."
    iptables -I INPUT -p tcp -j NFQUEUE --queue-num "${QUEUE_NUM}"
    iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num "${QUEUE_NUM}"
    iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num "${QUEUE_NUM}"
    echo "[+] iptables successfully redirected traffic to queue #${QUEUE_NUM}."
fi

echo "[*] Launching Stateful Firewall Daemon..."
echo "--------------------------------------------------------------------"

# 5. Execute Daemon
"${FIREWALL_BIN}" \
    --queue-num "${QUEUE_NUM}" \
    --rules "${RULES_FILE}" \
    --log-file "${LOG_FILE}" \
    --log-level INFO
