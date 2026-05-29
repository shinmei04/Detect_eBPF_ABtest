#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y \
  mininet \
  openvswitch-switch \
  iperf3 \
  tcpdump \
  python3-venv \
  python3-pip \
  git

sudo service openvswitch-switch start || true
