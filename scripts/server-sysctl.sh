#!/bin/bash
# Phantom Tunnel — Server kernel tuning for maximum throughput
# Run as root on the VPS: sudo bash scripts/server-sysctl.sh

set -e

cat >> /etc/sysctl.d/99-phantom-tunnel.conf << 'EOF'
# BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Large socket buffers (16MB max)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216

# Performance
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096

# Keepalive (belt-and-suspenders with app-level)
net.ipv4.tcp_keepalive_time = 15
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 3
EOF

sysctl --system
echo "Kernel tuning applied. Verify BBR:"
sysctl net.ipv4.tcp_congestion_control
