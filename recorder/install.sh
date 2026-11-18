#!/bin/bash
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
#
# Installs the recorder on Raspberry Pi OS or Debian 12/13 (arm64 or amd64). Run as root:
#   sudo ./install.sh <capture interface> [<capture interface> ...]
# Example: sudo ./install.sh eth1 eth2
#
# What it does:
#   - installs Zeek 8.0 (LTS) from the Zeek project's package repository, and the recorder
#   - makes the capture interfaces receive-only (no address, no ARP, no IPv6, every outgoing frame dropped)
#   - keeps raw logs in RAM only (tmpfs) and switches disk swap off so RAM never reaches the disk
#   - mounts the key stick (label IBE-KEY) and the data disk (label IBE-DATA) on demand
#   - starts nothing that records: capture needs the key stick, an arm file and a set clock
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ "$#" -ge 1 ] || { echo "usage: $0 <capture interface> [<capture interface> ...]"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. /etc/os-release
case "${VERSION_ID:-}" in
    12|13) ;;
    *) echo "Debian 12 or 13 (or Raspberry Pi OS based on them) expected, found: ${PRETTY_NAME:-unknown}"; exit 1 ;;
esac
for i in "$@"; do
    [ -d "/sys/class/net/$i" ] || { echo "no such interface: $i"; ip -br link; exit 1; }
    if ip -4 -o addr show dev "$i" | grep -q inet; then
        echo "$i has an IP address. A capture interface must not be the one you are logged in through."; exit 1
    fi
done

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 ethtool iproute2 nftables curl gpg ca-certificates \
    dosfstools exfatprogs tzdata
if [ ! -x /opt/zeek/bin/zeek ]; then
    REPO="https://download.opensuse.org/repositories/security:/zeek/Debian_${VERSION_ID}"
    echo "deb ${REPO}/ /" > /etc/apt/sources.list.d/security-zeek.list
    curl -fsSL "${REPO}/Release.key" | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg
    apt-get update
    apt-get install -y --no-install-recommends zeek-8.0-core
fi
/opt/zeek/bin/zeek --version
# firmware patches for Realtek network chips (RTL8125 on the PCIe adapter). Already present on Raspberry Pi OS.
apt-get install -y --no-install-recommends firmware-realtek || echo "firmware-realtek not available, continuing"

echo "== recorder files"
install -d -m 0755 /opt/ibe /opt/ibe/zeek /etc/ibe
install -d -m 0700 /var/lib/ibe /var/lib/ibe/anon /mnt/ibe-key /mnt/ibe-data
rm -rf /opt/ibe/ibe_recorder
cp -r "$HERE/ibe_recorder" /opt/ibe/ibe_recorder
find /opt/ibe -name __pycache__ -prune -exec rm -rf {} +
install -m 0644 "$HERE/zeek/ibe.zeek" /opt/ibe/zeek/ibe.zeek
# the researchers' public key: exports are encrypted for it, the private key never comes near the device
if [ -f "$HERE/recipient.asc" ]; then
    install -m 0644 "$HERE/recipient.asc" /etc/ibe/recipient.asc
fi
if [ ! -f /etc/ibe/config.json ]; then
    IFACES=$(printf '"%s", ' "$@"); IFACES="[${IFACES%, }]"
    sed "s/\"interfaces\": .*/\"interfaces\": ${IFACES},/" "$HERE/config.example.json" > /etc/ibe/config.json
fi

echo "== raw logs in RAM, no disk swap"
grep -q ' /run/ibe ' /etc/fstab || \
    echo 'tmpfs /run/ibe tmpfs rw,nosuid,nodev,noexec,mode=0700,size=2G 0 0' >> /etc/fstab
swapoff -a || true
systemctl disable --now dphys-swapfile.service 2>/dev/null || true
sed -i '/\sswap\s/ s/^\([^#]\)/#\1/' /etc/fstab

echo "== key stick and data disk, mounted on demand"
grep -q 'LABEL=IBE-KEY' /etc/fstab || echo \
    'LABEL=IBE-KEY /mnt/ibe-key vfat noauto,nofail,x-systemd.automount,x-systemd.idle-timeout=60,x-systemd.device-timeout=5,umask=077,flush 0 0' >> /etc/fstab
grep -q 'LABEL=IBE-DATA' /etc/fstab || echo \
    'LABEL=IBE-DATA /mnt/ibe-data exfat noauto,nofail,x-systemd.automount,x-systemd.idle-timeout=60,x-systemd.device-timeout=5,umask=077 0 0' >> /etc/fstab

echo "== capture interfaces are receive-only"
# One rule file per capture interface. The capture service loads it before it brings the interface up,
# and does not start if loading fails. With the rule in place not even a raw frame can leave.
: > /etc/sysctl.d/90-ibe.conf
for i in "$@"; do
    cat > "/etc/ibe/egress-$i.nft" <<NFT
table netdev ibe_$i
delete table netdev ibe_$i
table netdev ibe_$i {
    chain out { type filter hook egress device "$i" priority 0; policy drop; }
}
NFT
    echo "net.ipv6.conf.$i.disable_ipv6 = 1" >> /etc/sysctl.d/90-ibe.conf
    ip link set "$i" down
done
if [ -d /etc/NetworkManager/conf.d ]; then
    UNMANAGED=$(printf 'interface-name:%s;' "$@")
    printf '[keyfile]\nunmanaged-devices=%s\n' "${UNMANAGED%;}" > /etc/NetworkManager/conf.d/90-ibe-unmanaged.conf
fi

echo "== radios off, clock battery charging on, PCIe connector on (Raspberry Pi 5)"
rfkill block all 2>/dev/null || true
CFG=/boot/firmware/config.txt
if [ -f "$CFG" ]; then
    # pciex1: the PCIe connector is off by default unless a HAT+ with an ID EEPROM is attached
    for line in dtoverlay=disable-wifi dtoverlay=disable-bt dtparam=rtc_bbat_vchg=3000000 dtparam=pciex1; do
        grep -qx "$line" "$CFG" || echo "$line" >> "$CFG"
    done
fi

echo "== services"
install -m 0644 "$HERE"/systemd/ibe-zeek@.service "$HERE"/systemd/ibe-anonymise.service \
    "$HERE"/systemd/ibe-anonymise.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable ibe-anonymise.timer
for i in "$@"; do
    systemctl enable "ibe-zeek@$i.service"
done

cat <<EOF

Installed. Nothing is recorded yet. Reboot, then:
  1. Plug in a USB stick formatted FAT32 with the label IBE-KEY. The device creates its key on it.
  2. Plug in the data disk formatted exFAT with the label IBE-DATA.
  3. Check:  PYTHONPATH=/opt/ibe python3 -m ibe_recorder status
  4. Recording starts only when the stick holds armed.json with the ethics approval reference:
       PYTHONPATH=/opt/ibe python3 -m ibe_recorder arm --approval-ref "<date and number>"
EOF
