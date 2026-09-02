#!/bin/bash
# Prepares a fresh Oracle Cloud (or any Ubuntu) VM to run CatPhish.
# Run it ON THE VM, as a user with sudo:
#
#   sudo bash deploy/bootstrap.sh
#
# Installs Docker, then opens the firewall. The firewall is the part that
# catches people out on Oracle: there are TWO layers and both block traffic
# by default. This handles the one on the machine; the cloud-side one has to
# be done in the OCI console (see deploy/README.md step 3).

set -e

echo "==> Installing Docker"
if command -v docker >/dev/null 2>&1; then
  echo "    already installed, skipping"
else
  apt-get update
  apt-get install -y ca-certificates curl git
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
fi

# Let the login user run docker without sudo. Takes effect next login.
REAL_USER="${SUDO_USER:-$USER}"
if [ "$REAL_USER" != "root" ]; then
  usermod -aG docker "$REAL_USER"
  echo "==> Added $REAL_USER to the docker group (log out and back in)"
fi

# --- Firewall, layer 1 of 2: the instance itself ---------------------------
# Oracle's Ubuntu images ship with an iptables ruleset that REJECTs almost
# everything inbound except SSH, and it is saved to disk -- so opening a port
# with `ufw` alone does nothing, and the rule has to be inserted before the
# catch-all REJECT rather than appended after it.
echo "==> Opening ports 80 and 443 on the instance firewall"
for port in 80 443; do
  if iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
    echo "    port $port already open"
  else
    iptables -I INPUT 6 -p tcp --dport "$port" -m state --state NEW -j ACCEPT
    echo "    opened port $port"
  fi
done

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
  echo "==> Firewall rules saved (survive reboot)"
else
  apt-get install -y iptables-persistent
  netfilter-persistent save
  echo "==> Installed iptables-persistent and saved rules"
fi

echo ""
echo "==> Done on the VM side."
echo ""
echo "    STILL TO DO, and nothing will work without them:"
echo "    1. Open 80/443 in the OCI console too (Networking > VCN > Subnet >"
echo "       Security List > Add Ingress Rules). The console firewall is"
echo "       separate from the one this script just configured."
echo "    2. Point your domain's A record at this VM's public IP:"
echo "       $(curl -s --max-time 5 ifconfig.me || echo '<run: curl ifconfig.me>')"
echo "    3. Create .env in the repo root (see deploy/README.md)."
echo "    4. cd deploy && docker compose up -d --build"
