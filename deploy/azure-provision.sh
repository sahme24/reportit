#!/bin/bash
# Provisions the Azure VM that CatPhish runs on. Run once, from anywhere
# with the Azure CLI logged in (`az login`).
#
#   bash deploy/azure-provision.sh
#
# Creates: a resource group, an Ubuntu VM, an SSH key if you have none, and
# firewall rules for 80/443. Prints the hostname to use everywhere else.
#
# Safe to re-run: every step is idempotent, so a failure partway through can
# be fixed and the script run again without duplicating anything.

set -e

RG="${RG:-catphish-rg}"
LOCATION="${LOCATION:-canadacentral}"
VM="${VM:-catphish}"
# Must be unique within the region. Azure hands out
# <label>.<region>.cloudapp.azure.com free, which is a real hostname that
# Let's Encrypt will issue for -- that's why this app needs no purchased
# domain.
DNS_LABEL="${DNS_LABEL:-catphish-$RANDOM}"

# B1s (1 vCPU, 1 GB) is covered by the free 750 hours/month for 12 months,
# so it costs nothing against the student credit. 1 GB is genuinely tight
# for headless Chromium, which is why the bootstrap adds swap. If detonation
# turns out too slow, resizing to B1ms (2 GB) is two minutes and loses
# nothing:
#   az vm deallocate -g $RG -n $VM && \
#   az vm resize -g $RG -n $VM --size Standard_B1ms && \
#   az vm start -g $RG -n $VM
SIZE="${SIZE:-Standard_B1s}"

echo "==> Subscription"
az account show --query "{name:name, user:user.name}" -o tsv

echo "==> Resource group $RG in $LOCATION"
az group create --name "$RG" --location "$LOCATION" --output none

echo "==> VM $VM ($SIZE). This takes a couple of minutes."
# --generate-ssh-keys reuses ~/.ssh/id_rsa when it exists and creates one
# when it doesn't, so this neither overwrites an existing key nor demands
# you make one first.
az vm create \
  --resource-group "$RG" \
  --name "$VM" \
  --image Ubuntu2404 \
  --size "$SIZE" \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-address-dns-name "$DNS_LABEL" \
  --public-ip-sku Standard \
  --os-disk-size-gb 30 \
  --output none

echo "==> Opening 80 and 443"
# Azure blocks everything except SSH by default. The instance firewall is a
# separate layer, handled in azure-bootstrap.sh -- both have to allow the
# traffic or Let's Encrypt cannot reach the server to validate the domain.
az vm open-port --resource-group "$RG" --name "$VM" --port 80 --priority 1001 --output none
az vm open-port --resource-group "$RG" --name "$VM" --port 443 --priority 1002 --output none

FQDN="$(az vm show -d --resource-group "$RG" --name "$VM" --query fqdns -o tsv)"
IP="$(az vm show -d --resource-group "$RG" --name "$VM" --query publicIps -o tsv)"

echo ""
echo "============================================================"
echo "  Hostname : $FQDN"
echo "  IP       : $IP"
echo "  SSH      : ssh azureuser@$FQDN"
echo "============================================================"
echo ""
echo "Next:"
echo "  1. Register this OAuth redirect URI on your Google client:"
echo "       https://$FQDN/auth/google/callback"
echo "  2. Copy the bootstrap up and run it:"
echo "       scp deploy/azure-bootstrap.sh azureuser@$FQDN:~"
echo "       ssh azureuser@$FQDN 'bash azure-bootstrap.sh'"
echo ""
echo "Cost: B1s is covered by the free 750 hours/month for 12 months."
echo "Watch it at https://portal.azure.com > Cost Management."
