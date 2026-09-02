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

# northcentralus, and the reason is two constraints stacked on top of each
# other. Azure for Students carries a policy assignment ("Allowed resource
# deployment regions") limiting deployments to canadacentral, centralus,
# francecentral, northcentralus and mexicocentral -- anywhere else fails
# with RequestDisallowedByAzure, which reads like a permissions error rather
# than a region one. Of those, canadacentral has no unrestricted x86
# B-series (only the ARM Standard_B*p* variants, which would need an arm64
# image), and northcentralus does. Check both before changing this:
#   az policy assignment list --query "[].parameters" -o json
#   az vm list-skus --location <loc> --resource-type virtualMachines #     --query "[?starts_with(name,'"'"'Standard_B2'"'"')&&length(restrictions)==\`0\`].name" -o tsv
#   az vm list-skus --location <loc> --resource-type virtualMachines \
#     --query "[?starts_with(name,'Standard_B')&&length(restrictions)==\`0\`].name" -o tsv
LOCATION="${LOCATION:-northcentralus}"

VM="${VM:-catphish}"
# Must be unique within the region. Azure hands out
# <label>.<region>.cloudapp.azure.com free, which is a real hostname that
# Let's Encrypt will issue for -- that's why this app needs no purchased
# domain.
DNS_LABEL="${DNS_LABEL:-catphish-$RANDOM}"

# B2ats_v2: 2 vCPU, 1 GiB, $7.67/month -- so a $100 student credit runs ~13
# months, which outlasts the annual renewal cycle. The 4 GiB B2als_v2 is
# $14.89 and would run out after 6.7, leaving the site down for five months.
# 1 GiB is tight for headless Chromium, so azure-bootstrap.sh adds swap; the
# two cores here make that far less painful than a single-core B1s would.
# (B1s itself is capacity-restricted in both Canadian regions.)
#
# If detonation proves too slow, resizing loses nothing:
#   az vm deallocate -g $RG -n $VM && \
#   az vm resize -g $RG -n $VM --size Standard_B2als_v2 && \
#   az vm start -g $RG -n $VM
SIZE="${SIZE:-Standard_B2ats_v2}"

echo "==> Subscription"
# No spaces inside --query: the CLI parses the JMESPath as one argument and
# an unquoted space splits it into two, which fails with a confusing
# "invalid jmespath_type value".
az account show --query '{name:name,user:user.name}' -o tsv

echo "==> Resource group $RG in $LOCATION"
# A group's region is fixed when it is created. Re-creating an existing one
# in a different region fails with InvalidResourceGroupLocation, and worse,
# az vm create then inherits the OLD region -- which is how a run aimed at
# canadaeast ended up failing on canadacentral's capacity limits. Say so
# plainly instead.
EXISTING="$(az group show --name "$RG" --query location -o tsv 2>/dev/null || true)"
if [ -n "$EXISTING" ] && [ "$EXISTING" != "$LOCATION" ]; then
  echo "ERROR: resource group $RG already exists in $EXISTING, not $LOCATION."
  echo "       Either delete it:  az group delete -n $RG --yes"
  echo "       or use a new name: RG=catphish-rg2 bash deploy/azure-provision.sh"
  exit 1
fi
az group create --name "$RG" --location "$LOCATION" --output none

echo "==> VM $VM ($SIZE). This takes a couple of minutes."
# --generate-ssh-keys reuses ~/.ssh/id_rsa when it exists and creates one
# when it doesn't, so this neither overwrites an existing key nor demands
# you make one first.
az vm create \
  --resource-group "$RG" \
  --name "$VM" \
  --location "$LOCATION" \
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
echo "Cost: ~\$7.67/month against the student credit."
echo "Watch it at https://portal.azure.com > Cost Management."
