#!/usr/bin/env bash

# Azure Security Scanner - Quick Setup Script
# This script automates the initial setup of Azure resources

set -e  # Exit on error

echo "=========================================="
echo "Azure Security Scanner - Quick Setup"
echo "=========================================="
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
  echo "Azure CLI is not installed."
  echo "Please install it from: https://docs.microsoft.com/cli/azure/install-azure-cli"
  exit 1
fi

echo "Azure CLI found"

# Check if logged in
if ! az account show &> /dev/null; then
  echo "Not logged in to Azure."
  echo "Please run: az login"
  exit 1
fi

echo "Azure authentication verified"

# Get current subscription
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SUBSCRIPTION_NAME=$(az account show --query name -o tsv)

echo ""
echo "Current Subscription:"
echo "  Name: $SUBSCRIPTION_NAME"
echo "  ID: $SUBSCRIPTION_ID"
echo ""

read -p "Use this subscription? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Please select a subscription with: az account set --subscription <name-or-id>"
  exit 1
fi

# Get user input
read -p "Enter resource group name [security-scanner-rg]: " RG_NAME
RG_NAME=${RG_NAME:-security-scanner-rg}

read -p "Enter location [eastus]: " LOCATION
LOCATION=${LOCATION:-eastus}

DEFAULT_KV="secscan-kv-$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 6)"
read -p "Enter Key Vault name (3-24 chars, letters/digits/hyphens) [${DEFAULT_KV}]: " KV_NAME
KV_NAME=${KV_NAME:-$DEFAULT_KV}

# Validate Key Vault name rules
# - 3-24 characters
# - start with letter, end with letter or digit
# - only letters, digits, hyphens
# - no consecutive hyphens
while : ; do
  if [[ ${#KV_NAME} -lt 3 || ${#KV_NAME} -gt 24 ]]; then
    echo "Invalid Key Vault name: must be 3-24 characters."
  elif ! [[ $KV_NAME =~ ^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$ ]]; then
    echo "Invalid Key Vault name: must start with a letter, end with a letter or digit, and contain only letters, digits, and hyphens."
  elif [[ $KV_NAME == *"--"* ]]; then
    echo "Invalid Key Vault name: must not contain consecutive hyphens."
  else
    break
  fi
  read -p "Enter a valid Key Vault name [${DEFAULT_KV}]: " KV_NAME
  KV_NAME=${KV_NAME:-$DEFAULT_KV}
done

echo ""
echo "Configuration:"
echo "  Resource Group: $RG_NAME"
echo "  Location: $LOCATION"
echo "  Key Vault: $KV_NAME"
echo ""

read -p "Proceed with setup? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Setup cancelled."
  exit 0
fi

echo ""
echo "Creating resources..."
echo ""

# Create Resource Group
echo "-> Creating resource group..."
if az group show --name "$RG_NAME" &> /dev/null; then
  echo "  Resource group already exists"
else
  az group create --name "$RG_NAME" --location "$LOCATION" --output none
  echo "  Resource group created"
fi

# Create Service Principal
echo "-> Creating Service Principal..."
read CLIENT_ID CLIENT_SECRET TENANT_ID < <(az ad sp create-for-rbac \
  --name "AzureSecurityScanner-$(date +%s)" \
  --role "Reader" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --query '[appId,password,tenant]' \
  -o tsv)

echo "  Service Principal created"
echo "    App ID: $CLIENT_ID"

# Assign Security Reader role
echo "-> Assigning Security Reader role..."
SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv)
az role assignment create \
  --assignee "$SP_OBJECT_ID" \
  --role "Security Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --output none
echo "  Security Reader role assigned"

# Create Key Vault
echo "-> Creating Key Vault..."
if az keyvault show --name "$KV_NAME" &> /dev/null; then
  echo "  Key Vault name already taken, using existing vault"
else
  az keyvault create \
    --name "$KV_NAME" \
    --resource-group "$RG_NAME" \
    --location "$LOCATION" \
    --enable-rbac-authorization true \
    --output none
  echo "  Key Vault created"
fi

# Get Key Vault ID
KV_ID=$(az keyvault show --name "$KV_NAME" --query id -o tsv)

# Assign yourself Key Vault Secrets Officer
echo "-> Configuring Key Vault access..."
CURRENT_USER_ID=$(az ad signed-in-user show --query id -o tsv)
az role assignment create \
  --assignee "$CURRENT_USER_ID" \
  --role "Key Vault Secrets Officer" \
  --scope "$KV_ID" \
  --output none 2>/dev/null || echo "  Role may already be assigned"

# Wait a moment for RBAC to propagate
sleep 5

# Store secrets
echo "-> Storing credentials in Key Vault..."
az keyvault secret set --vault-name "$KV_NAME" --name "azure-client-id" --value "$CLIENT_ID" --output none
az keyvault secret set --vault-name "$KV_NAME" --name "azure-client-secret" --value "$CLIENT_SECRET" --output none
az keyvault secret set --vault-name "$KV_NAME" --name "azure-tenant-id" --value "$TENANT_ID" --output none
echo "  Credentials stored securely"

# Grant Service Principal access to Key Vault
echo "-> Granting Service Principal Key Vault access..."
az role assignment create \
  --assignee "$CLIENT_ID" \
  --role "Key Vault Secrets User" \
  --scope "$KV_ID" \
  --output none
echo "  Service Principal granted access"

# Create .env file
echo "-> Creating .env configuration file..."
cat > .env << EOF
# Azure Security Scanner Configuration
# Generated by quick-setup.sh on $(date)
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_KEY_VAULT_NAME=$KV_NAME
OUTPUT_FORMAT=json
EOF

echo "  .env file created"

# Create reports directory
mkdir -p reports

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Resources Created:"
echo "  - Resource Group: $RG_NAME"
echo "  - Service Principal: AzureSecurityScanner"
echo "  - Key Vault: $KV_NAME"
echo ""
echo "Configuration saved to .env"
echo ""
echo "Next Steps:"
echo "  1. Install dependencies: pip install -r requirements.txt"
echo "  2. Run the scanner: python azure_security_scanner.py"
echo "  3. View the report in the reports/ directory"
echo ""
echo "Important: Keep your .env file secure and never commit it to Git!"
echo ""
