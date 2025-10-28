# Azure Setup Guide

Complete step-by-step guide to set up Azure resources for the Security Scanner.

## Prerequisites

- Azure CLI installed ([Download here](https://docs.microsoft.com/cli/azure/install-azure-cli))
- An active Azure subscription
- Appropriate permissions to create resources and Service Principals

## Step 1: Login to Azure

```bash
az login
```

If you have multiple subscriptions, set the correct one:

```bash
# List subscriptions
az account list --output table

# Set active subscription
az account set --subscription "Your-Subscription-Name-or-ID"
```

## Step 2: Create Resource Group

Create a resource group to hold your security scanner resources:

```bash
az group create \
  --name "security-scanner-rg" \
  --location "eastus"
```

## Step 3: Create Service Principal

Create a Service Principal with Reader permissions for security scanning:

```bash
az ad sp create-for-rbac \
  --name "AzureSecurityScanner" \
  --role "Reader" \
  --scopes /subscriptions/$(az account show --query id -o tsv)
```

**Important**: Save the output! You’ll need:

- `appId` (Client ID)
- `password` (Client Secret)
- `tenant` (Tenant ID)

### Assign Additional Roles

For comprehensive scanning, also assign these roles:

```bash
# Get the Service Principal Object ID
SP_ID=$(az ad sp list --display-name "AzureSecurityScanner" --query "[0].id" -o tsv)

# Security Reader role
az role assignment create \
  --assignee $SP_ID \
  --role "Security Reader" \
  --scope /subscriptions/$(az account show --query id -o tsv)

# Key Vault Reader (for Key Vault scanning)
az role assignment create \
  --assignee $SP_ID \
  --role "Key Vault Reader" \
  --scope /subscriptions/$(az account show --query id -o tsv)
```

## Step 4: Create Azure Key Vault

Create a Key Vault to securely store your Service Principal credentials:

```bash
az keyvault create \
  --name "security-scanner-kv-$(whoami)" \
  --resource-group "security-scanner-rg" \
  --location "eastus" \
  --enable-rbac-authorization true
```

> **Note**: Key Vault names must be globally unique. We append your username to ensure uniqueness.

## Step 5: Store Credentials in Key Vault

### Option A: Using RBAC (Recommended)

1. Assign yourself the “Key Vault Secrets Officer” role:

```bash
KV_ID=$(az keyvault show --name "security-scanner-kv-$(whoami)" --query id -o tsv)

az role assignment create \
  --assignee $(az ad signed-in-user show --query id -o tsv) \
  --role "Key Vault Secrets Officer" \
  --scope $KV_ID
```

1. Store the Service Principal credentials:

```bash
# Replace these values with your Service Principal details from Step 3
az keyvault secret set \
  --vault-name "security-scanner-kv-$(whoami)" \
  --name "azure-client-id" \
  --value "YOUR_APP_ID_HERE"

az keyvault secret set \
  --vault-name "security-scanner-kv-$(whoami)" \
  --name "azure-client-secret" \
  --value "YOUR_PASSWORD_HERE"

az keyvault secret set \
  --vault-name "security-scanner-kv-$(whoami)" \
  --name "azure-tenant-id" \
  --value "YOUR_TENANT_ID_HERE"
```

### Option B: Using Access Policies (Legacy)

If you’re not using RBAC on your Key Vault:

```bash
az keyvault set-policy \
  --name "security-scanner-kv-$(whoami)" \
  --upn $(az account show --query user.name -o tsv) \
  --secret-permissions get set list delete
```

Then set the secrets as shown in Option A.

## Step 6: Grant Service Principal Access to Key Vault

The scanner needs to read secrets from Key Vault:

```bash
# Get Service Principal App ID
SP_APP_ID=$(az ad sp list --display-name "AzureSecurityScanner" --query "[0].appId" -o tsv)

# Assign Key Vault Secrets User role
az role assignment create \
  --assignee $SP_APP_ID \
  --role "Key Vault Secrets User" \
  --scope $(az keyvault show --name "security-scanner-kv-$(whoami)" --query id -o tsv)
```

## Step 7: Configure Environment Variables

Create a `.env` file in your project root:

```bash
cp .env.example .env
```

Edit `.env` and add your values:

```env
AZURE_SUBSCRIPTION_ID=your-subscription-id-here
AZURE_KEY_VAULT_NAME=security-scanner-kv-yourusername
OUTPUT_FORMAT=json
```

Get your subscription ID:

```bash
az account show --query id -o tsv
```

## Step 8: Test Authentication

Verify everything is set up correctly:

```bash
# Test Azure CLI access
az account show

# Test Key Vault access
az keyvault secret show \
  --vault-name "security-scanner-kv-$(whoami)" \
  --name "azure-client-id"
```

## Alternative: Using DefaultAzureCredential

Instead of storing credentials in Key Vault, you can use Azure CLI authentication:

1. Don’t specify `AZURE_KEY_VAULT_NAME` in `.env`
1. Make sure you’re logged in with `az login`
1. The scanner will use your Azure CLI credentials

This is good for local development but not recommended for production.

## Security Best Practices

### 1. Rotate Credentials Regularly

Set up a reminder to rotate Service Principal secrets every 90 days:

```bash
# Create a new secret for the Service Principal
az ad sp credential reset \
  --id $(az ad sp list --display-name "AzureSecurityScanner" --query "[0].appId" -o tsv)
```

### 2. Enable Key Vault Logging

```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group "security-scanner-rg" \
  --workspace-name "security-scanner-logs"

# Get workspace ID
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "security-scanner-rg" \
  --workspace-name "security-scanner-logs" \
  --query id -o tsv)

# Enable diagnostic settings for Key Vault
az monitor diagnostic-settings create \
  --name "kv-diagnostics" \
  --resource $(az keyvault show --name "security-scanner-kv-$(whoami)" --query id -o tsv) \
  --workspace $WORKSPACE_ID \
  --logs '[{"category": "AuditEvent","enabled": true}]' \
  --metrics '[{"category": "AllMetrics","enabled": true}]'
```

### 3. Enable Soft Delete and Purge Protection

```bash
az keyvault update \
  --name "security-scanner-kv-$(whoami)" \
  --enable-soft-delete true \
  --enable-purge-protection true
```

### 4. Use Managed Identity (For Azure VMs)

If running the scanner from an Azure VM:

1. Enable System-assigned Managed Identity:

```bash
az vm identity assign \
  --name "your-vm-name" \
  --resource-group "your-vm-rg"
```

1. Grant the VM’s identity the necessary permissions:

```bash
VM_PRINCIPAL_ID=$(az vm show \
  --name "your-vm-name" \
  --resource-group "your-vm-rg" \
  --query identity.principalId -o tsv)

az role assignment create \
  --assignee $VM_PRINCIPAL_ID \
  --role "Reader" \
  --scope /subscriptions/$(az account show --query id -o tsv)
```

1. Remove `AZURE_KEY_VAULT_NAME` from `.env` - the scanner will use Managed Identity automatically

## Troubleshooting

### Error: “Key Vault not found”

- Verify the Key Vault name is correct
- Ensure you have access permissions
- Check that the Key Vault exists: `az keyvault list --output table`

### Error: “Insufficient permissions”

- Verify Service Principal has Reader role
- Check role assignments: `az role assignment list --assignee $SP_APP_ID`

### Error: “Authentication failed”

- Verify credentials in Key Vault are correct
- Test Service Principal login:

```bash
az login --service-principal \
  -u YOUR_APP_ID \
  -p YOUR_PASSWORD \
  --tenant YOUR_TENANT_ID
```

### Error: “Access denied to Key Vault”

- Verify RBAC roles or Access Policies are set
- Check: `az role assignment list --scope $KV_ID`

## Next Steps

After completing setup:

1. Install Python dependencies: `pip install -r requirements.txt`
1. Run the scanner: `python azure_security_scanner.py`
1. Review the generated report in the `reports/` directory
1. Schedule regular scans using Azure DevOps, GitHub Actions, or cron

## Resources

- [Azure Service Principals Documentation](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)
- [Azure Key Vault Best Practices](https://docs.microsoft.com/azure/key-vault/general/best-practices)
- [Azure RBAC Documentation](https://docs.microsoft.com/azure/role-based-access-control/)
- [Managed Identity Overview](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)
