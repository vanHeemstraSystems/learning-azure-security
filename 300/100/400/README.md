# 400 - 🛠️ Setup Instructions

### Step 1: Clone the Repository

```bash
git clone https://github.com/[your-username]/learning-azure-security.git
cd learning-azure-security
```

### Step 2: Create a virtual environment for Python

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

**Note**: You should see `(venv)` at the beginning of your command prompt when the virtual environment is active.

### Step 3: Install Dependencies

**NOTE**: As we will be running our code from within the previously created virtual environment, the commandline should show (venv).

```bash
pip install -r requirements.txt
```

### Step 4: Prerequisites

Before setting up Azure resources, ensure you have the following prerequisites:

- **Azure CLI installed and logged in**
  ```bash
  # Check if Azure CLI is installed
  az --version
  ```
  
  **If Azure CLI is not installed**, see the detailed installation instructions in [`docs/AZURE_SETUP.md`](../docs/AZURE_SETUP.md) for:
  - macOS: `brew install azure-cli`
  - Windows: `winget install Microsoft.AzureCLI`
  - Linux: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`
  
  *WARNING**: The installation is one of the most time-consuming parts of the entire process, so once it's done, everything else will be much faster.

  ```bash
  # Login to Azure (if not already logged in)
  az login
  ```
- **Active Azure subscription**
  ```bash
  # List available subscriptions
  az account list --output table
  
  # Set the correct subscription (if needed)
  az account set --subscription "Your-Subscription-Name-or-ID"
  ```
- **Appropriate permissions** to create resources and Service Principals:
  - Create Service Principals (Application Administrator or Global Administrator)
  - Create Resource Groups
  - Create Key Vaults
  - Assign RBAC roles at subscription level

### Step 5: Azure Setup

Now that prerequisites are met, choose one of the following approaches to set up your Azure resources:

#### Option A: Quick Setup (Recommended)
Run the automated setup script for the fastest setup:

```bash
# Make the script executable and run it
chmod +x quick-setup.sh
./quick-setup.sh
```

This will automatically:
- ✅ Verify Azure CLI installation and login
- ✅ Create Resource Group, Service Principal, and Key Vault
- ✅ Configure RBAC permissions
- ✅ Store credentials securely in Key Vault
- ✅ Generate `.env` configuration file

#### Option B: Manual Setup
Follow the detailed setup guides for more control:

- **Comprehensive Guide**: See [`docs/AZURE_SETUP.md`](../docs/AZURE_SETUP.md) for complete setup with troubleshooting
- **Simplified Guide**: See [`SETUP_GUIDE.md`](../../SETUP_GUIDE.md) for step-by-step manual process

#### What Gets Created
Regardless of which option you choose, the setup will create:
- Resource Group for organizing resources
- Service Principal with appropriate permissions (Reader, Security Reader, Key Vault Reader)
- Azure Key Vault for secure credential storage
- RBAC role assignments for proper access control
- `.env` configuration file

**After completing the setup above, you can proceed to the next step.**

### Step 6: Create Azure Resources

#### Create a Service Principal

```bash
az ad sp create-for-rbac --name "AzureSecurityScanner" \
   --role "Reader" \
   --scopes /subscriptions/{subscription-id}
```

Save the output (appId, password, tenant).

#### Create an Azure Key Vault

```bash
az keyvault create --name "mysecurityscanner-kv" \
   --resource-group "security-learning-rg" \
   --location "eastus"
```

#### Store Credentials in Key Vault

```bash
az keyvault secret set --vault-name "mysecurityscanner-kv" \
   --name "azure-client-id" --value "{your-app-id}"

az keyvault secret set --vault-name "mysecurityscanner-kv" \
   --name "azure-client-secret" --value "{your-password}"

az keyvault secret set --vault-name "mysecurityscanner-kv" \
   --name "azure-tenant-id" --value "{your-tenant-id}"
```

#### Grant Service Principal Access to Key Vault

```bash
az keyvault set-policy --name "mysecurityscanner-kv" \
   --spn {your-app-id} \
   --secret-permissions get list
```

### Step 7: Configure Environment

Create a `.env` file:

```env
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_KEY_VAULT_NAME=mysecurityscanner-kv
```

### Step 8: Run the Scanner

```bash
python azure_security_scanner.py
```