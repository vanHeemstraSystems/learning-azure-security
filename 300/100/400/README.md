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

### Step 4: Create Azure Resources

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

### Step 5: Configure Environment

Create a `.env` file:

```env
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_KEY_VAULT_NAME=mysecurityscanner-kv
```

### Step 6: Run the Scanner

```bash
python azure_security_scanner.py
```