# 100 - Introduction

# Learning Azure Security

A comprehensive repository demonstrating Azure Security fundamentals through practical implementation and hands-on examples.

## 🎯 Project Overview

This repository contains a **Secure Azure Resource Scanner** - a Python-based tool that demonstrates core Azure Security concepts including authentication, secrets management, security monitoring, and compliance checking.

## 🔐 Azure Security Concepts Covered

### 1. **Identity and Access Management**

- Azure Active Directory (Microsoft Entra ID) authentication
- Service Principal authentication
- Managed Identity integration
- Role-Based Access Control (RBAC) validation

### 2. **Secrets Management**

- Azure Key Vault integration
- Secure credential storage and retrieval
- Certificate management
- Secrets rotation principles

### 3. **Security Monitoring**

- Azure Security Center integration
- Security posture assessment
- Compliance checking
- Threat detection awareness

### 4. **Network Security**

- Network Security Group (NSG) analysis
- Virtual Network security validation
- Firewall rule assessment
- Private endpoint verification

### 5. **Data Protection**

- Storage account encryption validation
- Database security configuration checks
- Data classification principles
- Backup and recovery verification

## 🚀 The Application: Secure Azure Resource Scanner

A security auditing tool that scans your Azure subscription for security misconfigurations and compliance issues.

### Features

- **Authentication**: Uses Azure AD Service Principal or Managed Identity
- **Key Vault Integration**: Securely retrieves credentials from Azure Key Vault
- **Resource Scanning**: Audits Storage Accounts, Virtual Machines, NSGs, and Key Vaults
- **Security Checks**: Validates encryption, public access, RBAC, and security configurations
- **Compliance Reporting**: Generates detailed security reports in JSON and HTML
- **Logging**: Comprehensive audit logging for all operations

### Security Checks Performed

- ✅ Storage account public access restrictions
- ✅ Encryption at rest validation
- ✅ HTTPS-only enforcement
- ✅ Network Security Group rule analysis
- ✅ Key Vault access policies review
- ✅ Virtual Machine security configuration
- ✅ Managed Identity usage validation
- ✅ Diagnostic logging enablement

## 📋 Prerequisites

- **Azure Subscription** (you already have this!)
- **Python 3.8+**
- **Azure CLI** (for initial setup)
- **Service Principal** with appropriate permissions

### Required Azure Permissions

The Service Principal needs the following roles:

- `Reader` - To read resource configurations
- `Security Reader` - To access security assessments
- `Key Vault Reader` - To access Key Vault metadata

## 🛠️ Setup Instructions

### Step 1: Clone the Repository

```bash
git clone https://github.com/[your-username]/Learning-Azure-Security.git
cd Learning-Azure-Security
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Create Azure Resources

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

### Step 4: Configure Environment

Create a `.env` file:

```env
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_KEY_VAULT_NAME=mysecurityscanner-kv
```

### Step 5: Run the Scanner

```bash
python azure_security_scanner.py
```

## 📁 Project Structure

```
Learning-Azure-Security/
├── README.md                      # This file
├── azure_security_scanner.py      # Main application
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variables template
├── .gitignore                     # Git ignore rules
├── reports/                       # Generated security reports
│   ├── security_report_*.json
│   └── security_report_*.html
└── docs/                          # Additional documentation
   ├── AZURE_SETUP.md            # Detailed Azure setup guide
   ├── SECURITY_BEST_PRACTICES.md
   └── TROUBLESHOOTING.md
```

## 🔍 Usage Examples

### Basic Scan

```bash
python azure_security_scanner.py
```

### Scan Specific Resource Group

```bash
python azure_security_scanner.py --resource-group "production-rg"
```

### Generate HTML Report

```bash
python azure_security_scanner.py --output html
```

### Verbose Output

```bash
python azure_security_scanner.py --verbose
```

## 📊 Sample Output

```
[INFO] Authenticating with Azure using Service Principal...
[SUCCESS] Authentication successful!
[INFO] Retrieving credentials from Key Vault: mysecurityscanner-kv
[SUCCESS] Credentials retrieved successfully

Starting Security Scan...
==================================================

[SCAN] Storage Accounts (3 found)
 ✅ mystorageacct001: Secure (Private, HTTPS-only, Encrypted)
 ⚠️  mystorageacct002: Public access enabled - SECURITY RISK
 ✅ mystorageacct003: Secure (Private, HTTPS-only, Encrypted)

[SCAN] Network Security Groups (5 found)
 ⚠️  web-nsg: Overly permissive rule detected (0.0.0.0/0 on port 22)
 ✅ db-nsg: All rules follow least privilege principle

[SCAN] Key Vaults (2 found)
 ✅ prod-keyvault: Secure (RBAC enabled, Soft delete on)
 ✅ dev-keyvault: Secure (RBAC enabled, Soft delete on)

==================================================
Scan Complete!
Total Issues Found: 2 High, 1 Medium, 0 Low
Report saved to: reports/security_report_20250115_143022.json
```

## 🎓 Learning Objectives

By working with this repository, you will learn:

1. **Azure Authentication Patterns**
- Service Principal vs Managed Identity
- When to use each authentication method
- Secure credential management
1. **Azure Key Vault Best Practices**
- Secrets vs Certificates vs Keys
- Access policies and RBAC
- Secrets rotation strategies
1. **Security Posture Management**
- Common Azure misconfigurations
- Security baseline requirements
- Compliance frameworks (CIS, NIST)
1. **Azure SDK Usage**
- Working with Azure Python SDKs
- Resource management operations
- Error handling and retries
1. **Security Monitoring**
- Logging and audit trails
- Security alerts and responses
- Incident response preparation

## 🔗 Additional Resources

### Official Microsoft Documentation

- [Azure Security Documentation](https://docs.microsoft.com/azure/security/)
- [Azure Security Best Practices](https://docs.microsoft.com/azure/security/fundamentals/best-practices-and-patterns)
- [Azure Security Baseline](https://docs.microsoft.com/security/benchmark/azure/)

### Learning Paths

- [Microsoft Learn: Azure Security](https://docs.microsoft.com/learn/paths/az-500-manage-identity-access/)
- [Azure Security Certifications (AZ-500)](https://docs.microsoft.com/certifications/azure-security-engineer/)

### Tools and SDKs

- [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python)
- [Azure CLI Documentation](https://docs.microsoft.com/cli/azure/)
- [Azure PowerShell](https://docs.microsoft.com/powershell/azure/)

## 🛡️ Security Considerations

### What This Project Teaches

- ✅ Proper credential management using Key Vault
- ✅ Principle of least privilege (read-only permissions)
- ✅ Audit logging for all operations
- ✅ Secure communication (HTTPS/TLS)

### Important Notes

- Never commit credentials to Git
- Always use Key Vault for secrets in production
- Regularly rotate Service Principal secrets
- Monitor and review RBAC assignments
- Enable Azure AD Multi-Factor Authentication

## 🚧 Roadmap

- [ ] Add Azure Policy compliance checking
- [ ] Implement Azure Sentinel integration
- [ ] Add Azure Defender recommendations parsing
- [ ] Create automated remediation workflows
- [ ] Add support for Azure Kubernetes Service (AKS) scanning
- [ ] Implement cost analysis for security resources
- [ ] Add Microsoft Defender for Cloud integration

## 🤝 Contributing

This is a learning repository, but contributions are welcome! If you have suggestions for additional security checks or improvements:

1. Fork the repository
1. Create a feature branch
1. Make your changes
1. Submit a pull request

## 📝 License

MIT License - feel free to use this for your learning and professional development.

## ✉️ Contact

Created as part of my Azure Security learning journey. Connect with me to discuss Azure Security topics!

-----

**Remember**: Security is not a destination, it’s a continuous journey. Keep learning, stay curious, and always follow the principle of least privilege! 🔐
