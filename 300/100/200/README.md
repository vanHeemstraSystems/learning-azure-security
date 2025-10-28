# 200 - 🚀 The Application: Secure Azure Resource Scanner

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