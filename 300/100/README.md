# 100 - Introduction

# Learning Azure Security

A comprehensive repository demonstrating Azure Security fundamentals through practical implementation and hands-on examples.

## 🎯 Project Overview

This repository contains a **Secure Azure Resource Scanner** - a Python-based tool that demonstrates core Azure Security concepts including authentication, secrets management, security monitoring, and compliance checking.

## 100 -  🔐 Azure Security Concepts Covered

See [README.md](./100/README.md)

## 200 - 🚀 The Application: Secure Azure Resource Scanner

See [README.md](./200/README.md)

## 300 - 📋 Prerequisites

See [README.md](./300/README.md)

## 400 - 🛠️ Setup Instructions

See [README.md](./400/README.md)

## 500 - 📁 Project Structure

```
Learning-Azure-Security/
├── 300/100/README.md                      # This file
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

## 600 - 🔍 Usage Examples

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

## 700 - 📊 Sample Output

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

## 800 - 🎓 Learning Objectives

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

## 900 - 🔗 Additional Resources

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

## 1000 - 🛡️ Security Considerations

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

## 1100 - 🚧 Roadmap

- [ ] Add Azure Policy compliance checking
- [ ] Implement Azure Sentinel integration
- [ ] Add Azure Defender recommendations parsing
- [ ] Create automated remediation workflows
- [ ] Add support for Azure Kubernetes Service (AKS) scanning
- [ ] Implement cost analysis for security resources
- [ ] Add Microsoft Defender for Cloud integration

## 1200 - 🤝 Contributing

This is a learning repository, but contributions are welcome! If you have suggestions for additional security checks or improvements:

1. Fork the repository
1. Create a feature branch
1. Make your changes
1. Submit a pull request

## 1300 - 📝 License

MIT License - feel free to use this for your learning and professional development.

## 1400 - ✉️ Contact

Created as part of my Azure Security learning journey. Connect with me to discuss Azure Security topics!

-----

**Remember**: Security is not a destination, it’s a continuous journey. Keep learning, stay curious, and always follow the principle of least privilege! 🔐
