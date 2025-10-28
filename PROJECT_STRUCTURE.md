# Learning Azure Security - Complete Project Structure

This document provides an overview of the complete repository structure.

## 📁 Directory Structure

```
Learning-Azure-Security/
│
├── README.md                          # Main project documentation
├── LICENSE                            # MIT License
├── .gitignore                         # Git ignore rules
├── .env.example                       # Environment configuration template
│
├── azure_security_scanner.py          # Main security scanner application (650+ lines)
├── requirements.txt                   # Python dependencies
├── quick-setup.sh                     # Automated Azure setup script
│
├── docs/                              # Additional documentation
│   ├── AZURE_SETUP.md                # Detailed Azure setup guide
│   ├── SECURITY_BEST_PRACTICES.md    # Security best practices and guidelines
│   └── TROUBLESHOOTING.md            # Common issues and solutions
│
└── reports/                           # Generated security reports (created at runtime)
    ├── security_report_*.json         # JSON format reports
    └── security_report_*.html         # HTML format reports
```

## 📄 File Descriptions

### Core Files

#### `README.md`

- **Purpose**: Main project documentation and entry point
- **Size**: ~400 lines
- **Contains**:
  - Project overview and learning objectives
  - Azure Security concepts covered
  - Setup instructions
  - Usage examples
  - Project roadmap
  - Links to additional resources

#### `azure_security_scanner.py`

- **Purpose**: Main application - Security scanning tool
- **Size**: ~650 lines
- **Key Features**:
  - Multiple authentication methods (Service Principal, Managed Identity, CLI)
  - Azure Key Vault integration for secure credential management
  - Resource scanning: Storage Accounts, NSGs, Key Vaults, Virtual Machines
  - Security checks: Encryption, public access, RBAC, network security
  - Report generation in JSON and HTML formats
  - Comprehensive logging and error handling
- **Demonstrates**:
  - Azure SDK usage
  - Security best practices
  - Professional Python code structure
  - Error handling and logging
  - Command-line interface design

#### `requirements.txt`

- **Purpose**: Python package dependencies
- **Contains**:
  - Azure SDK packages (identity, management, Key Vault)
  - Python utilities
- **Usage**: `pip install -r requirements.txt`

#### `quick-setup.sh`

- **Purpose**: Automated Azure resource setup
- **Size**: ~180 lines
- **What it does**:
  - Creates Resource Group
  - Creates Service Principal
  - Creates Key Vault
  - Configures RBAC permissions
  - Stores credentials securely
  - Generates .env file
- **Usage**: `./quick-setup.sh`

### Configuration Files

#### `.env.example`

- **Purpose**: Template for environment variables
- **Usage**: Copy to `.env` and fill in your values
- **Contains**:
  - AZURE_SUBSCRIPTION_ID
  - AZURE_KEY_VAULT_NAME
  - OUTPUT_FORMAT
  - VERBOSE

#### `.gitignore`

- **Purpose**: Prevent committing sensitive files
- **Ignores**:
  - Credentials and secrets
  - Python cache files
  - Virtual environments
  - Log files
  - Generated reports

#### `LICENSE`

- **Purpose**: MIT License for the project
- **Allows**: Free use, modification, and distribution

### Documentation Files

#### `docs/AZURE_SETUP.md`

- **Purpose**: Comprehensive Azure setup guide
- **Size**: ~550 lines
- **Sections**:
  - Prerequisites and required tools
  - Quick setup (automated)
  - Manual setup (step-by-step)
  - Azure resource overview
  - Authentication methods
  - Permissions and roles
  - Verification steps
  - Advanced configuration
  - Multi-subscription scanning
  - CI/CD integration examples

#### `docs/SECURITY_BEST_PRACTICES.md`

- **Purpose**: Azure security best practices
- **Size**: ~800 lines
- **Sections**:
  - Identity and Access Management
  - Secrets Management
  - Network Security
  - Data Protection
  - Monitoring and Logging
  - Compliance and Governance
  - Security Scanner best practices
  - Incident Response
  - Security checklist

#### `docs/TROUBLESHOOTING.md`

- **Purpose**: Common issues and solutions
- **Size**: ~750 lines
- **Sections**:
  - Authentication issues
  - Key Vault access problems
  - Permission errors
  - Scanner execution issues
  - Network connectivity
  - Python and dependencies
  - Azure CLI issues
  - Report generation problems
  - Performance issues
  - Known limitations
  - Error code reference

### Runtime Directories

#### `reports/`

- **Purpose**: Store generated security scan reports
- **Created**: Automatically by the scanner
- **Contains**:
  - JSON reports with detailed findings
  - HTML reports with visual presentation
- **Naming**: `security_report_YYYYMMDD_HHMMSS.[json|html]`

## 🔧 How Files Work Together

### Workflow 1: Initial Setup

```
1. Clone repository
2. Read README.md (understand the project)
3. Read docs/AZURE_SETUP.md (setup instructions)
4. Run quick-setup.sh (automated setup)
   └── Creates Azure resources
   └── Generates .env file
5. Install dependencies: pip install -r requirements.txt
6. Run scanner: python azure_security_scanner.py
```

### Workflow 2: Manual Setup

```
1. Clone repository
2. Read README.md
3. Follow docs/AZURE_SETUP.md manual steps
4. Create .env from .env.example
5. Install dependencies
6. Run scanner
7. If issues arise → docs/TROUBLESHOOTING.md
```

### Workflow 3: Learning Flow

```
1. README.md → Understanding project goals
2. azure_security_scanner.py → See code implementation
3. docs/SECURITY_BEST_PRACTICES.md → Learn security concepts
4. Run scanner on your subscription
5. Analyze generated reports
6. Implement fixes for findings
7. Re-scan to verify fixes
```

## 📊 File Statistics

|File                      |Lines|Primary Focus                  |
|--------------------------|-----|-------------------------------|
|README.md                 |~400 |Documentation & Getting Started|
|azure_security_scanner.py |~650 |Application Code               |
|AZURE_SETUP.md            |~550 |Setup Instructions             |
|SECURITY_BEST_PRACTICES.md|~800 |Security Guidelines            |
|TROUBLESHOOTING.md        |~750 |Problem Solving                |
|quick-setup.sh            |~180 |Automation                     |
|requirements.txt          |~10  |Dependencies                   |

**Total**: ~3,340 lines of documentation and code

## 🎯 Key Learning Resources

### For Azure Security Beginners

1. Start with **README.md** (overview)
1. Follow **quick-setup.sh** (hands-on setup)
1. Read **docs/SECURITY_BEST_PRACTICES.md** (learn concepts)
1. Run the scanner and analyze findings

### For Experienced Engineers

1. Review **azure_security_scanner.py** (implementation patterns)
1. Study **docs/SECURITY_BEST_PRACTICES.md** (advanced topics)
1. Customize the scanner for your needs
1. Integrate into CI/CD pipelines

### For Troubleshooting

1. Check **docs/TROUBLESHOOTING.md** first
1. Enable verbose logging: `--verbose`
1. Review `azure_security_scanner.log`
1. Consult error code reference

## 🚀 Quick Commands Reference

```bash
# Setup
./quick-setup.sh                                    # Automated setup
pip install -r requirements.txt                     # Install dependencies

# Running the Scanner
python azure_security_scanner.py                    # Basic scan
python azure_security_scanner.py --verbose          # Verbose output
python azure_security_scanner.py --output html      # HTML report
python azure_security_scanner.py --resource-group "rg-name"  # Specific RG

# Maintenance
az ad sp credential reset --id $SP_ID              # Rotate credentials
git pull origin main                                # Update scanner
pip install -r requirements.txt --upgrade          # Update dependencies
```

## 📚 External Documentation References

### Azure Official Docs

- [Azure Security Documentation](https://docs.microsoft.com/azure/security/)
- [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python)
- [Azure Security Best Practices](https://docs.microsoft.com/azure/security/fundamentals/best-practices-and-patterns)

### Compliance Frameworks

- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Azure Security Baseline](https://docs.microsoft.com/security/benchmark/azure/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Learning Paths

- [Microsoft Learn: Azure Security](https://docs.microsoft.com/learn/paths/az-500-manage-identity-access/)
- [Azure Security Certifications (AZ-500)](https://docs.microsoft.com/certifications/azure-security-engineer/)

## 🔄 Version Control Strategy

```
main                    # Stable release branch
├── feature/*          # New features
├── bugfix/*           # Bug fixes
└── docs/*             # Documentation updates
```

### Recommended Git Workflow

```bash
# Clone repository
git clone https://github.com/[username]/Learning-Azure-Security.git

# Create feature branch
git checkout -b feature/new-security-check

# Make changes
git add .
git commit -m "Add SQL Database security check"

# Push and create PR
git push origin feature/new-security-check
```

## 🎓 Learning Outcomes

By working through this repository, you will learn:

### Technical Skills

- ✅ Azure SDK for Python
- ✅ Azure Resource Manager API
- ✅ Azure Active Directory authentication
- ✅ Key Vault operations
- ✅ RBAC and IAM
- ✅ Python application development
- ✅ Error handling and logging
- ✅ Report generation

### Security Concepts

- ✅ Azure security best practices
- ✅ Common misconfigurations
- ✅ Security monitoring
- ✅ Compliance checking
- ✅ Incident response
- ✅ Defense in depth

### DevOps Practices

- ✅ Infrastructure as Code
- ✅ Security automation
- ✅ CI/CD integration
- ✅ Secrets management
- ✅ Logging and monitoring

## 🤝 Contributing

See contribution guidelines in README.md:

1. Fork the repository
1. Create a feature branch
1. Make your changes
1. Submit a pull request

## 📝 Changelog

### Version 1.0.0 (2025-10-28)

- Initial release
- Core security scanning functionality
- Support for Storage, Network, Compute, Key Vault
- JSON and HTML reporting
- Comprehensive documentation

### Planned Features

- [ ] Azure Policy compliance checking
- [ ] SQL Database security scanning
- [ ] App Service security assessment
- [ ] Azure Sentinel integration
- [ ] Automated remediation
- [ ] Cost analysis

## 📞 Support

- **Issues**: GitHub Issues
- **Documentation**: All docs in `/docs`
- **Troubleshooting**: `docs/TROUBLESHOOTING.md`
- **Security**: Report vulnerabilities privately

-----

**Ready to get started?** Begin with [README.md](../README.md)!
