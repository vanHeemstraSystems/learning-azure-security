# Azure Security Best Practices

This document outlines security best practices for Azure resources, demonstrated through the Security Scanner and applicable to production environments.

## Table of Contents

1. [Identity and Access Management](#identity-and-access-management)
1. [Secrets Management](#secrets-management)
1. [Network Security](#network-security)
1. [Data Protection](#data-protection)
1. [Monitoring and Logging](#monitoring-and-logging)
1. [Compliance and Governance](#compliance-and-governance)
1. [Security Scanner Best Practices](#security-scanner-best-practices)
1. [Incident Response](#incident-response)

## Identity and Access Management

### Principle of Least Privilege

**Always grant the minimum permissions necessary.**

```bash
# ❌ BAD: Giving Contributor role when only read access needed
az role assignment create \
  --assignee $SP_ID \
  --role "Contributor" \
  --scope "/subscriptions/$SUB_ID"

# ✅ GOOD: Using Reader role for read-only operations
az role assignment create \
  --assignee $SP_ID \
  --role "Reader" \
  --scope "/subscriptions/$SUB_ID"
```

### Service Principal Security

**Best Practices:**

1. **Use separate Service Principals for different purposes**
   
   ```bash
   # Production scanner
   az ad sp create-for-rbac --name "ProdSecurityScanner" --role "Reader"
   
   # Development scanner
   az ad sp create-for-rbac --name "DevSecurityScanner" --role "Reader"
   ```
1. **Set credential expiration**
   
   ```bash
   # Create SP with 90-day credential lifetime
   az ad sp create-for-rbac \
     --name "AzureSecurityScanner" \
     --years 0 \
     --create-cert false
   
   # Rotate credentials every 90 days
   az ad sp credential reset --id $SP_ID
   ```
1. **Use certificates instead of secrets when possible**
   
   ```bash
   # Create Service Principal with certificate
   az ad sp create-for-rbac \
     --name "AzureSecurityScanner" \
     --create-cert \
     --cert "scanner-cert"
   ```
1. **Regularly audit Service Principal usage**
   
   ```bash
   # List all sign-ins for a Service Principal
   az monitor activity-log list \
     --caller $SP_APP_ID \
     --max-events 100
   ```

### Multi-Factor Authentication (MFA)

**Enable MFA for all user accounts:**

- Interactive accounts should require MFA
- Service Principals use certificates/secrets (no MFA)
- Managed Identities automatically secure (no credentials to manage)

### Azure AD Conditional Access

**Implement conditional access policies:**

```json
{
  "displayName": "Require MFA for Security Scanning Tools",
  "state": "enabled",
  "conditions": {
    "applications": {
      "includeApplications": ["ServicePrincipalId"]
    },
    "locations": {
      "includeLocations": ["AllTrusted"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

### Managed Identity Best Practices

**When running on Azure resources, always prefer Managed Identity:**

✅ **Advantages:**

- No credential management
- Automatic credential rotation
- Cannot be exported or shared
- Audited through Azure AD logs

```bash
# Enable system-assigned managed identity for VM
az vm identity assign --name MyVM --resource-group MyRG

# Enable for App Service
az webapp identity assign --name MyApp --resource-group MyRG

# Enable for Azure Functions
az functionapp identity assign --name MyFunc --resource-group MyRG
```

## Secrets Management

### Azure Key Vault Best Practices

**1. Enable Soft Delete and Purge Protection**

```bash
# Enable soft delete (90-day retention)
az keyvault update \
  --name MyKeyVault \
  --enable-soft-delete true \
  --retention-days 90

# Enable purge protection (prevents permanent deletion)
az keyvault update \
  --name MyKeyVault \
  --enable-purge-protection true
```

**2. Use RBAC instead of Access Policies**

```bash
# ✅ GOOD: Use RBAC for centralized access management
az keyvault create \
  --name MyKeyVault \
  --resource-group MyRG \
  --enable-rbac-authorization true

# Assign granular permissions
az role assignment create \
  --assignee $USER_ID \
  --role "Key Vault Secrets Officer" \
  --scope $VAULT_ID
```

**3. Implement Network Restrictions**

```bash
# Restrict Key Vault to specific networks
az keyvault network-rule add \
  --name MyKeyVault \
  --vnet-name MyVNet \
  --subnet MySubnet

# Set default action to deny
az keyvault update \
  --name MyKeyVault \
  --default-action Deny
```

**4. Enable Diagnostic Logging**

```bash
# Send Key Vault logs to Log Analytics
az monitor diagnostic-settings create \
  --name kv-diagnostics \
  --resource $VAULT_ID \
  --workspace $WORKSPACE_ID \
  --logs '[{"category": "AuditEvent","enabled": true}]'
```

**5. Implement Secret Rotation**

```python
# Example: Automated secret rotation
from datetime import datetime, timedelta

def check_secret_age(secret_client, secret_name):
    secret = secret_client.get_secret(secret_name)
    created_on = secret.properties.created_on
    age = datetime.now(created_on.tzinfo) - created_on
    
    # Alert if secret is older than 90 days
    if age > timedelta(days=90):
        print(f"⚠️  Secret '{secret_name}' is {age.days} days old - rotation recommended")
        return True
    return False
```

**6. Use Separate Key Vaults for Different Environments**

```
Production:   prod-keyvault
Staging:      staging-keyvault  
Development:  dev-keyvault
```

**7. Never Hardcode Secrets**

```python
# ❌ BAD: Hardcoded secret
storage_key = "DefaultEndpointsProtocol=https;AccountName=..."

# ✅ GOOD: Retrieved from Key Vault
from azure.keyvault.secrets import SecretClient
secret_client = SecretClient(vault_url=vault_url, credential=credential)
storage_key = secret_client.get_secret("storage-key").value
```

## Network Security

### Network Security Groups (NSGs)

**1. Default Deny Principle**

```bash
# Create NSG with default deny
az network nsg create \
  --name MyNSG \
  --resource-group MyRG

# Only open required ports explicitly
az network nsg rule create \
  --name AllowHTTPS \
  --nsg-name MyNSG \
  --priority 100 \
  --source-address-prefixes "10.0.0.0/16" \
  --destination-port-ranges 443 \
  --access Allow
```

**2. Never Expose Management Ports to Internet**

```bash
# ❌ BAD: SSH open to the internet
az network nsg rule create \
  --name AllowSSH \
  --nsg-name MyNSG \
  --source-address-prefixes "*" \
  --destination-port-ranges 22 \
  --access Allow

# ✅ GOOD: Use Azure Bastion or VPN
az network bastion create \
  --name MyBastion \
  --resource-group MyRG \
  --vnet-name MyVNet
```

**3. Use Service Tags Instead of IP Ranges**

```bash
# Use service tags for Azure services
az network nsg rule create \
  --name AllowStorageOutbound \
  --nsg-name MyNSG \
  --direction Outbound \
  --source-address-prefixes "VirtualNetwork" \
  --destination-address-prefixes "Storage" \
  --destination-port-ranges 443 \
  --access Allow
```

**4. Enable NSG Flow Logs**

```bash
# Create storage account for flow logs
az storage account create \
  --name nsgflowlogs \
  --resource-group MyRG

# Enable NSG flow logs
az network watcher flow-log create \
  --name MyFlowLog \
  --nsg MyNSG \
  --storage-account nsgflowlogs \
  --enabled true \
  --retention 90
```

### Azure Firewall

**Use Azure Firewall for centralized network security:**

```bash
# Deploy Azure Firewall
az network firewall create \
  --name MyFirewall \
  --resource-group MyRG \
  --location eastus

# Create application rules
az network firewall application-rule create \
  --firewall-name MyFirewall \
  --name AllowAzureServices \
  --protocols "https=443" \
  --target-fqdns "*.azure.com" "*.microsoft.com" \
  --source-addresses "10.0.0.0/16"
```

### Private Endpoints

**Use Private Endpoints for Azure PaaS services:**

```bash
# Create private endpoint for Storage Account
az network private-endpoint create \
  --name MyStoragePrivateEndpoint \
  --resource-group MyRG \
  --vnet-name MyVNet \
  --subnet PrivateEndpointSubnet \
  --private-connection-resource-id $STORAGE_ID \
  --group-id blob \
  --connection-name MyConnection
```

## Data Protection

### Storage Account Security

**1. Disable Public Access**

```bash
# Disable public blob access
az storage account update \
  --name mystorageaccount \
  --resource-group MyRG \
  --allow-blob-public-access false
```

**2. Enforce HTTPS-Only**

```bash
# Require secure transfer
az storage account update \
  --name mystorageaccount \
  --https-only true \
  --min-tls-version TLS1_2
```

**3. Enable Encryption at Rest**

```bash
# Enable infrastructure encryption (double encryption)
az storage account create \
  --name mystorageaccount \
  --resource-group MyRG \
  --encryption-services blob file \
  --require-infrastructure-encryption true
```

**4. Use Customer-Managed Keys (CMK)**

```bash
# Enable CMK with Key Vault
az storage account update \
  --name mystorageaccount \
  --encryption-key-source Microsoft.Keyvault \
  --encryption-key-vault $VAULT_URI \
  --encryption-key-name my-key
```

**5. Enable Blob Versioning and Soft Delete**

```bash
# Enable blob soft delete (14-day retention)
az storage account blob-service-properties update \
  --account-name mystorageaccount \
  --enable-delete-retention true \
  --delete-retention-days 14

# Enable versioning
az storage account blob-service-properties update \
  --account-name mystorageaccount \
  --enable-versioning true
```

### SQL Database Security

**1. Enable Transparent Data Encryption (TDE)**

```bash
# TDE is enabled by default, verify it's on
az sql db tde show \
  --server myserver \
  --database mydb \
  --resource-group MyRG
```

**2. Use Azure AD Authentication**

```bash
# Set Azure AD admin
az sql server ad-admin create \
  --server myserver \
  --resource-group MyRG \
  --display-name "DB Admin" \
  --object-id $USER_OBJECT_ID
```

**3. Enable Advanced Threat Protection**

```bash
# Enable ATP
az sql server threat-policy update \
  --server myserver \
  --resource-group MyRG \
  --state Enabled \
  --email-addresses security@company.com
```

**4. Implement Dynamic Data Masking**

```sql
-- Mask sensitive columns
ALTER TABLE Customers
ALTER COLUMN Email ADD MASKED WITH (FUNCTION = 'email()');

ALTER TABLE Customers  
ALTER COLUMN CreditCard ADD MASKED WITH (FUNCTION = 'partial(0,"XXXX-XXXX-XXXX-",4)');
```

## Monitoring and Logging

### Enable Diagnostic Settings

**For all critical resources:**

```bash
# Enable diagnostics for Storage Account
az monitor diagnostic-settings create \
  --name storage-diagnostics \
  --resource $STORAGE_ID \
  --workspace $WORKSPACE_ID \
  --logs '[{"category": "StorageRead","enabled": true},
           {"category": "StorageWrite","enabled": true}]' \
  --metrics '[{"category": "Transaction","enabled": true}]'
```

### Azure Monitor Alerts

**Set up proactive alerts:**

```bash
# Alert on failed authentication attempts
az monitor metrics alert create \
  --name high-failed-auth \
  --resource-group MyRG \
  --scopes $KEYVAULT_ID \
  --condition "total FailedRequests > 10" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --action $ACTION_GROUP_ID
```

### Log Analytics Queries

**Common security queries:**

```kusto
// Failed Key Vault access attempts
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResultType != "Success"
| summarize FailedAttempts=count() by CallerIPAddress, OperationName
| order by FailedAttempts desc

// Unusual resource modifications
AzureActivity
| where OperationNameValue endswith "write"
| where ActivityStatusValue == "Success"
| where TimeGenerated > ago(24h)
| summarize Operations=count() by Caller, ResourceGroup
| where Operations > 100

// NSG rule changes
AzureActivity
| where OperationNameValue has "Microsoft.Network/networkSecurityGroups"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup
```

### Azure Sentinel

**For advanced threat detection:**

```bash
# Enable Sentinel on workspace
az sentinel workspace create \
  --resource-group MyRG \
  --workspace-name MyWorkspace
```

## Compliance and Governance

### Azure Policy

**Enforce security standards:**

```bash
# Assign built-in policy: Require HTTPS for storage accounts
az policy assignment create \
  --name require-https-storage \
  --policy /providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9 \
  --scope /subscriptions/$SUB_ID

# Custom policy: Require specific tags
az policy definition create \
  --name require-security-tags \
  --rules '{
    "if": {
      "allOf": [
        {"field": "type", "equals": "Microsoft.Resources/subscriptions/resourceGroups"},
        {"field": "tags.SecurityLevel", "exists": "false"}
      ]
    },
    "then": {
      "effect": "deny"
    }
  }'
```

### Azure Blueprints

**Deploy compliant environments:**

```bash
# Create blueprint with security baseline
az blueprint create \
  --name SecurityBaseline \
  --resource-group MyRG \
  --description "CIS Azure Foundations Benchmark"
```

### Resource Locks

**Prevent accidental deletion:**

```bash
# Apply CanNotDelete lock to production resources
az lock create \
  --name ProductionLock \
  --lock-type CanNotDelete \
  --resource-group production-rg
```

## Security Scanner Best Practices

### Running the Scanner Securely

**1. Use Managed Identity in Production**

```bash
# For Azure VMs
az vm identity assign --name ScannerVM --resource-group MyRG

# Run scanner without credentials
python azure_security_scanner.py
```

**2. Schedule Regular Scans**

```bash
# Using cron for weekly scans
0 2 * * 1 cd /opt/security-scanner && python azure_security_scanner.py --output html
```

**3. Secure Report Storage**

```python
# Upload reports to secure storage
from azure.storage.blob import BlobServiceClient

blob_client = BlobServiceClient.from_connection_string(conn_str)
container_client = blob_client.get_container_client("security-reports")

with open("report.html", "rb") as data:
    container_client.upload_blob(
        name=f"report-{datetime.now()}.html",
        data=data,
        overwrite=True
    )
```

**4. Implement Report Retention**

```bash
# Set lifecycle management on storage account
az storage account management-policy create \
  --account-name myreports \
  --policy '{
    "rules": [{
      "name": "deleteOldReports",
      "type": "Lifecycle",
      "definition": {
        "actions": {
          "baseBlob": {
            "delete": {"daysAfterModificationGreaterThan": 90}
          }
        }
      }
    }]
  }'
```

**5. Alert on High-Severity Findings**

```python
# Example: Send alert for HIGH severity findings
def send_alert_if_critical(findings):
    high_severity = [f for f in findings if f.severity == "HIGH"]
    
    if high_severity:
        # Send to Azure Monitor, email, or Teams
        send_alert(
            title=f"⚠️ {len(high_severity)} Critical Security Issues Found",
            findings=high_severity
        )
```

## Incident Response

### Preparation

**1. Create Incident Response Plan**

- Document roles and responsibilities
- Define escalation procedures
- Maintain contact lists
- Regular tabletop exercises

**2. Enable Azure Security Center**

```bash
# Enable Security Center Standard tier
az security pricing create \
  --name VirtualMachines \
  --tier Standard
```

**3. Configure Security Contacts**

```bash
# Set security contact
az security contact create \
  --name default \
  --email security@company.com \
  --phone "555-1234" \
  --alert-notifications On
```

### Detection

**Monitor for suspicious activities:**

```kusto
// Suspicious Service Principal activity
AzureActivity
| where Caller contains "ServicePrincipal"
| where ActivityStatusValue == "Failure"
| summarize FailureCount=count() by Caller, OperationNameValue
| where FailureCount > 50
```

### Response

**1. Isolate Compromised Resources**

```bash
# Update NSG to block all traffic
az network nsg rule update \
  --name DenyAll \
  --nsg-name CompromisedVM-NSG \
  --priority 100 \
  --access Deny \
  --source-address-prefixes "*"
```

**2. Rotate Compromised Credentials**

```bash
# Reset Service Principal credentials
az ad sp credential reset --id $SP_ID

# Update Key Vault secrets
az keyvault secret set \
  --vault-name MyVault \
  --name compromised-secret \
  --value NEW_SECRET_VALUE
```

**3. Review Audit Logs**

```bash
# Export activity logs
az monitor activity-log list \
  --start-time 2025-10-01 \
  --end-time 2025-10-28 \
  --caller $COMPROMISED_PRINCIPAL \
  --query "[].{Time:eventTimestamp, Operation:operationName.value, Resource:resourceId}" \
  --output table > incident-log.txt
```

### Recovery

**1. Restore from Clean Backup**
**2. Apply Security Patches**
**3. Re-scan Environment**
**4. Document Lessons Learned**

## Security Checklist

Use this checklist for regular security reviews:

### Identity & Access

- [ ] MFA enabled for all users
- [ ] Service Principals use least privilege
- [ ] Credentials rotated every 90 days
- [ ] Managed Identities used where possible
- [ ] Conditional Access policies configured

### Secrets Management

- [ ] All secrets stored in Key Vault
- [ ] RBAC enabled on Key Vaults
- [ ] Soft delete and purge protection enabled
- [ ] Network restrictions configured
- [ ] Diagnostic logging enabled

### Network Security

- [ ] NSGs follow default deny
- [ ] No management ports exposed to internet
- [ ] Private Endpoints used for PaaS services
- [ ] NSG flow logs enabled
- [ ] Azure Firewall or NVA deployed

### Data Protection

- [ ] Storage accounts require HTTPS
- [ ] Public blob access disabled
- [ ] Encryption at rest enabled
- [ ] TLS 1.2 minimum enforced
- [ ] Backup and retention configured

### Monitoring

- [ ] Diagnostic settings enabled
- [ ] Log Analytics workspace configured
- [ ] Security alerts configured
- [ ] Regular review of logs
- [ ] Incident response plan documented

## Additional Resources

- [Microsoft Security Best Practices](https://docs.microsoft.com/security/compass/compass)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Azure Security Baseline](https://docs.microsoft.com/security/benchmark/azure/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Azure Architecture Center - Security](https://docs.microsoft.com/azure/architecture/framework/security/)

## Contributing

Have additional best practices? Submit a pull request or open an issue!
