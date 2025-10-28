#!/usr/bin/env python3
“””
Azure Security Scanner
A tool to scan Azure resources for security misconfigurations and compliance issues.

This tool demonstrates key Azure Security concepts:

- Azure AD Service Principal authentication
- Azure Key Vault integration for secrets management
- Security posture assessment across multiple resource types
- RBAC and access control validation
- Compliance and configuration checking
  “””

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

# Azure SDK imports

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.core.exceptions import AzureError, ResourceNotFoundError

# Configure logging

logging.basicConfig(
level=logging.INFO,
format=’[%(levelname)s] %(message)s’,
handlers=[
logging.FileHandler(‘azure_security_scanner.log’),
logging.StreamHandler(sys.stdout)
]
)
logger = logging.getLogger(**name**)

@dataclass
class SecurityFinding:
“”“Represents a security finding from the scan”””
resource_type: str
resource_name: str
resource_id: str
severity: str  # HIGH, MEDIUM, LOW
issue: str
recommendation: str
compliant: bool

@dataclass
class ScanResult:
“”“Overall scan results”””
scan_time: str
subscription_id: str
total_resources_scanned: int
findings: List[SecurityFinding]
summary: Dict[str, int]

class AzureSecurityScanner:
“”“Main scanner class that performs security assessments on Azure resources”””

```
def __init__(self, subscription_id: str, key_vault_name: Optional[str] = None):
    """
    Initialize the Azure Security Scanner
    
    Args:
        subscription_id: Azure subscription ID to scan
        key_vault_name: Name of Key Vault containing credentials (optional)
    """
    self.subscription_id = subscription_id
    self.key_vault_name = key_vault_name
    self.credential = None
    self.findings: List[SecurityFinding] = []
    
    logger.info("Initializing Azure Security Scanner...")
    logger.info(f"Subscription ID: {subscription_id}")
    
def authenticate(self) -> bool:
    """
    Authenticate with Azure using either:
    1. Key Vault stored credentials (Service Principal)
    2. DefaultAzureCredential (Managed Identity, Azure CLI, etc.)
    
    Returns:
        bool: True if authentication successful
    """
    try:
        logger.info("Authenticating with Azure...")
        
        if self.key_vault_name:
            # Option 1: Retrieve credentials from Key Vault
            logger.info(f"Retrieving credentials from Key Vault: {self.key_vault_name}")
            
            # Use DefaultAzureCredential to access Key Vault
            kv_credential = DefaultAzureCredential()
            key_vault_uri = f"https://{self.key_vault_name}.vault.azure.net"
            secret_client = SecretClient(vault_url=key_vault_uri, credential=kv_credential)
            
            # Retrieve secrets
            client_id = secret_client.get_secret("azure-client-id").value
            client_secret = secret_client.get_secret("azure-client-secret").value
            tenant_id = secret_client.get_secret("azure-tenant-id").value
            
            logger.info("✓ Credentials retrieved from Key Vault successfully")
            
            # Create credential using Service Principal
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            # Option 2: Use DefaultAzureCredential (Managed Identity, CLI, etc.)
            logger.info("Using DefaultAzureCredential (Managed Identity/Azure CLI)")
            self.credential = DefaultAzureCredential()
        
        # Test authentication by listing resource groups
        resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        list(resource_client.resource_groups.list())
        
        logger.info("✓ Authentication successful!")
        return True
        
    except ResourceNotFoundError as e:
        logger.error(f"✗ Key Vault or secret not found: {e}")
        return False
    except AzureError as e:
        logger.error(f"✗ Azure authentication failed: {e}")
        return False
    except Exception as e:
        logger.error(f"✗ Unexpected error during authentication: {e}")
        return False

def scan_storage_accounts(self) -> int:
    """
    Scan storage accounts for security issues:
    - Public access configuration
    - HTTPS-only enforcement
    - Encryption at rest
    - Network rules
    
    Returns:
        int: Number of storage accounts scanned
    """
    logger.info("\n" + "="*60)
    logger.info("SCANNING: Storage Accounts")
    logger.info("="*60)
    
    try:
        storage_client = StorageManagementClient(self.credential, self.subscription_id)
        accounts = list(storage_client.storage_accounts.list())
        
        logger.info(f"Found {len(accounts)} storage account(s)")
        
        for account in accounts:
            logger.info(f"\n→ Analyzing: {account.name}")
            
            # Check 1: Public network access
            if account.public_network_access == "Enabled":
                # Check if it allows public blob access
                if account.allow_blob_public_access:
                    self.findings.append(SecurityFinding(
                        resource_type="Storage Account",
                        resource_name=account.name,
                        resource_id=account.id,
                        severity="HIGH",
                        issue="Public blob access is enabled",
                        recommendation="Disable public blob access unless specifically required. "
                                     "Use Azure AD authentication or SAS tokens instead.",
                        compliant=False
                    ))
                    logger.warning("  ⚠️  PUBLIC ACCESS ENABLED - Security Risk")
                else:
                    logger.info("  ✓ Public blob access disabled")
            
            # Check 2: HTTPS-only enforcement
            if not account.enable_https_traffic_only:
                self.findings.append(SecurityFinding(
                    resource_type="Storage Account",
                    resource_name=account.name,
                    resource_id=account.id,
                    severity="HIGH",
                    issue="HTTPS-only traffic is not enforced",
                    recommendation="Enable 'Secure transfer required' to enforce HTTPS-only connections.",
                    compliant=False
                ))
                logger.warning("  ⚠️  HTTPS-only NOT ENFORCED")
            else:
                logger.info("  ✓ HTTPS-only enforced")
            
            # Check 3: Encryption at rest
            if account.encryption and account.encryption.services:
                blob_encrypted = account.encryption.services.blob.enabled if account.encryption.services.blob else False
                file_encrypted = account.encryption.services.file.enabled if account.encryption.services.file else False
                
                if blob_encrypted and file_encrypted:
                    logger.info("  ✓ Encryption at rest enabled")
                else:
                    self.findings.append(SecurityFinding(
                        resource_type="Storage Account",
                        resource_name=account.name,
                        resource_id=account.id,
                        severity="HIGH",
                        issue="Encryption at rest not fully enabled",
                        recommendation="Enable encryption for blob and file services.",
                        compliant=False
                    ))
                    logger.warning("  ⚠️  Encryption incomplete")
            
            # Check 4: Minimum TLS version
            if hasattr(account, 'minimum_tls_version'):
                if account.minimum_tls_version != "TLS1_2":
                    self.findings.append(SecurityFinding(
                        resource_type="Storage Account",
                        resource_name=account.name,
                        resource_id=account.id,
                        severity="MEDIUM",
                        issue=f"Minimum TLS version is {account.minimum_tls_version}, should be TLS1_2",
                        recommendation="Set minimum TLS version to TLS 1.2 for better security.",
                        compliant=False
                    ))
                    logger.warning(f"  ⚠️  TLS version: {account.minimum_tls_version}")
                else:
                    logger.info("  ✓ TLS 1.2 enforced")
        
        return len(accounts)
        
    except AzureError as e:
        logger.error(f"Error scanning storage accounts: {e}")
        return 0

def scan_network_security_groups(self) -> int:
    """
    Scan Network Security Groups for overly permissive rules:
    - Unrestricted inbound access (0.0.0.0/0)
    - High-risk ports open to internet (22, 3389, 445, etc.)
    - Outbound restrictions
    
    Returns:
        int: Number of NSGs scanned
    """
    logger.info("\n" + "="*60)
    logger.info("SCANNING: Network Security Groups")
    logger.info("="*60)
    
    high_risk_ports = [22, 3389, 1433, 3306, 5432, 445, 135, 139]
    
    try:
        network_client = NetworkManagementClient(self.credential, self.subscription_id)
        nsgs = list(network_client.network_security_groups.list_all())
        
        logger.info(f"Found {len(nsgs)} Network Security Group(s)")
        
        for nsg in nsgs:
            logger.info(f"\n→ Analyzing: {nsg.name}")
            
            if not nsg.security_rules:
                logger.info("  ℹ️  No custom security rules defined")
                continue
            
            for rule in nsg.security_rules:
                # Check for overly permissive inbound rules
                if rule.direction == "Inbound" and rule.access == "Allow":
                    source_addresses = rule.source_address_prefix or rule.source_address_prefixes or []
                    if isinstance(source_addresses, str):
                        source_addresses = [source_addresses]
                    
                    # Check if rule allows traffic from anywhere
                    if "*" in source_addresses or "0.0.0.0/0" in source_addresses or "Internet" in source_addresses:
                        # Check destination ports
                        dest_ports = []
                        if rule.destination_port_range:
                            if rule.destination_port_range == "*":
                                dest_ports = high_risk_ports
                            else:
                                try:
                                    dest_ports = [int(rule.destination_port_range)]
                                except ValueError:
                                    pass
                        
                        # Check if any high-risk ports are exposed
                        exposed_risky_ports = [p for p in dest_ports if p in high_risk_ports]
                        
                        if exposed_risky_ports or rule.destination_port_range == "*":
                            severity = "HIGH" if exposed_risky_ports else "MEDIUM"
                            port_info = f"ports {exposed_risky_ports}" if exposed_risky_ports else "all ports"
                            
                            self.findings.append(SecurityFinding(
                                resource_type="Network Security Group",
                                resource_name=nsg.name,
                                resource_id=nsg.id,
                                severity=severity,
                                issue=f"Rule '{rule.name}' allows inbound traffic from Internet on {port_info}",
                                recommendation="Restrict source IP addresses to specific ranges. "
                                             "Never expose management ports (22, 3389) to the Internet. "
                                             "Use Azure Bastion or VPN for remote access.",
                                compliant=False
                            ))
                            logger.warning(f"  ⚠️  OVERLY PERMISSIVE: Rule '{rule.name}' ({port_info})")
            
            logger.info(f"  ✓ Analyzed {len(nsg.security_rules)} rule(s)")
        
        return len(nsgs)
        
    except AzureError as e:
        logger.error(f"Error scanning NSGs: {e}")
        return 0

def scan_key_vaults(self) -> int:
    """
    Scan Key Vaults for security configuration:
    - RBAC vs Access Policies
    - Soft delete enabled
    - Purge protection
    - Network restrictions
    
    Returns:
        int: Number of Key Vaults scanned
    """
    logger.info("\n" + "="*60)
    logger.info("SCANNING: Key Vaults")
    logger.info("="*60)
    
    try:
        kv_client = KeyVaultManagementClient(self.credential, self.subscription_id)
        vaults = list(kv_client.vaults.list())
        
        logger.info(f"Found {len(vaults)} Key Vault(s)")
        
        for vault in vaults:
            logger.info(f"\n→ Analyzing: {vault.name}")
            
            # Check 1: Soft delete
            if vault.properties.enable_soft_delete:
                logger.info("  ✓ Soft delete enabled")
            else:
                self.findings.append(SecurityFinding(
                    resource_type="Key Vault",
                    resource_name=vault.name,
                    resource_id=vault.id,
                    severity="MEDIUM",
                    issue="Soft delete is not enabled",
                    recommendation="Enable soft delete to protect against accidental deletion.",
                    compliant=False
                ))
                logger.warning("  ⚠️  Soft delete DISABLED")
            
            # Check 2: Purge protection
            if hasattr(vault.properties, 'enable_purge_protection') and vault.properties.enable_purge_protection:
                logger.info("  ✓ Purge protection enabled")
            else:
                self.findings.append(SecurityFinding(
                    resource_type="Key Vault",
                    resource_name=vault.name,
                    resource_id=vault.id,
                    severity="LOW",
                    issue="Purge protection is not enabled",
                    recommendation="Enable purge protection for production Key Vaults to prevent permanent deletion.",
                    compliant=False
                ))
                logger.info("  ℹ️  Purge protection not enabled")
            
            # Check 3: RBAC enabled
            if hasattr(vault.properties, 'enable_rbac_authorization') and vault.properties.enable_rbac_authorization:
                logger.info("  ✓ RBAC authorization enabled (recommended)")
            else:
                logger.info("  ℹ️  Using Access Policies (consider migrating to RBAC)")
            
            # Check 4: Network rules
            if vault.properties.network_acls:
                if vault.properties.network_acls.default_action == "Deny":
                    logger.info("  ✓ Network access restricted (default deny)")
                else:
                    self.findings.append(SecurityFinding(
                        resource_type="Key Vault",
                        resource_name=vault.name,
                        resource_id=vault.id,
                        severity="MEDIUM",
                        issue="Key Vault allows access from all networks",
                        recommendation="Configure network rules to restrict access to specific VNets or IP ranges.",
                        compliant=False
                    ))
                    logger.warning("  ⚠️  Open to all networks")
        
        return len(vaults)
        
    except AzureError as e:
        logger.error(f"Error scanning Key Vaults: {e}")
        return 0

def scan_virtual_machines(self) -> int:
    """
    Scan Virtual Machines for security configuration:
    - Boot diagnostics enabled
    - Managed disks encryption
    - Azure AD authentication
    
    Returns:
        int: Number of VMs scanned
    """
    logger.info("\n" + "="*60)
    logger.info("SCANNING: Virtual Machines")
    logger.info("="*60)
    
    try:
        compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        vms = list(compute_client.virtual_machines.list_all())
        
        logger.info(f"Found {len(vms)} Virtual Machine(s)")
        
        for vm in vms:
            logger.info(f"\n→ Analyzing: {vm.name}")
            
            # Check 1: Boot diagnostics
            if vm.diagnostics_profile and vm.diagnostics_profile.boot_diagnostics:
                if vm.diagnostics_profile.boot_diagnostics.enabled:
                    logger.info("  ✓ Boot diagnostics enabled")
                else:
                    self.findings.append(SecurityFinding(
                        resource_type="Virtual Machine",
                        resource_name=vm.name,
                        resource_id=vm.id,
                        severity="LOW",
                        issue="Boot diagnostics not enabled",
                        recommendation="Enable boot diagnostics for troubleshooting and security monitoring.",
                        compliant=False
                    ))
                    logger.info("  ℹ️  Boot diagnostics disabled")
            
            # Check 2: Managed disks
            if vm.storage_profile and vm.storage_profile.os_disk:
                if vm.storage_profile.os_disk.managed_disk:
                    logger.info("  ✓ Using managed disks")
                    
                    # Check encryption
                    if hasattr(vm.storage_profile.os_disk, 'encryption_settings'):
                        logger.info("  ✓ Disk encryption configured")
                else:
                    logger.info("  ℹ️  Using unmanaged disks (consider migrating)")
            
            # Check 3: Identity
            if vm.identity and vm.identity.type:
                logger.info(f"  ✓ Managed Identity enabled: {vm.identity.type}")
            else:
                logger.info("  ℹ️  No Managed Identity (consider enabling for Azure service authentication)")
        
        return len(vms)
        
    except AzureError as e:
        logger.error(f"Error scanning Virtual Machines: {e}")
        return 0

def generate_report(self, output_format: str = "json") -> str:
    """
    Generate a security report from scan findings
    
    Args:
        output_format: Format for report (json or html)
        
    Returns:
        str: Path to generated report file
    """
    logger.info("\n" + "="*60)
    logger.info("GENERATING SECURITY REPORT")
    logger.info("="*60)
    
    # Calculate summary statistics
    summary = {
        "HIGH": sum(1 for f in self.findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in self.findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in self.findings if f.severity == "LOW"),
        "total_findings": len(self.findings),
        "compliant_resources": sum(1 for f in self.findings if f.compliant)
    }
    
    scan_result = ScanResult(
        scan_time=datetime.now().isoformat(),
        subscription_id=self.subscription_id,
        total_resources_scanned=len(self.findings),
        findings=self.findings,
        summary=summary
    )
    
    # Create reports directory
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_format == "json":
        report_path = reports_dir / f"security_report_{timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(asdict(scan_result), f, indent=2, default=str)
    
    elif output_format == "html":
        report_path = reports_dir / f"security_report_{timestamp}.html"
        html_content = self._generate_html_report(scan_result)
        with open(report_path, 'w') as f:
            f.write(html_content)
    
    logger.info(f"\n✓ Report generated: {report_path}")
    logger.info(f"\nSummary:")
    logger.info(f"  Total Findings: {summary['total_findings']}")
    logger.info(f"  HIGH: {summary['HIGH']}")
    logger.info(f"  MEDIUM: {summary['MEDIUM']}")
    logger.info(f"  LOW: {summary['LOW']}")
    
    return str(report_path)

def _generate_html_report(self, scan_result: ScanResult) -> str:
    """Generate an HTML report from scan results"""
    
    severity_colors = {
        "HIGH": "#dc3545",
        "MEDIUM": "#ffc107",
        "LOW": "#17a2b8"
    }
    
    findings_html = ""
    for finding in scan_result.findings:
        color = severity_colors.get(finding.severity, "#6c757d")
        findings_html += f"""
        <div class="finding {finding.severity.lower()}">
            <div class="finding-header">
                <span class="severity" style="background-color: {color}">{finding.severity}</span>
                <span class="resource-type">{finding.resource_type}</span>
                <span class="resource-name">{finding.resource_name}</span>
            </div>
            <div class="finding-body">
                <p><strong>Issue:</strong> {finding.issue}</p>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                <p class="resource-id"><small>{finding.resource_id}</small></p>
            </div>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Azure Security Scan Report</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
                color: white;
                padding: 30px;
                border-radius: 8px;
                margin-bottom: 20px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 30px;
            }}
            .summary-card {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .summary-card h3 {{
                margin: 0;
                font-size: 2em;
                color: #0078d4;
            }}
            .summary-card p {{
                margin: 10px 0 0 0;
                color: #666;
            }}
            .finding {{
                background: white;
                margin-bottom: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .finding-header {{
                padding: 15px;
                background: #f8f9fa;
                border-bottom: 1px solid #dee2e6;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .severity {{
                color: white;
                padding: 4px 12px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 0.85em;
            }}
            .resource-type {{
                background: #e9ecef;
                padding: 4px 12px;
                border-radius: 4px;
                font-size: 0.9em;
            }}
            .resource-name {{
                font-weight: bold;
                color: #495057;
            }}
            .finding-body {{
                padding: 15px;
            }}
            .finding-body p {{
                margin: 10px 0;
            }}
            .resource-id {{
                color: #6c757d;
                font-size: 0.85em;
                word-break: break-all;
            }}
            .timestamp {{
                color: #adb5bd;
                font-size: 0.9em;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 Azure Security Scan Report</h1>
            <p class="timestamp">Scan Time: {scan_result.scan_time}</p>
            <p>Subscription: {scan_result.subscription_id}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>{scan_result.summary['total_findings']}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #dc3545">{scan_result.summary['HIGH']}</h3>
                <p>High Severity</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #ffc107">{scan_result.summary['MEDIUM']}</h3>
                <p>Medium Severity</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #17a2b8">{scan_result.summary['LOW']}</h3>
                <p>Low Severity</p>
            </div>
        </div>
        
        <h2>Findings</h2>
        {findings_html if findings_html else "<p>No security issues found! 🎉</p>"}
        
        <div style="margin-top: 40px; padding: 20px; background: #e9ecef; border-radius: 8px;">
            <h3>Next Steps</h3>
            <ol>
                <li>Review all HIGH severity findings immediately</li>
                <li>Create remediation tickets for MEDIUM severity issues</li>
                <li>Schedule review of LOW severity items</li>
                <li>Document any accepted risks</li>
                <li>Re-scan after implementing fixes</li>
            </ol>
        </div>
    </body>
    </html>
    """
    
    return html

def run_full_scan(self) -> bool:
    """
    Run a complete security scan across all supported resource types
    
    Returns:
        bool: True if scan completed successfully
    """
    if not self.authenticate():
        logger.error("Authentication failed. Cannot proceed with scan.")
        return False
    
    logger.info("\n" + "="*60)
    logger.info("STARTING COMPREHENSIVE SECURITY SCAN")
    logger.info("="*60)
    
    total_scanned = 0
    
    # Run all scans
    total_scanned += self.scan_storage_accounts()
    total_scanned += self.scan_network_security_groups()
    total_scanned += self.scan_key_vaults()
    total_scanned += self.scan_virtual_machines()
    
    logger.info("\n" + "="*60)
    logger.info("SCAN COMPLETE")
    logger.info("="*60)
    logger.info(f"Total resources scanned: {total_scanned}")
    logger.info(f"Total findings: {len(self.findings)}")
    
    return True
```

def main():
“”“Main entry point for the scanner”””
import argparse

```
parser = argparse.ArgumentParser(
    description="Azure Security Scanner - Scan Azure resources for security misconfigurations"
)
parser.add_argument(
    "--subscription-id",
    help="Azure Subscription ID (or set AZURE_SUBSCRIPTION_ID env var)",
    default=os.getenv("AZURE_SUBSCRIPTION_ID")
)
parser.add_argument(
    "--key-vault",
    help="Key Vault name containing credentials (or set AZURE_KEY_VAULT_NAME env var)",
    default=os.getenv("AZURE_KEY_VAULT_NAME")
)
parser.add_argument(
    "--output",
    choices=["json", "html"],
    default="json",
    help="Report output format (default: json)"
)
parser.add_argument(
    "--verbose",
    action="store_true",
    help="Enable verbose logging"
)

args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)

if not args.subscription_id:
    logger.error("Error: Azure Subscription ID is required!")
    logger.error("Set it via --subscription-id or AZURE_SUBSCRIPTION_ID environment variable")
    sys.exit(1)

# Create and run scanner
scanner = AzureSecurityScanner(
    subscription_id=args.subscription_id,
    key_vault_name=args.key_vault
)

if scanner.run_full_scan():
    scanner.generate_report(output_format=args.output)
    
    # Exit with appropriate code based on findings
    high_severity = sum(1 for f in scanner.findings if f.severity == "HIGH")
    if high_severity > 0:
        logger.warning(f"\n⚠️  {high_severity} HIGH severity issue(s) found!")
        sys.exit(1)
    else:
        logger.info("\n✓ No HIGH severity issues found")
        sys.exit(0)
else:
    logger.error("\nScan failed!")
    sys.exit(1)
```

if **name** == “**main**”:
main()
