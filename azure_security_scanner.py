#!/usr/bin/env python3
"""
Azure Security Scanner

A tool to scan Azure resources for security misconfigurations and
compliance issues.

Key concepts demonstrated:
- Azure AD Service Principal authentication
- Azure Key Vault integration for secrets management
- Security posture assessment across multiple resource types
- RBAC and access control validation
- Compliance and configuration checking
"""

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
    format='[%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('azure_security_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """Represents a security finding from the scan"""
    resource_type: str
    resource_name: str
    resource_id: str
    severity: str  # HIGH, MEDIUM, LOW
    issue: str
    recommendation: str
    compliant: bool


@dataclass
class ScanResult:
    """Overall scan results"""
    scan_time: str
    subscription_id: str
    total_resources_scanned: int
    findings: List[SecurityFinding]
    summary: Dict[str, int]


class AzureSecurityScanner:
    """Main scanner class that performs security assessments on Azure resources"""

    def __init__(self, subscription_id: str, key_vault_name: Optional[str] = None):
        self.subscription_id = subscription_id
        self.key_vault_name = key_vault_name
        self.credential = None
        self.findings: List[SecurityFinding] = []

        logger.info("Initializing Azure Security Scanner...")
        logger.info(
            f"Subscription ID: {subscription_id}"
        )

    def authenticate(self) -> bool:
        """Authenticate using Key Vault-stored SP credentials or DefaultAzureCredential."""
        try:
            logger.info("Authenticating with Azure...")

            if self.key_vault_name:
                # Retrieve credentials from Key Vault
                logger.info(
                    f"Retrieving credentials from Key Vault: {self.key_vault_name}"
                )
                kv_credential = DefaultAzureCredential()
                key_vault_uri = (
                    f"https://{self.key_vault_name}.vault.azure.net"
                )
                secret_client = SecretClient(
                    vault_url=key_vault_uri,
                    credential=kv_credential,
                )

                client_id = secret_client.get_secret("azure-client-id").value
                client_secret = secret_client.get_secret("azure-client-secret").value
                tenant_id = secret_client.get_secret("azure-tenant-id").value

                logger.info("Credentials retrieved from Key Vault successfully")

                self.credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            else:
                logger.info(
                    "Using DefaultAzureCredential (Managed Identity/Azure CLI)"
                )
                self.credential = DefaultAzureCredential()

            # Test by listing resource groups
            resource_client = ResourceManagementClient(
                self.credential,
                self.subscription_id,
            )
            list(resource_client.resource_groups.list())

            logger.info("Authentication successful")
            return True

        except ResourceNotFoundError as e:
            logger.error(f"Key Vault or secret not found: {e}")
            return False
        except AzureError as e:
            logger.error(f"Azure authentication failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {e}")
            return False

    def scan_storage_accounts(self) -> int:
        """Scan storage accounts for common security misconfigurations."""
        logger.info("\n" + "=" * 60)
        logger.info("SCANNING: Storage Accounts")
        logger.info("=" * 60)

        try:
            storage_client = StorageManagementClient(
                self.credential,
                self.subscription_id,
            )
            accounts = list(
                storage_client.storage_accounts.list()
            )
            logger.info(f"Found {len(accounts)} storage account(s)")

            for account in accounts:
                logger.info(f"\n→ Analyzing: {account.name}")

                # Public access
                if getattr(account, 'public_network_access', None) == "Enabled":
                    if getattr(account, 'allow_blob_public_access', False):
                        self.findings.append(
                            SecurityFinding(
                                resource_type="Storage Account",
                                resource_name=account.name,
                                resource_id=account.id,
                                severity="HIGH",
                                issue="Public blob access is enabled",
                                recommendation=(
                                    "Disable public blob access unless required. "
                                    "Use Azure AD or SAS tokens."
                                ),
                                compliant=False,
                            )
                        )
                        logger.warning(
                            "  PUBLIC ACCESS ENABLED - Security Risk"
                        )
                    else:
                        logger.info("  Public blob access disabled")

                # HTTPS-only
                if not getattr(account, 'enable_https_traffic_only', True):
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Storage Account",
                            resource_name=account.name,
                            resource_id=account.id,
                            severity="HIGH",
                            issue="HTTPS-only traffic is not enforced",
                            recommendation=(
                                "Enable 'Secure transfer required' to enforce HTTPS-only."
                            ),
                            compliant=False,
                        )
                    )
                    logger.warning(
                        "  HTTPS-only NOT ENFORCED"
                    )
                else:
                    logger.info("  HTTPS-only enforced")

                # Encryption at rest
                enc = getattr(account, 'encryption', None)
                services = getattr(enc, 'services', None) if enc else None
                blob_encrypted = (
                    bool(getattr(services.blob, 'enabled', False))
                    if services and getattr(services, 'blob', None)
                    else False
                )
                file_encrypted = (
                    bool(getattr(services.file, 'enabled', False))
                    if services and getattr(services, 'file', None)
                    else False
                )
                if blob_encrypted and file_encrypted:
                    logger.info("  Encryption at rest enabled")
                else:
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Storage Account",
                            resource_name=account.name,
                            resource_id=account.id,
                            severity="HIGH",
                            issue="Encryption at rest not fully enabled",
                            recommendation=(
                                "Enable encryption for blob and file services."
                            ),
                            compliant=False,
                        )
                    )
                    logger.warning(
                        "  Encryption incomplete"
                    )

                # Minimum TLS version
                min_tls = getattr(account, 'minimum_tls_version', None)
                if min_tls and min_tls != "TLS1_2":
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Storage Account",
                            resource_name=account.name,
                            resource_id=account.id,
                            severity="MEDIUM",
                            issue=(
                                f"Minimum TLS version is {min_tls}, should be TLS1_2"
                            ),
                            recommendation=(
                                "Set minimum TLS version to TLS 1.2."
                            ),
                            compliant=False,
                        )
                    )
                    logger.warning(
                        f"  TLS version: {min_tls}"
                    )
                elif min_tls:
                    logger.info("  TLS 1.2 enforced")

            return len(accounts)

        except AzureError as e:
            logger.error(f"Error scanning storage accounts: {e}")
            return 0

    def scan_network_security_groups(self) -> int:
        """Scan NSGs for overly permissive rules."""
        logger.info("\n" + "=" * 60)
        logger.info("SCANNING: Network Security Groups")
        logger.info("=" * 60)

        high_risk_ports = [22, 3389, 1433, 3306, 5432, 445, 135, 139]

        try:
            network_client = NetworkManagementClient(
                self.credential,
                self.subscription_id,
            )
            nsgs = list(
                network_client.network_security_groups.list_all()
            )
            logger.info(f"Found {len(nsgs)} Network Security Group(s)")

            for nsg in nsgs:
                logger.info(f"\n→ Analyzing: {nsg.name}")
                if not getattr(nsg, 'security_rules', None):
                    logger.info("  No custom security rules defined")
                    continue

                for rule in nsg.security_rules:
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        source_addresses = rule.source_address_prefix or rule.source_address_prefixes or []
                        if isinstance(source_addresses, str):
                            source_addresses = [source_addresses]

                        if (
                            "*" in source_addresses
                            or "0.0.0.0/0" in source_addresses
                            or "Internet" in source_addresses
                        ):
                            dest_ports: List[int] = []
                            if rule.destination_port_range:
                                if rule.destination_port_range == "*":
                                    dest_ports = high_risk_ports
                                else:
                                    try:
                                        dest_ports = [int(rule.destination_port_range)]
                                    except ValueError:
                                        pass

                            exposed = [p for p in dest_ports if p in high_risk_ports]
                            if exposed or rule.destination_port_range == "*":
                                severity = "HIGH" if exposed else "MEDIUM"
                                port_info = (
                                    f"ports {exposed}" if exposed else "all ports"
                                )
                                self.findings.append(
                                    SecurityFinding(
                                        resource_type=(
                                            "Network Security Group"
                                        ),
                                        resource_name=nsg.name,
                                        resource_id=nsg.id,
                                        severity=severity,
                                        issue=(
                                            f"Rule '{rule.name}' allows inbound Internet on "
                                            f"{port_info}"
                                        ),
                                        recommendation=(
                                            "Restrict source IP ranges. Avoid exposing 22/3389; "
                                            "use Bastion or VPN."
                                        ),
                                        compliant=False,
                                    )
                                )
                                logger.warning(f"  OVERLY PERMISSIVE: Rule '{rule.name}' ({port_info})")

                logger.info(f"  Analyzed {len(nsg.security_rules)} rule(s)")

            return len(nsgs)

        except AzureError as e:
            logger.error(f"Error scanning NSGs: {e}")
            return 0

    def scan_key_vaults(self) -> int:
        """Scan Key Vaults for secure configuration.

        Handles cases where the SDK returns generic Resource objects by
        fetching the full Vault resource via get(resource_group, name).
        """
        logger.info("\n" + "=" * 60)
        logger.info("SCANNING: Key Vaults")
        logger.info("=" * 60)

        try:
            kv_client = KeyVaultManagementClient(
                self.credential,
                self.subscription_id,
            )
            vaults = list(
                kv_client.vaults.list()
            )
            logger.info(f"Found {len(vaults)} Key Vault(s)")

            for vault in vaults:
                # Ensure we have a full Vault model (some SDK versions return
                # generic Resource)
                vault_id = getattr(vault, 'id', None)
                vault_name = getattr(vault, 'name', None)
                logger.info(
                    f"\n→ Analyzing: {vault_name}"
                )

                if not hasattr(vault, 'properties') or vault.properties is None:
                    # Extract resource group from resource ID:
                    # /subscriptions/.../resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}
                    try:
                        parts = (vault_id or '').split('/')
                        rg_idx = parts.index('resourceGroups') + 1
                        resource_group = parts[rg_idx]
                        # Fetch full vault
                        vault = kv_client.vaults.get(resource_group, vault_name)
                    except Exception:
                        logger.debug(
                            "Could not resolve full Key Vault model for "
                            f"{vault_name}; skipping detailed checks."
                        )
                        continue

                # Soft delete
                if getattr(vault.properties, 'enable_soft_delete', False):
                    logger.info("  Soft delete enabled")
                else:
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Key Vault",
                            resource_name=vault.name,
                            resource_id=vault.id,
                            severity="MEDIUM",
                            issue="Soft delete is not enabled",
                            recommendation="Enable soft delete.",
                            compliant=False,
                        )
                    )
                    logger.warning(
                        "  Soft delete DISABLED"
                    )

                # Purge protection
                if getattr(vault.properties, 'enable_purge_protection', False):
                    logger.info("  Purge protection enabled")
                else:
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Key Vault",
                            resource_name=vault.name,
                            resource_id=vault.id,
                            severity="LOW",
                            issue="Purge protection is not enabled",
                            recommendation=(
                                "Enable purge protection for production vaults."
                            ),
                            compliant=False,
                        )
                    )

                # Network rules
                acls = getattr(vault.properties, 'network_acls', None)
                if acls and getattr(acls, 'default_action', None) == "Deny":
                    logger.info("  Network access restricted (default deny)")
                elif acls:
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Key Vault",
                            resource_name=vault.name,
                            resource_id=vault.id,
                            severity="MEDIUM",
                            issue="Key Vault allows access from all networks",
                            recommendation=(
                                "Restrict access to specific VNets or IP ranges."
                            ),
                            compliant=False,
                        )
                    )
                    logger.warning(
                        "  Open to all networks"
                    )

            return len(vaults)

        except AzureError as e:
            logger.error(f"Error scanning Key Vaults: {e}")
            return 0

    def scan_virtual_machines(self) -> int:
        """Scan Virtual Machines for selected security settings."""
        logger.info("\n" + "=" * 60)
        logger.info("SCANNING: Virtual Machines")
        logger.info("=" * 60)

        try:
            compute_client = ComputeManagementClient(
                self.credential,
                self.subscription_id,
            )
            vms = list(
                compute_client.virtual_machines.list_all()
            )
            logger.info(f"Found {len(vms)} Virtual Machine(s)")

            for vm in vms:
                logger.info(f"\n→ Analyzing: {vm.name}")

                # Boot diagnostics
                diag_profile = getattr(vm, 'diagnostics_profile', None)
                boot_diag = (
                    getattr(diag_profile, 'boot_diagnostics', None)
                    if diag_profile else None
                )
                if boot_diag and getattr(boot_diag, 'enabled', False):
                    logger.info("  Boot diagnostics enabled")
                else:
                    self.findings.append(
                        SecurityFinding(
                            resource_type="Virtual Machine",
                            resource_name=vm.name,
                            resource_id=vm.id,
                            severity="LOW",
                            issue="Boot diagnostics not enabled",
                            recommendation="Enable boot diagnostics.",
                            compliant=False,
                        )
                    )

                # Identity
                identity = getattr(vm, 'identity', None)
                if identity and getattr(identity, 'type', None):
                    logger.info(f"  Managed Identity enabled: {identity.type}")
                else:
                    logger.info("  No Managed Identity")

            return len(vms)

        except AzureError as e:
            logger.error(f"Error scanning Virtual Machines: {e}")
            return 0

    def generate_report(self, output_format: str = "json") -> str:
        """Generate a report with findings in JSON or HTML."""
        logger.info("\n" + "=" * 60)
        logger.info("GENERATING SECURITY REPORT")
        logger.info("=" * 60)

        summary = {
            "HIGH": sum(1 for f in self.findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in self.findings if f.severity == "LOW"),
            "total_findings": len(self.findings),
            "compliant_resources": sum(1 for f in self.findings if f.compliant),
        }

        scan_result = ScanResult(
            scan_time=datetime.now().isoformat(),
            subscription_id=self.subscription_id,
            total_resources_scanned=len(self.findings),
            findings=self.findings,
            summary=summary,
        )

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
        else:
            raise ValueError("Unsupported output format")

        logger.info(f"\nReport generated: {report_path}")
        logger.info("\nSummary:")
        logger.info(f"  Total Findings: {summary['total_findings']}")
        logger.info(f"  HIGH: {summary['HIGH']}")
        logger.info(f"  MEDIUM: {summary['MEDIUM']}")
        logger.info(f"  LOW: {summary['LOW']}")

        return str(report_path)

    def _generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate an HTML report from scan results."""
        severity_colors = {
            "HIGH": "#dc3545",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
        }
        findings_html = ""
        for finding in scan_result.findings:
            color = severity_colors.get(finding.severity, "#6c757d")
            findings_html += f"""
        <div class="finding {finding.severity.lower()}">
            <div class="finding-header">
                <span class="severity" style="background-color: {color}">
                    {finding.severity}
                </span>
                <span class="resource-type">{finding.resource_type}</span>
                <span class="resource-name">{finding.resource_name}</span>
            </div>
            <div class="finding-body">
                <p><strong>Issue:</strong>
                    {finding.issue}
                </p>
                <p><strong>Recommendation:</strong>
                    {finding.recommendation}
                </p>
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
                font-family: -apple-system, BlinkMacSystemFont,
                  'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(
                  135deg, #0078d4 0%, #005a9e 100%
                );
                color: white;
                padding: 30px;
                border-radius: 8px;
                margin-bottom: 20px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(
                  auto-fit, minmax(200px, 1fr)
                );
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
                <h3 style="color: #dc3545">
                    {scan_result.summary['HIGH']}
                </h3>
                <p>High Severity</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #ffc107">
                    {scan_result.summary['MEDIUM']}
                </h3>
                <p>Medium Severity</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #17a2b8">
                    {scan_result.summary['LOW']}
                </h3>
                <p>Low Severity</p>
            </div>
        </div>

        <h2>Findings</h2>
        {findings_html if findings_html else (
            "<p>No security issues found! 🎉</p>"
        )}

        <div style="margin-top: 40px; padding: 20px; background: #e9ecef; \
          border-radius: 8px;">
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
        """Run a complete security scan across supported resource types."""
        if not self.authenticate():
            logger.error("Authentication failed. Cannot proceed with scan.")
            return False

        logger.info("\n" + "=" * 60)
        logger.info("STARTING COMPREHENSIVE SECURITY SCAN")
        logger.info("=" * 60)

        total_scanned = 0
        total_scanned += self.scan_storage_accounts()
        total_scanned += self.scan_network_security_groups()
        total_scanned += self.scan_key_vaults()
        total_scanned += self.scan_virtual_machines()

        logger.info("\n" + "=" * 60)
        logger.info("SCAN COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Total resources scanned: {total_scanned}")
        logger.info(f"Total findings: {len(self.findings)}")

        return True


def main() -> None:
    """Main entry point for the scanner."""
    import argparse

    # Load variables from a local .env file if present (no external deps)
    env_path = Path('.env')
    if env_path.exists():
        try:
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    os.environ.setdefault(key, value)
        except Exception as e:
            logger.debug(f"Could not parse .env file: {e}")

    parser = argparse.ArgumentParser(
        description="Azure Security Scanner - Scan Azure resources for security misconfigurations"
    )
    parser.add_argument(
        "--subscription-id",
        help="Azure Subscription ID (or set AZURE_SUBSCRIPTION_ID env var)",
        default=os.getenv("AZURE_SUBSCRIPTION_ID"),
    )
    parser.add_argument(
        "--key-vault",
        help="Key Vault name containing credentials (or set AZURE_KEY_VAULT_NAME env var)",
        default=os.getenv("AZURE_KEY_VAULT_NAME"),
    )
    parser.add_argument(
        "--output",
        choices=["json", "html"],
        default="json",
        help="Report output format (default: json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.subscription_id:
        logger.error("Error: Azure Subscription ID is required!")
        logger.error("Set it via --subscription-id or AZURE_SUBSCRIPTION_ID environment variable")
        sys.exit(1)

    scanner = AzureSecurityScanner(
        subscription_id=args.subscription_id,
        key_vault_name=args.key_vault,
    )

    if scanner.run_full_scan():
        scanner.generate_report(output_format=args.output)

        high_severity = sum(1 for f in scanner.findings if f.severity == "HIGH")
        if high_severity > 0:
            logger.warning(f"\n{high_severity} HIGH severity issue(s) found!")
            sys.exit(1)
        else:
            logger.info("\nNo HIGH severity issues found")
            sys.exit(0)
    else:
        logger.error("\nScan failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
