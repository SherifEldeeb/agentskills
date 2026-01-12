#!/usr/bin/env python3
"""
Containment Utilities

Comprehensive containment playbooks for isolating security threats during
active incidents across network, endpoint, identity, cloud, and application layers.

Usage:
    from containment_utils import NetworkContainment, EndpointContainment, IdentityContainment
"""

import json
import hashlib
import logging
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ContainmentStatus(Enum):
    """Status of containment actions."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ContainmentAction:
    """Represents a containment action."""
    id: str
    action_type: str
    target: str
    target_type: str
    reason: str
    status: ContainmentStatus = ContainmentStatus.PENDING
    commands: List[str] = field(default_factory=list)
    api_payload: Dict = field(default_factory=dict)
    rollback_commands: List[str] = field(default_factory=list)
    rollback_available: bool = True
    evidence_path: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    analyst: str = ""
    notes: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'action_type': self.action_type,
            'target': self.target,
            'target_type': self.target_type,
            'reason': self.reason,
            'status': self.status.value,
            'commands': self.commands,
            'rollback_available': self.rollback_available,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'analyst': self.analyst,
            'notes': self.notes
        }

    def get_rollback(self) -> 'ContainmentAction':
        """Get rollback action."""
        if not self.rollback_available:
            raise ValueError("Rollback not available for this action")

        return ContainmentAction(
            id=f"{self.id}-rollback",
            action_type=f"{self.action_type}_rollback",
            target=self.target,
            target_type=self.target_type,
            reason=f"Rollback of {self.id}",
            commands=self.rollback_commands,
            rollback_available=False
        )


def generate_action_id() -> str:
    """Generate unique action ID."""
    return f"ACT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"


# =============================================================================
# Network Containment
# =============================================================================

class NetworkContainment:
    """Network-based containment actions."""

    def isolate_host(self, ip_address: str, hostname: str, reason: str,
                     isolation_type: str = 'full',
                     allow_list: List[str] = None) -> ContainmentAction:
        """
        Isolate a host from the network.

        Args:
            ip_address: IP address to isolate
            hostname: Hostname for reference
            reason: Reason for isolation
            isolation_type: 'full', 'partial', or 'monitor'
            allow_list: IPs to allow access from (e.g., IR team)
        """
        allow_list = allow_list or []
        action_id = generate_action_id()

        commands = []
        rollback_commands = []

        if isolation_type == 'full':
            # Full isolation - block all traffic
            commands.extend([
                f"# Firewall rules to isolate {hostname} ({ip_address})",
                f"iptables -I INPUT -s {ip_address} -j DROP",
                f"iptables -I OUTPUT -d {ip_address} -j DROP",
                f"iptables -I FORWARD -s {ip_address} -j DROP",
                f"iptables -I FORWARD -d {ip_address} -j DROP",
            ])

            # Allow list exceptions
            for allowed_ip in allow_list:
                commands.extend([
                    f"iptables -I INPUT -s {ip_address} -d {allowed_ip} -j ACCEPT",
                    f"iptables -I OUTPUT -s {allowed_ip} -d {ip_address} -j ACCEPT",
                ])

            # Rollback
            rollback_commands.extend([
                f"iptables -D INPUT -s {ip_address} -j DROP",
                f"iptables -D OUTPUT -d {ip_address} -j DROP",
                f"iptables -D FORWARD -s {ip_address} -j DROP",
                f"iptables -D FORWARD -d {ip_address} -j DROP",
            ])

        elif isolation_type == 'partial':
            # Block external access only
            commands.extend([
                f"# Partial isolation - block external access for {hostname}",
                f"iptables -I FORWARD -s {ip_address} ! -d 10.0.0.0/8 -j DROP",
                f"iptables -I FORWARD -s {ip_address} ! -d 172.16.0.0/12 -j DROP",
                f"iptables -I FORWARD -s {ip_address} ! -d 192.168.0.0/16 -j DROP",
            ])

        elif isolation_type == 'monitor':
            # Log but don't block
            commands.extend([
                f"# Monitor mode - logging traffic for {hostname}",
                f"iptables -I INPUT -s {ip_address} -j LOG --log-prefix 'ISOLATED_HOST: '",
                f"iptables -I OUTPUT -d {ip_address} -j LOG --log-prefix 'ISOLATED_HOST: '",
            ])

        # Switch port isolation (Cisco example)
        commands.extend([
            f"\n# Switch port isolation (Cisco)",
            f"interface [port]",
            f"  switchport port-security",
            f"  switchport port-security violation shutdown",
            f"  shutdown",
        ])

        return ContainmentAction(
            id=action_id,
            action_type='network_isolation',
            target=ip_address,
            target_type='host',
            reason=reason,
            commands=commands,
            rollback_commands=rollback_commands,
            status=ContainmentStatus.PENDING,
            metadata={
                'hostname': hostname,
                'isolation_type': isolation_type,
                'allow_list': allow_list
            }
        )

    def firewall_block(self, target: str, target_type: str, direction: str,
                       reason: str, duration_hours: int = 0) -> ContainmentAction:
        """
        Block IP, domain, or port at firewall.

        Args:
            target: IP, domain, or port to block
            target_type: 'ip', 'domain', or 'port'
            direction: 'inbound', 'outbound', or 'both'
            reason: Reason for block
            duration_hours: Block duration (0 = permanent)
        """
        action_id = generate_action_id()
        commands = []
        rollback_commands = []

        if target_type == 'ip':
            if direction in ['inbound', 'both']:
                commands.append(f"iptables -I INPUT -s {target} -j DROP")
                rollback_commands.append(f"iptables -D INPUT -s {target} -j DROP")
            if direction in ['outbound', 'both']:
                commands.append(f"iptables -I OUTPUT -d {target} -j DROP")
                rollback_commands.append(f"iptables -D OUTPUT -d {target} -j DROP")

        elif target_type == 'domain':
            commands.extend([
                f"# Block domain {target}",
                f"# Add to DNS blackhole",
                f"echo '127.0.0.1 {target}' >> /etc/hosts",
                f"# Or use firewall with domain resolution",
                f"# Note: Requires DNS-aware firewall"
            ])
            rollback_commands.append(f"sed -i '/{target}/d' /etc/hosts")

        elif target_type == 'port':
            ports = target.split('-') if '-' in target else [target, target]
            if direction in ['inbound', 'both']:
                commands.append(f"iptables -I INPUT -p tcp --dport {ports[0]}:{ports[1]} -j DROP")
                commands.append(f"iptables -I INPUT -p udp --dport {ports[0]}:{ports[1]} -j DROP")
            if direction in ['outbound', 'both']:
                commands.append(f"iptables -I OUTPUT -p tcp --dport {ports[0]}:{ports[1]} -j DROP")
                commands.append(f"iptables -I OUTPUT -p udp --dport {ports[0]}:{ports[1]} -j DROP")

        action = ContainmentAction(
            id=action_id,
            action_type='firewall_block',
            target=target,
            target_type=target_type,
            reason=reason,
            commands=commands,
            rollback_commands=rollback_commands,
            status=ContainmentStatus.PENDING,
            metadata={
                'direction': direction,
                'duration_hours': duration_hours
            }
        )

        return action

    def generate_firewall_rules(self, action: ContainmentAction) -> str:
        """Generate firewall rules in multiple formats."""
        target = action.target
        target_type = action.target_type
        direction = action.metadata.get('direction', 'both')

        rules = f"""# Firewall Rules for {action.id}
# Reason: {action.reason}
# Generated: {datetime.now().isoformat()}

# === iptables ===
{chr(10).join(action.commands)}

# === Cisco ASA ===
"""
        if target_type == 'ip':
            rules += f"""access-list BLOCK_THREATS deny ip host {target} any
access-list BLOCK_THREATS deny ip any host {target}
"""

        rules += """
# === Palo Alto ===
"""
        if target_type == 'ip':
            rules += f"""set address BLOCKED_{target.replace('.', '_')} ip-netmask {target}/32
set rulebase security rules BLOCK_MALICIOUS from any to any source BLOCKED_{target.replace('.', '_')} action deny
"""

        return rules

    def dns_sinkhole(self, domains: List[str], sinkhole_ip: str,
                     reason: str, log_queries: bool = True) -> ContainmentAction:
        """
        Redirect domains to DNS sinkhole.

        Args:
            domains: List of domains to sinkhole
            sinkhole_ip: IP of sinkhole server
            reason: Reason for sinkholing
            log_queries: Whether to log DNS queries
        """
        action_id = generate_action_id()

        # Generate DNS configurations
        bind_config = []
        hosts_entries = []

        for domain in domains:
            bind_config.append(f'zone "{domain}" {{ type master; file "/etc/bind/db.sinkhole"; }};')
            hosts_entries.append(f"{sinkhole_ip} {domain}")
            hosts_entries.append(f"{sinkhole_ip} www.{domain}")

        commands = [
            "# BIND Configuration",
            *bind_config,
            "",
            "# /etc/hosts entries (simple method)",
            *hosts_entries,
            "",
            "# Windows DNS Server PowerShell",
            *[f'Add-DnsServerZone -Name "{d}" -ZoneFile "sinkhole.dns"' for d in domains]
        ]

        rollback_commands = [
            *[f'sed -i "/{domain}/d" /etc/hosts' for domain in domains],
            "# Remove BIND zone configurations manually"
        ]

        return ContainmentAction(
            id=action_id,
            action_type='dns_sinkhole',
            target=', '.join(domains),
            target_type='domain',
            reason=reason,
            commands=commands,
            rollback_commands=rollback_commands,
            status=ContainmentStatus.PENDING,
            metadata={
                'domains': domains,
                'sinkhole_ip': sinkhole_ip,
                'log_queries': log_queries,
                'dns_config': '\n'.join(bind_config)
            }
        )

    def segment_network(self, source_vlan: int, target_vlan: int,
                        affected_hosts: List[str], allow_ir_access: bool = True,
                        ir_subnet: str = '') -> ContainmentAction:
        """
        Emergency network segmentation.

        Args:
            source_vlan: Current VLAN of affected hosts
            target_vlan: Quarantine VLAN to move hosts to
            affected_hosts: List of host IPs to move
            allow_ir_access: Allow IR team access
            ir_subnet: IR team subnet
        """
        action_id = generate_action_id()

        vlan_config = [
            f"# Create quarantine VLAN {target_vlan}",
            f"vlan {target_vlan}",
            f"  name QUARANTINE_VLAN",
            f"  state active",
            "",
            "# Move ports to quarantine VLAN",
            "# (Identify ports by MAC address lookup)",
        ]

        for host in affected_hosts:
            vlan_config.append(f"# Host {host} - move to VLAN {target_vlan}")

        acl_rules = [
            f"# ACL for quarantine VLAN {target_vlan}",
            f"ip access-list extended QUARANTINE_ACL",
            f"  deny ip any any",  # Default deny
        ]

        if allow_ir_access and ir_subnet:
            acl_rules.insert(-1, f"  permit ip {ir_subnet} any")
            acl_rules.insert(-1, f"  permit ip any {ir_subnet}")

        commands = vlan_config + [""] + acl_rules

        return ContainmentAction(
            id=action_id,
            action_type='network_segmentation',
            target=f"VLAN {source_vlan} -> VLAN {target_vlan}",
            target_type='network',
            reason='Emergency network segmentation',
            commands=commands,
            rollback_commands=[
                f"# Move hosts back to VLAN {source_vlan}",
                f"# Remove quarantine ACLs"
            ],
            status=ContainmentStatus.PENDING,
            metadata={
                'source_vlan': source_vlan,
                'target_vlan': target_vlan,
                'affected_hosts': affected_hosts,
                'vlan_config': '\n'.join(vlan_config),
                'acl_rules': '\n'.join(acl_rules)
            }
        )


# =============================================================================
# Endpoint Containment
# =============================================================================

class EndpointContainment:
    """Endpoint-based containment actions."""

    EDR_PLATFORMS = ['crowdstrike', 'sentinelone', 'defender', 'carbon_black', 'cortex_xdr']

    def quarantine_endpoint(self, hostname: str, edr_platform: str,
                           isolation_level: str = 'full',
                           allow_list: List[str] = None,
                           preserve_evidence: bool = True) -> ContainmentAction:
        """
        Quarantine endpoint using EDR platform.

        Args:
            hostname: Hostname to quarantine
            edr_platform: EDR platform (crowdstrike, sentinelone, etc.)
            isolation_level: 'full' or 'selective'
            allow_list: CIDRs to allow access from
            preserve_evidence: Whether to preserve volatile evidence first
        """
        action_id = generate_action_id()
        allow_list = allow_list or []

        api_payloads = {
            'crowdstrike': {
                'action': 'contain',
                'hostname': hostname,
                'isolation_type': isolation_level,
                'exceptions': allow_list
            },
            'sentinelone': {
                'filter': {'computerName__contains': hostname},
                'data': {'networkQuarantineEnabled': True}
            },
            'defender': {
                'Comment': f'Containment action {action_id}',
                'IsolationType': 'Full' if isolation_level == 'full' else 'Selective'
            },
            'carbon_black': {
                'action_type': 'QUARANTINE_DEVICE',
                'device_id': hostname,
                'options': {'toggle': 'ON'}
            }
        }

        api_payload = api_payloads.get(edr_platform, {})

        commands = [
            f"# EDR Quarantine via {edr_platform}",
            f"# Hostname: {hostname}",
            f"# Isolation Level: {isolation_level}",
        ]

        if preserve_evidence:
            commands.extend([
                "",
                "# Pre-isolation evidence collection",
                "# Capture memory dump",
                "# Export process list",
                "# Capture network connections"
            ])

        if edr_platform == 'crowdstrike':
            commands.extend([
                "",
                "# CrowdStrike Falcon API",
                f"POST /devices/entities/devices-actions/v2",
                f"Body: {json.dumps(api_payload, indent=2)}"
            ])
        elif edr_platform == 'defender':
            commands.extend([
                "",
                "# Microsoft Defender for Endpoint",
                f"POST /api/machines/{{machine_id}}/isolate",
                f"Body: {json.dumps(api_payload, indent=2)}"
            ])

        return ContainmentAction(
            id=action_id,
            action_type='edr_quarantine',
            target=hostname,
            target_type='endpoint',
            reason=f'EDR quarantine via {edr_platform}',
            commands=commands,
            api_payload=api_payload,
            rollback_commands=[
                f"# Release from {edr_platform} quarantine",
                f"# POST /devices/release or equivalent"
            ],
            status=ContainmentStatus.PENDING,
            metadata={
                'edr_platform': edr_platform,
                'isolation_level': isolation_level,
                'allow_list': allow_list,
                'preserve_evidence': preserve_evidence
            }
        )

    def terminate_process(self, hostname: str, process_name: str,
                          process_id: int = None, kill_children: bool = True,
                          create_memory_dump: bool = True) -> ContainmentAction:
        """
        Terminate malicious process.

        Args:
            hostname: Target hostname
            process_name: Process name to terminate
            process_id: Specific PID (optional)
            kill_children: Also kill child processes
            create_memory_dump: Create memory dump before termination
        """
        action_id = generate_action_id()

        commands = []
        evidence_path = None

        if create_memory_dump:
            dump_path = f"/evidence/{action_id}/{process_name}.dmp"
            evidence_path = dump_path
            commands.extend([
                f"# Create memory dump before termination",
                f"# Windows:",
                f'procdump -ma {process_id or process_name} "{dump_path}"',
                "",
                "# Linux:",
                f"gcore -o {dump_path} {process_id or '$(pgrep ' + process_name + ')'}",
                ""
            ])

        # Windows commands
        commands.extend([
            "# Windows Process Termination",
            f"taskkill /F /IM {process_name}" + (" /T" if kill_children else ""),
        ])

        if process_id:
            commands.append(f"taskkill /F /PID {process_id}" + (" /T" if kill_children else ""))

        # Linux commands
        commands.extend([
            "",
            "# Linux Process Termination",
            f"pkill -9 {process_name}",
        ])

        if kill_children:
            commands.append(f"pkill -9 -P $(pgrep {process_name})")

        # PowerShell for remote execution
        commands.extend([
            "",
            "# Remote PowerShell",
            f"Invoke-Command -ComputerName {hostname} -ScriptBlock {{",
            f"    Stop-Process -Name '{process_name.replace('.exe', '')}' -Force",
            f"}}"
        ])

        return ContainmentAction(
            id=action_id,
            action_type='process_termination',
            target=f"{process_name} on {hostname}",
            target_type='process',
            reason=f'Terminate malicious process {process_name}',
            commands=commands,
            evidence_path=evidence_path,
            rollback_available=False,  # Can't "un-terminate" a process
            status=ContainmentStatus.PENDING,
            metadata={
                'hostname': hostname,
                'process_name': process_name,
                'process_id': process_id,
                'kill_children': kill_children,
                'memory_dump_created': create_memory_dump
            }
        )

    def disable_service(self, hostname: str, service_name: str,
                        stop_immediately: bool = True,
                        disable_autostart: bool = True,
                        backup_config: bool = True) -> ContainmentAction:
        """
        Disable Windows/Linux service.

        Args:
            hostname: Target hostname
            service_name: Service to disable
            stop_immediately: Stop service now
            disable_autostart: Prevent service from starting on boot
            backup_config: Backup service configuration
        """
        action_id = generate_action_id()

        commands = []
        rollback_commands = []

        if backup_config:
            commands.extend([
                f"# Backup service configuration",
                f"# Windows:",
                f"sc qc {service_name} > C:\\evidence\\{action_id}_{service_name}_config.txt",
                f"reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name} C:\\evidence\\{action_id}_{service_name}.reg",
                "",
                f"# Linux:",
                f"systemctl show {service_name} > /evidence/{action_id}_{service_name}_config.txt",
                ""
            ])

        if stop_immediately:
            commands.extend([
                f"# Stop service immediately",
                f"# Windows:",
                f"sc stop {service_name}",
                f"Stop-Service -Name {service_name} -Force",
                "",
                f"# Linux:",
                f"systemctl stop {service_name}",
                ""
            ])
            rollback_commands.extend([
                f"sc start {service_name}",
                f"systemctl start {service_name}"
            ])

        if disable_autostart:
            commands.extend([
                f"# Disable autostart",
                f"# Windows:",
                f"sc config {service_name} start= disabled",
                "",
                f"# Linux:",
                f"systemctl disable {service_name}",
            ])
            rollback_commands.extend([
                f"sc config {service_name} start= auto",
                f"systemctl enable {service_name}"
            ])

        return ContainmentAction(
            id=action_id,
            action_type='service_disable',
            target=f"{service_name} on {hostname}",
            target_type='service',
            reason=f'Disable service {service_name}',
            commands=commands,
            rollback_commands=rollback_commands,
            status=ContainmentStatus.PENDING,
            metadata={
                'hostname': hostname,
                'service_name': service_name,
                'stopped': stop_immediately,
                'disabled': disable_autostart,
                'config_backed_up': backup_config
            }
        )

    def preserve_memory(self, hostname: str, output_path: str,
                        tool: str = 'winpmem',
                        compress: bool = True,
                        hash_output: bool = True) -> ContainmentAction:
        """
        Capture memory dump for forensics.

        Args:
            hostname: Target hostname
            output_path: Path to save memory dump
            tool: Memory capture tool (winpmem, dumpit, magnet_ram)
            compress: Compress the output
            hash_output: Generate hash of output
        """
        action_id = generate_action_id()
        output_file = f"{output_path}/{hostname}_{action_id}.raw"
        if compress:
            output_file += '.gz'

        commands = []

        tool_commands = {
            'winpmem': [
                f"winpmem_{hostname}.exe {output_file}",
            ],
            'dumpit': [
                f"DumpIt.exe /OUTPUT {output_file} /QUIET",
            ],
            'magnet_ram': [
                f"MagnetRAMCapture.exe /accepteula /go /output:{output_file}",
            ],
            'lime': [
                f"# Linux memory acquisition",
                f"insmod /path/to/lime.ko 'path={output_file} format=lime'",
            ]
        }

        commands.extend(tool_commands.get(tool, tool_commands['winpmem']))

        if compress and tool != 'dumpit':
            commands.append(f"gzip {output_file.replace('.gz', '')}")

        if hash_output:
            commands.extend([
                "",
                f"# Generate hash",
                f"sha256sum {output_file} > {output_file}.sha256",
                f"certutil -hashfile {output_file} SHA256 > {output_file}.sha256"
            ])

        # Chain of custody record
        custody_record = {
            'action_id': action_id,
            'hostname': hostname,
            'collected_at': datetime.now().isoformat(),
            'output_file': output_file,
            'tool': tool,
            'compressed': compress
        }

        return ContainmentAction(
            id=action_id,
            action_type='memory_preservation',
            target=hostname,
            target_type='endpoint',
            reason='Preserve volatile memory evidence',
            commands=commands,
            evidence_path=output_file,
            rollback_available=False,
            status=ContainmentStatus.PENDING,
            metadata={
                'output_file': output_file,
                'tool': tool,
                'compressed': compress,
                'hash_output': hash_output,
                'custody_record': custody_record
            }
        )


# =============================================================================
# Identity Containment
# =============================================================================

class IdentityContainment:
    """Identity and access containment actions."""

    def disable_account(self, username: str, reason: str,
                        directory: str = 'active_directory',
                        preserve_data: bool = True,
                        notify_manager: bool = True) -> ContainmentAction:
        """
        Disable user account.

        Args:
            username: Account to disable
            reason: Reason for disabling
            directory: 'active_directory', 'azure_ad', 'okta', 'google'
            preserve_data: Keep mailbox/data accessible
            notify_manager: Send notification to manager
        """
        action_id = generate_action_id()

        commands = []
        rollback_commands = []

        if directory == 'active_directory':
            commands.extend([
                f"# Active Directory - Disable Account",
                f"Disable-ADAccount -Identity {username}",
                f"Set-ADUser -Identity {username} -Description 'DISABLED: {reason} ({action_id})'",
                "",
                f"# Move to Disabled Users OU",
                f"Move-ADObject -Identity (Get-ADUser {username}).DistinguishedName -TargetPath 'OU=Disabled Users,DC=domain,DC=com'",
            ])
            rollback_commands.extend([
                f"Enable-ADAccount -Identity {username}",
                f"# Move back to original OU"
            ])

        elif directory == 'azure_ad':
            commands.extend([
                f"# Azure AD - Disable Account",
                f"Update-MgUser -UserId {username} -AccountEnabled:$false",
                f"# Revoke all sessions",
                f"Revoke-MgUserSignInSession -UserId {username}",
            ])
            rollback_commands.append(f"Update-MgUser -UserId {username} -AccountEnabled:$true")

        elif directory == 'okta':
            commands.extend([
                f"# Okta - Suspend User",
                f"POST /api/v1/users/{username}/lifecycle/suspend",
            ])
            rollback_commands.append(f"POST /api/v1/users/{username}/lifecycle/unsuspend")

        elif directory == 'google':
            commands.extend([
                f"# Google Workspace - Suspend User",
                f"gam update user {username} suspended on",
            ])
            rollback_commands.append(f"gam update user {username} suspended off")

        if notify_manager:
            commands.extend([
                "",
                f"# Notify manager",
                f"Send-MailMessage -To manager@company.com -Subject 'Account {username} disabled'"
            ])

        return ContainmentAction(
            id=action_id,
            action_type='account_disable',
            target=username,
            target_type='user_account',
            reason=reason,
            commands=commands,
            rollback_commands=rollback_commands,
            status=ContainmentStatus.PENDING,
            metadata={
                'directory': directory,
                'preserve_data': preserve_data,
                'notify_manager': notify_manager
            }
        )

    def terminate_sessions(self, username: str,
                           session_types: List[str] = None,
                           force: bool = True,
                           invalidate_tokens: bool = True) -> ContainmentAction:
        """
        Terminate all active user sessions.

        Args:
            username: User whose sessions to terminate
            session_types: 'all', 'vpn', 'rdp', 'web', 'cloud'
            force: Force termination
            invalidate_tokens: Also invalidate OAuth/refresh tokens
        """
        session_types = session_types or ['all']
        action_id = generate_action_id()

        commands = [
            f"# Terminate sessions for {username}",
            ""
        ]

        if 'all' in session_types or 'rdp' in session_types:
            commands.extend([
                "# RDP Sessions",
                f"query session /server:* | findstr {username}",
                f"logoff <session_id> /server:<server>",
                ""
            ])

        if 'all' in session_types or 'vpn' in session_types:
            commands.extend([
                "# VPN Sessions",
                f"# Terminate via VPN management console or API",
                f"# Check Cisco AnyConnect, Palo Alto GlobalProtect, etc.",
                ""
            ])

        if 'all' in session_types or 'cloud' in session_types:
            commands.extend([
                "# Azure AD Sessions",
                f"Revoke-MgUserSignInSession -UserId {username}",
                "",
                "# Google Workspace",
                f"gam user {username} signout",
                "",
                "# Okta",
                f"DELETE /api/v1/users/{username}/sessions",
                ""
            ])

        if invalidate_tokens:
            commands.extend([
                "# Invalidate refresh tokens",
                f"Revoke-MgUserSignInSession -UserId {username}",
                f"# For Azure: Update user to revoke all tokens",
                f"Update-MgUser -UserId {username} -PasswordProfile @{{ForceChangePasswordNextSignIn=$true}}"
            ])

        return ContainmentAction(
            id=action_id,
            action_type='session_termination',
            target=username,
            target_type='user_sessions',
            reason='Terminate all active sessions',
            commands=commands,
            rollback_available=False,
            status=ContainmentStatus.PENDING,
            metadata={
                'session_types': session_types,
                'force': force,
                'tokens_invalidated': invalidate_tokens,
                'session_count': 0  # Would be populated after execution
            }
        )

    def force_password_reset(self, username: str,
                             require_mfa_reenroll: bool = True,
                             expire_immediately: bool = True,
                             notify_user: bool = True,
                             generate_temp_password: bool = True) -> ContainmentAction:
        """
        Force password reset for user.

        Args:
            username: User account
            require_mfa_reenroll: Also require MFA re-enrollment
            expire_immediately: Expire password now
            notify_user: Send notification to user
            generate_temp_password: Generate temporary password
        """
        action_id = generate_action_id()

        temp_password = None
        if generate_temp_password:
            chars = string.ascii_letters + string.digits + "!@#$%"
            temp_password = ''.join(secrets.choice(chars) for _ in range(16))

        commands = [
            f"# Force password reset for {username}",
            ""
        ]

        if generate_temp_password:
            commands.extend([
                "# Active Directory",
                f"Set-ADAccountPassword -Identity {username} -Reset -NewPassword (ConvertTo-SecureString '{temp_password}' -AsPlainText -Force)",
                f"Set-ADUser -Identity {username} -ChangePasswordAtLogon $true",
                "",
                "# Azure AD",
                f"Update-MgUser -UserId {username} -PasswordProfile @{{Password='{temp_password}'; ForceChangePasswordNextSignIn=$true}}",
            ])

        if require_mfa_reenroll:
            commands.extend([
                "",
                "# Reset MFA",
                f"# Azure AD - Remove MFA methods",
                f"Remove-MgUserAuthenticationPhoneMethod -UserId {username}",
                f"Remove-MgUserAuthenticationEmailMethod -UserId {username}",
                "",
                f"# Okta - Reset MFA factors",
                f"DELETE /api/v1/users/{username}/factors",
            ])

        return ContainmentAction(
            id=action_id,
            action_type='password_reset',
            target=username,
            target_type='user_account',
            reason='Force credential reset',
            commands=commands,
            rollback_available=False,
            status=ContainmentStatus.PENDING,
            metadata={
                'temp_password': temp_password,
                'mfa_reset': require_mfa_reenroll,
                'expired_immediately': expire_immediately,
                'user_notified': notify_user
            }
        )

    def rotate_service_account(self, account_name: str,
                                credential_type: str = 'password',
                                update_dependent_services: bool = True,
                                services: List[str] = None) -> ContainmentAction:
        """
        Rotate service account credentials.

        Args:
            account_name: Service account name
            credential_type: 'password', 'api_key', or 'certificate'
            update_dependent_services: Update services using this account
            services: List of dependent services
        """
        services = services or []
        action_id = generate_action_id()

        # Generate new credentials
        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

        commands = [
            f"# Rotate credentials for {account_name}",
            ""
        ]

        if credential_type == 'password':
            commands.extend([
                "# Generate new password and update",
                f"Set-ADAccountPassword -Identity {account_name} -Reset -NewPassword (ConvertTo-SecureString '{new_password}' -AsPlainText -Force)",
            ])

        elif credential_type == 'api_key':
            commands.extend([
                "# Rotate API key",
                f"# Create new key, then disable old key",
                f"aws iam create-access-key --user-name {account_name}",
                f"aws iam update-access-key --access-key-id OLD_KEY --status Inactive --user-name {account_name}",
            ])

        if update_dependent_services and services:
            commands.append("")
            commands.append("# Update dependent services")
            for service in services:
                commands.append(f"# Update {service} with new credentials")

        return ContainmentAction(
            id=action_id,
            action_type='credential_rotation',
            target=account_name,
            target_type='service_account',
            reason='Rotate compromised service account credentials',
            commands=commands,
            rollback_available=False,
            status=ContainmentStatus.PENDING,
            metadata={
                'credential_type': credential_type,
                'services_updated': services,
                'credential_rotated': True
            }
        )


# =============================================================================
# Cloud Containment
# =============================================================================

class CloudContainment:
    """Cloud platform containment actions."""

    def revoke_iam_permissions(self, principal: str, cloud_provider: str,
                                revocation_type: str = 'all',
                                preserve_audit_logs: bool = True) -> ContainmentAction:
        """
        Revoke cloud IAM permissions.

        Args:
            principal: User/role ARN or ID
            cloud_provider: 'aws', 'azure', 'gcp'
            revocation_type: 'all' or 'specific'
            preserve_audit_logs: Keep audit logging enabled
        """
        action_id = generate_action_id()

        commands = []
        policies_removed = []

        if cloud_provider == 'aws':
            commands.extend([
                f"# AWS IAM Permission Revocation",
                f"# List attached policies",
                f"aws iam list-attached-user-policies --user-name {principal}",
                "",
                f"# Detach all policies",
                f"for policy in $(aws iam list-attached-user-policies --user-name {principal} --query 'AttachedPolicies[*].PolicyArn' --output text); do",
                f"    aws iam detach-user-policy --user-name {principal} --policy-arn $policy",
                f"done",
                "",
                f"# Disable access keys",
                f"for key in $(aws iam list-access-keys --user-name {principal} --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do",
                f"    aws iam update-access-key --user-name {principal} --access-key-id $key --status Inactive",
                f"done",
                "",
                f"# Add explicit deny policy",
                f"aws iam put-user-policy --user-name {principal} --policy-name DenyAll --policy-document file://deny-all.json",
            ])

        elif cloud_provider == 'azure':
            commands.extend([
                f"# Azure IAM Revocation",
                f"# Remove role assignments",
                f"az role assignment list --assignee {principal} --query '[].id' -o tsv | xargs -I {{}} az role assignment delete --ids {{}}",
                "",
                f"# Block sign-in",
                f"az ad user update --id {principal} --account-enabled false",
            ])

        elif cloud_provider == 'gcp':
            commands.extend([
                f"# GCP IAM Revocation",
                f"# Remove all IAM bindings",
                f"gcloud projects get-iam-policy PROJECT_ID --flatten='bindings[].members' --filter='bindings.members:{principal}' --format='value(bindings.role)' | xargs -I {{}} gcloud projects remove-iam-policy-binding PROJECT_ID --member={principal} --role={{}}",
                "",
                f"# Disable service account (if applicable)",
                f"gcloud iam service-accounts disable {principal}",
            ])

        return ContainmentAction(
            id=action_id,
            action_type='iam_revocation',
            target=principal,
            target_type='cloud_identity',
            reason='Revoke cloud IAM permissions',
            commands=commands,
            rollback_commands=[f"# Re-attach policies manually after investigation"],
            status=ContainmentStatus.PENDING,
            metadata={
                'cloud_provider': cloud_provider,
                'revocation_type': revocation_type,
                'policies_removed': policies_removed,
                'keys_disabled': True
            }
        )

    def isolate_resource(self, resource_id: str, resource_type: str,
                         cloud_provider: str, isolation_method: str = 'security_group',
                         allow_forensic_access: bool = True,
                         forensic_ip: str = '') -> ContainmentAction:
        """
        Isolate cloud resource.

        Args:
            resource_id: Resource ID to isolate
            resource_type: 'ec2_instance', 'vm', 'container', etc.
            cloud_provider: 'aws', 'azure', 'gcp'
            isolation_method: 'security_group', 'nacl', 'vpc'
            allow_forensic_access: Allow forensic team access
            forensic_ip: Forensic workstation IP
        """
        action_id = generate_action_id()
        isolation_sg = f"isolation-sg-{action_id}"

        commands = []
        isolation_rules = []

        if cloud_provider == 'aws':
            # Create isolation security group
            commands.extend([
                f"# Create isolation security group",
                f"aws ec2 create-security-group --group-name {isolation_sg} --description 'Incident isolation' --vpc-id VPC_ID",
                "",
            ])

            if allow_forensic_access and forensic_ip:
                commands.extend([
                    f"# Allow forensic access",
                    f"aws ec2 authorize-security-group-ingress --group-name {isolation_sg} --protocol tcp --port 22 --cidr {forensic_ip}/32",
                    f"aws ec2 authorize-security-group-ingress --group-name {isolation_sg} --protocol tcp --port 3389 --cidr {forensic_ip}/32",
                ])
                isolation_rules.extend([
                    {'port': 22, 'source': forensic_ip},
                    {'port': 3389, 'source': forensic_ip}
                ])

            commands.extend([
                "",
                f"# Apply isolation security group to instance",
                f"aws ec2 modify-instance-attribute --instance-id {resource_id} --groups {isolation_sg}",
                "",
                f"# Optional: Stop instance to prevent further activity",
                f"aws ec2 stop-instances --instance-ids {resource_id}",
            ])

        elif cloud_provider == 'azure':
            commands.extend([
                f"# Azure VM isolation",
                f"# Create NSG with deny all rules",
                f"az network nsg create --name {isolation_sg} --resource-group RG_NAME",
                f"az network nsg rule create --nsg-name {isolation_sg} --name DenyAll --priority 100 --access Deny --direction Inbound --source-address-prefixes '*'",
                "",
                f"# Apply to NIC",
                f"az network nic update --name NIC_NAME --resource-group RG_NAME --network-security-group {isolation_sg}",
            ])

        return ContainmentAction(
            id=action_id,
            action_type='resource_isolation',
            target=resource_id,
            target_type=resource_type,
            reason='Isolate compromised cloud resource',
            commands=commands,
            rollback_commands=[
                f"# Remove isolation security group",
                f"# Restore original security group"
            ],
            status=ContainmentStatus.PENDING,
            metadata={
                'cloud_provider': cloud_provider,
                'isolation_method': isolation_method,
                'security_group_id': isolation_sg,
                'isolation_rules': isolation_rules,
                'forensic_access': allow_forensic_access
            }
        )

    def revoke_api_keys(self, key_ids: List[str], cloud_provider: str,
                        create_new_keys: bool = False,
                        notify_owner: bool = True) -> ContainmentAction:
        """
        Revoke API keys.

        Args:
            key_ids: List of key IDs to revoke
            cloud_provider: 'aws', 'azure', 'gcp'
            create_new_keys: Create replacement keys
            notify_owner: Notify key owner
        """
        action_id = generate_action_id()

        commands = [f"# Revoke API keys"]

        for key_id in key_ids:
            if cloud_provider == 'aws':
                commands.extend([
                    f"aws iam update-access-key --access-key-id {key_id} --status Inactive",
                    f"aws iam delete-access-key --access-key-id {key_id}",
                ])
            elif cloud_provider == 'azure':
                commands.append(f"az ad sp credential delete --id {key_id}")
            elif cloud_provider == 'gcp':
                commands.append(f"gcloud iam service-accounts keys delete {key_id}")

        return ContainmentAction(
            id=action_id,
            action_type='api_key_revocation',
            target=', '.join(key_ids),
            target_type='api_keys',
            reason='Revoke compromised API keys',
            commands=commands,
            rollback_available=False,
            status=ContainmentStatus.PENDING,
            metadata={
                'cloud_provider': cloud_provider,
                'keys_revoked': key_ids,
                'new_keys_created': create_new_keys,
                'affected_services': []
            }
        )

    def lockdown_security_group(self, security_group_id: str, cloud_provider: str,
                                 lockdown_type: str = 'deny_all',
                                 ir_cidrs: List[str] = None,
                                 preserve_logging: bool = True) -> ContainmentAction:
        """
        Lock down security group.

        Args:
            security_group_id: Security group to lock down
            cloud_provider: 'aws', 'azure', 'gcp'
            lockdown_type: 'deny_all', 'allow_ir_only', 'block_egress'
            ir_cidrs: CIDRs for IR team access
            preserve_logging: Keep VPC flow logs
        """
        ir_cidrs = ir_cidrs or []
        action_id = generate_action_id()

        commands = [
            f"# Security Group Lockdown: {security_group_id}",
            ""
        ]

        if cloud_provider == 'aws':
            if lockdown_type == 'deny_all':
                commands.extend([
                    f"# Remove all inbound rules",
                    f"aws ec2 describe-security-groups --group-ids {security_group_id} --query 'SecurityGroups[0].IpPermissions' --output json > /tmp/sg_backup.json",
                    f"aws ec2 revoke-security-group-ingress --group-id {security_group_id} --ip-permissions file:///tmp/sg_backup.json",
                    "",
                    f"# Remove all outbound rules",
                    f"aws ec2 describe-security-groups --group-ids {security_group_id} --query 'SecurityGroups[0].IpPermissionsEgress' --output json > /tmp/sg_egress_backup.json",
                    f"aws ec2 revoke-security-group-egress --group-id {security_group_id} --ip-permissions file:///tmp/sg_egress_backup.json",
                ])

            if lockdown_type in ['allow_ir_only', 'deny_all'] and ir_cidrs:
                commands.append("")
                for cidr in ir_cidrs:
                    commands.extend([
                        f"# Allow IR access from {cidr}",
                        f"aws ec2 authorize-security-group-ingress --group-id {security_group_id} --protocol tcp --port 22 --cidr {cidr}",
                        f"aws ec2 authorize-security-group-ingress --group-id {security_group_id} --protocol tcp --port 3389 --cidr {cidr}",
                    ])

        return ContainmentAction(
            id=action_id,
            action_type='security_group_lockdown',
            target=security_group_id,
            target_type='security_group',
            reason=f'Security group lockdown - {lockdown_type}',
            commands=commands,
            rollback_commands=[
                f"# Restore from backup",
                f"aws ec2 authorize-security-group-ingress --group-id {security_group_id} --ip-permissions file:///tmp/sg_backup.json"
            ],
            status=ContainmentStatus.PENDING,
            metadata={
                'cloud_provider': cloud_provider,
                'lockdown_type': lockdown_type,
                'ir_cidrs': ir_cidrs,
                'rules_removed': [],
                'new_rules': []
            }
        )


# =============================================================================
# Application Containment
# =============================================================================

class ApplicationContainment:
    """Application layer containment actions."""

    def deploy_waf_rule(self, rule_name: str, rule_type: str,
                        conditions: List[Dict], waf_provider: str,
                        priority: int = 1) -> ContainmentAction:
        """
        Deploy WAF rule.

        Args:
            rule_name: Name for the rule
            rule_type: 'block', 'rate_limit', 'challenge'
            conditions: Rule conditions
            waf_provider: 'cloudflare', 'aws_waf', 'akamai'
            priority: Rule priority
        """
        action_id = generate_action_id()
        rule_id = f"rule-{action_id}"

        waf_config = {
            'id': rule_id,
            'name': rule_name,
            'action': rule_type,
            'priority': priority,
            'conditions': conditions
        }

        commands = [f"# Deploy WAF rule: {rule_name}"]

        if waf_provider == 'cloudflare':
            commands.extend([
                "",
                "# Cloudflare WAF Rule",
                f"curl -X POST 'https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/rules'",
                f"-H 'Authorization: Bearer API_TOKEN'",
                f"-d '{json.dumps(waf_config)}'",
            ])

        elif waf_provider == 'aws_waf':
            commands.extend([
                "",
                "# AWS WAF Rule",
                f"aws wafv2 create-rule --name {rule_name} --scope REGIONAL --action Block",
            ])

        return ContainmentAction(
            id=action_id,
            action_type='waf_rule_deployment',
            target=rule_name,
            target_type='waf_rule',
            reason='Deploy emergency WAF rule',
            commands=commands,
            rollback_commands=[f"# Delete rule {rule_id}"],
            status=ContainmentStatus.PENDING,
            metadata={
                'waf_provider': waf_provider,
                'rule_id': rule_id,
                'waf_config': waf_config
            }
        )

    def rate_limit(self, endpoint: str, limit: int, window_seconds: int,
                   action: str = 'block', scope: str = 'ip',
                   whitelist: List[str] = None) -> ContainmentAction:
        """
        Implement rate limiting.

        Args:
            endpoint: Endpoint to rate limit
            limit: Request limit
            window_seconds: Time window
            action: 'block', 'throttle', 'challenge'
            scope: 'ip', 'user', 'global'
            whitelist: Excluded IPs/users
        """
        whitelist = whitelist or []
        action_id = generate_action_id()

        config = {
            'endpoint': endpoint,
            'limit': limit,
            'window': window_seconds,
            'action': action,
            'scope': scope,
            'whitelist': whitelist
        }

        commands = [
            f"# Rate Limiting Configuration",
            f"# Endpoint: {endpoint}",
            f"# Limit: {limit} requests per {window_seconds} seconds",
            "",
            "# nginx rate limiting",
            f"limit_req_zone $binary_remote_addr zone=incident:10m rate={limit}r/m;",
            f"location {endpoint} {{",
            f"    limit_req zone=incident burst=5 nodelay;",
            f"}}",
        ]

        return ContainmentAction(
            id=action_id,
            action_type='rate_limiting',
            target=endpoint,
            target_type='endpoint',
            reason='Emergency rate limiting',
            commands=commands,
            rollback_commands=["# Remove rate limiting configuration"],
            status=ContainmentStatus.PENDING,
            metadata={
                'config': config
            }
        )

    def shutdown_service(self, service_name: str, shutdown_type: str = 'graceful',
                         drain_connections: bool = True,
                         display_maintenance_page: bool = True,
                         notify_stakeholders: List[str] = None) -> ContainmentAction:
        """
        Emergency service shutdown.

        Args:
            service_name: Service to shutdown
            shutdown_type: 'graceful' or 'immediate'
            drain_connections: Drain existing connections
            display_maintenance_page: Show maintenance page
            notify_stakeholders: Email addresses to notify
        """
        notify_stakeholders = notify_stakeholders or []
        action_id = generate_action_id()

        commands = [f"# Emergency shutdown: {service_name}"]

        if drain_connections and shutdown_type == 'graceful':
            commands.extend([
                "",
                "# Drain connections",
                f"kubectl drain node --ignore-daemonsets --delete-local-data",
                f"# Or for load balancer:",
                f"aws elbv2 modify-target-group --target-group-arn ARN --health-check-path /health --healthy-threshold-count 10",
            ])

        if display_maintenance_page:
            commands.extend([
                "",
                "# Enable maintenance page",
                "# Update nginx/load balancer to serve static maintenance page",
            ])

        commands.extend([
            "",
            f"# Stop service",
            f"systemctl stop {service_name}",
            f"# Or Kubernetes:",
            f"kubectl scale deployment {service_name} --replicas=0",
        ])

        return ContainmentAction(
            id=action_id,
            action_type='service_shutdown',
            target=service_name,
            target_type='application_service',
            reason='Emergency service shutdown',
            commands=commands,
            rollback_commands=[
                f"systemctl start {service_name}",
                f"kubectl scale deployment {service_name} --replicas=ORIGINAL_COUNT"
            ],
            status=ContainmentStatus.PENDING,
            metadata={
                'shutdown_type': shutdown_type,
                'connections_drained': drain_connections,
                'maintenance_page': display_maintenance_page,
                'stakeholders_notified': notify_stakeholders
            }
        )

    def lockdown_database(self, database: str, db_type: str,
                          lockdown_level: str = 'read_only',
                          revoke_users: List[str] = None,
                          preserve_admin: List[str] = None) -> ContainmentAction:
        """
        Lock down database access.

        Args:
            database: Database name
            db_type: 'postgresql', 'mysql', 'mssql', 'mongodb'
            lockdown_level: 'read_only', 'admin_only', 'full_lockdown'
            revoke_users: Users to revoke
            preserve_admin: Admin users to keep
        """
        revoke_users = revoke_users or []
        preserve_admin = preserve_admin or []
        action_id = generate_action_id()

        commands = [f"# Database lockdown: {database}"]
        rollback_script = []

        if db_type == 'postgresql':
            if lockdown_level == 'read_only':
                commands.extend([
                    "",
                    f"ALTER DATABASE {database} SET default_transaction_read_only = on;",
                ])
                rollback_script.append(f"ALTER DATABASE {database} SET default_transaction_read_only = off;")

            for user in revoke_users:
                if user not in preserve_admin:
                    commands.append(f"REVOKE ALL ON DATABASE {database} FROM {user};")
                    rollback_script.append(f"GRANT ALL ON DATABASE {database} TO {user};")

        elif db_type == 'mysql':
            if lockdown_level == 'read_only':
                commands.append("SET GLOBAL read_only = ON;")
                rollback_script.append("SET GLOBAL read_only = OFF;")

            for user in revoke_users:
                commands.append(f"REVOKE ALL PRIVILEGES ON {database}.* FROM '{user}'@'%';")

        elif db_type == 'mongodb':
            if lockdown_level == 'read_only':
                commands.append(f"db.fsyncLock()")
            for user in revoke_users:
                commands.append(f"db.revokeRolesFromUser('{user}', ['readWrite'])")

        return ContainmentAction(
            id=action_id,
            action_type='database_lockdown',
            target=database,
            target_type='database',
            reason=f'Database lockdown - {lockdown_level}',
            commands=commands,
            rollback_commands=rollback_script,
            status=ContainmentStatus.PENDING,
            metadata={
                'db_type': db_type,
                'lockdown_level': lockdown_level,
                'users_revoked': revoke_users,
                'rollback_script': '\n'.join(rollback_script)
            }
        )


# =============================================================================
# Email Containment
# =============================================================================

class EmailContainment:
    """Email containment actions."""

    def quarantine_messages(self, search_criteria: Dict, email_platform: str,
                            delete_from_mailboxes: bool = True,
                            preserve_for_analysis: bool = True) -> ContainmentAction:
        """
        Quarantine malicious emails.

        Args:
            search_criteria: Search criteria (sender, subject, date_range)
            email_platform: 'office365', 'google', 'exchange'
            delete_from_mailboxes: Remove from user mailboxes
            preserve_for_analysis: Keep copy for analysis
        """
        action_id = generate_action_id()

        commands = [f"# Email quarantine operation"]

        if email_platform == 'office365':
            sender = search_criteria.get('sender', '')
            subject = search_criteria.get('subject_contains', '')

            commands.extend([
                "",
                "# Office 365 Content Search and Purge",
                f"$search = New-ComplianceSearch -Name 'Incident-{action_id}' -ExchangeLocation All -ContentMatchQuery 'from:{sender} AND subject:{subject}'",
                "Start-ComplianceSearch -Identity $search.Name",
                "",
                "# After search completes, purge messages",
                f"New-ComplianceSearchAction -SearchName 'Incident-{action_id}' -Purge -PurgeType SoftDelete",
            ])

        elif email_platform == 'google':
            commands.extend([
                "",
                "# Google Workspace Admin SDK",
                f"# Use Gmail API to search and delete matching messages",
                f"gam all users delete messages query 'from:{search_criteria.get('sender', '')}'"
            ])

        return ContainmentAction(
            id=action_id,
            action_type='email_quarantine',
            target=str(search_criteria),
            target_type='email_messages',
            reason='Quarantine malicious emails',
            commands=commands,
            rollback_available=False,  # Can't undelete purged emails easily
            status=ContainmentStatus.PENDING,
            metadata={
                'email_platform': email_platform,
                'search_criteria': search_criteria,
                'message_count': 0,
                'affected_users': []
            }
        )

    def block_sender(self, sender: str, block_type: str = 'email',
                     email_platform: str = 'office365',
                     add_to_threat_list: bool = True) -> ContainmentAction:
        """
        Block malicious sender.

        Args:
            sender: Email address or domain to block
            block_type: 'email' or 'domain'
            email_platform: 'office365', 'google', 'exchange'
            add_to_threat_list: Add to threat intelligence list
        """
        action_id = generate_action_id()

        commands = [f"# Block sender: {sender}"]

        if email_platform == 'office365':
            if block_type == 'domain':
                domain = sender.split('@')[-1] if '@' in sender else sender
                commands.extend([
                    "",
                    f"# Block domain in Exchange Online",
                    f"Set-HostedContentFilterPolicy -Identity Default -BlockedSenderDomains @{{Add='{domain}'}}",
                ])
            else:
                commands.extend([
                    "",
                    f"# Block sender in Exchange Online",
                    f"Set-HostedContentFilterPolicy -Identity Default -BlockedSenders @{{Add='{sender}'}}",
                ])

        elif email_platform == 'google':
            commands.extend([
                "",
                f"# Google Workspace - Add to blocked senders",
                f"# Via Admin Console or API",
            ])

        return ContainmentAction(
            id=action_id,
            action_type='sender_block',
            target=sender,
            target_type='email_sender',
            reason='Block malicious sender',
            commands=commands,
            rollback_commands=[f"# Remove {sender} from blocked list"],
            status=ContainmentStatus.PENDING,
            metadata={
                'email_platform': email_platform,
                'block_type': block_type,
                'block_rule': f"Block {block_type}: {sender}"
            }
        )

    def remove_inbox_rules(self, username: str, rule_criteria: Dict,
                           email_platform: str = 'office365') -> ContainmentAction:
        """
        Remove malicious inbox rules.

        Args:
            username: User whose rules to examine
            rule_criteria: Criteria for malicious rules
            email_platform: 'office365', 'google', 'exchange'
        """
        action_id = generate_action_id()

        commands = [f"# Remove malicious inbox rules for {username}"]

        if email_platform == 'office365':
            commands.extend([
                "",
                "# List all inbox rules",
                f"Get-InboxRule -Mailbox {username} | Format-List Name,Description,ForwardTo,DeleteMessage",
                "",
                "# Remove suspicious rules",
                f"# Rules that forward externally:",
                f"Get-InboxRule -Mailbox {username} | Where-Object {{$_.ForwardTo -ne $null}} | Remove-InboxRule -Confirm:$false",
                "",
                f"# Rules that delete messages:",
                f"Get-InboxRule -Mailbox {username} | Where-Object {{$_.DeleteMessage -eq $true}} | Remove-InboxRule -Confirm:$false",
            ])

        elif email_platform == 'google':
            commands.extend([
                "",
                f"# Google Workspace - Remove filters",
                f"gam user {username} show filters",
                f"gam user {username} delete filter <filter_id>",
            ])

        return ContainmentAction(
            id=action_id,
            action_type='inbox_rule_removal',
            target=username,
            target_type='inbox_rules',
            reason='Remove malicious inbox rules',
            commands=commands,
            rollback_available=False,
            status=ContainmentStatus.PENDING,
            metadata={
                'email_platform': email_platform,
                'rule_criteria': rule_criteria,
                'rules_removed': [],
                'rule_details': []
            }
        )


# =============================================================================
# Playbook Management
# =============================================================================

class ContainmentPlaybook:
    """Manage containment playbook execution."""

    def __init__(self, incident_id: str, name: str, analyst: str = ''):
        self.incident_id = incident_id
        self.name = name
        self.analyst = analyst
        self.created_at = datetime.now()
        self.actions: List[ContainmentAction] = []
        self.status = 'active'

    def add_action(self, action: ContainmentAction):
        """Add a containment action."""
        action.analyst = self.analyst
        self.actions.append(action)

    def complete_action(self, action_id: str, notes: str = ''):
        """Mark action as completed."""
        for action in self.actions:
            if action.id == action_id:
                action.status = ContainmentStatus.COMPLETED
                action.completed_at = datetime.now()
                action.notes = notes
                return

    def fail_action(self, action_id: str, reason: str, rollback: bool = False):
        """Mark action as failed."""
        for action in self.actions:
            if action.id == action_id:
                action.status = ContainmentStatus.FAILED
                action.notes = reason
                if rollback and action.rollback_available:
                    # Queue rollback
                    pass
                return

    def generate_report(self) -> str:
        """Generate containment report."""
        report = f"""# Containment Report: {self.incident_id}

**Playbook:** {self.name}
**Analyst:** {self.analyst}
**Started:** {self.created_at.strftime('%Y-%m-%d %H:%M')}
**Status:** {self.status}

---

## Actions Summary

| ID | Type | Target | Status | Time |
|----|------|--------|--------|------|
"""
        for action in self.actions:
            time_str = action.completed_at.strftime('%H:%M') if action.completed_at else 'Pending'
            report += f"| {action.id} | {action.action_type} | {action.target[:30]} | {action.status.value} | {time_str} |\n"

        report += f"""

## Detailed Actions

"""
        for action in self.actions:
            report += f"""### {action.id}: {action.action_type}

**Target:** {action.target}
**Reason:** {action.reason}
**Status:** {action.status.value}

**Commands:**
```
{chr(10).join(action.commands[:10])}
```

"""
        return report

    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        completed = len([a for a in self.actions if a.status == ContainmentStatus.COMPLETED])
        failed = len([a for a in self.actions if a.status == ContainmentStatus.FAILED])
        pending = len([a for a in self.actions if a.status == ContainmentStatus.PENDING])

        return f"""# Containment Executive Summary

**Incident:** {self.incident_id}
**Playbook:** {self.name}

## Status
- **Completed Actions:** {completed}
- **Failed Actions:** {failed}
- **Pending Actions:** {pending}

## Key Actions Taken
"""

    def to_json(self) -> str:
        """Export to JSON."""
        return json.dumps({
            'incident_id': self.incident_id,
            'name': self.name,
            'analyst': self.analyst,
            'created_at': self.created_at.isoformat(),
            'status': self.status,
            'actions': [a.to_dict() for a in self.actions]
        }, indent=2)
