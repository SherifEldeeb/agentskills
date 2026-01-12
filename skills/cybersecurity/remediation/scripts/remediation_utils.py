#!/usr/bin/env python3
"""
Remediation Utilities

Comprehensive remediation playbooks for removing security threats, restoring systems,
and recovering from incidents.

Usage:
    from remediation_utils import MalwareRemediation, AccessRemediation, SystemRemediation
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


class RemediationStatus(Enum):
    """Status of remediation actions."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass
class RemediationAction:
    """Represents a remediation action."""
    id: str
    action_type: str
    target: str
    target_type: str
    description: str
    status: RemediationStatus = RemediationStatus.PENDING
    commands: List[str] = field(default_factory=list)
    recovery_steps: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    verification_required: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    analyst: str = ""
    notes: str = ""
    metadata: Dict = field(default_factory=dict)
    audit_results: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'action_type': self.action_type,
            'target': self.target,
            'target_type': self.target_type,
            'description': self.description,
            'status': self.status.value,
            'commands': self.commands,
            'verification_required': self.verification_required,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'analyst': self.analyst,
            'metadata': self.metadata
        }

    def get_verification_failures(self) -> List[str]:
        """Get list of verification failures."""
        return self.metadata.get('verification_failures', [])


def generate_action_id() -> str:
    """Generate unique action ID."""
    return f"REM-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"


# =============================================================================
# Malware Remediation
# =============================================================================

class MalwareRemediation:
    """Malware removal and recovery procedures."""

    def remove_malware(self, hostname: str, malware_type: str,
                       malware_artifacts: Dict[str, List[str]],
                       quarantine_before_delete: bool = True,
                       scan_after_removal: bool = True) -> RemediationAction:
        """
        Remove malware from infected system.

        Args:
            hostname: Target hostname
            malware_type: Type of malware (trojan, ransomware, rootkit, etc.)
            malware_artifacts: Dict with files, registry, scheduled_tasks, services, processes
            quarantine_before_delete: Quarantine files before deletion
            scan_after_removal: Run AV scan after removal
        """
        action_id = generate_action_id()

        commands = [
            f"# Malware Removal: {malware_type} from {hostname}",
            f"# Action ID: {action_id}",
            ""
        ]

        # Process termination
        processes = malware_artifacts.get('processes', [])
        if processes:
            commands.append("# Step 1: Terminate malicious processes")
            for proc in processes:
                commands.append(f"taskkill /F /IM {proc}")
                commands.append(f"pkill -9 {proc}")
            commands.append("")

        # Service removal
        services = malware_artifacts.get('services', [])
        if services:
            commands.append("# Step 2: Stop and remove malicious services")
            for svc in services:
                commands.extend([
                    f"sc stop {svc}",
                    f"sc delete {svc}",
                    f"systemctl stop {svc}",
                    f"systemctl disable {svc}",
                ])
            commands.append("")

        # Scheduled task removal
        tasks = malware_artifacts.get('scheduled_tasks', [])
        if tasks:
            commands.append("# Step 3: Remove malicious scheduled tasks")
            for task in tasks:
                commands.append(f"schtasks /delete /tn \"{task}\" /f")
                commands.append(f"rm /etc/cron.d/{task}")
            commands.append("")

        # Registry cleanup (Windows)
        registry = malware_artifacts.get('registry', [])
        if registry:
            commands.append("# Step 4: Clean registry entries")
            for reg in registry:
                commands.append(f"reg delete \"{reg}\" /f")
            commands.append("")

        # File removal
        files = malware_artifacts.get('files', [])
        if files:
            if quarantine_before_delete:
                commands.append("# Step 5: Quarantine malicious files")
                quarantine_dir = f"C:\\Quarantine\\{action_id}"
                commands.append(f"mkdir {quarantine_dir}")
                for f in files:
                    filename = f.split('\\')[-1].split('/')[-1]
                    commands.append(f"move \"{f}\" \"{quarantine_dir}\\{filename}\"")
                    commands.append(f"mv \"{f}\" \"/quarantine/{action_id}/{filename}\"")
            else:
                commands.append("# Step 5: Delete malicious files")
                for f in files:
                    commands.append(f"del /f /q \"{f}\"")
                    commands.append(f"rm -f \"{f}\"")
            commands.append("")

        verification_steps = [
            "# Verification Steps",
            "1. Run full AV/EDR scan",
            "2. Check running processes for malware indicators",
            "3. Verify registry entries removed",
            "4. Verify scheduled tasks removed",
            "5. Verify services removed",
            "6. Check network connections for C2 traffic",
            "7. Review event logs for suspicious activity",
        ]

        if scan_after_removal:
            commands.extend([
                "# Step 6: Run post-removal scan",
                "# Windows Defender",
                "Start-MpScan -ScanType FullScan",
                "# ClamAV",
                "clamscan -r /",
            ])

        return RemediationAction(
            id=action_id,
            action_type='malware_removal',
            target=hostname,
            target_type='endpoint',
            description=f'Remove {malware_type} malware',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'malware_type': malware_type,
                'files_removed': len(files),
                'registry_cleaned': len(registry),
                'services_removed': len(services),
                'tasks_removed': len(tasks),
                'quarantined': quarantine_before_delete
            }
        )

    def ransomware_recovery(self, hostname: str, ransomware_family: str,
                            encrypted_extensions: List[str],
                            recovery_method: str = 'backup',
                            backup_location: str = '',
                            verify_decryption: bool = True) -> RemediationAction:
        """
        Recover from ransomware infection.

        Args:
            hostname: Target hostname
            ransomware_family: Ransomware variant name
            encrypted_extensions: File extensions used by ransomware
            recovery_method: 'backup', 'decryptor', 'shadow_copies'
            backup_location: Backup source location
            verify_decryption: Verify file integrity after recovery
        """
        action_id = generate_action_id()

        commands = [
            f"# Ransomware Recovery: {ransomware_family} on {hostname}",
            ""
        ]

        recovery_steps = []

        if recovery_method == 'backup':
            recovery_steps = [
                "1. Verify backup integrity and scan for malware",
                "2. Prepare clean system or format affected drives",
                "3. Restore data from verified clean backup",
                "4. Verify restored file integrity",
                "5. Apply security patches before reconnecting to network",
            ]
            commands.extend([
                "# Verify backup integrity",
                f"# Scan backup location: {backup_location}",
                "",
                "# Restore from backup",
                f"robocopy \"{backup_location}\" \"D:\\Restored\" /E /Z /MT:8",
                f"rsync -avz {backup_location}/ /restored/",
            ])

        elif recovery_method == 'decryptor':
            recovery_steps = [
                f"1. Download verified decryptor for {ransomware_family}",
                "2. Verify decryptor hash against known good value",
                "3. Run decryptor in isolated environment first",
                "4. Decrypt files on affected system",
                "5. Verify decryption success",
            ]
            commands.extend([
                f"# Check for available decryptor at:",
                f"# - https://www.nomoreransom.org/",
                f"# - https://id-ransomware.malwarehunterteam.com/",
                "",
                f"# Ransomware family: {ransomware_family}",
                f"# Encrypted extensions: {', '.join(encrypted_extensions)}",
            ])

        elif recovery_method == 'shadow_copies':
            recovery_steps = [
                "1. Check for available shadow copies",
                "2. Mount shadow copy volumes",
                "3. Copy files from shadow copies",
                "4. Verify file integrity",
            ]
            commands.extend([
                "# List shadow copies",
                "vssadmin list shadows",
                "",
                "# Mount shadow copy",
                "mklink /d C:\\ShadowMount \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\",
                "",
                "# Copy files from shadow copy",
                "robocopy C:\\ShadowMount\\Users D:\\Recovered\\Users /E",
            ])

        validation_steps = [
            "# Validation Steps",
            "1. Verify file counts match expected",
            "2. Check file hashes against known good values",
            "3. Open sample files to verify content integrity",
            "4. Run integrity checks on databases if applicable",
            "5. Test application functionality with restored data",
        ]

        return RemediationAction(
            id=action_id,
            action_type='ransomware_recovery',
            target=hostname,
            target_type='endpoint',
            description=f'Recover from {ransomware_family} ransomware',
            commands=commands,
            recovery_steps=recovery_steps,
            verification_steps=validation_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'ransomware_family': ransomware_family,
                'encrypted_extensions': encrypted_extensions,
                'recovery_method': recovery_method,
                'backup_location': backup_location
            }
        )

    def rootkit_removal(self, hostname: str, rootkit_type: str,
                        detection_tool: str = 'gmer',
                        offline_scan: bool = True,
                        rebuild_mbr: bool = False) -> RemediationAction:
        """
        Remove rootkits and bootkits.

        Args:
            hostname: Target hostname
            rootkit_type: 'kernel', 'bootkit', 'firmware'
            detection_tool: Tool used for detection
            offline_scan: Perform offline boot scan
            rebuild_mbr: Rebuild Master Boot Record
        """
        action_id = generate_action_id()

        commands = [
            f"# Rootkit Removal: {rootkit_type} on {hostname}",
            ""
        ]

        if rootkit_type == 'kernel':
            commands.extend([
                "# Boot from clean media for offline analysis",
                "# Run rootkit scanner",
                f"{detection_tool} /scan /deep",
                "",
                "# Check for hidden processes",
                "Get-Process | Where-Object {$_.Path -eq $null}",
                "",
                "# Check for hooked system calls",
                "# Use kernel debugger to inspect SSDT",
            ])

        elif rootkit_type == 'bootkit':
            commands.extend([
                "# Boot from clean Windows installation media",
                "# Open command prompt",
                "",
                "# Fix boot records",
                "bootrec /fixmbr",
                "bootrec /fixboot",
                "bootrec /scanos",
                "bootrec /rebuildbcd",
            ])

            if rebuild_mbr:
                commands.extend([
                    "",
                    "# Complete MBR rebuild",
                    "bootrec /fixmbr",
                    "bcdboot C:\\Windows /s C:",
                ])

        elif rootkit_type == 'firmware':
            commands.extend([
                "# Firmware rootkit - requires hardware intervention",
                "# 1. Update BIOS/UEFI to latest version",
                "# 2. Reflash firmware from known good source",
                "# 3. Consider hardware replacement if persistent",
                "",
                "# Check UEFI Secure Boot status",
                "bcdedit /enum all",
                "Confirm-SecureBootUEFI",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Boot system and run rootkit scanner",
            "2. Check for hidden processes and files",
            "3. Verify system call table integrity",
            "4. Monitor for suspicious kernel activity",
            "5. Run memory forensics to verify clean state",
        ]

        return RemediationAction(
            id=action_id,
            action_type='rootkit_removal',
            target=hostname,
            target_type='endpoint',
            description=f'Remove {rootkit_type} rootkit',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'rootkit_type': rootkit_type,
                'detection_tool': detection_tool,
                'offline_scan': offline_scan,
                'rebuild_mbr': rebuild_mbr
            }
        )

    def webshell_removal(self, hostname: str, webshell_paths: List[str],
                         web_root: str, scan_for_additional: bool = True,
                         patch_upload_vulnerability: bool = True,
                         restore_from_clean: bool = False) -> RemediationAction:
        """
        Remove web shells from compromised servers.

        Args:
            hostname: Target hostname
            webshell_paths: Known web shell paths
            web_root: Web server document root
            scan_for_additional: Scan for additional web shells
            patch_upload_vulnerability: Fix upload vulnerability
            restore_from_clean: Restore from clean backup
        """
        action_id = generate_action_id()

        commands = [
            f"# Web Shell Removal on {hostname}",
            f"# Web root: {web_root}",
            ""
        ]

        # Remove known web shells
        commands.append("# Step 1: Remove known web shells")
        for path in webshell_paths:
            commands.extend([
                f"# Backup for analysis",
                f"cp \"{path}\" \"/evidence/{action_id}/$(basename {path})\"",
                f"# Remove web shell",
                f"rm -f \"{path}\"",
            ])
        commands.append("")

        if scan_for_additional:
            commands.extend([
                "# Step 2: Scan for additional web shells",
                f"# Check for suspicious PHP files",
                f"grep -r 'eval\\|base64_decode\\|shell_exec\\|passthru\\|system\\|exec' {web_root} --include='*.php'",
                "",
                f"# Check for recently modified files",
                f"find {web_root} -type f -mtime -7 -name '*.php'",
                "",
                f"# Check file permissions",
                f"find {web_root} -type f -perm -o+w",
                "",
                "# Use YARA rules for web shell detection",
                f"yara webshell_rules.yar {web_root}",
            ])

        if patch_upload_vulnerability:
            commands.extend([
                "",
                "# Step 3: Patch upload vulnerability",
                "# Review and fix upload handling code",
                "# Implement file type validation",
                "# Add upload directory restrictions",
                "# Example nginx config to block PHP in uploads:",
                "# location /uploads/ {",
                "#     location ~ \\.php$ { deny all; }",
                "# }",
            ])

        if restore_from_clean:
            commands.extend([
                "",
                "# Step 4: Restore from clean backup",
                f"# Backup current state for analysis",
                f"tar -czf /evidence/{action_id}/webroot_compromised.tar.gz {web_root}",
                f"# Restore from clean backup",
                f"rsync -av --delete /backup/webroot/ {web_root}/",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify all known web shells removed",
            "2. Run web shell scanner",
            "3. Check file integrity against baseline",
            "4. Review web server access logs",
            "5. Test upload functionality with malicious file",
            "6. Monitor for new suspicious files",
        ]

        return RemediationAction(
            id=action_id,
            action_type='webshell_removal',
            target=hostname,
            target_type='web_server',
            description='Remove web shells',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'files_removed': webshell_paths,
                'web_root': web_root,
                'scanned_for_additional': scan_for_additional,
                'vulnerability_patched': patch_upload_vulnerability
            }
        )


# =============================================================================
# Access Remediation
# =============================================================================

class AccessRemediation:
    """Access and credential remediation procedures."""

    def full_credential_reset(self, scope: str, users: List[str],
                              reset_types: List[str],
                              force_mfa_reenroll: bool = True,
                              expire_all_sessions: bool = True,
                              notify_users: bool = True) -> RemediationAction:
        """
        Perform comprehensive credential reset.

        Args:
            scope: 'domain', 'local', 'cloud', 'all'
            users: List of users to reset
            reset_types: List of credential types to reset
            force_mfa_reenroll: Require MFA re-enrollment
            expire_all_sessions: Invalidate all sessions
            notify_users: Send notification to users
        """
        action_id = generate_action_id()

        commands = [
            f"# Credential Reset - Scope: {scope}",
            f"# Users: {len(users)}",
            ""
        ]

        for user in users:
            if 'password' in reset_types:
                temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
                commands.extend([
                    f"# Reset password for {user}",
                    f"Set-ADAccountPassword -Identity {user} -Reset -NewPassword (ConvertTo-SecureString '{temp_password}' -AsPlainText -Force)",
                    f"Set-ADUser -Identity {user} -ChangePasswordAtLogon $true",
                ])

            if 'kerberos' in reset_types:
                commands.extend([
                    f"# Reset Kerberos tickets for {user}",
                    f"klist purge -li 0x3e7",  # Purge SYSTEM tickets
                ])

            if 'certificates' in reset_types:
                commands.extend([
                    f"# Revoke certificates for {user}",
                    f"# Check CA for issued certificates and revoke",
                ])

        if force_mfa_reenroll:
            commands.extend([
                "",
                "# Force MFA re-enrollment",
                "# Azure AD:",
                "# Remove-MgUserAuthenticationPhoneMethod",
                "# Remove-MgUserAuthenticationEmailMethod",
            ])

        if expire_all_sessions:
            commands.extend([
                "",
                "# Expire all active sessions",
                "Revoke-MgUserSignInSession -UserId {user}",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify all passwords changed",
            "2. Confirm MFA re-enrollment required",
            "3. Test user logon with new credentials",
            "4. Verify old sessions invalidated",
            "5. Check audit logs for credential changes",
        ]

        return RemediationAction(
            id=action_id,
            action_type='credential_reset',
            target=f'{len(users)} users',
            target_type='credentials',
            description=f'Full credential reset - {scope}',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'scope': scope,
                'users': users,
                'reset_types': reset_types,
                'mfa_reenroll': force_mfa_reenroll,
                'sessions_expired': expire_all_sessions
            }
        )

    def backdoor_removal(self, hostname: str, backdoors: Dict[str, List[str]],
                         audit_all_persistence: bool = True,
                         compare_to_baseline: bool = True) -> RemediationAction:
        """
        Remove attacker persistence and backdoors.

        Args:
            hostname: Target hostname
            backdoors: Dict with accounts, ssh_keys, scheduled_tasks, services, etc.
            audit_all_persistence: Audit all persistence mechanisms
            compare_to_baseline: Compare to known good baseline
        """
        action_id = generate_action_id()

        commands = [
            f"# Backdoor Removal on {hostname}",
            ""
        ]

        removed_count = 0

        # Remove backdoor accounts
        accounts = backdoors.get('accounts', [])
        if accounts:
            commands.append("# Remove backdoor accounts")
            for account in accounts:
                commands.extend([
                    f"net user {account} /delete",
                    f"userdel -r {account}",
                ])
                removed_count += 1
            commands.append("")

        # Remove SSH keys
        ssh_keys = backdoors.get('ssh_keys', [])
        if ssh_keys:
            commands.append("# Remove unauthorized SSH keys")
            for key_file in ssh_keys:
                commands.extend([
                    f"# Backup for analysis",
                    f"cp {key_file} /evidence/{action_id}/",
                    f"# Remove unauthorized entries from authorized_keys",
                    f"# Manual review required for: {key_file}",
                ])
                removed_count += 1
            commands.append("")

        # Remove scheduled tasks
        tasks = backdoors.get('scheduled_tasks', [])
        if tasks:
            commands.append("# Remove malicious scheduled tasks")
            for task in tasks:
                commands.extend([
                    f"schtasks /delete /tn \"{task}\" /f",
                ])
                removed_count += 1
            commands.append("")

        # Remove services
        services = backdoors.get('services', [])
        if services:
            commands.append("# Remove malicious services")
            for svc in services:
                commands.extend([
                    f"sc stop {svc}",
                    f"sc delete {svc}",
                ])
                removed_count += 1
            commands.append("")

        # Remove registry entries
        registry = backdoors.get('registry', [])
        if registry:
            commands.append("# Remove registry persistence")
            for reg in registry:
                commands.append(f"reg delete \"{reg}\" /f")
                removed_count += 1
            commands.append("")

        # Remove web shells
        web_shells = backdoors.get('web_shells', [])
        if web_shells:
            commands.append("# Remove web shells")
            for shell in web_shells:
                commands.append(f"rm -f {shell}")
                removed_count += 1
            commands.append("")

        # Remove cron jobs
        cron_jobs = backdoors.get('cron_jobs', [])
        if cron_jobs:
            commands.append("# Remove malicious cron jobs")
            for cron in cron_jobs:
                commands.append(f"rm -f {cron}")
                removed_count += 1
            commands.append("")

        if audit_all_persistence:
            commands.extend([
                "# Audit all persistence mechanisms",
                "",
                "# Check all auto-start locations",
                "autoruns -accepteula -a *",
                "",
                "# List all scheduled tasks",
                "schtasks /query /fo LIST /v",
                "",
                "# List all services",
                "Get-Service | Where-Object {$_.Status -eq 'Running'}",
                "",
                "# Check startup folders",
                "dir 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'",
                "dir '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'",
                "",
                "# Linux persistence check",
                "ls -la /etc/cron.d/",
                "cat /etc/crontab",
                "ls -la /etc/init.d/",
                "systemctl list-unit-files --state=enabled",
            ])

        audit_results = {
            'accounts_removed': len(accounts),
            'ssh_keys_removed': len(ssh_keys),
            'tasks_removed': len(tasks),
            'services_removed': len(services),
            'registry_removed': len(registry),
            'webshells_removed': len(web_shells),
            'cron_removed': len(cron_jobs)
        }

        verification_steps = [
            "# Verification Steps",
            "1. Re-run autoruns and compare to baseline",
            "2. Verify accounts removed",
            "3. Check SSH authorized_keys files",
            "4. Verify scheduled tasks clean",
            "5. Verify services clean",
            "6. Check for new persistence mechanisms",
        ]

        return RemediationAction(
            id=action_id,
            action_type='backdoor_removal',
            target=hostname,
            target_type='endpoint',
            description='Remove backdoors and persistence',
            commands=commands,
            verification_steps=verification_steps,
            audit_results=audit_results,
            status=RemediationStatus.PENDING,
            metadata={
                'removed_count': removed_count,
                'audit_results': audit_results,
                'baseline_compared': compare_to_baseline
            }
        )

    def privilege_cleanup(self, affected_accounts: List[str],
                          unauthorized_groups: List[str],
                          unauthorized_permissions: List[str],
                          reset_to_baseline: bool = True,
                          audit_privileged_groups: bool = True) -> RemediationAction:
        """
        Clean up privilege escalation artifacts.

        Args:
            affected_accounts: Accounts with unauthorized privileges
            unauthorized_groups: Groups to remove accounts from
            unauthorized_permissions: Permissions to revoke
            reset_to_baseline: Reset to known good state
            audit_privileged_groups: Audit all privileged groups
        """
        action_id = generate_action_id()

        commands = [
            "# Privilege Escalation Cleanup",
            ""
        ]

        # Remove from unauthorized groups
        commands.append("# Remove users from unauthorized groups")
        groups_cleaned = []
        for account in affected_accounts:
            for group in unauthorized_groups:
                commands.append(f"Remove-ADGroupMember -Identity '{group}' -Members '{account}' -Confirm:$false")
                groups_cleaned.append(f"{account} from {group}")
        commands.append("")

        # Revoke unauthorized permissions
        commands.append("# Revoke unauthorized permissions")
        permissions_revoked = []
        for account in affected_accounts:
            for perm in unauthorized_permissions:
                commands.append(f"# Revoke {perm} from {account}")
                permissions_revoked.append(f"{perm} from {account}")
        commands.append("")

        if audit_privileged_groups:
            commands.extend([
                "# Audit privileged groups",
                "Get-ADGroupMember -Identity 'Domain Admins'",
                "Get-ADGroupMember -Identity 'Enterprise Admins'",
                "Get-ADGroupMember -Identity 'Schema Admins'",
                "Get-ADGroupMember -Identity 'Administrators'",
                "",
                "# Compare to baseline",
                "# diff baseline_admins.txt current_admins.txt",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify accounts removed from privileged groups",
            "2. Verify permissions revoked",
            "3. Test affected accounts cannot perform privileged actions",
            "4. Compare privileged group membership to baseline",
            "5. Review security event logs",
        ]

        return RemediationAction(
            id=action_id,
            action_type='privilege_cleanup',
            target=f'{len(affected_accounts)} accounts',
            target_type='permissions',
            description='Clean up privilege escalation',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'affected_accounts': affected_accounts,
                'groups_cleaned': groups_cleaned,
                'permissions_revoked': permissions_revoked
            }
        )

    def golden_ticket_remediation(self, domain: str,
                                  reset_krbtgt: bool = True,
                                  reset_interval_hours: int = 10,
                                  force_all_ticket_renewal: bool = True,
                                  audit_service_accounts: bool = True) -> RemediationAction:
        """
        Remediate Kerberos golden ticket attack.

        Args:
            domain: Active Directory domain
            reset_krbtgt: Reset KRBTGT password (must be done twice)
            reset_interval_hours: Hours between KRBTGT resets
            force_all_ticket_renewal: Force all clients to renew tickets
            audit_service_accounts: Audit service account SPNs
        """
        action_id = generate_action_id()

        commands = [
            f"# Golden Ticket Remediation for {domain}",
            "",
            "# CRITICAL: KRBTGT must be reset TWICE with interval between resets",
            f"# Recommended interval: {reset_interval_hours} hours",
            ""
        ]

        if reset_krbtgt:
            commands.extend([
                "# First KRBTGT reset",
                "# Run on DC with KRBTGT reset script",
                "Import-Module .\\Reset-KrbtgtKeyInteractive.ps1",
                "Reset-KrbtgtKeyInteractive -Domain $domain -Mode Execute",
                "",
                f"# WAIT {reset_interval_hours} HOURS",
                f"# This allows all legitimate tickets to be renewed",
                "",
                "# Second KRBTGT reset (after wait period)",
                "Reset-KrbtgtKeyInteractive -Domain $domain -Mode Execute",
                "",
                "# Alternative manual method:",
                "# Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force)",
            ])

        if force_all_ticket_renewal:
            commands.extend([
                "",
                "# Force ticket renewal on clients",
                "# Clear Kerberos ticket cache",
                "klist purge",
                "",
                "# For all workstations, run:",
                "Invoke-Command -ComputerName $computers -ScriptBlock {klist purge}",
            ])

        if audit_service_accounts:
            commands.extend([
                "",
                "# Audit service accounts",
                "# List all SPNs",
                "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName",
                "",
                "# Check for Kerberoastable accounts",
                "Get-ADUser -Filter {ServicePrincipalName -ne '$null' -and Enabled -eq $true} -Properties ServicePrincipalName, PasswordLastSet",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify KRBTGT password was reset twice",
            "2. Confirm wait period between resets",
            "3. Test Kerberos authentication is working",
            "4. Monitor for failed authentication attempts",
            "5. Check for golden ticket indicators in logs",
            "6. Verify all service accounts reviewed",
        ]

        return RemediationAction(
            id=action_id,
            action_type='golden_ticket_remediation',
            target=domain,
            target_type='domain',
            description='Remediate golden ticket attack',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'domain': domain,
                'krbtgt_reset': reset_krbtgt,
                'wait_hours': reset_interval_hours,
                'ticket_renewal_forced': force_all_ticket_renewal
            }
        )


# =============================================================================
# System Remediation
# =============================================================================

class SystemRemediation:
    """System rebuild and recovery procedures."""

    def rebuild_system(self, hostname: str, os_version: str,
                       image_source: str = 'gold_image',
                       preserve_data: bool = False,
                       join_domain: bool = True,
                       apply_security_baseline: bool = True,
                       install_edr: bool = True) -> RemediationAction:
        """
        Rebuild compromised system from scratch.

        Args:
            hostname: Target hostname
            os_version: Operating system version to install
            image_source: Source of clean image
            preserve_data: Preserve user data (if already backed up)
            join_domain: Join Active Directory domain
            apply_security_baseline: Apply security hardening
            install_edr: Install EDR agent
        """
        action_id = generate_action_id()

        commands = [
            f"# System Rebuild: {hostname}",
            f"# OS: {os_version}",
            f"# Image source: {image_source}",
            ""
        ]

        # Pre-rebuild steps
        commands.extend([
            "# Pre-rebuild checklist",
            "# [ ] Backup any needed data (already done if preserve_data=False)",
            "# [ ] Document current configuration",
            "# [ ] Collect evidence if needed",
            "# [ ] Verify clean image hash",
            "",
        ])

        # Rebuild steps
        commands.extend([
            "# Step 1: Boot from clean installation media",
            "# Verify installation media hash matches known good value",
            "",
            "# Step 2: Format and install OS",
            "# Delete all existing partitions",
            "# Create new partitions",
            f"# Install {os_version}",
            "",
        ])

        if join_domain:
            commands.extend([
                "# Step 3: Join domain",
                "Add-Computer -DomainName corp.example.com -Credential $cred -Restart",
                "",
            ])

        if apply_security_baseline:
            commands.extend([
                "# Step 4: Apply security baseline",
                "# Import GPO baseline",
                "Import-GPO -BackupGpoName 'Security Baseline' -TargetName 'Workstation Baseline' -Path '\\\\server\\GPOBackups'",
                "",
                "# Or apply LGPO settings",
                "LGPO.exe /g '\\\\server\\Baselines\\CIS_Win11'",
                "",
            ])

        if install_edr:
            commands.extend([
                "# Step 5: Install EDR agent",
                "msiexec /i 'EDRAgent.msi' /qn",
                "",
            ])

        commands.extend([
            "# Step 6: Install required applications",
            "# Install from approved software repository",
            "",
            "# Step 7: Configure user profile",
            "# Restore user data if preserved",
            "",
            "# Step 8: Final verification",
            "# Run compliance scan",
            "# Verify EDR agent reporting",
        ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify OS installation completed successfully",
            "2. Confirm domain join if applicable",
            "3. Verify security baseline applied",
            "4. Confirm EDR agent reporting to console",
            "5. Run vulnerability scan",
            "6. Test user can log in and work",
            "7. Verify all required applications installed",
        ]

        return RemediationAction(
            id=action_id,
            action_type='system_rebuild',
            target=hostname,
            target_type='endpoint',
            description=f'Rebuild system with {os_version}',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'os_version': os_version,
                'image_source': image_source,
                'data_preserved': preserve_data,
                'domain_joined': join_domain,
                'baseline_applied': apply_security_baseline,
                'edr_installed': install_edr
            }
        )

    def emergency_patching(self, targets: List[str], patches: List[str],
                           patch_source: str = 'wsus',
                           reboot_allowed: bool = True,
                           verify_after_patch: bool = True,
                           rollback_on_failure: bool = True) -> RemediationAction:
        """
        Deploy emergency security patches.

        Args:
            targets: List of target systems
            patches: List of patches to apply (KB numbers or CVE IDs)
            patch_source: 'wsus', 'sccm', 'manual'
            reboot_allowed: Allow system reboot
            verify_after_patch: Verify patch installation
            rollback_on_failure: Rollback if patch fails
        """
        action_id = generate_action_id()

        commands = [
            f"# Emergency Patching",
            f"# Targets: {len(targets)} systems",
            f"# Patches: {', '.join(patches)}",
            ""
        ]

        if patch_source == 'wsus':
            commands.extend([
                "# Deploy via WSUS",
                "# Approve patches for target group",
                "",
                "# Force Windows Update check",
                "Invoke-Command -ComputerName $targets -ScriptBlock {",
                "    wuauclt /detectnow",
                "    wuauclt /updatenow",
                "}",
            ])

        elif patch_source == 'sccm':
            commands.extend([
                "# Deploy via SCCM",
                "# Create deployment for required patches",
                "# Target collection with affected systems",
            ])

        elif patch_source == 'manual':
            commands.extend([
                "# Manual patch deployment",
                "",
            ])
            for patch in patches:
                commands.extend([
                    f"# Install {patch}",
                    f"wusa.exe {patch}.msu /quiet /norestart",
                ])

        if reboot_allowed:
            commands.extend([
                "",
                "# Reboot systems",
                "Restart-Computer -ComputerName $targets -Force",
            ])

        if verify_after_patch:
            commands.extend([
                "",
                "# Verify patch installation",
                "Get-HotFix -Id KB* | Where-Object {$patches -contains $_.HotFixId}",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify all patches installed via Get-HotFix",
            "2. Confirm systems rebooted if required",
            "3. Test application functionality",
            "4. Run vulnerability scan to confirm remediation",
            "5. Check event logs for installation errors",
        ]

        return RemediationAction(
            id=action_id,
            action_type='emergency_patching',
            target=f'{len(targets)} systems',
            target_type='systems',
            description=f'Emergency patches: {", ".join(patches)}',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'targets': targets,
                'patches': patches,
                'patch_source': patch_source,
                'reboot_allowed': reboot_allowed,
                'rollback_enabled': rollback_on_failure
            }
        )

    def configuration_hardening(self, hostname: str, baseline: str,
                                focus_areas: List[str],
                                disable_legacy_protocols: bool = True,
                                enable_advanced_audit: bool = True) -> RemediationAction:
        """
        Apply security hardening after incident.

        Args:
            hostname: Target hostname
            baseline: 'cis_level_1', 'cis_level_2', 'disa_stig', 'custom'
            focus_areas: Areas to harden
            disable_legacy_protocols: Disable SMBv1, LLMNR, etc.
            enable_advanced_audit: Enable advanced audit policies
        """
        action_id = generate_action_id()

        commands = [
            f"# Security Hardening: {hostname}",
            f"# Baseline: {baseline}",
            ""
        ]

        if 'authentication' in focus_areas:
            commands.extend([
                "# Authentication Hardening",
                "# Enforce strong passwords",
                "net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24",
                "",
                "# Enable account lockout",
                "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
                "",
            ])

        if 'network' in focus_areas:
            commands.extend([
                "# Network Hardening",
            ])

            if disable_legacy_protocols:
                commands.extend([
                    "# Disable SMBv1",
                    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                    "",
                    "# Disable LLMNR",
                    "reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' /v EnableMulticast /t REG_DWORD /d 0 /f",
                    "",
                    "# Disable NetBIOS",
                    "# Via DHCP or network adapter settings",
                    "",
                ])

        if 'logging' in focus_areas:
            commands.extend([
                "# Logging Hardening",
            ])

            if enable_advanced_audit:
                commands.extend([
                    "# Enable advanced audit policies",
                    "auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable",
                    "auditpol /set /category:'Account Logon' /success:enable /failure:enable",
                    "auditpol /set /category:'Account Management' /success:enable /failure:enable",
                    "auditpol /set /category:'Privilege Use' /success:enable /failure:enable",
                    "auditpol /set /category:'Process Tracking' /success:enable /failure:enable",
                    "",
                    "# Increase log sizes",
                    "wevtutil sl Security /ms:1073741824",
                    "wevtutil sl System /ms:134217728",
                    "",
                ])

        if 'services' in focus_areas:
            commands.extend([
                "# Service Hardening",
                "# Disable unnecessary services",
                "Set-Service -Name 'RemoteRegistry' -StartupType Disabled",
                "Set-Service -Name 'Browser' -StartupType Disabled",
                "",
            ])

        verification_steps = [
            "# Verification Steps",
            f"1. Run compliance scan against {baseline}",
            "2. Verify legacy protocols disabled",
            "3. Confirm audit policies applied",
            "4. Test authentication mechanisms",
            "5. Review hardening report",
        ]

        return RemediationAction(
            id=action_id,
            action_type='configuration_hardening',
            target=hostname,
            target_type='endpoint',
            description=f'Apply {baseline} hardening',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'baseline': baseline,
                'focus_areas': focus_areas,
                'legacy_protocols_disabled': disable_legacy_protocols,
                'advanced_audit': enable_advanced_audit,
                'compliance_score': 0  # To be filled after scan
            }
        )

    def log_recovery(self, hostname: str, log_types: List[str],
                     recovery_sources: List[str],
                     time_range: tuple,
                     verify_integrity: bool = True) -> RemediationAction:
        """
        Recover and restore audit logs.

        Args:
            hostname: Target hostname
            log_types: Types of logs to recover
            recovery_sources: Sources to recover from
            time_range: Tuple of (start_date, end_date)
            verify_integrity: Verify log integrity
        """
        action_id = generate_action_id()

        commands = [
            f"# Log Recovery for {hostname}",
            f"# Time range: {time_range[0]} to {time_range[1]}",
            ""
        ]

        for source in recovery_sources:
            if source == 'backup':
                commands.extend([
                    "# Recover from backup",
                    "# Restore event logs from backup location",
                    f"xcopy /s /e '\\\\backup\\{hostname}\\logs' 'C:\\RecoveredLogs'",
                ])

            elif source == 'siem':
                commands.extend([
                    "# Export from SIEM",
                    f"# Query SIEM for logs from {hostname}",
                    f"# Time range: {time_range[0]} to {time_range[1]}",
                    "# Export to local storage",
                ])

            elif source == 'shadow_copy':
                commands.extend([
                    "# Recover from shadow copies",
                    "vssadmin list shadows",
                    "# Mount shadow copy and copy logs",
                ])

        if verify_integrity:
            commands.extend([
                "",
                "# Verify log integrity",
                "# Check for gaps in event IDs",
                "# Verify log file hashes if available",
                "# Compare against known good baselines",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify all log types recovered",
            "2. Check for time gaps in logs",
            "3. Verify log integrity/chain",
            "4. Import into analysis tool",
            "5. Correlate with other data sources",
        ]

        return RemediationAction(
            id=action_id,
            action_type='log_recovery',
            target=hostname,
            target_type='logs',
            description='Recover audit logs',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'log_types': log_types,
                'recovery_sources': recovery_sources,
                'time_range': time_range,
                'logs_recovered': [],
                'integrity_verified': False
            }
        )


# =============================================================================
# Data Remediation
# =============================================================================

class DataRemediation:
    """Data breach response and recovery procedures."""

    def breach_response(self, breach_type: str, affected_data_types: List[str],
                        affected_record_count: int,
                        notification_required: bool = True,
                        regulatory_requirements: List[str] = None,
                        legal_hold: bool = True) -> RemediationAction:
        """
        Execute data breach response procedures.

        Args:
            breach_type: Type of breach (pii_exposure, credential_leak, etc.)
            affected_data_types: Types of data affected
            affected_record_count: Number of records affected
            notification_required: Whether notification is required
            regulatory_requirements: Applicable regulations
            legal_hold: Implement legal hold
        """
        action_id = generate_action_id()
        regulatory_requirements = regulatory_requirements or []

        commands = [
            f"# Data Breach Response",
            f"# Breach type: {breach_type}",
            f"# Records affected: {affected_record_count}",
            ""
        ]

        notification_timeline = {}

        # Determine notification timelines
        for reg in regulatory_requirements:
            if reg.lower() == 'gdpr':
                notification_timeline['GDPR - DPA'] = '72 hours'
                notification_timeline['GDPR - Individuals'] = 'Without undue delay if high risk'
            elif reg.lower() == 'hipaa':
                notification_timeline['HIPAA - HHS'] = '60 days'
                notification_timeline['HIPAA - Individuals'] = '60 days'
            elif reg.lower() == 'ccpa':
                notification_timeline['CCPA - Individuals'] = 'Most expedient time possible'

        commands.extend([
            "# Step 1: Contain the breach",
            "# - Secure affected systems",
            "# - Revoke compromised credentials",
            "# - Block unauthorized access paths",
            "",
            "# Step 2: Assess the scope",
            f"# - Identify all affected records ({affected_record_count})",
            f"# - Document affected data types: {', '.join(affected_data_types)}",
            "# - Determine exposure timeline",
            "",
        ])

        if legal_hold:
            commands.extend([
                "# Step 3: Implement legal hold",
                "# - Preserve all relevant evidence",
                "# - Suspend data retention policies",
                "# - Document chain of custody",
                "",
            ])

        if notification_required:
            commands.extend([
                "# Step 4: Prepare notifications",
                "# Notification timeline:",
            ])
            for entity, timeline in notification_timeline.items():
                commands.append(f"# - {entity}: {timeline}")
            commands.extend([
                "",
                "# Step 5: Notify affected parties",
                "# - Draft notification letters",
                "# - Set up call center if needed",
                "# - Prepare FAQ for inquiries",
                "",
            ])

        commands.extend([
            "# Step 6: Remediate root cause",
            "# - Patch vulnerabilities",
            "# - Update access controls",
            "# - Implement additional monitoring",
            "",
            "# Step 7: Document lessons learned",
            "# - Update incident response plan",
            "# - Conduct tabletop exercises",
        ])

        regulatory_actions = []
        for reg in regulatory_requirements:
            regulatory_actions.append({
                'regulation': reg,
                'notification_required': True,
                'timeline': notification_timeline.get(reg, 'As required')
            })

        verification_steps = [
            "# Verification Steps",
            "1. Confirm breach contained",
            "2. Verify all affected records identified",
            "3. Confirm notifications sent per timeline",
            "4. Verify remediation actions completed",
            "5. Document regulatory compliance",
        ]

        return RemediationAction(
            id=action_id,
            action_type='breach_response',
            target=f'{affected_record_count} records',
            target_type='data',
            description=f'Breach response: {breach_type}',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'breach_type': breach_type,
                'affected_data_types': affected_data_types,
                'affected_record_count': affected_record_count,
                'notification_timeline': notification_timeline,
                'regulatory_actions': regulatory_actions,
                'legal_hold': legal_hold
            }
        )

    def backup_restoration(self, target_system: str, backup_source: str,
                           restore_type: str = 'full',
                           restore_paths: List[str] = None,
                           verify_after_restore: bool = True,
                           scan_before_restore: bool = True) -> RemediationAction:
        """
        Restore data from backups.

        Args:
            target_system: System to restore to
            backup_source: Backup location
            restore_type: 'full', 'incremental', 'selective'
            restore_paths: Specific paths to restore
            verify_after_restore: Verify data integrity
            scan_before_restore: Scan backup for malware
        """
        action_id = generate_action_id()
        restore_paths = restore_paths or []

        commands = [
            f"# Backup Restoration to {target_system}",
            f"# Source: {backup_source}",
            f"# Type: {restore_type}",
            ""
        ]

        if scan_before_restore:
            commands.extend([
                "# Step 1: Scan backup for malware",
                f"clamscan -r {backup_source}",
                "# Or use EDR scanning",
                "",
            ])

        commands.extend([
            "# Step 2: Verify backup integrity",
            f"# Check backup catalog",
            f"# Verify backup checksums",
            "",
        ])

        if restore_type == 'full':
            commands.extend([
                "# Step 3: Full system restore",
                f"# Mount backup volume",
                f"robocopy '{backup_source}' 'D:\\' /E /Z /MT:8 /R:3 /W:10",
            ])

        elif restore_type == 'selective' and restore_paths:
            commands.append("# Step 3: Selective restore")
            for path in restore_paths:
                commands.append(f"robocopy '{backup_source}\\{path}' 'D:\\{path}' /E /Z")

        elif restore_type == 'incremental':
            commands.extend([
                "# Step 3: Incremental restore",
                "# Restore base backup first, then apply incrementals",
            ])

        if verify_after_restore:
            commands.extend([
                "",
                "# Step 4: Verify restoration",
                "# Compare file counts",
                f"Get-ChildItem -Recurse D:\\ | Measure-Object",
                "# Verify file hashes for critical files",
                "# Test application functionality",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify all files restored",
            "2. Check file integrity/hashes",
            "3. Test data accessibility",
            "4. Verify application functionality",
            "5. Confirm no malware in restored data",
        ]

        return RemediationAction(
            id=action_id,
            action_type='backup_restoration',
            target=target_system,
            target_type='data',
            description=f'{restore_type} restore from backup',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'backup_source': backup_source,
                'restore_type': restore_type,
                'restore_paths': restore_paths,
                'scanned': scan_before_restore,
                'verified': False
            }
        )

    def integrity_verification(self, target_paths: List[str],
                               baseline_hashes: str,
                               verification_method: str = 'sha256',
                               report_modifications: bool = True,
                               quarantine_suspicious: bool = True) -> RemediationAction:
        """
        Verify data integrity after incident.

        Args:
            target_paths: Paths to verify
            baseline_hashes: Path to baseline hash file
            verification_method: Hash algorithm
            report_modifications: Report modified files
            quarantine_suspicious: Quarantine suspicious files
        """
        action_id = generate_action_id()

        commands = [
            f"# Data Integrity Verification",
            f"# Method: {verification_method}",
            ""
        ]

        for path in target_paths:
            commands.extend([
                f"# Verify {path}",
                f"find {path} -type f -exec sha256sum {{}} \\; > /tmp/current_hashes.txt",
                f"diff {baseline_hashes} /tmp/current_hashes.txt > /tmp/modifications.txt",
            ])

        if quarantine_suspicious:
            commands.extend([
                "",
                "# Quarantine modified files",
                f"mkdir -p /quarantine/{action_id}",
                "# Move suspicious files to quarantine",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Compare current hashes to baseline",
            "2. Review all modified files",
            "3. Investigate unauthorized changes",
            "4. Restore clean versions if needed",
            "5. Update baseline after remediation",
        ]

        return RemediationAction(
            id=action_id,
            action_type='integrity_verification',
            target=', '.join(target_paths),
            target_type='data',
            description='Verify data integrity',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'target_paths': target_paths,
                'baseline_hashes': baseline_hashes,
                'verification_method': verification_method,
                'files_checked': 0,
                'modifications': []
            }
        )


# =============================================================================
# Cloud Remediation
# =============================================================================

class CloudRemediation:
    """Cloud environment remediation procedures."""

    def account_recovery(self, cloud_provider: str, account_id: str,
                         compromised_resources: List[str],
                         reset_all_credentials: bool = True,
                         audit_cloudtrail: bool = True,
                         enable_guardduty: bool = True) -> RemediationAction:
        """
        Recover compromised cloud account.

        Args:
            cloud_provider: 'aws', 'azure', 'gcp'
            account_id: Cloud account ID
            compromised_resources: List of compromised resource types
            reset_all_credentials: Reset all IAM credentials
            audit_cloudtrail: Review CloudTrail/audit logs
            enable_guardduty: Enable threat detection
        """
        action_id = generate_action_id()

        commands = [
            f"# Cloud Account Recovery: {cloud_provider}",
            f"# Account: {account_id}",
            ""
        ]

        if cloud_provider == 'aws':
            if reset_all_credentials:
                commands.extend([
                    "# Reset all IAM credentials",
                    "",
                    "# List all users",
                    "aws iam list-users",
                    "",
                    "# For each user, rotate credentials",
                    "# Delete old access keys",
                    "aws iam delete-access-key --user-name USER --access-key-id KEY_ID",
                    "",
                    "# Reset console passwords",
                    "aws iam update-login-profile --user-name USER --password-reset-required",
                    "",
                    "# Rotate root account credentials",
                    "# Must be done via console",
                ])

            if audit_cloudtrail:
                commands.extend([
                    "",
                    "# Audit CloudTrail",
                    "aws cloudtrail lookup-events --start-time 2024-01-01 --end-time 2024-01-15",
                    "",
                    "# Look for suspicious activity",
                    "# - Unauthorized API calls",
                    "# - New IAM users/roles",
                    "# - Resource modifications",
                ])

            if enable_guardduty:
                commands.extend([
                    "",
                    "# Enable GuardDuty",
                    "aws guardduty create-detector --enable",
                    "",
                    "# Enable Security Hub",
                    "aws securityhub enable-security-hub",
                ])

        resources_remediated = []
        for resource in compromised_resources:
            resources_remediated.append({'type': resource, 'status': 'pending'})

        verification_steps = [
            "# Verification Steps",
            "1. Verify all credentials rotated",
            "2. Review CloudTrail for remaining suspicious activity",
            "3. Confirm GuardDuty/detection enabled",
            "4. Test legitimate access still works",
            "5. Review and close security findings",
        ]

        return RemediationAction(
            id=action_id,
            action_type='cloud_account_recovery',
            target=account_id,
            target_type='cloud_account',
            description=f'{cloud_provider} account recovery',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'cloud_provider': cloud_provider,
                'resources_remediated': resources_remediated,
                'credentials_reset': reset_all_credentials
            }
        )

    def iam_remediation(self, cloud_provider: str, issues: List[Dict],
                        apply_least_privilege: bool = True,
                        remove_unused_permissions: bool = True) -> RemediationAction:
        """
        Fix IAM policy misconfigurations.

        Args:
            cloud_provider: 'aws', 'azure', 'gcp'
            issues: List of IAM issues to fix
            apply_least_privilege: Apply least privilege principle
            remove_unused_permissions: Remove unused permissions
        """
        action_id = generate_action_id()

        commands = [
            f"# IAM Remediation: {cloud_provider}",
            ""
        ]

        policies_fixed = []

        for issue in issues:
            issue_type = issue.get('type', '')
            resource = issue.get('resource', '')

            if issue_type == 'overly_permissive':
                commands.extend([
                    f"# Fix overly permissive policy: {resource}",
                    "# Review and reduce permissions",
                    f"# aws iam get-policy --policy-arn {resource}",
                ])
                policies_fixed.append(resource)

            elif issue_type == 'public_access':
                commands.extend([
                    f"# Fix public access: {resource}",
                    "# Remove public access",
                ])
                policies_fixed.append(resource)

            elif issue_type == 'unused_credentials':
                commands.extend([
                    f"# Remove unused credentials: {resource}",
                    f"aws iam delete-access-key --access-key-id {resource}",
                ])
                policies_fixed.append(resource)

        if apply_least_privilege:
            commands.extend([
                "",
                "# Apply least privilege",
                "# Use IAM Access Analyzer to identify unused permissions",
                "aws accessanalyzer list-analyzers",
            ])

        verification_steps = [
            "# Verification Steps",
            "1. Verify policy changes applied",
            "2. Run IAM Access Analyzer",
            "3. Test legitimate access still works",
            "4. Review security findings",
        ]

        return RemediationAction(
            id=action_id,
            action_type='iam_remediation',
            target=f'{len(issues)} issues',
            target_type='iam',
            description='Fix IAM misconfigurations',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'cloud_provider': cloud_provider,
                'issues': issues,
                'policies_fixed': policies_fixed
            }
        )

    def s3_remediation(self, bucket_name: str, issues: List[str],
                       block_public_access: bool = True,
                       enable_encryption: str = 'aws:kms',
                       enable_versioning: bool = True,
                       enable_access_logging: bool = True) -> RemediationAction:
        """
        Fix S3 bucket security issues.

        Args:
            bucket_name: S3 bucket name
            issues: List of issues to fix
            block_public_access: Block all public access
            enable_encryption: Encryption type
            enable_versioning: Enable versioning
            enable_access_logging: Enable access logging
        """
        action_id = generate_action_id()

        commands = [
            f"# S3 Bucket Remediation: {bucket_name}",
            ""
        ]

        fixes_applied = []

        if block_public_access or 'public_access' in issues:
            commands.extend([
                "# Block public access",
                f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
            ])
            fixes_applied.append('public_access_blocked')

        if enable_encryption or 'no_encryption' in issues:
            commands.extend([
                "",
                "# Enable encryption",
                f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"{enable_encryption}\"}}}}]}}'",
            ])
            fixes_applied.append('encryption_enabled')

        if enable_versioning or 'no_versioning' in issues:
            commands.extend([
                "",
                "# Enable versioning",
                f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
            ])
            fixes_applied.append('versioning_enabled')

        if enable_access_logging or 'no_logging' in issues:
            commands.extend([
                "",
                "# Enable access logging",
                f"aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status '{{\"LoggingEnabled\": {{\"TargetBucket\": \"logs-bucket\", \"TargetPrefix\": \"{bucket_name}/\"}}}}'",
            ])
            fixes_applied.append('logging_enabled')

        verification_steps = [
            "# Verification Steps",
            "1. Verify public access blocked",
            "2. Confirm encryption enabled",
            "3. Verify versioning enabled",
            "4. Confirm logging enabled",
            "5. Test access still works for authorized users",
        ]

        return RemediationAction(
            id=action_id,
            action_type='s3_remediation',
            target=bucket_name,
            target_type='s3_bucket',
            description='Fix S3 security issues',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'bucket_name': bucket_name,
                'issues': issues,
                'fixes_applied': fixes_applied
            }
        )

    def container_remediation(self, registry: str, images: List[str],
                              issues: List[str],
                              rebuild_from_source: bool = True,
                              scan_before_deploy: bool = True,
                              update_base_images: bool = True) -> RemediationAction:
        """
        Remediate compromised container images.

        Args:
            registry: Container registry (ecr, gcr, etc.)
            images: List of images to remediate
            issues: Issues found in images
            rebuild_from_source: Rebuild from source code
            scan_before_deploy: Scan images before deployment
            update_base_images: Update base images
        """
        action_id = generate_action_id()

        commands = [
            f"# Container Image Remediation",
            f"# Registry: {registry}",
            ""
        ]

        images_fixed = []

        for image in images:
            commands.append(f"# Remediate {image}")

            if rebuild_from_source:
                commands.extend([
                    f"# Pull source and rebuild",
                    f"docker build -t {image} --no-cache .",
                ])

            if update_base_images:
                commands.extend([
                    f"# Update base image in Dockerfile",
                    f"# FROM base:latest -> FROM base:specific-version",
                ])

            if scan_before_deploy:
                commands.extend([
                    f"# Scan image before deployment",
                    f"trivy image {image}",
                ])

            commands.extend([
                f"# Push remediated image",
                f"docker push {image}",
                "",
            ])

            images_fixed.append(image)

        verification_steps = [
            "# Verification Steps",
            "1. Verify images rebuilt from clean source",
            "2. Confirm vulnerability scan passes",
            "3. Test container functionality",
            "4. Verify deployment successful",
            "5. Monitor for anomalous behavior",
        ]

        return RemediationAction(
            id=action_id,
            action_type='container_remediation',
            target=f'{len(images)} images',
            target_type='container_images',
            description='Remediate container images',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'registry': registry,
                'images_fixed': images_fixed,
                'issues': issues
            }
        )


# =============================================================================
# Business Remediation
# =============================================================================

class BusinessRemediation:
    """Business process remediation procedures."""

    def bec_recovery(self, incident_type: str, financial_impact: float,
                     compromised_accounts: List[str],
                     fraudulent_transactions: List[str],
                     bank_notification: bool = True,
                     law_enforcement: bool = True) -> RemediationAction:
        """
        Recover from Business Email Compromise.

        Args:
            incident_type: Type of BEC (invoice_fraud, ceo_fraud, etc.)
            financial_impact: Financial loss amount
            compromised_accounts: List of compromised email accounts
            fraudulent_transactions: Transaction IDs
            bank_notification: Notify bank
            law_enforcement: Report to law enforcement
        """
        action_id = generate_action_id()

        commands = [
            f"# BEC Recovery",
            f"# Incident type: {incident_type}",
            f"# Financial impact: ${financial_impact:,.2f}",
            ""
        ]

        recovery_actions = []

        # Secure compromised accounts
        commands.append("# Step 1: Secure compromised accounts")
        for account in compromised_accounts:
            commands.extend([
                f"# Disable {account}",
                f"# Reset password and MFA",
                f"# Remove forwarding rules",
                f"# Review sent items for additional fraud",
            ])
        commands.append("")

        if bank_notification:
            commands.extend([
                "# Step 2: Contact financial institutions",
                "# - Notify bank fraud department",
                "# - Request transaction recall/reversal",
                "# - Provide transaction details:",
            ])
            for txn in fraudulent_transactions:
                commands.append(f"#   - Transaction: {txn}")
            commands.append("")
            recovery_actions.append({
                'action': 'bank_notification',
                'status': 'pending',
                'transactions': fraudulent_transactions
            })

        if law_enforcement:
            commands.extend([
                "# Step 3: Report to law enforcement",
                "# - File report with FBI IC3 (ic3.gov)",
                "# - Contact local FBI field office",
                "# - Provide all evidence and transaction details",
                "",
            ])
            recovery_actions.append({
                'action': 'law_enforcement',
                'status': 'pending'
            })

        commands.extend([
            "# Step 4: Implement preventive controls",
            "# - Enable MFA for all email accounts",
            "# - Implement email authentication (DMARC, DKIM, SPF)",
            "# - Add secondary verification for wire transfers",
            "# - Conduct user awareness training",
        ])

        verification_steps = [
            "# Verification Steps",
            "1. Confirm compromised accounts secured",
            "2. Verify bank notified and pursuing recovery",
            "3. Confirm law enforcement report filed",
            "4. Test preventive controls implemented",
            "5. Verify user training completed",
        ]

        return RemediationAction(
            id=action_id,
            action_type='bec_recovery',
            target=f'${financial_impact:,.2f}',
            target_type='financial',
            description=f'BEC recovery: {incident_type}',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'incident_type': incident_type,
                'financial_impact': financial_impact,
                'compromised_accounts': compromised_accounts,
                'recovery_actions': recovery_actions
            }
        )

    def vendor_compromise_response(self, vendor_name: str, compromise_type: str,
                                   affected_products: List[str],
                                   exposure_assessment: bool = True,
                                   revoke_access: bool = True,
                                   communication_plan: bool = True) -> RemediationAction:
        """
        Respond to compromised vendor/third-party.

        Args:
            vendor_name: Name of compromised vendor
            compromise_type: Type of compromise
            affected_products: Products/services affected
            exposure_assessment: Assess exposure
            revoke_access: Revoke vendor access
            communication_plan: Develop communication plan
        """
        action_id = generate_action_id()

        commands = [
            f"# Vendor Compromise Response",
            f"# Vendor: {vendor_name}",
            f"# Compromise type: {compromise_type}",
            ""
        ]

        communications = []

        if revoke_access:
            commands.extend([
                "# Step 1: Revoke vendor access",
                "# - Disable vendor VPN accounts",
                "# - Revoke API keys/tokens",
                "# - Block vendor IP ranges",
                "# - Disable SSO/federation",
                "",
            ])

        if exposure_assessment:
            commands.extend([
                "# Step 2: Assess exposure",
                f"# - Identify all systems using {vendor_name} products",
                "# - Review vendor access logs",
                "# - Check for indicators of compromise",
                "# - Inventory affected products:",
            ])
            for product in affected_products:
                commands.append(f"#   - {product}")
            commands.append("")

        commands.extend([
            "# Step 3: Containment actions",
            "# - Isolate affected systems if needed",
            "# - Apply vendor-provided patches/mitigations",
            "# - Implement compensating controls",
            "",
        ])

        if communication_plan:
            communications = [
                {'audience': 'Executive team', 'timing': 'Immediate'},
                {'audience': 'Legal/Compliance', 'timing': 'Immediate'},
                {'audience': 'Affected customers', 'timing': 'As required'},
                {'audience': 'Regulators', 'timing': 'Per requirements'}
            ]

            commands.extend([
                "# Step 4: Communications",
                "# Stakeholder communication plan:",
            ])
            for comm in communications:
                commands.append(f"#   - {comm['audience']}: {comm['timing']}")

        verification_steps = [
            "# Verification Steps",
            "1. Confirm vendor access revoked",
            "2. Verify exposure assessment complete",
            "3. Confirm containment actions effective",
            "4. Test compensating controls",
            "5. Verify communications completed",
        ]

        return RemediationAction(
            id=action_id,
            action_type='vendor_compromise_response',
            target=vendor_name,
            target_type='vendor',
            description=f'Response to {vendor_name} compromise',
            commands=commands,
            verification_steps=verification_steps,
            status=RemediationStatus.PENDING,
            metadata={
                'vendor_name': vendor_name,
                'compromise_type': compromise_type,
                'affected_products': affected_products,
                'communications': communications
            }
        )


# =============================================================================
# Playbook Management
# =============================================================================

class RemediationPlaybook:
    """Manage remediation playbook execution."""

    def __init__(self, incident_id: str, name: str, analyst: str = ''):
        self.incident_id = incident_id
        self.name = name
        self.analyst = analyst
        self.created_at = datetime.now()
        self.actions: List[RemediationAction] = []
        self.status = 'active'

    def add_action(self, action: RemediationAction):
        """Add a remediation action."""
        action.analyst = self.analyst
        self.actions.append(action)

    def complete_action(self, action_id: str, notes: str = ''):
        """Mark action as completed."""
        for action in self.actions:
            if action.id == action_id:
                action.status = RemediationStatus.COMPLETED
                action.completed_at = datetime.now()
                action.notes = notes
                return

    def verify_action(self, action_id: str, verification_notes: str = ''):
        """Mark action as verified."""
        for action in self.actions:
            if action.id == action_id:
                if action.status == RemediationStatus.COMPLETED:
                    action.status = RemediationStatus.VERIFIED
                    action.verified_at = datetime.now()
                    action.notes += f"\nVerification: {verification_notes}"
                return

    def fail_action(self, action_id: str, reason: str):
        """Mark action as failed."""
        for action in self.actions:
            if action.id == action_id:
                action.status = RemediationStatus.FAILED
                action.notes = reason
                return

    def generate_report(self) -> str:
        """Generate remediation report."""
        report = f"""# Remediation Report: {self.incident_id}

**Playbook:** {self.name}
**Analyst:** {self.analyst}
**Started:** {self.created_at.strftime('%Y-%m-%d %H:%M')}
**Status:** {self.status}

---

## Actions Summary

| ID | Type | Target | Status | Verified |
|----|------|--------|--------|----------|
"""
        for action in self.actions:
            verified = 'Yes' if action.status == RemediationStatus.VERIFIED else 'No'
            report += f"| {action.id} | {action.action_type} | {action.target[:30]} | {action.status.value} | {verified} |\n"

        report += f"""

## Statistics

- **Total Actions:** {len(self.actions)}
- **Completed:** {len([a for a in self.actions if a.status in [RemediationStatus.COMPLETED, RemediationStatus.VERIFIED]])}
- **Verified:** {len([a for a in self.actions if a.status == RemediationStatus.VERIFIED])}
- **Failed:** {len([a for a in self.actions if a.status == RemediationStatus.FAILED])}
- **Pending:** {len([a for a in self.actions if a.status == RemediationStatus.PENDING])}

## Detailed Actions

"""
        for action in self.actions:
            report += f"""### {action.id}: {action.action_type}

**Target:** {action.target}
**Description:** {action.description}
**Status:** {action.status.value}

"""
        return report

    def generate_recovery_certification(self) -> str:
        """Generate recovery certification document."""
        verified_count = len([a for a in self.actions if a.status == RemediationStatus.VERIFIED])
        total_count = len(self.actions)

        return f"""# Recovery Certification

**Incident:** {self.incident_id}
**Playbook:** {self.name}
**Date:** {datetime.now().strftime('%Y-%m-%d')}

## Certification Statement

This document certifies that remediation actions for incident {self.incident_id}
have been completed and verified.

## Summary

- **Total Remediation Actions:** {total_count}
- **Verified Actions:** {verified_count}
- **Verification Rate:** {(verified_count/total_count*100) if total_count > 0 else 0:.1f}%

## Sign-off

- [ ] Security Team Lead
- [ ] IT Operations Lead
- [ ] Business Owner
- [ ] Risk Management
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
