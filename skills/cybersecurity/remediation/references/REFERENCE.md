# Remediation Playbooks - API Reference

## RemediationAction Dataclass

All remediation actions return a `RemediationAction` object:

```python
@dataclass
class RemediationAction:
    id: str                           # Unique action identifier
    action_type: str                  # Type of remediation action
    target: str                       # Target of the action
    target_type: str                  # Type of target
    description: str                  # Action description
    status: RemediationStatus         # Current status
    commands: List[str]               # Commands to execute
    recovery_steps: List[str]         # Recovery procedure steps
    verification_steps: List[str]     # Steps to verify success
    verification_required: bool       # Whether verification is needed
    created_at: datetime              # Creation timestamp
    completed_at: Optional[datetime]  # Completion timestamp
    verified_at: Optional[datetime]   # Verification timestamp
    analyst: str                      # Analyst performing action
    notes: str                        # Additional notes
    metadata: Dict                    # Action-specific metadata
    audit_results: Dict               # Audit findings
```

## RemediationStatus Enum

```python
class RemediationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VERIFIED = "verified"
    FAILED = "failed"
```

---

## MalwareRemediation

### remove_malware(hostname, malware_type, malware_artifacts, quarantine_before_delete=True, scan_after_removal=True)

Remove malware from infected system.

**Parameters:**
- `hostname` (str): Target hostname
- `malware_type` (str): Type of malware
- `malware_artifacts` (Dict): Contains:
  - `files`: List of file paths
  - `registry`: List of registry keys
  - `scheduled_tasks`: List of task names
  - `services`: List of service names
  - `processes`: List of process names
- `quarantine_before_delete` (bool): Quarantine files first
- `scan_after_removal` (bool): Run scan after removal

### ransomware_recovery(hostname, ransomware_family, encrypted_extensions, recovery_method='backup', backup_location='', verify_decryption=True)

Recover from ransomware infection.

**Parameters:**
- `hostname` (str): Target hostname
- `ransomware_family` (str): Ransomware variant
- `encrypted_extensions` (List[str]): File extensions used
- `recovery_method` (str): 'backup', 'decryptor', 'shadow_copies'
- `backup_location` (str): Backup source path
- `verify_decryption` (bool): Verify file integrity

### rootkit_removal(hostname, rootkit_type, detection_tool='gmer', offline_scan=True, rebuild_mbr=False)

Remove rootkits and bootkits.

**Parameters:**
- `hostname` (str): Target hostname
- `rootkit_type` (str): 'kernel', 'bootkit', 'firmware'
- `detection_tool` (str): Tool used for detection
- `offline_scan` (bool): Perform offline scan
- `rebuild_mbr` (bool): Rebuild Master Boot Record

### webshell_removal(hostname, webshell_paths, web_root, scan_for_additional=True, patch_upload_vulnerability=True, restore_from_clean=False)

Remove web shells from servers.

**Parameters:**
- `hostname` (str): Target hostname
- `webshell_paths` (List[str]): Known web shell paths
- `web_root` (str): Web server document root
- `scan_for_additional` (bool): Scan for more shells
- `patch_upload_vulnerability` (bool): Fix upload vuln
- `restore_from_clean` (bool): Restore from backup

---

## AccessRemediation

### full_credential_reset(scope, users, reset_types, force_mfa_reenroll=True, expire_all_sessions=True, notify_users=True)

Comprehensive credential reset.

**Parameters:**
- `scope` (str): 'domain', 'local', 'cloud', 'all'
- `users` (List[str]): Users to reset
- `reset_types` (List[str]): 'password', 'kerberos', 'certificates'
- `force_mfa_reenroll` (bool): Require MFA re-enrollment
- `expire_all_sessions` (bool): Invalidate sessions
- `notify_users` (bool): Send notifications

### backdoor_removal(hostname, backdoors, audit_all_persistence=True, compare_to_baseline=True)

Remove persistence and backdoors.

**Parameters:**
- `hostname` (str): Target hostname
- `backdoors` (Dict): Contains:
  - `accounts`: Backdoor accounts
  - `ssh_keys`: SSH key files
  - `scheduled_tasks`: Malicious tasks
  - `services`: Malicious services
  - `registry`: Registry persistence
  - `web_shells`: Web shell paths
  - `cron_jobs`: Malicious cron entries
- `audit_all_persistence` (bool): Full audit
- `compare_to_baseline` (bool): Compare to known good

### privilege_cleanup(affected_accounts, unauthorized_groups, unauthorized_permissions, reset_to_baseline=True, audit_privileged_groups=True)

Clean up privilege escalation.

**Parameters:**
- `affected_accounts` (List[str]): Accounts to clean
- `unauthorized_groups` (List[str]): Groups to remove from
- `unauthorized_permissions` (List[str]): Permissions to revoke
- `reset_to_baseline` (bool): Reset to baseline
- `audit_privileged_groups` (bool): Audit all privileged groups

### golden_ticket_remediation(domain, reset_krbtgt=True, reset_interval_hours=10, force_all_ticket_renewal=True, audit_service_accounts=True)

Remediate golden ticket attack.

**Parameters:**
- `domain` (str): AD domain
- `reset_krbtgt` (bool): Reset KRBTGT (twice)
- `reset_interval_hours` (int): Hours between resets
- `force_all_ticket_renewal` (bool): Force ticket renewal
- `audit_service_accounts` (bool): Audit SPNs

---

## SystemRemediation

### rebuild_system(hostname, os_version, image_source='gold_image', preserve_data=False, join_domain=True, apply_security_baseline=True, install_edr=True)

Rebuild system from scratch.

**Parameters:**
- `hostname` (str): Target hostname
- `os_version` (str): OS to install
- `image_source` (str): Clean image source
- `preserve_data` (bool): Keep user data
- `join_domain` (bool): Join AD domain
- `apply_security_baseline` (bool): Apply hardening
- `install_edr` (bool): Install EDR agent

### emergency_patching(targets, patches, patch_source='wsus', reboot_allowed=True, verify_after_patch=True, rollback_on_failure=True)

Deploy emergency patches.

**Parameters:**
- `targets` (List[str]): Target systems
- `patches` (List[str]): Patches to apply
- `patch_source` (str): 'wsus', 'sccm', 'manual'
- `reboot_allowed` (bool): Allow reboots
- `verify_after_patch` (bool): Verify installation
- `rollback_on_failure` (bool): Enable rollback

### configuration_hardening(hostname, baseline, focus_areas, disable_legacy_protocols=True, enable_advanced_audit=True)

Apply security hardening.

**Parameters:**
- `hostname` (str): Target hostname
- `baseline` (str): 'cis_level_1', 'cis_level_2', 'disa_stig'
- `focus_areas` (List[str]): 'authentication', 'network', 'logging', 'services'
- `disable_legacy_protocols` (bool): Disable SMBv1, etc.
- `enable_advanced_audit` (bool): Enable audit policies

### log_recovery(hostname, log_types, recovery_sources, time_range, verify_integrity=True)

Recover audit logs.

**Parameters:**
- `hostname` (str): Target hostname
- `log_types` (List[str]): 'security', 'system', etc.
- `recovery_sources` (List[str]): 'backup', 'siem', 'shadow_copy'
- `time_range` (tuple): (start_date, end_date)
- `verify_integrity` (bool): Verify log integrity

---

## DataRemediation

### breach_response(breach_type, affected_data_types, affected_record_count, notification_required=True, regulatory_requirements=None, legal_hold=True)

Execute breach response.

**Parameters:**
- `breach_type` (str): Type of breach
- `affected_data_types` (List[str]): Data types affected
- `affected_record_count` (int): Records affected
- `notification_required` (bool): Notification needed
- `regulatory_requirements` (List[str]): 'gdpr', 'hipaa', etc.
- `legal_hold` (bool): Implement legal hold

### backup_restoration(target_system, backup_source, restore_type='full', restore_paths=None, verify_after_restore=True, scan_before_restore=True)

Restore from backups.

**Parameters:**
- `target_system` (str): Restore target
- `backup_source` (str): Backup location
- `restore_type` (str): 'full', 'incremental', 'selective'
- `restore_paths` (List[str]): Specific paths
- `verify_after_restore` (bool): Verify integrity
- `scan_before_restore` (bool): Scan for malware

### integrity_verification(target_paths, baseline_hashes, verification_method='sha256', report_modifications=True, quarantine_suspicious=True)

Verify data integrity.

**Parameters:**
- `target_paths` (List[str]): Paths to verify
- `baseline_hashes` (str): Baseline file
- `verification_method` (str): Hash algorithm
- `report_modifications` (bool): Report changes
- `quarantine_suspicious` (bool): Quarantine changes

---

## CloudRemediation

### account_recovery(cloud_provider, account_id, compromised_resources, reset_all_credentials=True, audit_cloudtrail=True, enable_guardduty=True)

Recover cloud account.

**Parameters:**
- `cloud_provider` (str): 'aws', 'azure', 'gcp'
- `account_id` (str): Account ID
- `compromised_resources` (List[str]): Affected resources
- `reset_all_credentials` (bool): Reset all creds
- `audit_cloudtrail` (bool): Review logs
- `enable_guardduty` (bool): Enable detection

### iam_remediation(cloud_provider, issues, apply_least_privilege=True, remove_unused_permissions=True)

Fix IAM misconfigurations.

**Parameters:**
- `cloud_provider` (str): 'aws', 'azure', 'gcp'
- `issues` (List[Dict]): Issues to fix
- `apply_least_privilege` (bool): Apply least privilege
- `remove_unused_permissions` (bool): Remove unused

### s3_remediation(bucket_name, issues, block_public_access=True, enable_encryption='aws:kms', enable_versioning=True, enable_access_logging=True)

Fix S3 security issues.

**Parameters:**
- `bucket_name` (str): Bucket name
- `issues` (List[str]): Issues to fix
- `block_public_access` (bool): Block public
- `enable_encryption` (str): Encryption type
- `enable_versioning` (bool): Enable versioning
- `enable_access_logging` (bool): Enable logging

### container_remediation(registry, images, issues, rebuild_from_source=True, scan_before_deploy=True, update_base_images=True)

Remediate container images.

**Parameters:**
- `registry` (str): Container registry
- `images` (List[str]): Images to fix
- `issues` (List[str]): Issues found
- `rebuild_from_source` (bool): Rebuild images
- `scan_before_deploy` (bool): Scan before deploy
- `update_base_images` (bool): Update base images

---

## BusinessRemediation

### bec_recovery(incident_type, financial_impact, compromised_accounts, fraudulent_transactions, bank_notification=True, law_enforcement=True)

Recover from BEC.

**Parameters:**
- `incident_type` (str): 'invoice_fraud', 'ceo_fraud'
- `financial_impact` (float): Loss amount
- `compromised_accounts` (List[str]): Affected accounts
- `fraudulent_transactions` (List[str]): Transaction IDs
- `bank_notification` (bool): Notify bank
- `law_enforcement` (bool): File report

### vendor_compromise_response(vendor_name, compromise_type, affected_products, exposure_assessment=True, revoke_access=True, communication_plan=True)

Respond to vendor compromise.

**Parameters:**
- `vendor_name` (str): Vendor name
- `compromise_type` (str): Type of compromise
- `affected_products` (List[str]): Products affected
- `exposure_assessment` (bool): Assess exposure
- `revoke_access` (bool): Revoke vendor access
- `communication_plan` (bool): Plan communications

---

## RemediationPlaybook

### __init__(incident_id, name, analyst='')

Create a remediation playbook.

### add_action(action: RemediationAction)

Add action to playbook.

### complete_action(action_id, notes='')

Mark action completed.

### verify_action(action_id, verification_notes='')

Mark action verified.

### fail_action(action_id, reason)

Mark action failed.

### generate_report() -> str

Generate remediation report.

### generate_recovery_certification() -> str

Generate certification document.

### to_json() -> str

Export to JSON format.
