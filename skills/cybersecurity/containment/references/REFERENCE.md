# Containment Playbooks - API Reference

## ContainmentAction Dataclass

All containment actions return a `ContainmentAction` object:

```python
@dataclass
class ContainmentAction:
    id: str                          # Unique action identifier
    action_type: str                 # Type of containment action
    target: str                      # Target of the action
    target_type: str                 # Type of target
    reason: str                      # Reason for action
    status: ContainmentStatus        # Current status
    commands: List[str]              # Commands to execute
    api_payload: Dict                # API payload for platform actions
    rollback_commands: List[str]     # Commands to rollback
    rollback_available: bool         # Whether rollback is possible
    evidence_path: Optional[str]     # Path to preserved evidence
    created_at: datetime             # Creation timestamp
    completed_at: Optional[datetime] # Completion timestamp
    analyst: str                     # Analyst performing action
    notes: str                       # Additional notes
    metadata: Dict                   # Action-specific metadata
```

---

## NetworkContainment

### isolate_host(ip_address, hostname, reason, isolation_type='full', allow_list=None)

Isolate a host from the network.

**Parameters:**
- `ip_address` (str): IP address to isolate
- `hostname` (str): Hostname for reference
- `reason` (str): Reason for isolation
- `isolation_type` (str): 'full', 'partial', or 'monitor'
- `allow_list` (List[str]): IPs to allow access from

**Isolation Types:**
- `full`: Block all traffic except allow_list
- `partial`: Block external access only
- `monitor`: Log traffic without blocking

### firewall_block(target, target_type, direction, reason, duration_hours=0)

Block IP, domain, or port at firewall.

**Parameters:**
- `target` (str): IP, domain, or port to block
- `target_type` (str): 'ip', 'domain', or 'port'
- `direction` (str): 'inbound', 'outbound', or 'both'
- `reason` (str): Reason for block
- `duration_hours` (int): Block duration (0 = permanent)

### dns_sinkhole(domains, sinkhole_ip, reason, log_queries=True)

Redirect domains to DNS sinkhole.

**Parameters:**
- `domains` (List[str]): Domains to sinkhole
- `sinkhole_ip` (str): Sinkhole server IP
- `reason` (str): Reason for sinkholing
- `log_queries` (bool): Enable query logging

### segment_network(source_vlan, target_vlan, affected_hosts, allow_ir_access=True, ir_subnet='')

Emergency network segmentation.

**Parameters:**
- `source_vlan` (int): Current VLAN
- `target_vlan` (int): Quarantine VLAN
- `affected_hosts` (List[str]): Host IPs to move
- `allow_ir_access` (bool): Allow IR team access
- `ir_subnet` (str): IR team subnet

---

## EndpointContainment

### quarantine_endpoint(hostname, edr_platform, isolation_level='full', allow_list=None, preserve_evidence=True)

Quarantine endpoint using EDR platform.

**Parameters:**
- `hostname` (str): Hostname to quarantine
- `edr_platform` (str): 'crowdstrike', 'sentinelone', 'defender', 'carbon_black', 'cortex_xdr'
- `isolation_level` (str): 'full' or 'selective'
- `allow_list` (List[str]): CIDRs to allow
- `preserve_evidence` (bool): Capture evidence first

### terminate_process(hostname, process_name, process_id=None, kill_children=True, create_memory_dump=True)

Terminate malicious process.

**Parameters:**
- `hostname` (str): Target hostname
- `process_name` (str): Process to terminate
- `process_id` (int): Specific PID (optional)
- `kill_children` (bool): Kill child processes
- `create_memory_dump` (bool): Dump memory first

### disable_service(hostname, service_name, stop_immediately=True, disable_autostart=True, backup_config=True)

Disable Windows/Linux service.

**Parameters:**
- `hostname` (str): Target hostname
- `service_name` (str): Service to disable
- `stop_immediately` (bool): Stop now
- `disable_autostart` (bool): Prevent autostart
- `backup_config` (bool): Backup configuration

### preserve_memory(hostname, output_path, tool='winpmem', compress=True, hash_output=True)

Capture memory dump for forensics.

**Parameters:**
- `hostname` (str): Target hostname
- `output_path` (str): Output directory
- `tool` (str): 'winpmem', 'dumpit', 'magnet_ram', 'lime'
- `compress` (bool): Compress output
- `hash_output` (bool): Generate hash

---

## IdentityContainment

### disable_account(username, reason, directory='active_directory', preserve_data=True, notify_manager=True)

Disable user account.

**Parameters:**
- `username` (str): Account to disable
- `reason` (str): Reason for disabling
- `directory` (str): 'active_directory', 'azure_ad', 'okta', 'google'
- `preserve_data` (bool): Keep data accessible
- `notify_manager` (bool): Send notification

### terminate_sessions(username, session_types=None, force=True, invalidate_tokens=True)

Terminate all active sessions.

**Parameters:**
- `username` (str): User account
- `session_types` (List[str]): 'all', 'vpn', 'rdp', 'web', 'cloud'
- `force` (bool): Force termination
- `invalidate_tokens` (bool): Invalidate OAuth tokens

### force_password_reset(username, require_mfa_reenroll=True, expire_immediately=True, notify_user=True, generate_temp_password=True)

Force password reset.

**Parameters:**
- `username` (str): User account
- `require_mfa_reenroll` (bool): Reset MFA
- `expire_immediately` (bool): Expire now
- `notify_user` (bool): Send notification
- `generate_temp_password` (bool): Generate temp password

### rotate_service_account(account_name, credential_type='password', update_dependent_services=True, services=None)

Rotate service account credentials.

**Parameters:**
- `account_name` (str): Service account
- `credential_type` (str): 'password', 'api_key', 'certificate'
- `update_dependent_services` (bool): Update services
- `services` (List[str]): Dependent services

---

## CloudContainment

### revoke_iam_permissions(principal, cloud_provider, revocation_type='all', preserve_audit_logs=True)

Revoke cloud IAM permissions.

**Parameters:**
- `principal` (str): User/role ARN or ID
- `cloud_provider` (str): 'aws', 'azure', 'gcp'
- `revocation_type` (str): 'all' or 'specific'
- `preserve_audit_logs` (bool): Keep audit logs

### isolate_resource(resource_id, resource_type, cloud_provider, isolation_method='security_group', allow_forensic_access=True, forensic_ip='')

Isolate cloud resource.

**Parameters:**
- `resource_id` (str): Resource ID
- `resource_type` (str): 'ec2_instance', 'vm', etc.
- `cloud_provider` (str): 'aws', 'azure', 'gcp'
- `isolation_method` (str): 'security_group', 'nacl', 'vpc'
- `allow_forensic_access` (bool): Allow forensics
- `forensic_ip` (str): Forensic workstation IP

### revoke_api_keys(key_ids, cloud_provider, create_new_keys=False, notify_owner=True)

Revoke API keys.

**Parameters:**
- `key_ids` (List[str]): Key IDs to revoke
- `cloud_provider` (str): 'aws', 'azure', 'gcp'
- `create_new_keys` (bool): Create replacements
- `notify_owner` (bool): Notify owner

### lockdown_security_group(security_group_id, cloud_provider, lockdown_type='deny_all', ir_cidrs=None, preserve_logging=True)

Lock down security group.

**Parameters:**
- `security_group_id` (str): Security group ID
- `cloud_provider` (str): 'aws', 'azure', 'gcp'
- `lockdown_type` (str): 'deny_all', 'allow_ir_only', 'block_egress'
- `ir_cidrs` (List[str]): IR team CIDRs
- `preserve_logging` (bool): Keep flow logs

---

## ApplicationContainment

### deploy_waf_rule(rule_name, rule_type, conditions, waf_provider, priority=1)

Deploy WAF rule.

**Parameters:**
- `rule_name` (str): Rule name
- `rule_type` (str): 'block', 'rate_limit', 'challenge'
- `conditions` (List[Dict]): Rule conditions
- `waf_provider` (str): 'cloudflare', 'aws_waf', 'akamai'
- `priority` (int): Rule priority

### rate_limit(endpoint, limit, window_seconds, action='block', scope='ip', whitelist=None)

Implement rate limiting.

**Parameters:**
- `endpoint` (str): Endpoint to limit
- `limit` (int): Request limit
- `window_seconds` (int): Time window
- `action` (str): 'block', 'throttle', 'challenge'
- `scope` (str): 'ip', 'user', 'global'
- `whitelist` (List[str]): Excluded IPs

### shutdown_service(service_name, shutdown_type='graceful', drain_connections=True, display_maintenance_page=True, notify_stakeholders=None)

Emergency service shutdown.

**Parameters:**
- `service_name` (str): Service to shutdown
- `shutdown_type` (str): 'graceful' or 'immediate'
- `drain_connections` (bool): Drain connections
- `display_maintenance_page` (bool): Show maintenance
- `notify_stakeholders` (List[str]): Emails to notify

### lockdown_database(database, db_type, lockdown_level='read_only', revoke_users=None, preserve_admin=None)

Lock down database.

**Parameters:**
- `database` (str): Database name
- `db_type` (str): 'postgresql', 'mysql', 'mssql', 'mongodb'
- `lockdown_level` (str): 'read_only', 'admin_only', 'full_lockdown'
- `revoke_users` (List[str]): Users to revoke
- `preserve_admin` (List[str]): Admins to keep

---

## EmailContainment

### quarantine_messages(search_criteria, email_platform, delete_from_mailboxes=True, preserve_for_analysis=True)

Quarantine malicious emails.

**Parameters:**
- `search_criteria` (Dict): Search criteria
- `email_platform` (str): 'office365', 'google', 'exchange'
- `delete_from_mailboxes` (bool): Remove from mailboxes
- `preserve_for_analysis` (bool): Keep copy

### block_sender(sender, block_type='email', email_platform='office365', add_to_threat_list=True)

Block malicious sender.

**Parameters:**
- `sender` (str): Email or domain to block
- `block_type` (str): 'email' or 'domain'
- `email_platform` (str): 'office365', 'google', 'exchange'
- `add_to_threat_list` (bool): Add to TI list

### remove_inbox_rules(username, rule_criteria, email_platform='office365')

Remove malicious inbox rules.

**Parameters:**
- `username` (str): User account
- `rule_criteria` (Dict): Criteria for malicious rules
- `email_platform` (str): 'office365', 'google', 'exchange'

---

## ContainmentPlaybook

### __init__(incident_id, name, analyst='')

Create a containment playbook.

### add_action(action: ContainmentAction)

Add a containment action to the playbook.

### complete_action(action_id, notes='')

Mark an action as completed.

### fail_action(action_id, reason, rollback=False)

Mark an action as failed.

### generate_report() -> str

Generate detailed containment report.

### generate_executive_summary() -> str

Generate executive summary.

### to_json() -> str

Export playbook to JSON format.
