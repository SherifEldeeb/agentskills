# Detection Use Cases - API Reference

## NetworkDetector

### detect_port_scan(conn_logs, threshold=50, time_window=60)
Detect port scanning reconnaissance activity.

**Parameters:**
- `conn_logs` (List[Dict]): Connection logs with `src_ip`, `dst_ip`, `dst_port`, `timestamp`
- `threshold` (int): Unique ports to trigger (default: 50)
- `time_window` (int): Seconds to analyze (default: 60)

**Returns:** Dict with `detected`, `detections`, `detection_type`

### detect_dns_tunneling(dns_queries, entropy_threshold=3.5, length_threshold=50)
Detect DNS tunneling for data exfiltration.

**Parameters:**
- `dns_queries` (List[Dict]): DNS queries with `query`, `query_type`, `timestamp`
- `entropy_threshold` (float): Shannon entropy threshold (default: 3.5)
- `length_threshold` (int): Subdomain length threshold (default: 50)

### detect_beaconing(connections, jitter_threshold=0.2, min_beacons=10)
Detect C2 beaconing communication patterns.

**Parameters:**
- `connections` (List[Dict]): Connections with `dst_ip`, `dst_port`, `bytes`, `timestamp`
- `jitter_threshold` (float): Max interval variance (default: 0.2)
- `min_beacons` (int): Minimum connections to analyze (default: 10)

### detect_lateral_movement(internal_traffic, baseline_connections=None)
Detect lateral movement within the network.

**Parameters:**
- `internal_traffic` (List[Dict]): Internal connections
- `baseline_connections` (Dict): Normal patterns {src: [dst1, dst2]}

### detect_exfiltration(transfers, baseline_bytes=None, threshold_multiplier=10)
Detect data exfiltration attempts.

**Parameters:**
- `transfers` (List[Dict]): Transfers with `src_ip`, `dst_ip`, `bytes_out`, `protocol`
- `baseline_bytes` (Dict): Normal transfer volumes by source
- `threshold_multiplier` (float): Anomaly threshold (default: 10)

---

## EndpointDetector

### detect_malware_behavior(process_events)
Detect malware through behavioral indicators.

**Parameters:**
- `process_events` (List[Dict]): Process events with:
  - `process_name`: Executable name
  - `parent_process`: Parent process name
  - `command_line`: Full command line
  - `file_writes`: List of file paths written
  - `registry_writes`: List of registry keys modified
  - `network_connections`: List of network connections

### detect_ransomware(file_events, threshold=100, time_window=60)
Detect ransomware encryption activity.

**Parameters:**
- `file_events` (List[Dict]): File operations with `operation`, `path`, `timestamp`
- `threshold` (int): File modifications to trigger (default: 100)
- `time_window` (int): Time window in seconds (default: 60)

### detect_credential_dumping(process_events)
Detect credential theft attempts.

**Parameters:**
- `process_events` (List[Dict]): Process events with:
  - `process_name`: Executing process
  - `command_line`: Command line
  - `target_process`: Process being accessed
  - `access_rights`: Access rights requested

### detect_persistence(system_changes)
Detect persistence mechanism installation.

**Parameters:**
- `system_changes` (List[Dict]): System modifications with:
  - `type`: 'registry', 'scheduled_task', 'service', etc.
  - `path`: Registry path or file path
  - `value`: Value set
  - `name`: Task/service name
  - `action`/`binary`: Executable path

### detect_lolbin_abuse(process_events)
Detect Living-off-the-Land Binary abuse.

**Parameters:**
- `process_events` (List[Dict]): Process events with `process_name`, `command_line`, `parent_process`

### detect_process_injection(process_events)
Detect process injection techniques.

**Parameters:**
- `process_events` (List[Dict]): Process events with `api_calls`, `process_name`, `target_process`

---

## IdentityDetector

### detect_brute_force(auth_logs, failure_threshold=10, time_window=300)
Detect brute force authentication attacks.

**Parameters:**
- `auth_logs` (List[Dict]): Auth events with `user`, `result`, `source_ip`, `timestamp`
- `failure_threshold` (int): Failed attempts threshold (default: 10)
- `time_window` (int): Time window in seconds (default: 300)

### detect_password_spray(auth_logs, user_threshold=5, time_window=600)
Detect password spray attacks.

**Parameters:**
- `auth_logs` (List[Dict]): Auth events
- `user_threshold` (int): Minimum unique users (default: 5)
- `time_window` (int): Time window in seconds (default: 600)

### detect_impossible_travel(login_events, max_speed_kmh=1000)
Detect geographically impossible logins.

**Parameters:**
- `login_events` (List[Dict]): Logins with `user`, `location`, `timestamp`, `ip`
- `max_speed_kmh` (int): Maximum realistic travel speed (default: 1000)

### detect_kerberoasting(kerberos_events, request_threshold=5, time_window=60)
Detect Kerberoasting attacks.

**Parameters:**
- `kerberos_events` (List[Dict]): Kerberos events with `user`, `event_type`, `service`, `encryption`
- `request_threshold` (int): TGS requests to trigger (default: 5)
- `time_window` (int): Time window in seconds (default: 60)

### detect_privilege_abuse(admin_events, baseline_hours=None)
Detect privilege/admin account abuse.

**Parameters:**
- `admin_events` (List[Dict]): Admin activities with `user`, `timestamp`, `action`, `logon_type`
- `baseline_hours` (List[int]): Normal working hours 0-23 (default: 8-17)

---

## CloudDetector

### detect_iam_abuse(cloudtrail_events)
Detect IAM abuse in cloud environments.

**Parameters:**
- `cloudtrail_events` (List[Dict]): CloudTrail events with `event`, `user`, `target`, `policy`

### detect_cryptomining(resource_events)
Detect cryptomining through resource abuse.

**Parameters:**
- `resource_events` (List[Dict]): Compute events with `event`, `instance_type`, `count`, `region`

### detect_s3_exposure(s3_events)
Detect S3 bucket exposure risks.

**Parameters:**
- `s3_events` (List[Dict]): S3 config events with `bucket`, `public_access`, `acl`, `bucket_policy`

### detect_container_escape(container_events)
Detect container escape attempts.

**Parameters:**
- `container_events` (List[Dict]): Container events with `container_id`, `config`, `runtime_args`, `syscalls`

---

## ApplicationDetector

### detect_sql_injection(web_requests)
Detect SQL injection attempts.

**Parameters:**
- `web_requests` (List[Dict]): Requests with `url`, `params`, `method`

### detect_xss(web_requests)
Detect cross-site scripting attempts.

**Parameters:**
- `web_requests` (List[Dict]): Requests with `url`, `params`, `body`

### detect_webshell(web_logs)
Detect web shell activity.

**Parameters:**
- `web_logs` (List[Dict]): Access logs with `url`, `params`, `response_size`

### detect_api_abuse(api_logs, rate_threshold=100, time_window=60)
Detect API abuse patterns.

**Parameters:**
- `api_logs` (List[Dict]): API logs with `client_ip`, `api_key`, `endpoint`, `status_code`
- `rate_threshold` (int): Requests per window (default: 100)
- `time_window` (int): Time window in seconds (default: 60)

---

## EmailDetector

### detect_phishing(emails)
Detect phishing emails.

**Parameters:**
- `emails` (List[Dict]): Emails with `from`, `subject`, `body`, `links`, `attachments`

### detect_bec(emails, executive_list=None)
Detect Business Email Compromise attempts.

**Parameters:**
- `emails` (List[Dict]): Emails
- `executive_list` (List[str]): Executive email addresses

### detect_malicious_attachment(emails)
Detect malicious email attachments.

**Parameters:**
- `emails` (List[Dict]): Emails with attachment information

---

## DetectionRule

### __init__(name, category, severity, description='')
Create a detection rule.

### add_condition(field, operator, value)
Add a detection condition.

**Operators:** `equals`, `contains`, `startswith`, `endswith`, `regex`, `gt`, `lt`, `in`, `not_equals`

### add_mitre_mapping(technique_id, technique_name)
Add MITRE ATT&CK mapping.

### to_sigma() -> str
Export to SIGMA format.

### to_kql() -> str
Export to Kusto Query Language.

### to_splunk() -> str
Export to Splunk SPL.

---

## ThreatHunter

### __init__(hunt_id, hunt_name)
Create a threat hunt.

### add_hypothesis(hypothesis: HuntHypothesis)
Add a hypothesis.

### add_finding(hypothesis, description, evidence, severity)
Document a finding.

### generate_report() -> str
Generate hunt report.

### close_hunt(summary='')
Close the hunt.

---

## MITRE ATT&CK Mappings

| Detection | Technique ID | Technique Name |
|-----------|-------------|----------------|
| Port Scanning | T1046 | Network Service Discovery |
| DNS Tunneling | T1071.004 | Application Layer Protocol: DNS |
| C2 Beaconing | T1071 | Application Layer Protocol |
| Lateral Movement | T1021 | Remote Services |
| Data Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Malware Behavior | T1059 | Command and Scripting Interpreter |
| Ransomware | T1486 | Data Encrypted for Impact |
| Credential Dumping | T1003 | OS Credential Dumping |
| Persistence | T1547 | Boot or Logon Autostart Execution |
| LOLBin Abuse | T1218 | System Binary Proxy Execution |
| Process Injection | T1055 | Process Injection |
| Brute Force | T1110 | Brute Force |
| Password Spray | T1110.003 | Password Spraying |
| Impossible Travel | T1078 | Valid Accounts |
| Kerberoasting | T1558.003 | Kerberoasting |
| IAM Abuse | T1098 | Account Manipulation |
| Cryptomining | T1496 | Resource Hijacking |
| SQL Injection | T1190 | Exploit Public-Facing Application |
| Web Shell | T1505.003 | Server Software Component: Web Shell |
| Phishing | T1566 | Phishing |
| BEC | T1534 | Internal Spearphishing |
