---
name: memory-forensics
description: |
  Analyze volatile memory (RAM) dumps for forensic investigation. Use when investigating
  malware infections, rootkits, process injection, credential theft, or any incident
  requiring analysis of system memory state. Supports Windows, Linux, and macOS memory images.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Optional: volatility3, yara-python, rekall
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: forensics
---

# Memory Forensics

Comprehensive memory forensics skill for analyzing RAM dumps and volatile memory artifacts. Enables detection of malware, rootkits, process injection, credential harvesting, and other memory-resident threats that leave no disk footprint.

## Capabilities

- **Memory Image Acquisition**: Guide acquisition of memory dumps using various tools (WinPMEM, LIME, DumpIt, FTK Imager)
- **Process Analysis**: Enumerate running processes, detect hidden/injected processes, analyze process trees
- **DLL/Module Analysis**: Identify loaded modules, detect DLL injection, find hollowed processes
- **Network Connection Analysis**: Extract active network connections, listening ports, socket information
- **Registry Hive Extraction**: Extract registry hives from memory for offline analysis
- **Credential Extraction**: Locate and extract credentials, password hashes, Kerberos tickets
- **Malware Detection**: Detect code injection, API hooks, SSDT hooks, IDT modifications
- **String Extraction**: Extract strings, URLs, IPs, and other IOCs from memory regions
- **Timeline Generation**: Create memory-based timelines of process execution and system events
- **Rootkit Detection**: Identify kernel-level rootkits, hidden drivers, DKOM techniques

## Quick Start

```python
from memory_forensics import MemoryAnalyzer, ProcessScanner, MalwareDetector

# Initialize analyzer with memory image
analyzer = MemoryAnalyzer("/path/to/memory.raw")

# Get system profile
profile = analyzer.identify_profile()
print(f"Detected OS: {profile.os_name} {profile.version}")

# Scan for processes
scanner = ProcessScanner(analyzer)
processes = scanner.list_processes(include_hidden=True)

# Detect malware indicators
detector = MalwareDetector(analyzer)
findings = detector.scan_all()
```

## Usage

### Task 1: Memory Image Acquisition
**Input**: Target system requiring memory acquisition

**Process**:
1. Select appropriate acquisition tool based on OS
2. Verify tool integrity (hash validation)
3. Execute acquisition with minimal system impact
4. Calculate and record hash of acquired image
5. Document acquisition metadata

**Output**: Raw memory dump with integrity verification

**Example**:
```python
from memory_forensics import MemoryAcquisition

# Windows acquisition guidance
acquisition = MemoryAcquisition()

# Get tool recommendations
tools = acquisition.recommend_tools(
    os_type="windows",
    os_version="10",
    acquisition_type="live"
)

# Generate acquisition command
cmd = acquisition.generate_command(
    tool="winpmem",
    output_path="E:\\evidence\\memory.raw",
    format="raw"
)
print(f"Execute: {cmd}")

# Create acquisition documentation
doc = acquisition.create_documentation(
    case_id="INC-2024-001",
    examiner="John Doe",
    target_hostname="WORKSTATION01",
    acquisition_tool="WinPMEM 4.0",
    hash_algorithm="SHA256"
)
```

### Task 2: Process Analysis
**Input**: Memory image file path

**Process**:
1. Load memory image and identify OS profile
2. Enumerate all processes (visible and hidden)
3. Analyze process tree relationships
4. Detect anomalous processes
5. Identify process injection indicators

**Output**: Comprehensive process listing with anomaly flags

**Example**:
```python
from memory_forensics import MemoryAnalyzer, ProcessScanner

analyzer = MemoryAnalyzer("/evidence/memory.raw")
scanner = ProcessScanner(analyzer)

# List all processes with details
processes = scanner.list_processes(
    include_hidden=True,
    include_terminated=False
)

for proc in processes:
    print(f"PID: {proc.pid}, Name: {proc.name}, PPID: {proc.ppid}")
    print(f"  Created: {proc.create_time}")
    print(f"  Command Line: {proc.cmdline}")
    print(f"  Suspicious: {proc.is_suspicious}")

# Detect hidden processes
hidden = scanner.find_hidden_processes()
for proc in hidden:
    print(f"HIDDEN: PID {proc.pid} - {proc.name}")

# Analyze process tree
tree = scanner.build_process_tree()
tree.print_tree()

# Find orphan processes
orphans = scanner.find_orphan_processes()

# Detect process hollowing
hollowed = scanner.detect_hollowing()
for proc in hollowed:
    print(f"HOLLOWED: {proc.pid} - {proc.name}")
    print(f"  Image path mismatch: {proc.image_mismatch}")
```

### Task 3: DLL and Module Analysis
**Input**: Memory image and target process(es)

**Process**:
1. Enumerate loaded DLLs for target processes
2. Identify unsigned or suspicious modules
3. Detect DLL injection techniques
4. Compare loaded modules to expected baseline
5. Extract suspicious modules for analysis

**Output**: Module analysis report with injection indicators

**Example**:
```python
from memory_forensics import MemoryAnalyzer, ModuleScanner

analyzer = MemoryAnalyzer("/evidence/memory.raw")
module_scanner = ModuleScanner(analyzer)

# Analyze all loaded modules
modules = module_scanner.enumerate_modules(pid=4892)

for mod in modules:
    print(f"Module: {mod.name}")
    print(f"  Base: 0x{mod.base_address:x}")
    print(f"  Size: {mod.size}")
    print(f"  Path: {mod.path}")

# Detect DLL injection
injections = module_scanner.detect_dll_injection()
for inj in injections:
    print(f"INJECTION in PID {inj.target_pid}:")
    print(f"  Technique: {inj.technique}")
    print(f"  Injected DLL: {inj.dll_name}")
    print(f"  Source PID: {inj.source_pid}")

# Find unlinked modules
unlinked = module_scanner.find_unlinked_modules()

# Detect reflective DLL loading
reflective = module_scanner.detect_reflective_loading()

# Extract suspicious module
module_scanner.extract_module(
    pid=4892,
    module_name="suspicious.dll",
    output_path="/evidence/extracted/"
)
```

### Task 4: Network Connection Analysis
**Input**: Memory image file

**Process**:
1. Extract active TCP/UDP connections
2. Identify listening ports and services
3. Map connections to processes
4. Detect suspicious external connections
5. Extract connection artifacts

**Output**: Network connection inventory with process mapping

**Example**:
```python
from memory_forensics import MemoryAnalyzer, NetworkScanner

analyzer = MemoryAnalyzer("/evidence/memory.raw")
net_scanner = NetworkScanner(analyzer)

# Get all network connections
connections = net_scanner.get_connections()

for conn in connections:
    print(f"PID {conn.pid} ({conn.process_name}):")
    print(f"  Protocol: {conn.protocol}")
    print(f"  Local: {conn.local_addr}:{conn.local_port}")
    print(f"  Remote: {conn.remote_addr}:{conn.remote_port}")
    print(f"  State: {conn.state}")

# Find connections to suspicious IPs
suspicious = net_scanner.find_suspicious_connections(
    threat_intel_feed="/feeds/malicious_ips.txt"
)

# Get listening ports
listening = net_scanner.get_listening_ports()
for port in listening:
    print(f"Port {port.port}/{port.protocol} - PID {port.pid}")

# Detect covert channels
covert = net_scanner.detect_covert_channels()

# Export to CSV
net_scanner.export_connections("/evidence/network_connections.csv")
```

### Task 5: Credential Extraction
**Input**: Memory image file

**Process**:
1. Locate credential storage structures
2. Extract password hashes (NTLM, LM)
3. Find Kerberos tickets
4. Identify cached credentials
5. Extract plaintext passwords (if available)

**Output**: Extracted credentials for further analysis

**Example**:
```python
from memory_forensics import MemoryAnalyzer, CredentialExtractor

analyzer = MemoryAnalyzer("/evidence/memory.raw")
cred_extractor = CredentialExtractor(analyzer)

# Extract all credentials
credentials = cred_extractor.extract_all()

# Get NTLM hashes
ntlm_hashes = cred_extractor.get_ntlm_hashes()
for cred in ntlm_hashes:
    print(f"User: {cred.username}")
    print(f"Domain: {cred.domain}")
    print(f"NTLM Hash: {cred.ntlm_hash}")

# Extract Kerberos tickets
tickets = cred_extractor.get_kerberos_tickets()
for ticket in tickets:
    print(f"Service: {ticket.service_name}")
    print(f"Client: {ticket.client_name}")
    print(f"Expiry: {ticket.expiry_time}")

# Find LSA secrets
lsa_secrets = cred_extractor.get_lsa_secrets()

# Extract cached domain credentials
cached = cred_extractor.get_cached_credentials()

# Export credentials report
cred_extractor.export_report("/evidence/credentials_report.json")
```

### Task 6: Malware Detection
**Input**: Memory image file

**Process**:
1. Scan for known malware signatures
2. Detect code injection techniques
3. Identify API hooks and SSDT modifications
4. Find hidden/rootkit artifacts
5. Analyze suspicious memory regions

**Output**: Malware detection findings with IOCs

**Example**:
```python
from memory_forensics import MemoryAnalyzer, MalwareDetector

analyzer = MemoryAnalyzer("/evidence/memory.raw")
detector = MalwareDetector(analyzer)

# Run comprehensive malware scan
findings = detector.scan_all()

# Detect code injection
injections = detector.detect_code_injection()
for inj in injections:
    print(f"Injection found in PID {inj.pid}:")
    print(f"  Type: {inj.injection_type}")
    print(f"  Address: 0x{inj.address:x}")
    print(f"  Size: {inj.size}")

# Scan with YARA rules
yara_matches = detector.scan_yara(
    rules_path="/rules/malware_rules.yar"
)
for match in yara_matches:
    print(f"YARA Match: {match.rule_name}")
    print(f"  PID: {match.pid}")
    print(f"  Offset: 0x{match.offset:x}")

# Detect API hooks
hooks = detector.detect_api_hooks()
for hook in hooks:
    print(f"Hook: {hook.function_name}")
    print(f"  Original: 0x{hook.original_address:x}")
    print(f"  Hooked: 0x{hook.hook_address:x}")

# Check SSDT integrity
ssdt_mods = detector.check_ssdt()

# Detect DKOM (Direct Kernel Object Manipulation)
dkom = detector.detect_dkom()

# Export IOCs
detector.export_iocs("/evidence/memory_iocs.json")
```

### Task 7: Registry Analysis from Memory
**Input**: Memory image file

**Process**:
1. Locate registry hives in memory
2. Extract hives to disk
3. Parse registry keys and values
4. Identify suspicious registry entries
5. Extract persistence mechanisms

**Output**: Registry analysis with persistence indicators

**Example**:
```python
from memory_forensics import MemoryAnalyzer, RegistryAnalyzer

analyzer = MemoryAnalyzer("/evidence/memory.raw")
reg_analyzer = RegistryAnalyzer(analyzer)

# List available registry hives
hives = reg_analyzer.list_hives()
for hive in hives:
    print(f"Hive: {hive.name} at 0x{hive.virtual_address:x}")

# Extract hive to file
reg_analyzer.extract_hive(
    hive_name="SYSTEM",
    output_path="/evidence/SYSTEM_hive"
)

# Query specific key
value = reg_analyzer.query_key(
    hive="SOFTWARE",
    key_path="Microsoft\\Windows\\CurrentVersion\\Run"
)

# Find persistence mechanisms
persistence = reg_analyzer.find_persistence()
for entry in persistence:
    print(f"Persistence: {entry.location}")
    print(f"  Value: {entry.value}")
    print(f"  Type: {entry.persistence_type}")

# Get recently modified keys
recent = reg_analyzer.get_recent_modifications(hours=24)

# Search registry for pattern
matches = reg_analyzer.search(pattern="*.exe", include_values=True)
```

### Task 8: String and IOC Extraction
**Input**: Memory image or specific memory regions

**Process**:
1. Extract ASCII and Unicode strings
2. Identify URLs, IPs, domains
3. Find email addresses and file paths
4. Extract potential C2 indicators
5. Correlate IOCs with threat intelligence

**Output**: Extracted IOCs categorized by type

**Example**:
```python
from memory_forensics import MemoryAnalyzer, IOCExtractor

analyzer = MemoryAnalyzer("/evidence/memory.raw")
ioc_extractor = IOCExtractor(analyzer)

# Extract all IOCs
iocs = ioc_extractor.extract_all()

# Get URLs
urls = ioc_extractor.extract_urls()
for url in urls:
    print(f"URL: {url.value}")
    print(f"  Found at: 0x{url.offset:x}")
    print(f"  Process: {url.process_name}")

# Get IP addresses
ips = ioc_extractor.extract_ips()
for ip in ips:
    print(f"IP: {ip.value} ({ip.geo_location})")

# Get domains
domains = ioc_extractor.extract_domains()

# Get file paths
paths = ioc_extractor.extract_file_paths()

# Extract strings from specific process
proc_strings = ioc_extractor.extract_strings(
    pid=4892,
    min_length=4,
    encoding="both"  # ascii and unicode
)

# Correlate with threat intel
enriched = ioc_extractor.enrich_iocs(
    threat_feed="/feeds/threat_intel.json"
)

# Export IOCs in STIX format
ioc_extractor.export_stix("/evidence/memory_iocs.stix")
```

### Task 9: Rootkit Detection
**Input**: Memory image file

**Process**:
1. Check kernel integrity
2. Detect hidden drivers
3. Analyze SSDT/IDT modifications
4. Find DKOM artifacts
5. Identify inline kernel hooks

**Output**: Rootkit detection results with remediation guidance

**Example**:
```python
from memory_forensics import MemoryAnalyzer, RootkitDetector

analyzer = MemoryAnalyzer("/evidence/memory.raw")
rootkit_detector = RootkitDetector(analyzer)

# Run comprehensive rootkit scan
results = rootkit_detector.scan_all()

# Check for hidden drivers
hidden_drivers = rootkit_detector.find_hidden_drivers()
for driver in hidden_drivers:
    print(f"Hidden Driver: {driver.name}")
    print(f"  Base: 0x{driver.base:x}")
    print(f"  Size: {driver.size}")

# Analyze SSDT
ssdt_hooks = rootkit_detector.analyze_ssdt()
for hook in ssdt_hooks:
    print(f"SSDT Hook: {hook.function}")
    print(f"  Expected: 0x{hook.expected:x}")
    print(f"  Actual: 0x{hook.actual:x}")

# Check IDT (Interrupt Descriptor Table)
idt_mods = rootkit_detector.analyze_idt()

# Detect inline hooks in kernel
inline_hooks = rootkit_detector.detect_inline_hooks()

# Check kernel callbacks
callbacks = rootkit_detector.analyze_callbacks()
for cb in callbacks:
    print(f"Callback: {cb.type}")
    print(f"  Address: 0x{cb.address:x}")
    print(f"  Module: {cb.module}")

# Generate rootkit report
rootkit_detector.generate_report("/evidence/rootkit_analysis.html")
```

### Task 10: Memory Timeline Analysis
**Input**: Memory image file

**Process**:
1. Extract timestamps from memory structures
2. Correlate process creation times
3. Analyze recent file handles
4. Build execution timeline
5. Identify temporal anomalies

**Output**: Memory-based timeline of system activity

**Example**:
```python
from memory_forensics import MemoryAnalyzer, MemoryTimeline

analyzer = MemoryAnalyzer("/evidence/memory.raw")
timeline = MemoryTimeline(analyzer)

# Generate comprehensive timeline
events = timeline.generate()

for event in events:
    print(f"{event.timestamp}: {event.event_type}")
    print(f"  Source: {event.source}")
    print(f"  Details: {event.details}")

# Get process timeline
proc_timeline = timeline.get_process_timeline()

# Get network timeline
net_timeline = timeline.get_network_timeline()

# Find events around specific time
window = timeline.get_events_around(
    timestamp="2024-01-15T10:30:00",
    window_minutes=30
)

# Export to timeline format
timeline.export_csv("/evidence/memory_timeline.csv")
timeline.export_json("/evidence/memory_timeline.json")

# Generate visual timeline
timeline.generate_html_report("/evidence/timeline_report.html")
```

## Configuration

### Environment Variables
| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `VOLATILITY_PATH` | Path to Volatility installation | No | System PATH |
| `YARA_RULES_PATH` | Default YARA rules directory | No | ./rules |
| `SYMBOL_PATH` | Path to debug symbols | No | None |
| `THREAT_INTEL_FEED` | Threat intelligence feed URL | No | None |

### Options
| Option | Type | Description |
|--------|------|-------------|
| `profile` | string | Force specific OS profile |
| `output_format` | string | Output format (json, csv, html) |
| `verbose` | boolean | Enable verbose output |
| `use_yara` | boolean | Enable YARA scanning |
| `parallel` | boolean | Enable parallel processing |

## Examples

### Example 1: Incident Response Memory Analysis
**Scenario**: Investigating a potential ransomware infection

```python
from memory_forensics import MemoryAnalyzer, ProcessScanner, MalwareDetector, NetworkScanner

# Load memory dump from infected system
analyzer = MemoryAnalyzer("/evidence/infected_host.raw")

# Step 1: Identify suspicious processes
scanner = ProcessScanner(analyzer)
suspicious = scanner.find_suspicious_processes()
print(f"Found {len(suspicious)} suspicious processes")

# Step 2: Check for known ransomware indicators
detector = MalwareDetector(analyzer)
ransomware_iocs = detector.scan_yara("/rules/ransomware.yar")

# Step 3: Identify C2 connections
net_scanner = NetworkScanner(analyzer)
external_conns = net_scanner.find_external_connections()
suspicious_c2 = net_scanner.check_against_threat_intel("/feeds/c2_ips.txt")

# Step 4: Extract encryption keys (if in memory)
keys = detector.find_crypto_keys()

# Step 5: Generate comprehensive report
analyzer.generate_report(
    output_path="/evidence/ransomware_analysis.html",
    include_timeline=True,
    include_iocs=True
)
```

### Example 2: Credential Theft Investigation
**Scenario**: Investigating Mimikatz or similar credential harvesting

```python
from memory_forensics import MemoryAnalyzer, CredentialExtractor, ProcessScanner

analyzer = MemoryAnalyzer("/evidence/dc_memory.raw")

# Look for Mimikatz artifacts
scanner = ProcessScanner(analyzer)
mimikatz_indicators = scanner.search_command_lines(
    patterns=["sekurlsa", "logonpasswords", "lsadump"]
)

# Extract compromised credentials
extractor = CredentialExtractor(analyzer)
credentials = extractor.extract_all()

# Check for Kerberos ticket theft (Golden/Silver ticket)
tickets = extractor.get_kerberos_tickets()
for ticket in tickets:
    if ticket.is_suspicious():
        print(f"ALERT: Suspicious ticket for {ticket.service_name}")

# Document affected accounts
extractor.generate_affected_accounts_report("/evidence/compromised_accounts.csv")
```

### Example 3: Rootkit Investigation
**Scenario**: Investigating suspected kernel-level compromise

```python
from memory_forensics import MemoryAnalyzer, RootkitDetector, ModuleScanner

analyzer = MemoryAnalyzer("/evidence/server_memory.raw")

# Comprehensive rootkit analysis
rootkit_detector = RootkitDetector(analyzer)

# Check kernel integrity
integrity = rootkit_detector.verify_kernel_integrity()
if not integrity.is_clean:
    print("ALERT: Kernel modifications detected!")
    for mod in integrity.modifications:
        print(f"  - {mod.description}")

# Find hidden components
hidden_drivers = rootkit_detector.find_hidden_drivers()
hidden_processes = rootkit_detector.find_hidden_processes()

# Analyze all hooks
all_hooks = rootkit_detector.find_all_hooks()

# Generate remediation guidance
rootkit_detector.generate_remediation_guide("/evidence/rootkit_remediation.md")
```

## Limitations

- Memory analysis accuracy depends on image acquisition quality
- Encrypted memory regions may not be analyzable
- Some anti-forensics techniques may evade detection
- Profile identification may fail for custom or rare OS versions
- Large memory dumps (>32GB) may require significant processing time
- Credential extraction requires appropriate access permissions
- YARA scanning effectiveness depends on rule quality

## Troubleshooting

### Common Issue 1: Profile Detection Failure
**Problem**: Unable to automatically detect OS profile
**Solution**:
- Manually specify profile using `--profile` option
- Ensure memory image is not corrupted
- Check if OS version is supported

### Common Issue 2: Incomplete Process Listing
**Problem**: Known processes not appearing in output
**Solution**:
- Enable hidden process detection
- Check for memory corruption
- Verify image acquisition was complete

### Common Issue 3: Slow Analysis Performance
**Problem**: Analysis taking too long
**Solution**:
- Enable parallel processing
- Use targeted scans instead of full analysis
- Ensure adequate system resources

### Common Issue 4: YARA Scan Errors
**Problem**: YARA rules failing to load
**Solution**:
- Validate YARA rule syntax
- Check rule file encoding (UTF-8)
- Update YARA to latest version

## Related Skills

- [disk-forensics](../disk-forensics/): Complements memory analysis with persistent storage investigation
- [malware-forensics](../malware-forensics/): Detailed malware analysis of extracted samples
- [timeline-forensics](../timeline-forensics/): Integrate memory timeline with other data sources
- [artifact-collection](../artifact-collection/): Evidence collection and preservation procedures
- [incident-response](../../cybersecurity/incident-response/): Overall IR workflow integration

## References

- [Memory Analysis Reference](references/REFERENCE.md)
- [Volatility Plugin Guide](references/VOLATILITY_PLUGINS.md)
- [Memory Acquisition Best Practices](references/ACQUISITION_GUIDE.md)
