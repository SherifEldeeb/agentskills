#!/usr/bin/env python3
"""
Detection Utilities

Comprehensive detection capabilities for identifying security threats across
network, endpoint, identity, cloud, application, and email vectors.

Usage:
    from detection_utils import NetworkDetector, EndpointDetector, IdentityDetector
"""

import json
import re
import math
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from statistics import mean, stdev

logger = logging.getLogger(__name__)


# =============================================================================
# Network Detection
# =============================================================================

class NetworkDetector:
    """Network-based threat detection."""

    SUSPICIOUS_PORTS = [4444, 5555, 6666, 8080, 8443, 9001, 31337]
    COMMON_C2_PORTS = [80, 443, 8080, 8443, 53]

    def detect_port_scan(self, conn_logs: List[Dict], threshold: int = 50,
                         time_window: int = 60) -> Dict[str, Any]:
        """
        Detect port scanning activity.

        Args:
            conn_logs: List of connection logs with src_ip, dst_ip, dst_port, timestamp
            threshold: Number of unique ports to trigger detection
            time_window: Time window in seconds
        """
        # Group by source IP
        by_source = defaultdict(list)
        for log in conn_logs:
            by_source[log['src_ip']].append(log)

        detections = []
        for src_ip, logs in by_source.items():
            # Sort by timestamp
            logs.sort(key=lambda x: x['timestamp'])

            # Sliding window analysis
            for i, start_log in enumerate(logs):
                window_logs = []
                start_time = self._parse_timestamp(start_log['timestamp'])

                for log in logs[i:]:
                    log_time = self._parse_timestamp(log['timestamp'])
                    if (log_time - start_time).total_seconds() <= time_window:
                        window_logs.append(log)
                    else:
                        break

                # Count unique ports and destinations
                unique_ports = set(log['dst_port'] for log in window_logs)
                unique_dests = set(log['dst_ip'] for log in window_logs)

                if len(unique_ports) >= threshold:
                    scan_type = self._determine_scan_type(unique_ports, unique_dests)
                    detections.append({
                        'source_ip': src_ip,
                        'port_count': len(unique_ports),
                        'destination_count': len(unique_dests),
                        'scan_type': scan_type,
                        'ports': list(unique_ports)[:20],  # First 20
                        'start_time': start_log['timestamp']
                    })
                    break  # One detection per source

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'port_scan'
        }

    def _determine_scan_type(self, ports: set, destinations: set) -> str:
        """Determine scan type based on pattern."""
        if len(destinations) > 10 and len(ports) < 5:
            return 'horizontal'  # Same ports, many hosts
        elif len(destinations) <= 2 and len(ports) > 20:
            return 'vertical'  # Many ports, few hosts
        else:
            return 'block'  # Many ports, many hosts

    def detect_dns_tunneling(self, dns_queries: List[Dict],
                             entropy_threshold: float = 3.5,
                             length_threshold: int = 50) -> Dict[str, Any]:
        """
        Detect DNS tunneling for data exfiltration.

        Args:
            dns_queries: List of DNS queries with query, query_type, timestamp
            entropy_threshold: Shannon entropy threshold for subdomain
            length_threshold: Suspicious subdomain length
        """
        detections = []
        domain_stats = defaultdict(lambda: {'queries': [], 'entropy_scores': []})

        for query in dns_queries:
            domain = query['query']
            parts = domain.split('.')

            if len(parts) >= 3:
                subdomain = parts[0]
                parent_domain = '.'.join(parts[-2:])

                entropy = self._calculate_entropy(subdomain)
                domain_stats[parent_domain]['queries'].append(query)
                domain_stats[parent_domain]['entropy_scores'].append(entropy)

        for domain, stats in domain_stats.items():
            indicators = []
            avg_entropy = mean(stats['entropy_scores']) if stats['entropy_scores'] else 0

            if avg_entropy > entropy_threshold:
                indicators.append(f'high_entropy:{avg_entropy:.2f}')

            # Check for long subdomains
            long_queries = [q for q in stats['queries']
                          if len(q['query'].split('.')[0]) > length_threshold]
            if long_queries:
                indicators.append(f'long_subdomains:{len(long_queries)}')

            # Check for unusual record types
            txt_queries = [q for q in stats['queries'] if q.get('query_type') == 'TXT']
            if len(txt_queries) > len(stats['queries']) * 0.5:
                indicators.append('high_txt_ratio')

            # High query frequency
            if len(stats['queries']) > 100:
                indicators.append(f'high_frequency:{len(stats["queries"])}')

            if len(indicators) >= 2:
                detections.append({
                    'tunnel_domain': domain,
                    'query_count': len(stats['queries']),
                    'avg_entropy': avg_entropy,
                    'indicators': indicators
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'dns_tunneling'
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def detect_beaconing(self, connections: List[Dict],
                         jitter_threshold: float = 0.2,
                         min_beacons: int = 10) -> Dict[str, Any]:
        """
        Detect C2 beaconing patterns.

        Args:
            connections: List of connections with dst_ip, dst_port, bytes, timestamp
            jitter_threshold: Maximum coefficient of variation for intervals
            min_beacons: Minimum number of connections to analyze
        """
        # Group by destination
        by_dest = defaultdict(list)
        for conn in connections:
            key = f"{conn['dst_ip']}:{conn['dst_port']}"
            by_dest[key].append(conn)

        detections = []
        for dest, conns in by_dest.items():
            if len(conns) < min_beacons:
                continue

            # Sort by timestamp and calculate intervals
            conns.sort(key=lambda x: x['timestamp'])
            intervals = []

            for i in range(1, len(conns)):
                t1 = self._parse_timestamp(conns[i-1]['timestamp'])
                t2 = self._parse_timestamp(conns[i]['timestamp'])
                intervals.append((t2 - t1).total_seconds())

            if not intervals:
                continue

            avg_interval = mean(intervals)
            if avg_interval < 1:  # Less than 1 second is likely legitimate
                continue

            try:
                interval_stdev = stdev(intervals) if len(intervals) > 1 else 0
                jitter = interval_stdev / avg_interval if avg_interval > 0 else 0
            except:
                continue

            if jitter <= jitter_threshold:
                # Also check byte size consistency (another beacon indicator)
                byte_sizes = [c.get('bytes', 0) for c in conns]
                byte_variance = stdev(byte_sizes) / mean(byte_sizes) if mean(byte_sizes) > 0 else 1

                confidence = 'high' if jitter < 0.1 and byte_variance < 0.3 else 'medium'

                detections.append({
                    'destination': dest,
                    'interval_seconds': round(avg_interval, 2),
                    'jitter': round(jitter * 100, 2),
                    'beacon_count': len(conns),
                    'confidence': confidence,
                    'byte_variance': round(byte_variance, 2)
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'c2_beaconing'
        }

    def detect_lateral_movement(self, internal_traffic: List[Dict],
                                baseline_connections: Dict[str, List[str]] = None) -> Dict[str, Any]:
        """
        Detect lateral movement within the network.

        Args:
            internal_traffic: List of internal connections
            baseline_connections: Normal connection patterns {src: [dst1, dst2]}
        """
        baseline_connections = baseline_connections or {}
        detections = []

        # Group by source
        by_source = defaultdict(list)
        for conn in internal_traffic:
            by_source[conn['src_ip']].append(conn)

        for src_ip, conns in by_source.items():
            baseline_dests = set(baseline_connections.get(src_ip, []))
            current_dests = set(c['dst_ip'] for c in conns)
            new_dests = current_dests - baseline_dests

            # Check for lateral movement indicators
            indicators = []

            # New destinations
            if new_dests:
                indicators.append(f'new_destinations:{len(new_dests)}')

            # Admin protocols to multiple hosts
            admin_protocols = ['SMB', 'RDP', 'WinRM', 'SSH', 'PSExec']
            admin_conns = [c for c in conns if c.get('service', '').upper() in admin_protocols
                         or c.get('dst_port') in [445, 3389, 5985, 22, 135]]

            admin_dests = set(c['dst_ip'] for c in admin_conns)
            if len(admin_dests) > 3:
                indicators.append(f'admin_protocol_spread:{len(admin_dests)}')

            # Rapid succession connections
            conns.sort(key=lambda x: x.get('timestamp', ''))
            if len(conns) > 5:
                indicators.append('rapid_connections')

            if indicators:
                detections.append({
                    'source': src_ip,
                    'new_destinations': list(new_dests),
                    'protocols': list(set(c.get('service', 'unknown') for c in conns)),
                    'indicators': indicators,
                    'connection_count': len(conns)
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'lateral_movement'
        }

    def detect_exfiltration(self, transfers: List[Dict],
                            baseline_bytes: Dict[str, int] = None,
                            threshold_multiplier: float = 10) -> Dict[str, Any]:
        """
        Detect data exfiltration attempts.

        Args:
            transfers: List of transfers with src_ip, dst_ip, bytes_out, protocol
            baseline_bytes: Normal daily transfer volumes by source
            threshold_multiplier: Multiplier over baseline to trigger alert
        """
        baseline_bytes = baseline_bytes or {}
        detections = []

        # Group by source
        by_source = defaultdict(list)
        for transfer in transfers:
            by_source[transfer['src_ip']].append(transfer)

        for src_ip, xfers in by_source.items():
            total_bytes = sum(x.get('bytes_out', 0) for x in xfers)
            baseline = baseline_bytes.get(src_ip, 10000000)  # Default 10MB baseline

            anomaly_score = total_bytes / baseline if baseline > 0 else 100

            indicators = []

            if anomaly_score >= threshold_multiplier:
                indicators.append(f'volume_anomaly:{anomaly_score:.1f}x')

            # Check for unusual destinations
            external_dests = [x for x in xfers if not self._is_internal_ip(x['dst_ip'])]
            if external_dests:
                indicators.append(f'external_transfers:{len(external_dests)}')

            # Check for unusual protocols
            unusual_protocols = [x for x in xfers if x.get('protocol', '').upper()
                               in ['FTP', 'SFTP', 'DNS', 'ICMP']]
            if unusual_protocols:
                indicators.append('unusual_protocol')

            # Large single transfers
            large_transfers = [x for x in xfers if x.get('bytes_out', 0) > 100000000]
            if large_transfers:
                indicators.append(f'large_transfers:{len(large_transfers)}')

            if indicators:
                detections.append({
                    'source': src_ip,
                    'bytes_transferred': total_bytes,
                    'destination': xfers[0]['dst_ip'] if len(xfers) == 1 else 'multiple',
                    'anomaly_score': round(anomaly_score, 2),
                    'indicators': indicators
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'data_exfiltration'
        }

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal (RFC1918)."""
        if ip.startswith('10.') or ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            second_octet = int(ip.split('.')[1])
            return 16 <= second_octet <= 31
        return False

    def _parse_timestamp(self, ts: str) -> datetime:
        """Parse timestamp string to datetime."""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%SZ'
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        return datetime.now()


# =============================================================================
# Endpoint Detection
# =============================================================================

class EndpointDetector:
    """Endpoint-based threat detection."""

    LOLBINS = {
        'certutil.exe': ['urlcache', 'decode', 'encode'],
        'mshta.exe': ['http', 'https', 'javascript'],
        'regsvr32.exe': ['/s', '/u', '/i:http'],
        'rundll32.exe': ['javascript', 'http', 'shell32'],
        'wmic.exe': ['process', 'call', 'create'],
        'powershell.exe': ['-enc', '-encodedcommand', '-nop', 'downloadstring', 'iex'],
        'cmd.exe': ['/c', 'powershell', 'wscript'],
        'bitsadmin.exe': ['/transfer', '/download'],
        'msiexec.exe': ['/q', 'http', 'https'],
        'cscript.exe': ['http', 'https'],
        'wscript.exe': ['http', 'https']
    }

    SUSPICIOUS_PROCESSES = [
        'mimikatz', 'procdump', 'psexec', 'bloodhound', 'sharphound',
        'rubeus', 'lazagne', 'crackmapexec', 'impacket'
    ]

    RANSOMWARE_EXTENSIONS = [
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.locky',
        '.cerber', '.zepto', '.thor', '.aaa', '.abc', '.xyz', '.zzz'
    ]

    def detect_malware_behavior(self, process_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect malware through behavioral indicators.

        Args:
            process_events: List of process events with behavioral data
        """
        detections = []

        for event in process_events:
            indicators = []
            mitre_techniques = []

            process_name = event.get('process_name', '').lower()
            command_line = event.get('command_line', '').lower()
            parent = event.get('parent_process', '').lower()

            # Check for known malicious tools
            for tool in self.SUSPICIOUS_PROCESSES:
                if tool in process_name or tool in command_line:
                    indicators.append(f'known_tool:{tool}')
                    mitre_techniques.append('T1588.002')

            # Check file writes to suspicious locations
            for write in event.get('file_writes', []):
                if any(loc in write.lower() for loc in ['\\temp\\', '/tmp/', '\\appdata\\local\\temp']):
                    indicators.append('temp_file_write')
                if write.lower().endswith(('.exe', '.dll', '.scr', '.bat', '.ps1')):
                    indicators.append('executable_drop')
                    mitre_techniques.append('T1105')

            # Check registry modifications for persistence
            for reg in event.get('registry_writes', []):
                if 'run' in reg.lower() or 'currentversion\\run' in reg.lower():
                    indicators.append('registry_persistence')
                    mitre_techniques.append('T1547.001')

            # Check for network connections
            net_conns = event.get('network_connections', [])
            if net_conns:
                indicators.append(f'network_activity:{len(net_conns)}')
                mitre_techniques.append('T1071')

            # Check parent-child relationship
            if parent in ['outlook.exe', 'excel.exe', 'word.exe', 'powerpnt.exe']:
                if process_name in ['cmd.exe', 'powershell.exe', 'wscript.exe']:
                    indicators.append('office_spawn_shell')
                    mitre_techniques.append('T1566.001')

            if indicators:
                detections.append({
                    'process': event.get('process_name'),
                    'indicators': indicators,
                    'mitre_techniques': list(set(mitre_techniques)),
                    'parent_process': parent,
                    'command_line': event.get('command_line', '')[:200]
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'malware_behavior'
        }

    def detect_ransomware(self, file_events: List[Dict], threshold: int = 100,
                          time_window: int = 60) -> Dict[str, Any]:
        """
        Detect ransomware encryption activity.

        Args:
            file_events: List of file operations with operation, path, timestamp
            threshold: Number of file modifications to trigger
            time_window: Time window in seconds
        """
        detections = []

        # Sort by timestamp
        file_events.sort(key=lambda x: x.get('timestamp', ''))

        encrypted_files = []
        deleted_files = []
        ransom_notes = []

        for event in file_events:
            path = event.get('path', '').lower()
            operation = event.get('operation', '').lower()

            # Check for encryption indicators
            if operation == 'write':
                for ext in self.RANSOMWARE_EXTENSIONS:
                    if path.endswith(ext):
                        encrypted_files.append(path)
                        break

            if operation == 'delete':
                deleted_files.append(path)

            # Check for ransom notes
            if operation in ['create', 'write']:
                if any(note in path for note in ['readme', 'decrypt', 'recover', 'ransom']):
                    if path.endswith(('.txt', '.html', '.hta')):
                        ransom_notes.append(path)

        # Calculate modification rate
        if len(file_events) >= 2:
            first_time = file_events[0].get('timestamp')
            last_time = file_events[-1].get('timestamp')
            # Simple check without complex time parsing
            modification_count = len(encrypted_files) + len(deleted_files)
        else:
            modification_count = 0

        indicators = []
        if len(encrypted_files) > 10:
            indicators.append(f'encrypted_files:{len(encrypted_files)}')
        if len(deleted_files) > 50:
            indicators.append(f'mass_deletion:{len(deleted_files)}')
        if ransom_notes:
            indicators.append('ransom_note_created')
        if modification_count > threshold:
            indicators.append('high_modification_rate')

        if indicators:
            detections.append({
                'file_count': len(encrypted_files),
                'deleted_count': len(deleted_files),
                'pattern': self._identify_ransomware_pattern(encrypted_files),
                'ransom_note_path': ransom_notes[0] if ransom_notes else None,
                'indicators': indicators
            })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'ransomware'
        }

    def _identify_ransomware_pattern(self, encrypted_files: List[str]) -> str:
        """Identify ransomware family by extension pattern."""
        if not encrypted_files:
            return 'unknown'

        extensions = set(f.split('.')[-1] for f in encrypted_files if '.' in f)

        patterns = {
            'locky': ['locky', 'zepto', 'odin'],
            'cerber': ['cerber', 'cerber2', 'cerber3'],
            'wannacry': ['wncry', 'wcry', 'wncryt'],
            'ryuk': ['ryk', 'ryuk'],
            'lockbit': ['lockbit', 'abcd']
        }

        for family, exts in patterns.items():
            if any(ext in extensions for ext in exts):
                return family

        return 'generic_encryption'

    def detect_credential_dumping(self, process_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect credential theft attempts.

        Args:
            process_events: List of process events with access patterns
        """
        detections = []

        credential_techniques = {
            'lsass_dump': {
                'indicators': ['lsass.exe', 'procdump', 'minidump', 'comsvcs'],
                'mitre': 'T1003.001'
            },
            'sam_access': {
                'indicators': ['sam', 'system', 'security', 'reg save'],
                'mitre': 'T1003.002'
            },
            'ntds_dump': {
                'indicators': ['ntds.dit', 'ntdsutil', 'vssadmin', 'shadow'],
                'mitre': 'T1003.003'
            },
            'dcsync': {
                'indicators': ['drsuapi', 'dcsync', 'mimikatz', 'lsadump'],
                'mitre': 'T1003.006'
            }
        }

        for event in process_events:
            command_line = event.get('command_line', '').lower()
            process_name = event.get('process_name', '').lower()
            target_process = event.get('target_process', '').lower()

            detected_techniques = []
            tool_indicators = []

            for technique, data in credential_techniques.items():
                if any(ind in command_line or ind in process_name
                       for ind in data['indicators']):
                    detected_techniques.append({
                        'technique': technique,
                        'mitre': data['mitre']
                    })

            # Check for LSASS access
            if target_process == 'lsass.exe':
                access_rights = event.get('access_rights', '')
                if 'all_access' in access_rights.lower() or 'vm_read' in access_rights.lower():
                    detected_techniques.append({
                        'technique': 'lsass_memory_access',
                        'mitre': 'T1003.001'
                    })

            # Known tools
            known_tools = ['mimikatz', 'procdump', 'lazagne', 'pwdump', 'fgdump']
            for tool in known_tools:
                if tool in command_line or tool in process_name:
                    tool_indicators.append(tool)

            if detected_techniques or tool_indicators:
                detections.append({
                    'process': event.get('process_name'),
                    'technique': detected_techniques[0]['technique'] if detected_techniques else 'unknown',
                    'mitre_id': detected_techniques[0]['mitre'] if detected_techniques else 'T1003',
                    'tool_indicators': tool_indicators,
                    'command_line': event.get('command_line', '')[:200]
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'credential_dumping'
        }

    def detect_persistence(self, system_changes: List[Dict]) -> Dict[str, Any]:
        """
        Detect persistence mechanism installation.

        Args:
            system_changes: List of system modifications
        """
        detections = []

        persistence_locations = {
            'registry': {
                'run_keys': ['currentversion\\run', 'currentversion\\runonce'],
                'services': ['services\\'],
                'winlogon': ['winlogon\\notify', 'winlogon\\shell'],
                'mitre': 'T1547.001'
            },
            'scheduled_task': {
                'mitre': 'T1053.005'
            },
            'service': {
                'mitre': 'T1543.003'
            },
            'startup_folder': {
                'paths': ['startup', 'start menu\\programs\\startup'],
                'mitre': 'T1547.001'
            },
            'wmi': {
                'indicators': ['wmi', 'subscription', '__eventfilter'],
                'mitre': 'T1546.003'
            }
        }

        mechanisms = []

        for change in system_changes:
            change_type = change.get('type', '').lower()

            if change_type == 'registry':
                path = change.get('path', '').lower()
                for reg_type, locations in persistence_locations['registry'].items():
                    if isinstance(locations, list):
                        if any(loc in path for loc in locations):
                            mechanisms.append({
                                'type': f'registry_{reg_type}',
                                'details': path,
                                'value': change.get('value', ''),
                                'mitre': 'T1547.001'
                            })

            elif change_type == 'scheduled_task':
                mechanisms.append({
                    'type': 'scheduled_task',
                    'details': change.get('name', ''),
                    'action': change.get('action', ''),
                    'mitre': 'T1053.005'
                })

            elif change_type == 'service':
                mechanisms.append({
                    'type': 'service',
                    'details': change.get('name', ''),
                    'binary': change.get('binary', ''),
                    'mitre': 'T1543.003'
                })

        if mechanisms:
            detections.append({
                'mechanisms': mechanisms,
                'count': len(mechanisms)
            })

        return {
            'detected': len(mechanisms) > 0,
            'detections': detections,
            'detection_type': 'persistence'
        }

    def detect_lolbin_abuse(self, process_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect Living-off-the-Land Binary abuse.

        Args:
            process_events: List of process execution events
        """
        detections = []

        mitre_mapping = {
            'certutil.exe': 'T1140',
            'mshta.exe': 'T1218.005',
            'regsvr32.exe': 'T1218.010',
            'rundll32.exe': 'T1218.011',
            'wmic.exe': 'T1047',
            'powershell.exe': 'T1059.001',
            'bitsadmin.exe': 'T1197',
            'msiexec.exe': 'T1218.007'
        }

        for event in process_events:
            process_name = event.get('process_name', '').lower()
            command_line = event.get('command_line', '').lower()
            parent = event.get('parent_process', '').lower()

            for lolbin, suspicious_args in self.LOLBINS.items():
                if process_name == lolbin.lower():
                    matched_args = [arg for arg in suspicious_args
                                   if arg.lower() in command_line]

                    if matched_args:
                        detections.append({
                            'binary': lolbin,
                            'suspicious_args': matched_args,
                            'command_line': event.get('command_line', '')[:200],
                            'parent_process': parent,
                            'mitre_technique': mitre_mapping.get(lolbin, 'T1218')
                        })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'lolbin_abuse'
        }

    def detect_process_injection(self, process_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect process injection techniques.

        Args:
            process_events: List of process events with API call data
        """
        detections = []

        injection_apis = {
            'classic_injection': ['virtualallocex', 'writeprocessmemory', 'createremotethread'],
            'apc_injection': ['queueuserapc', 'ntqueueapcthread'],
            'process_hollowing': ['ntunmapviewofsection', 'zwunmapviewofsection'],
            'atom_bombing': ['globaladdatom', 'queueuserapc'],
            'dll_injection': ['loadlibrary', 'ldrloaddll']
        }

        for event in process_events:
            api_calls = event.get('api_calls', [])
            api_calls_lower = [api.lower() for api in api_calls]

            for technique, apis in injection_apis.items():
                matched_apis = [api for api in apis if any(api in call for call in api_calls_lower)]

                if len(matched_apis) >= 2:
                    detections.append({
                        'technique': technique,
                        'source_process': event.get('process_name'),
                        'target_process': event.get('target_process'),
                        'apis_used': matched_apis,
                        'mitre_technique': 'T1055'
                    })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'process_injection'
        }


# =============================================================================
# Identity Detection
# =============================================================================

class IdentityDetector:
    """Identity and authentication threat detection."""

    def detect_brute_force(self, auth_logs: List[Dict], failure_threshold: int = 10,
                           time_window: int = 300) -> Dict[str, Any]:
        """
        Detect brute force authentication attacks.

        Args:
            auth_logs: List of auth events with user, result, source_ip, timestamp
            failure_threshold: Failed attempts to trigger alert
            time_window: Time window in seconds
        """
        detections = []

        # Group by target user and source
        by_target = defaultdict(list)
        for log in auth_logs:
            key = (log.get('user', ''), log.get('source_ip', ''))
            by_target[key].append(log)

        for (user, source_ip), logs in by_target.items():
            failures = [l for l in logs if l.get('result') == 'failure']
            successes = [l for l in logs if l.get('result') == 'success']

            if len(failures) >= failure_threshold:
                compromised = False
                if successes:
                    # Check if success came after failures
                    last_failure_time = max(f.get('timestamp', '') for f in failures)
                    for success in successes:
                        if success.get('timestamp', '') > last_failure_time:
                            compromised = True
                            break

                detections.append({
                    'target_user': user,
                    'source_ip': source_ip,
                    'failure_count': len(failures),
                    'success_count': len(successes),
                    'compromised': compromised,
                    'attack_type': 'brute_force'
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'brute_force'
        }

    def detect_password_spray(self, auth_logs: List[Dict],
                              user_threshold: int = 5,
                              time_window: int = 600) -> Dict[str, Any]:
        """
        Detect password spray attacks (few attempts per user, many users).

        Args:
            auth_logs: List of auth events
            user_threshold: Minimum unique users targeted
            time_window: Time window in seconds
        """
        detections = []

        # Group by source IP
        by_source = defaultdict(list)
        for log in auth_logs:
            by_source[log.get('source_ip', '')].append(log)

        for source_ip, logs in by_source.items():
            failures = [l for l in logs if l.get('result') == 'failure']

            # Count failures per user
            users_targeted = defaultdict(int)
            for f in failures:
                users_targeted[f.get('user', '')] += 1

            # Password spray: many users, few attempts each
            unique_users = len(users_targeted)
            avg_attempts = len(failures) / unique_users if unique_users > 0 else 0

            if unique_users >= user_threshold and avg_attempts <= 3:
                detections.append({
                    'source_ip': source_ip,
                    'users_targeted': unique_users,
                    'total_attempts': len(failures),
                    'avg_attempts_per_user': round(avg_attempts, 2),
                    'attack_type': 'password_spray'
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'password_spray'
        }

    def detect_impossible_travel(self, login_events: List[Dict],
                                  max_speed_kmh: int = 1000) -> Dict[str, Any]:
        """
        Detect impossible travel (geographically impossible logins).

        Args:
            login_events: List of logins with user, location, timestamp, ip
            max_speed_kmh: Maximum realistic travel speed
        """
        detections = []

        # Group by user
        by_user = defaultdict(list)
        for event in login_events:
            by_user[event.get('user', '')].append(event)

        # Simplified location to coordinates (would need real geo-IP in production)
        location_coords = {
            'new york, us': (40.7128, -74.0060),
            'los angeles, us': (34.0522, -118.2437),
            'london, uk': (51.5074, -0.1278),
            'tokyo, jp': (35.6762, 139.6503),
            'sydney, au': (-33.8688, 151.2093),
            'paris, fr': (48.8566, 2.3522),
            'berlin, de': (52.5200, 13.4050),
            'mumbai, in': (19.0760, 72.8777),
            'singapore, sg': (1.3521, 103.8198),
            'dubai, ae': (25.2048, 55.2708)
        }

        for user, events in by_user.items():
            events.sort(key=lambda x: x.get('timestamp', ''))

            for i in range(1, len(events)):
                prev = events[i-1]
                curr = events[i]

                loc1 = prev.get('location', '').lower()
                loc2 = curr.get('location', '').lower()

                if loc1 in location_coords and loc2 in location_coords:
                    coords1 = location_coords[loc1]
                    coords2 = location_coords[loc2]

                    distance_km = self._haversine_distance(coords1, coords2)

                    # Calculate time difference (simplified)
                    time_diff_minutes = 30  # Placeholder - would parse timestamps

                    if time_diff_minutes > 0:
                        required_speed = (distance_km / time_diff_minutes) * 60

                        if required_speed > max_speed_kmh:
                            detections.append({
                                'user': user,
                                'location_1': prev.get('location'),
                                'location_2': curr.get('location'),
                                'distance_km': round(distance_km, 2),
                                'time_minutes': time_diff_minutes,
                                'required_speed_kmh': round(required_speed, 2),
                                'ip_1': prev.get('ip'),
                                'ip_2': curr.get('ip')
                            })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'impossible_travel'
        }

    def _haversine_distance(self, coord1: Tuple[float, float],
                            coord2: Tuple[float, float]) -> float:
        """Calculate distance between two coordinates in km."""
        lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
        lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))

        return 6371 * c  # Earth radius in km

    def detect_kerberoasting(self, kerberos_events: List[Dict],
                             request_threshold: int = 5,
                             time_window: int = 60) -> Dict[str, Any]:
        """
        Detect Kerberoasting attacks.

        Args:
            kerberos_events: List of Kerberos events with user, event_type, service
            request_threshold: TGS requests to trigger alert
            time_window: Time window in seconds
        """
        detections = []

        # Group by user
        by_user = defaultdict(list)
        for event in kerberos_events:
            if event.get('event_type') == 'TGS_REQ':
                by_user[event.get('user', '')].append(event)

        for user, events in by_user.items():
            if len(events) >= request_threshold:
                services = [e.get('service', '') for e in events]

                # Check for weak encryption requests (RC4)
                rc4_requests = [e for e in events if e.get('encryption', '').upper() == 'RC4']

                indicators = []
                if len(rc4_requests) > len(events) * 0.5:
                    indicators.append('weak_encryption_preference')
                if len(services) == len(set(services)):  # All unique services
                    indicators.append('service_enumeration')

                if indicators:
                    detections.append({
                        'user': user,
                        'ticket_count': len(events),
                        'services': list(set(services)),
                        'rc4_requests': len(rc4_requests),
                        'indicators': indicators,
                        'mitre_technique': 'T1558.003'
                    })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'kerberoasting'
        }

    def detect_privilege_abuse(self, admin_events: List[Dict],
                               baseline_hours: List[int] = None) -> Dict[str, Any]:
        """
        Detect privilege/admin account abuse.

        Args:
            admin_events: List of admin account activities
            baseline_hours: Normal working hours (0-23)
        """
        baseline_hours = baseline_hours or list(range(8, 18))  # 8 AM - 6 PM
        detections = []

        # Group by user
        by_user = defaultdict(list)
        for event in admin_events:
            by_user[event.get('user', '')].append(event)

        for user, events in by_user.items():
            indicators = []

            # Check for off-hours activity
            off_hours_events = []
            for event in events:
                ts = event.get('timestamp', '')
                try:
                    hour = int(ts.split(' ')[1].split(':')[0])
                    if hour not in baseline_hours:
                        off_hours_events.append(event)
                except:
                    pass

            if len(off_hours_events) > len(events) * 0.3:
                indicators.append(f'off_hours_activity:{len(off_hours_events)}')

            # Check for unusual actions
            sensitive_actions = ['create_user', 'modify_permissions', 'disable_audit',
                               'export_data', 'modify_security_policy']
            sensitive_events = [e for e in events
                              if e.get('action', '') in sensitive_actions]
            if sensitive_events:
                indicators.append(f'sensitive_actions:{len(sensitive_events)}')

            # Check for service account interactive logon
            if 'svc' in user.lower() or 'service' in user.lower():
                interactive = [e for e in events if e.get('logon_type') == 'interactive']
                if interactive:
                    indicators.append('service_account_interactive')

            if indicators:
                detections.append({
                    'user': user,
                    'event_count': len(events),
                    'off_hours_count': len(off_hours_events),
                    'indicators': indicators
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'privilege_abuse'
        }


# =============================================================================
# Cloud Detection
# =============================================================================

class CloudDetector:
    """Cloud platform threat detection."""

    SENSITIVE_IAM_ACTIONS = [
        'CreateUser', 'CreateRole', 'AttachUserPolicy', 'AttachRolePolicy',
        'PutUserPolicy', 'PutRolePolicy', 'CreateAccessKey', 'UpdateAccessKey',
        'DeleteTrail', 'StopLogging', 'UpdateTrail'
    ]

    GPU_INSTANCE_TYPES = [
        'p3.', 'p4.', 'g4.', 'g5.', 'p2.', 'inf1.', 'trn1.'
    ]

    def detect_iam_abuse(self, cloudtrail_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect IAM abuse in cloud environments.

        Args:
            cloudtrail_events: List of CloudTrail events
        """
        detections = []

        # Group by actor
        by_actor = defaultdict(list)
        for event in cloudtrail_events:
            by_actor[event.get('user', '')].append(event)

        for actor, events in by_actor.items():
            sensitive_events = [e for e in events
                              if e.get('event') in self.SENSITIVE_IAM_ACTIONS]

            if not sensitive_events:
                continue

            risk_indicators = []

            # Check for privilege escalation pattern
            create_events = [e for e in sensitive_events
                           if 'Create' in e.get('event', '')]
            attach_events = [e for e in sensitive_events
                           if 'Attach' in e.get('event', '') or 'Put' in e.get('event', '')]

            if create_events and attach_events:
                risk_indicators.append('privilege_escalation_pattern')

            # Check for admin policy attachment
            admin_policies = [e for e in sensitive_events
                            if 'Admin' in e.get('policy', '')]
            if admin_policies:
                risk_indicators.append('admin_policy_attached')

            # Check for audit trail tampering
            audit_events = [e for e in sensitive_events
                          if 'Trail' in e.get('event', '') or 'Logging' in e.get('event', '')]
            if audit_events:
                risk_indicators.append('audit_tampering')

            risk_level = 'critical' if len(risk_indicators) >= 2 else 'high'

            detections.append({
                'actor': actor,
                'actions': [e.get('event') for e in sensitive_events],
                'risk_level': risk_level,
                'indicators': risk_indicators,
                'event_count': len(sensitive_events)
            })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'iam_abuse'
        }

    def detect_cryptomining(self, resource_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect cryptomining through resource abuse.

        Args:
            resource_events: List of compute resource events
        """
        detections = []

        gpu_instances = []
        total_cost = 0

        # Hourly costs (approximate)
        instance_costs = {
            'p3.2xlarge': 3.06,
            'p3.8xlarge': 12.24,
            'p3.16xlarge': 24.48,
            'p4d.24xlarge': 32.77,
            'g4dn.xlarge': 0.526,
            'g4dn.12xlarge': 3.912
        }

        for event in resource_events:
            if event.get('event') == 'RunInstances':
                instance_type = event.get('instance_type', '')
                count = event.get('count', 1)

                is_gpu = any(gpu in instance_type for gpu in self.GPU_INSTANCE_TYPES)

                if is_gpu:
                    gpu_instances.append({
                        'type': instance_type,
                        'count': count,
                        'region': event.get('region', 'unknown')
                    })

                    # Estimate cost
                    for cost_type, cost in instance_costs.items():
                        if cost_type in instance_type:
                            total_cost += cost * count
                            break

        if gpu_instances:
            total_gpus = sum(i['count'] for i in gpu_instances)
            regions = list(set(i['region'] for i in gpu_instances))

            indicators = []
            if total_gpus > 5:
                indicators.append('high_gpu_count')
            if len(regions) > 2:
                indicators.append('multi_region_deployment')
            if total_cost > 50:
                indicators.append('high_estimated_cost')

            if indicators:
                detections.append({
                    'gpu_instance_count': total_gpus,
                    'instance_types': [i['type'] for i in gpu_instances],
                    'regions': regions,
                    'estimated_hourly_cost': round(total_cost, 2),
                    'indicators': indicators
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'cryptomining'
        }

    def detect_s3_exposure(self, s3_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect S3 bucket exposure risks.

        Args:
            s3_events: List of S3 configuration events
        """
        detections = []

        for event in s3_events:
            bucket = event.get('bucket', '')
            indicators = []

            # Check for public access
            if event.get('public_access', False):
                indicators.append('public_access_enabled')

            # Check ACL
            acl = event.get('acl', '')
            if 'public' in acl.lower() or 'authenticated-users' in acl.lower():
                indicators.append('permissive_acl')

            # Check for policy allowing public access
            policy = event.get('bucket_policy', {})
            if isinstance(policy, dict):
                principal = str(policy.get('Principal', ''))
                if principal == '*' or 'AWS' in principal:
                    indicators.append('overly_permissive_policy')

            if indicators:
                detections.append({
                    'bucket': bucket,
                    'indicators': indicators,
                    'risk_level': 'critical' if 'public_access_enabled' in indicators else 'high'
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 's3_exposure'
        }

    def detect_container_escape(self, container_events: List[Dict]) -> Dict[str, Any]:
        """
        Detect container escape attempts.

        Args:
            container_events: List of container runtime events
        """
        detections = []

        escape_indicators = {
            'privileged_container': ['privileged=true', '--privileged'],
            'host_namespace': ['--pid=host', '--net=host', '--ipc=host'],
            'sensitive_mount': ['/var/run/docker.sock', '/proc', '/sys'],
            'capability_abuse': ['SYS_ADMIN', 'SYS_PTRACE', 'DAC_READ_SEARCH'],
            'kernel_exploit': ['dirty_cow', 'dirty_pipe', 'overlayfs']
        }

        for event in container_events:
            container_id = event.get('container_id', '')
            indicators = []

            config = str(event.get('config', '')).lower()
            runtime_args = str(event.get('runtime_args', '')).lower()
            syscalls = event.get('syscalls', [])

            for indicator_type, patterns in escape_indicators.items():
                for pattern in patterns:
                    if pattern.lower() in config or pattern.lower() in runtime_args:
                        indicators.append(indicator_type)
                        break

            # Check for suspicious syscalls
            dangerous_syscalls = ['mount', 'ptrace', 'process_vm_readv', 'setns']
            syscall_matches = [s for s in syscalls if s in dangerous_syscalls]
            if syscall_matches:
                indicators.append(f'dangerous_syscalls:{len(syscall_matches)}')

            if indicators:
                detections.append({
                    'container_id': container_id,
                    'indicators': list(set(indicators)),
                    'risk_level': 'critical' if len(indicators) >= 2 else 'high',
                    'mitre_technique': 'T1611'
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'container_escape'
        }


# =============================================================================
# Application Detection
# =============================================================================

class ApplicationDetector:
    """Application layer threat detection."""

    SQLI_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION(\s+)SELECT",
        r"SELECT(\s+).+(\s+)FROM",
        r"INSERT(\s+)INTO",
        r"DELETE(\s+)FROM",
        r"DROP(\s+)TABLE",
        r"OR(\s+)1(\s*)=(\s*)1",
        r"AND(\s+)1(\s*)=(\s*)1"
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img[^>]+src[^>]+onerror",
        r"<svg[^>]+onload",
        r"document\.cookie",
        r"document\.location",
        r"eval\s*\("
    ]

    def detect_sql_injection(self, web_requests: List[Dict]) -> Dict[str, Any]:
        """
        Detect SQL injection attempts.

        Args:
            web_requests: List of web requests with url, params, method
        """
        detections = []

        for request in web_requests:
            url = request.get('url', '')
            params = request.get('params', {})

            # Check all parameters
            for param_name, param_value in params.items():
                if not isinstance(param_value, str):
                    continue

                for pattern in self.SQLI_PATTERNS:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        detections.append({
                            'endpoint': url,
                            'parameter': param_name,
                            'payload': param_value[:100],
                            'pattern': pattern[:30],
                            'method': request.get('method', 'GET'),
                            'mitre_technique': 'T1190'
                        })
                        break

        return {
            'detected': len(detections) > 0,
            'attacks': detections,
            'detection_type': 'sql_injection'
        }

    def detect_xss(self, web_requests: List[Dict]) -> Dict[str, Any]:
        """
        Detect cross-site scripting attempts.

        Args:
            web_requests: List of web requests
        """
        detections = []

        for request in web_requests:
            url = request.get('url', '')
            params = request.get('params', {})
            body = request.get('body', '')

            # Check parameters and body
            check_values = list(params.values()) + [body]

            for value in check_values:
                if not isinstance(value, str):
                    continue

                for pattern in self.XSS_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        detections.append({
                            'endpoint': url,
                            'payload': value[:100],
                            'pattern_matched': pattern[:30],
                            'attack_type': self._classify_xss(value),
                            'mitre_technique': 'T1189'
                        })
                        break

        return {
            'detected': len(detections) > 0,
            'attacks': detections,
            'detection_type': 'xss'
        }

    def _classify_xss(self, payload: str) -> str:
        """Classify XSS attack type."""
        payload_lower = payload.lower()
        if '<script' in payload_lower:
            return 'stored_or_reflected'
        if 'javascript:' in payload_lower:
            return 'dom_based'
        if re.search(r'on\w+=', payload_lower):
            return 'event_handler'
        return 'unknown'

    def detect_webshell(self, web_logs: List[Dict]) -> Dict[str, Any]:
        """
        Detect web shell activity.

        Args:
            web_logs: List of web access logs
        """
        detections = []

        webshell_indicators = {
            'command_params': ['cmd', 'command', 'exec', 'shell', 'c', 'run'],
            'suspicious_extensions': ['.php', '.asp', '.aspx', '.jsp', '.cgi'],
            'suspicious_paths': ['/uploads/', '/images/', '/tmp/', '/temp/'],
            'command_patterns': ['whoami', 'cat /etc', 'dir c:', 'net user', 'id']
        }

        for log in web_logs:
            url = log.get('url', '').lower()
            params = log.get('params', {})

            indicators = []

            # Check for suspicious file extensions in unusual locations
            for ext in webshell_indicators['suspicious_extensions']:
                if ext in url:
                    for path in webshell_indicators['suspicious_paths']:
                        if path in url:
                            indicators.append('suspicious_location')
                            break

            # Check for command parameters
            for param_name in params.keys():
                if param_name.lower() in webshell_indicators['command_params']:
                    indicators.append('command_parameter')
                    break

            # Check parameter values for command patterns
            for value in params.values():
                if isinstance(value, str):
                    for pattern in webshell_indicators['command_patterns']:
                        if pattern in value.lower():
                            indicators.append('command_execution')
                            break

            if indicators:
                detections.append({
                    'path': log.get('url'),
                    'commands': [v for v in params.values() if isinstance(v, str)][:3],
                    'indicators': list(set(indicators)),
                    'response_size': log.get('response_size', 0),
                    'mitre_technique': 'T1505.003'
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'webshell'
        }

    def detect_api_abuse(self, api_logs: List[Dict],
                         rate_threshold: int = 100,
                         time_window: int = 60) -> Dict[str, Any]:
        """
        Detect API abuse patterns.

        Args:
            api_logs: List of API request logs
            rate_threshold: Requests per time window to trigger
            time_window: Time window in seconds
        """
        detections = []

        # Group by client
        by_client = defaultdict(list)
        for log in api_logs:
            client = log.get('client_ip', '') or log.get('api_key', '')
            by_client[client].append(log)

        for client, logs in by_client.items():
            indicators = []

            # Check rate
            if len(logs) > rate_threshold:
                indicators.append(f'high_rate:{len(logs)}')

            # Check for enumeration patterns
            endpoints = [l.get('endpoint', '') for l in logs]
            unique_endpoints = set(endpoints)
            if len(unique_endpoints) > 20:
                indicators.append('endpoint_enumeration')

            # Check for authentication failures
            auth_failures = [l for l in logs if l.get('status_code') in [401, 403]]
            if len(auth_failures) > 10:
                indicators.append(f'auth_failures:{len(auth_failures)}')

            # Check for error responses (fuzzing indicator)
            error_responses = [l for l in logs if l.get('status_code', 0) >= 400]
            if len(error_responses) > len(logs) * 0.3:
                indicators.append('high_error_rate')

            if indicators:
                detections.append({
                    'client': client,
                    'request_count': len(logs),
                    'unique_endpoints': len(unique_endpoints),
                    'indicators': indicators
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'api_abuse'
        }


# =============================================================================
# Email Detection
# =============================================================================

class EmailDetector:
    """Email threat detection."""

    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'action required', 'suspended', 'locked',
        'verify', 'confirm', 'expire', 'limited time', 'act now'
    ]

    IMPERSONATION_DOMAINS = {
        'microsoft': ['micros0ft', 'mircosoft', 'microsft', 'microsoft-support'],
        'google': ['g00gle', 'googIe', 'google-support', 'accounts-google'],
        'apple': ['app1e', 'appleid-support', 'apple-support'],
        'amazon': ['amaz0n', 'amazon-support', 'amazonn'],
        'paypal': ['paypa1', 'paypal-support', 'secure-paypal']
    }

    def detect_phishing(self, emails: List[Dict]) -> Dict[str, Any]:
        """
        Detect phishing emails.

        Args:
            emails: List of emails with from, subject, body, links, attachments
        """
        detections = []

        for email in emails:
            indicators = []
            sender = email.get('from', '').lower()
            subject = email.get('subject', '').lower()
            body = email.get('body', '').lower()
            links = email.get('links', [])

            # Check for impersonation
            impersonation = self._check_impersonation(sender)
            if impersonation:
                indicators.append(f'impersonation:{impersonation}')

            # Check for urgency
            urgency_score = sum(1 for kw in self.URGENCY_KEYWORDS
                               if kw in subject or kw in body)
            if urgency_score >= 2:
                indicators.append(f'urgency_score:{urgency_score}')

            # Check links
            suspicious_links = []
            for link in links:
                link_lower = link.lower()
                # Check for IP-based URLs
                if re.match(r'https?://\d+\.\d+\.\d+\.\d+', link):
                    suspicious_links.append(link)
                # Check for suspicious TLDs
                if any(tld in link_lower for tld in ['.xyz', '.top', '.tk', '.ml', '.ga']):
                    suspicious_links.append(link)
                # Check for URL shorteners
                if any(short in link_lower for short in ['bit.ly', 'tinyurl', 'goo.gl']):
                    suspicious_links.append(link)

            if suspicious_links:
                indicators.append('suspicious_links')

            # Check for credential harvesting keywords
            cred_keywords = ['password', 'login', 'credential', 'account', 'verify']
            cred_score = sum(1 for kw in cred_keywords if kw in body)
            if cred_score >= 2:
                indicators.append('credential_harvesting_language')

            if indicators:
                detections.append({
                    'sender': email.get('from'),
                    'subject': email.get('subject'),
                    'impersonation': impersonation,
                    'suspicious_links': suspicious_links[:3],
                    'urgency_score': urgency_score,
                    'indicators': indicators
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'phishing'
        }

    def _check_impersonation(self, sender: str) -> Optional[str]:
        """Check if sender impersonates a known brand."""
        for brand, variants in self.IMPERSONATION_DOMAINS.items():
            if any(variant in sender for variant in variants):
                return brand
            # Also check for legitimate but spoofed
            if brand in sender and not sender.endswith(f'@{brand}.com'):
                # Could be spoofing
                return f'{brand}_possible'
        return None

    def detect_bec(self, emails: List[Dict],
                   executive_list: List[str] = None) -> Dict[str, Any]:
        """
        Detect Business Email Compromise attempts.

        Args:
            emails: List of emails
            executive_list: List of executive email addresses
        """
        executive_list = executive_list or []
        detections = []

        bec_patterns = {
            'wire_transfer': ['wire transfer', 'bank transfer', 'payment', 'invoice'],
            'gift_card': ['gift card', 'purchase card', 'itunes', 'google play'],
            'urgency': ['asap', 'urgent', 'today', 'immediately', 'quick favor'],
            'secrecy': ['confidential', 'between us', 'private', 'do not share']
        }

        for email in emails:
            sender = email.get('from', '').lower()
            subject = email.get('subject', '').lower()
            body = email.get('body', '').lower()

            indicators = []

            # Check for executive impersonation
            exec_impersonation = None
            for exec_email in executive_list:
                exec_name = exec_email.split('@')[0]
                if exec_name in sender and sender != exec_email:
                    exec_impersonation = exec_email
                    indicators.append('executive_impersonation')
                    break

            # Check for BEC patterns
            for pattern_type, keywords in bec_patterns.items():
                if any(kw in subject or kw in body for kw in keywords):
                    indicators.append(pattern_type)

            # Reply-to mismatch
            reply_to = email.get('reply_to', '').lower()
            if reply_to and reply_to != sender:
                indicators.append('reply_to_mismatch')

            if len(indicators) >= 2:
                detections.append({
                    'sender': email.get('from'),
                    'subject': email.get('subject'),
                    'executive_impersonated': exec_impersonation,
                    'indicators': indicators,
                    'risk_level': 'critical' if 'wire_transfer' in indicators else 'high'
                })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'bec'
        }

    def detect_malicious_attachment(self, emails: List[Dict]) -> Dict[str, Any]:
        """
        Detect malicious email attachments.

        Args:
            emails: List of emails with attachment information
        """
        detections = []

        dangerous_extensions = [
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.hta', '.wsf', '.jar', '.iso', '.img'
        ]

        double_extension_pattern = r'\.\w+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$'

        macro_extensions = ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm']

        for email in emails:
            attachments = email.get('attachments', [])

            for attachment in attachments:
                if isinstance(attachment, str):
                    filename = attachment.lower()
                elif isinstance(attachment, dict):
                    filename = attachment.get('filename', '').lower()
                else:
                    continue

                indicators = []

                # Check for dangerous extensions
                for ext in dangerous_extensions:
                    if filename.endswith(ext):
                        indicators.append(f'dangerous_extension:{ext}')
                        break

                # Check for double extensions
                if re.search(double_extension_pattern, filename, re.IGNORECASE):
                    indicators.append('double_extension')

                # Check for macro-enabled documents
                for ext in macro_extensions:
                    if filename.endswith(ext):
                        indicators.append('macro_enabled')
                        break

                # Check for password-protected archives
                if filename.endswith('.zip') or filename.endswith('.7z'):
                    if isinstance(attachment, dict) and attachment.get('password_protected'):
                        indicators.append('password_protected_archive')

                if indicators:
                    detections.append({
                        'email_from': email.get('from'),
                        'email_subject': email.get('subject'),
                        'filename': filename,
                        'indicators': indicators
                    })

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'detection_type': 'malicious_attachment'
        }


# =============================================================================
# Detection Rule Management
# =============================================================================

class DetectionRule:
    """Create and manage detection rules."""

    def __init__(self, name: str, category: str, severity: str,
                 description: str = ''):
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description
        self.conditions = []
        self.mitre_mappings = []
        self.created_at = datetime.now()
        self.id = hashlib.md5(f"{name}{datetime.now()}".encode()).hexdigest()[:8]

    def add_condition(self, field: str, operator: str, value: str):
        """Add a detection condition."""
        valid_operators = ['equals', 'contains', 'startswith', 'endswith',
                          'regex', 'gt', 'lt', 'in', 'not_equals']
        if operator not in valid_operators:
            raise ValueError(f"Invalid operator: {operator}")

        self.conditions.append({
            'field': field,
            'operator': operator,
            'value': value
        })

    def add_mitre_mapping(self, technique_id: str, technique_name: str):
        """Add MITRE ATT&CK mapping."""
        self.mitre_mappings.append({
            'technique_id': technique_id,
            'technique_name': technique_name
        })

    def to_sigma(self) -> str:
        """Export rule to SIGMA format."""
        sigma = f"""title: {self.name}
id: {self.id}
status: experimental
description: {self.description}
author: Detection Utils
date: {self.created_at.strftime('%Y/%m/%d')}
tags:
"""
        for mapping in self.mitre_mappings:
            sigma += f"    - attack.{mapping['technique_id'].lower()}\n"

        sigma += f"""logsource:
    category: {self.category}
detection:
    selection:
"""
        for condition in self.conditions:
            if condition['operator'] == 'equals':
                sigma += f"        {condition['field']}: '{condition['value']}'\n"
            elif condition['operator'] == 'contains':
                sigma += f"        {condition['field']}|contains: '{condition['value']}'\n"
            elif condition['operator'] == 'startswith':
                sigma += f"        {condition['field']}|startswith: '{condition['value']}'\n"
            elif condition['operator'] == 'endswith':
                sigma += f"        {condition['field']}|endswith: '{condition['value']}'\n"
            elif condition['operator'] == 'regex':
                sigma += f"        {condition['field']}|re: '{condition['value']}'\n"

        sigma += f"""    condition: selection
level: {self.severity.lower()}
"""
        return sigma

    def to_kql(self) -> str:
        """Export rule to Kusto Query Language (Microsoft Sentinel)."""
        kql = f"// {self.name}\n// {self.description}\n"

        table = 'SecurityEvent' if self.category == 'endpoint' else 'CommonSecurityLog'
        kql += f"{table}\n"

        where_clauses = []
        for condition in self.conditions:
            field = condition['field']
            value = condition['value']

            if condition['operator'] == 'equals':
                where_clauses.append(f'{field} == "{value}"')
            elif condition['operator'] == 'contains':
                where_clauses.append(f'{field} contains "{value}"')
            elif condition['operator'] == 'startswith':
                where_clauses.append(f'{field} startswith "{value}"')
            elif condition['operator'] == 'regex':
                where_clauses.append(f'{field} matches regex "{value}"')

        if where_clauses:
            kql += "| where " + " and ".join(where_clauses) + "\n"

        return kql

    def to_splunk(self) -> str:
        """Export rule to Splunk SPL."""
        spl = f"| tstats count from datamodel=Endpoint "

        where_clauses = []
        for condition in self.conditions:
            field = condition['field']
            value = condition['value']

            if condition['operator'] == 'equals':
                where_clauses.append(f'{field}="{value}"')
            elif condition['operator'] == 'contains':
                where_clauses.append(f'{field}="*{value}*"')
            elif condition['operator'] == 'startswith':
                where_clauses.append(f'{field}="{value}*"')

        if where_clauses:
            spl += "where " + " ".join(where_clauses)

        spl += f"\n`comment(\"{self.name} - {self.description}\")`"

        return spl

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'conditions': self.conditions,
            'mitre_mappings': self.mitre_mappings,
            'created_at': self.created_at.isoformat()
        }


class DetectionRuleSet:
    """Manage a collection of detection rules."""

    def __init__(self, name: str):
        self.name = name
        self.rules = []

    def add_rule(self, rule: DetectionRule):
        """Add a rule to the set."""
        self.rules.append(rule)

    def export_all(self, output_dir: str, format: str = 'sigma'):
        """Export all rules to files."""
        import os
        os.makedirs(output_dir, exist_ok=True)

        for rule in self.rules:
            filename = f"{rule.name.lower().replace(' ', '_')}.{format}"
            filepath = os.path.join(output_dir, filename)

            if format == 'sigma':
                content = rule.to_sigma()
            elif format == 'kql':
                content = rule.to_kql()
            elif format == 'spl':
                content = rule.to_splunk()
            else:
                content = json.dumps(rule.to_dict(), indent=2)

            with open(filepath, 'w') as f:
                f.write(content)


# =============================================================================
# Threat Hunting
# =============================================================================

class HuntHypothesis:
    """Define a threat hunting hypothesis."""

    def __init__(self, name: str, description: str,
                 mitre_techniques: List[str] = None):
        self.name = name
        self.description = description
        self.mitre_techniques = mitre_techniques or []
        self.data_sources = []
        self.queries = []

    def add_data_source(self, source_type: str, description: str):
        """Add a data source for the hunt."""
        self.data_sources.append({
            'type': source_type,
            'description': description
        })

    def add_query(self, data_source: str, description: str, query: str):
        """Add a hunt query."""
        self.queries.append({
            'data_source': data_source,
            'description': description,
            'query': query
        })


class ThreatHunter:
    """Conduct threat hunting operations."""

    def __init__(self, hunt_id: str, hunt_name: str):
        self.hunt_id = hunt_id
        self.hunt_name = hunt_name
        self.started_at = datetime.now()
        self.hypotheses = []
        self.findings = []
        self.status = 'active'

    def add_hypothesis(self, hypothesis: HuntHypothesis):
        """Add a hypothesis to the hunt."""
        self.hypotheses.append(hypothesis)

    def add_finding(self, hypothesis: str, description: str,
                    evidence: List[str], severity: str):
        """Document a finding."""
        self.findings.append({
            'hypothesis': hypothesis,
            'description': description,
            'evidence': evidence,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })

    def generate_report(self) -> str:
        """Generate hunt report."""
        report = f"""# Threat Hunt Report: {self.hunt_id}

**Hunt Name:** {self.hunt_name}
**Started:** {self.started_at.strftime('%Y-%m-%d %H:%M')}
**Status:** {self.status}

---

## Hypotheses

"""
        for hyp in self.hypotheses:
            report += f"""### {hyp.name}

{hyp.description}

**MITRE Techniques:** {', '.join(hyp.mitre_techniques)}

**Data Sources:**
"""
            for ds in hyp.data_sources:
                report += f"- {ds['type']}: {ds['description']}\n"

            report += "\n**Queries:**\n"
            for q in hyp.queries:
                report += f"- [{q['data_source']}] {q['description']}\n"
            report += "\n"

        report += """## Findings

| Hypothesis | Description | Severity | Evidence |
|------------|-------------|----------|----------|
"""
        for finding in self.findings:
            evidence_str = ', '.join(finding['evidence'][:2])
            report += f"| {finding['hypothesis'][:30]} | {finding['description'][:40]} | {finding['severity']} | {evidence_str} |\n"

        report += f"""
## Summary

- **Hypotheses Tested:** {len(self.hypotheses)}
- **Findings:** {len(self.findings)}
- **Critical Findings:** {len([f for f in self.findings if f['severity'] == 'Critical'])}
- **High Findings:** {len([f for f in self.findings if f['severity'] == 'High'])}
"""
        return report

    def close_hunt(self, summary: str = ''):
        """Close the hunt."""
        self.status = 'closed'
        self.closed_at = datetime.now()
        self.summary = summary
