#!/usr/bin/env python3
"""
Feature extraction module for Suricata JSON analysis
"""
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from typing import Dict, List, Any, Union, Tuple, Optional
import ipaddress
import datetime
import logging
from sklearn.preprocessing import StandardScaler

# Local imports (assuming the core processing module is in the same directory)
from core_processing import (
    SuricataParser, SuricataFlow, SuricataHTTP, SuricataDNS, 
    SuricataTLS, SuricataAlert, convert_to_datetime
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('feature_extraction')


class FeatureExtractor:
    """Extract features from Suricata events for ML processing"""
    
    def __init__(self):
        """Initialize the feature extractor"""
        self.parser = SuricataParser()
        self.flow_features = {}  # Features indexed by flow_id
        self.ip_features = {}    # Features indexed by IP address
        self.scaler = StandardScaler()
        self.trained = False
        # This patch fixes the port type handling in the extract_flow_features method

    def extract_flow_features(self, flow: SuricataFlow) -> Dict[str, Any]:
        """
        Extract features from a flow event
        
        Args:
            flow: SuricataFlow object
            
        Returns:
            Dictionary of extracted features
        """
        # Handle port values that might be either strings or integers
        if isinstance(flow.sport, str):
            src_port = int(flow.sport) if flow.sport.isdigit() else 0
        else:
            src_port = flow.sport if isinstance(flow.sport, (int, float)) else 0
            
        if isinstance(flow.dport, str):
            dst_port = int(flow.dport) if flow.dport.isdigit() else 0
        else:
            dst_port = flow.dport if isinstance(flow.dport, (int, float)) else 0
        
        features = {
            'uid': flow.uid,
            'src_ip': flow.saddr,
            'dst_ip': flow.daddr,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': flow.proto,
            'app_protocol': flow.appproto if flow.appproto else "unknown",
            'duration': flow.dur,
            'total_bytes': flow.bytes,
            'total_packets': flow.pkts,
            'bytes_per_packet': flow.bytes / flow.pkts if flow.pkts > 0 else 0,
            'packets_per_second': flow.pkts / flow.dur if flow.dur > 0 else 0,
            'bytes_per_second': flow.bytes / flow.dur if flow.dur > 0 else 0,
            'src_to_dst_bytes': flow.sbytes,
            'dst_to_src_bytes': flow.dbytes,
            'src_to_dst_packets': flow.spkts,
            'dst_to_src_packets': flow.dpkts,
            'bytes_ratio': flow.sbytes / flow.dbytes if flow.dbytes > 0 else float('inf'),
            'packets_ratio': flow.spkts / flow.dpkts if flow.dpkts > 0 else float('inf'),
            'state': flow.state,
            'timestamp': convert_to_datetime(flow.starttime).timestamp(),
            # Time-based features
            'hour_of_day': convert_to_datetime(flow.starttime).hour,
            'day_of_week': convert_to_datetime(flow.starttime).weekday(),
            'is_weekend': 1 if convert_to_datetime(flow.starttime).weekday() >= 5 else 0,
        }
        
        # Add features for special ports
        features['is_web_port'] = 1 if features['dst_port'] in [80, 443, 8000, 8080, 8443] else 0
        features['is_dns_port'] = 1 if features['dst_port'] == 53 else 0
        features['is_mail_port'] = 1 if features['dst_port'] in [25, 465, 587, 110, 995, 143, 993] else 0
        features['is_ssh_port'] = 1 if features['dst_port'] == 22 else 0
        features['is_high_port'] = 1 if features['dst_port'] >= 1024 else 0
        
        # IP-based features
        try:
            src_ip = ipaddress.ip_address(flow.saddr)
            dst_ip = ipaddress.ip_address(flow.daddr)
            
            features['src_is_private'] = 1 if src_ip.is_private else 0
            features['dst_is_private'] = 1 if dst_ip.is_private else 0
            features['src_is_loopback'] = 1 if src_ip.is_loopback else 0
            features['dst_is_loopback'] = 1 if dst_ip.is_loopback else 0
            features['src_is_multicast'] = 1 if src_ip.is_multicast else 0
            features['dst_is_multicast'] = 1 if dst_ip.is_multicast else 0
            features['src_is_ipv6'] = 1 if src_ip.version == 6 else 0
            features['dst_is_ipv6'] = 1 if dst_ip.version == 6 else 0
        except ValueError:
            # Invalid IP address
            features['src_is_private'] = 0
            features['dst_is_private'] = 0
            features['src_is_loopback'] = 0
            features['dst_is_loopback'] = 0
            features['src_is_multicast'] = 0
            features['dst_is_multicast'] = 0
            features['src_is_ipv6'] = 0
            features['dst_is_ipv6'] = 0
        
        return features
    
    def extract_http_features(self, http: SuricataHTTP) -> Dict[str, Any]:
        """
        Extract features from an HTTP event
        
        Args:
            http: SuricataHTTP object
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'uid': http.uid,
            'method': http.method,
            'host': http.host,
            'uri': http.uri,
            'user_agent': http.user_agent,
            'status_code': http.status_code,
            'request_body_len': http.request_body_len,
            'response_body_len': http.response_body_len,
            'has_user_agent': 1 if http.user_agent else 0,
            'is_success': 1 if http.status_code.startswith('2') else 0,
            'is_redirect': 1 if http.status_code.startswith('3') else 0,
            'is_client_error': 1 if http.status_code.startswith('4') else 0,
            'is_server_error': 1 if http.status_code.startswith('5') else 0,
            'uri_length': len(http.uri) if http.uri else 0,
            'host_length': len(http.host) if http.host else 0,
            'user_agent_length': len(http.user_agent) if http.user_agent else 0,
        }
        
        # Extract HTTP method features
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'PATCH']:
            features[f'method_{method}'] = 1 if http.method == method else 0
            
        # Check for suspicious URI patterns
        suspicious_patterns = [
            'admin', 'login', 'wp-admin', 'install', 'setup', 'config', 'backup',
            'shell', 'cmd', 'exec', 'passwd', 'password', '.php', '.asp', '.jsp'
        ]
        features['suspicious_uri'] = 0
        if http.uri:
            for pattern in suspicious_patterns:
                if pattern in http.uri.lower():
                    features['suspicious_uri'] = 1
                    break
                    
        # Check for suspicious user agent patterns
        suspicious_ua_patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'gobuster', 'dirb',
            'curl', 'wget', 'python-requests', 'go-http-client', 'scanners'
        ]
        features['suspicious_user_agent'] = 0
        if http.user_agent:
            for pattern in suspicious_ua_patterns:
                if pattern in http.user_agent.lower():
                    features['suspicious_user_agent'] = 1
                    break
                    
        return features
    
    def extract_dns_features(self, dns: SuricataDNS) -> Dict[str, Any]:
        """
        Extract features from a DNS event
        
        Args:
            dns: SuricataDNS object
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'uid': dns.uid,
            'query': dns.query,
            'query_length': len(dns.query) if dns.query else 0,
            'has_answers': 1 if dns.answers else 0,
            'answer_count': len(dns.answers) if dns.answers else 0,
        }
        
        # Check for DGA-like patterns
        if dns.query:
            # Entropy of domain name (high entropy could indicate DGA)
            entropy = self._calculate_entropy(dns.query)
            features['query_entropy'] = entropy
            
            # Consonant to vowel ratio (high ratio could indicate DGA)
            vowels = sum(1 for c in dns.query if c.lower() in 'aeiou')
            consonants = sum(1 for c in dns.query if c.lower() in 'bcdfghjklmnpqrstvwxyz')
            features['consonant_vowel_ratio'] = consonants / vowels if vowels > 0 else float('inf')
            
            # Digit ratio (high digit ratio could indicate DGA)
            digits = sum(1 for c in dns.query if c.isdigit())
            features['digit_ratio'] = digits / len(dns.query) if dns.query else 0
            
            # Domain levels (how many parts, separated by dots)
            parts = dns.query.split('.')
            features['domain_levels'] = len(parts)
            
            # Length of longest level
            features['longest_level_length'] = max(len(part) for part in parts) if parts else 0
            
            # Check for suspicious TLD
            suspicious_tlds = [
                'xyz', 'top', 'club', 'site', 'info', 'online', 'biz', 'ru', 'cn',
                'tk', 'ga', 'cf', 'ml', 'gq', 'download', 'stream'
            ]
            features['suspicious_tld'] = 0
            if parts and len(parts) > 1:
                tld = parts[-1].lower()
                if tld in suspicious_tlds:
                    features['suspicious_tld'] = 1
        else:
            features['query_entropy'] = 0
            features['consonant_vowel_ratio'] = 0
            features['digit_ratio'] = 0
            features['domain_levels'] = 0
            features['longest_level_length'] = 0
            features['suspicious_tld'] = 0
            
        return features
    
    def extract_tls_features(self, tls: SuricataTLS) -> Dict[str, Any]:
        """
        Extract features from a TLS event
        
        Args:
            tls: SuricataTLS object
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'uid': tls.uid,
            'sslversion': tls.sslversion,
            'server_name': tls.server_name,
            'has_subject': 1 if tls.subject else 0,
            'subject_length': len(tls.subject) if tls.subject else 0,
            'has_server_name': 1 if tls.server_name else 0,
            'server_name_length': len(tls.server_name) if tls.server_name else 0,
        }
        
        # Check for weak SSL/TLS versions
        weak_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']
        features['is_weak_version'] = 1 if tls.sslversion in weak_versions else 0
        
        # Calculate certificate validity period (if available)
        if tls.notbefore and tls.notafter:
            try:
                notbefore = convert_to_datetime(tls.notbefore)
                notafter = convert_to_datetime(tls.notafter)
                validity_days = (notafter - notbefore).days
                features['cert_validity_days'] = validity_days
                
                # Check if cert is expired
                now = datetime.datetime.now()
                features['is_expired'] = 1 if now > notafter else 0
                
                # Check if cert was issued recently (potentially suspicious)
                features['is_recently_issued'] = 1 if (now - notbefore).days < 7 else 0
                
                # Check for unusually long validity period
                features['is_long_validity'] = 1 if validity_days > 825 else 0  # > ~27 months
            except (ValueError, TypeError):
                features['cert_validity_days'] = 0
                features['is_expired'] = 0
                features['is_recently_issued'] = 0
                features['is_long_validity'] = 0
        else:
            features['cert_validity_days'] = 0
            features['is_expired'] = 0
            features['is_recently_issued'] = 0
            features['is_long_validity'] = 0
            
        # Check for suspicious server names (entropy, length)
        if tls.server_name:
            features['server_name_entropy'] = self._calculate_entropy(tls.server_name)
            
            # Suspicious TLD check
            parts = tls.server_name.split('.')
            suspicious_tlds = [
                'xyz', 'top', 'club', 'site', 'info', 'online', 'biz', 'ru', 'cn',
                'tk', 'ga', 'cf', 'ml', 'gq', 'download', 'stream'
            ]
            features['suspicious_tld'] = 0
            if parts and len(parts) > 1:
                tld = parts[-1].lower()
                if tld in suspicious_tlds:
                    features['suspicious_tld'] = 1
        else:
            features['server_name_entropy'] = 0
            features['suspicious_tld'] = 0
            
        return features
    
    def extract_alert_features(self, alert: SuricataAlert) -> Dict[str, Any]:
        """
        Extract features from an alert event
        
        Args:
            alert: SuricataAlert object
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'uid': alert.uid,
            'signature': alert.signature,
            'signature_id': alert.signature_id,
            'category': alert.category,
            'severity': alert.severity,
        }
        
        # Map common categories to binary features
        categories = [
            'Web Application Attack', 'Attempted Information Leak',
            'Attempted Administrator Privilege Gain', 'Attempted User Privilege Gain',
            'Potentially Bad Traffic', 'Attempted Denial of Service',
            'Executable Code was Detected', 'A Network Trojan was Detected',
            'Suspicious Login', 'System Call Detected', 'Malware Command and Control',
            'Web Application Activity', 'ICMP Event', 'Misc activity', 'Protocol Command Decode'
        ]
        
        for cat in categories:
            features[f'category_{cat.replace(" ", "_").lower()}'] = 1 if alert.category == cat else 0
            
        # High severity flag
        features['is_high_severity'] = 1 if alert.severity >= 3 else 0
        
        return features
    
    def process_events(self, events: List[Any]) -> Dict[str, Dict[str, Any]]:
        """
        Process a list of events and extract features
        
        Args:
            events: List of Suricata event objects
            
        Returns:
            Dictionary of features by flow_id
        """
        # Process each event and extract features
        for event in events:
            if isinstance(event, SuricataFlow):
                features = self.extract_flow_features(event)
                self.flow_features[event.uid] = features
                
                # Update IP features
                src_ip = event.saddr
                dst_ip = event.daddr
                
                if src_ip not in self.ip_features:
                    self.ip_features[src_ip] = self._init_ip_features(src_ip)
                if dst_ip not in self.ip_features:
                    self.ip_features[dst_ip] = self._init_ip_features(dst_ip)
                    
                # Update IP feature stats
                self._update_ip_features(src_ip, event, features, is_src=True)
                self._update_ip_features(dst_ip, event, features, is_src=False)
                
            elif isinstance(event, SuricataHTTP):
                http_features = self.extract_http_features(event)
                
                # Add HTTP features to flow if it exists
                if event.uid in self.flow_features:
                    self.flow_features[event.uid].update({
                        f'http_{k}': v for k, v in http_features.items() if k != 'uid'
                    })
                    
            elif isinstance(event, SuricataDNS):
                dns_features = self.extract_dns_features(event)
                
                # Add DNS features to flow if it exists
                if event.uid in self.flow_features:
                    self.flow_features[event.uid].update({
                        f'dns_{k}': v for k, v in dns_features.items() if k != 'uid'
                    })
                    
            elif isinstance(event, SuricataTLS):
                tls_features = self.extract_tls_features(event)
                
                # Add TLS features to flow if it exists
                if event.uid in self.flow_features:
                    self.flow_features[event.uid].update({
                        f'tls_{k}': v for k, v in tls_features.items() if k != 'uid'
                    })
                    
            elif isinstance(event, SuricataAlert):
                alert_features = self.extract_alert_features(event)
                
                # Add alert features to flow if it exists
                if event.uid in self.flow_features:
                    self.flow_features[event.uid].update({
                        f'alert_{k}': v for k, v in alert_features.items() if k != 'uid'
                    })
                    # Mark flow as having an alert
                    self.flow_features[event.uid]['has_alert'] = 1
                    
        # Create aggregate features for each flow
        self._create_aggregate_features()
        
        return self.flow_features
    
    def process_file(self, file_path: str) -> pd.DataFrame:
        """
        Process a Suricata JSON file and extract features
        
        Args:
            file_path: Path to the Suricata JSON file
            
        Returns:
            DataFrame with extracted features
        """
        # Reset state
        self.flow_features = {}
        self.ip_features = {}
        
        # Parse file
        events = self.parser.parse_file(file_path)
        
        # Process events
        self.process_events(events)
        
        # Convert to DataFrame
        df = pd.DataFrame.from_dict(self.flow_features, orient='index')
        
        # Make sure all flows have the same columns
        # This handles cases where some flows don't have HTTP/DNS/TLS/alert data
        for flow_id, features in self.flow_features.items():
            for col in df.columns:
                if col not in features:
                    self.flow_features[flow_id][col] = 0
                    
        # Update DataFrame
        df = pd.DataFrame.from_dict(self.flow_features, orient='index')
        
        # Fill NaN values with 0
        df = df.fillna(0)
        
        return df
    
    def get_feature_vector(self, df: pd.DataFrame) -> np.ndarray:
        """
        Convert feature DataFrame to normalized feature vectors for ML models
        
        Args:
            df: DataFrame with extracted features
            
        Returns:
            Normalized numpy array of features
        """
        # Drop non-numeric columns
        numeric_df = df.select_dtypes(include=[np.number])
        
        # Drop identifier columns that shouldn't be used in ML
        cols_to_drop = ['uid', 'timestamp', 'src_port', 'dst_port']
        for col in cols_to_drop:
            if col in numeric_df.columns:
                numeric_df = numeric_df.drop(columns=[col])
                
        # Handle inf values
        numeric_df = numeric_df.replace([np.inf, -np.inf], np.nan)
        numeric_df = numeric_df.fillna(0)
        
        # Fit scaler if not trained yet
        if not self.trained:
            self.scaler.fit(numeric_df)
            self.trained = True
            
        # Return scaled values
        return self.scaler.transform(numeric_df)
    
    def _init_ip_features(self, ip: str) -> Dict[str, Any]:
        """
        Initialize features for an IP address
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with initial features
        """
        return {
            'ip': ip,
            'flow_count': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'total_packets_sent': 0,
            'total_packets_received': 0,
            'unique_dst_ips': set(),
            'unique_src_ips': set(),
            'unique_dst_ports': set(),
            'unique_src_ports': set(),
            'protocols': Counter(),
            'app_protocols': Counter(),
            'has_alerts': False,
            'alert_count': 0,
            'http_count': 0,
            'dns_count': 0,
            'tls_count': 0,
            'last_seen': None,
            'first_seen': None,
            'port_entropy': 0,
            'communication_patterns': defaultdict(int),  # (dst_ip, dst_port, proto) -> count
        }
    
    def _update_ip_features(self, ip: str, event: Any, features: Dict[str, Any], is_src: bool) -> None:
        """
        Update features for an IP address based on an event
        
        Args:
            ip: IP address
            event: Suricata event
            features: Extracted features for the event
            is_src: Whether this IP is the source in the event
        """
        ip_feat = self.ip_features[ip]
        ip_feat['flow_count'] += 1
        
        # Update timestamp info
        timestamp = convert_to_datetime(event.starttime)
        if ip_feat['first_seen'] is None or timestamp < ip_feat['first_seen']:
            ip_feat['first_seen'] = timestamp
        if ip_feat['last_seen'] is None or timestamp > ip_feat['last_seen']:
            ip_feat['last_seen'] = timestamp
            
        # Update counters based on whether this IP is source or destination
        if is_src:
            ip_feat['total_bytes_sent'] += event.sbytes
            ip_feat['total_bytes_received'] += event.dbytes
            ip_feat['total_packets_sent'] += event.spkts
            ip_feat['total_packets_received'] += event.dpkts
            ip_feat['unique_dst_ips'].add(event.daddr)
            ip_feat['unique_dst_ports'].add(event.dport)
            
            # Update communication pattern
            pattern = (event.daddr, event.dport, event.proto)
            ip_feat['communication_patterns'][pattern] += 1
        else:
            ip_feat['total_bytes_sent'] += event.dbytes
            ip_feat['total_bytes_received'] += event.sbytes
            ip_feat['total_packets_sent'] += event.dpkts
            ip_feat['total_packets_received'] += event.spkts
            ip_feat['unique_src_ips'].add(event.saddr)
            ip_feat['unique_src_ports'].add(event.sport)
            
        # Update protocol counters
        ip_feat['protocols'][event.proto] += 1
        if event.appproto and event.appproto != 'failed':
            ip_feat['app_protocols'][event.appproto] += 1
            
        # Handle different event types
        if isinstance(event, SuricataHTTP):
            ip_feat['http_count'] += 1
        elif isinstance(event, SuricataDNS):
            ip_feat['dns_count'] += 1
        elif isinstance(event, SuricataTLS):
            ip_feat['tls_count'] += 1
        elif isinstance(event, SuricataAlert):
            ip_feat['has_alerts'] = True
            ip_feat['alert_count'] += 1
    
    def _create_aggregate_features(self) -> None:
        """
        Create aggregate features for each flow based on IP behaviors
        """
        for flow_id, flow in self.flow_features.items():
            src_ip = flow['src_ip']
            dst_ip = flow['dst_ip']
            
            if src_ip in self.ip_features:
                src_features = self.ip_features[src_ip]
                
                # Add aggregated source IP features to flow
                self.flow_features[flow_id].update({
                    'src_flow_count': src_features['flow_count'],
                    'src_unique_dst_ips': len(src_features['unique_dst_ips']),
                    'src_unique_dst_ports': len(src_features['unique_dst_ports']),
                    'src_protocols_count': len(src_features['protocols']),
                    'src_app_protocols_count': len(src_features['app_protocols']),
                    'src_has_alerts': 1 if src_features['has_alerts'] else 0,
                    'src_alert_count': src_features['alert_count'],
                    'src_http_count': src_features['http_count'],
                    'src_dns_count': src_features['dns_count'],
                    'src_tls_count': src_features['tls_count'],
                })
                
                # Calculate port entropy for source IP
                if src_features['unique_dst_ports']:
                    port_counts = Counter()
                    for pattern, count in src_features['communication_patterns'].items():
                        _, port, _ = pattern
                        port_counts[port] += count
                        
                    total = sum(port_counts.values())
                    port_entropy = 0
                    if total > 0:
                        for port, count in port_counts.items():
                            prob = count / total
                            port_entropy -= prob * np.log2(prob)
                            
                    self.flow_features[flow_id]['src_port_entropy'] = port_entropy
                else:
                    self.flow_features[flow_id]['src_port_entropy'] = 0
                    
            if dst_ip in self.ip_features:
                dst_features = self.ip_features[dst_ip]
                
                # Add aggregated destination IP features to flow
                self.flow_features[flow_id].update({
                    'dst_flow_count': dst_features['flow_count'],
                    'dst_unique_src_ips': len(dst_features['unique_src_ips']),
                    'dst_unique_src_ports': len(dst_features['unique_src_ports']),
                    'dst_protocols_count': len(dst_features['protocols']),
                    'dst_app_protocols_count': len(dst_features['app_protocols']),
                    'dst_has_alerts': 1 if dst_features['has_alerts'] else 0,
                    'dst_alert_count': dst_features['alert_count'],
                    'dst_http_count': dst_features['http_count'],
                    'dst_dns_count': dst_features['dns_count'],
                    'dst_tls_count': dst_features['tls_count'],
                })
    
    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            string: Input string
            
        Returns:
            Shannon entropy value
        """
        if not string:
            return 0
            
        # Count character frequencies
        char_count = Counter(string)
        
        # Calculate entropy
        length = len(string)
        entropy = 0
        for count in char_count.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
            
        return entropy


# Example usage
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # Process a file
    df = extractor.process_file("example.json")
    print(f"Extracted {len(df)} flow features")
    
    # Get feature vectors for ML
    feature_vectors = extractor.get_feature_vector(df)
    print(f"Feature vector shape: {feature_vectors.shape}")
