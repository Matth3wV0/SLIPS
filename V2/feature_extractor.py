import ipaddress
from datetime import datetime
import math

class FeatureExtractor:
    """
    Extracts machine learning features from parsed Suricata events
    """
    
    def __init__(self):
        """Initialize feature extractor"""
        # Track unique IPs, ports, and other metrics across events
        self.ip_frequency = {}
        self.port_frequency = {}
        self.known_malicious_ips = set()  # Can be populated from threat intel
        
    def extract_features(self, event):
        """
        Extract features from a parsed Suricata event
        
        Args:
            event (dict): Parsed Suricata event
            
        Returns:
            dict: Feature dictionary
        """
        features = {}
        
        # Basic features common to all events
        features.update(self._extract_basic_features(event))
        
        # Event type specific features
        event_type = event.get('event_type')
        if event_type == 'alert':
            features.update(self._extract_alert_features(event))
        elif event_type == 'dns':
            features.update(self._extract_dns_features(event))
        elif event_type == 'flow':
            features.update(self._extract_flow_features(event))
        
        # Track IP and port frequencies
        self._update_frequency_trackers(event)
        
        return features
    
    def _extract_basic_features(self, event):
        """Extract basic features common to all events"""
        features = {}
        
        # IP-related features
        src_ip = event.get('src_ip')
        dest_ip = event.get('dest_ip')
        
        if src_ip:
            features['src_ip_is_private'] = self._is_private_ip(src_ip)
            features['src_ip_known_malicious'] = src_ip in self.known_malicious_ips
        
        if dest_ip:
            features['dest_ip_is_private'] = self._is_private_ip(dest_ip)
            features['dest_ip_known_malicious'] = dest_ip in self.known_malicious_ips
            
        # Check for scanning patterns
        if src_ip in self.ip_frequency:
            features['src_ip_connection_count'] = self.ip_frequency[src_ip]
        else:
            features['src_ip_connection_count'] = 1
            
        if dest_ip in self.ip_frequency:
            features['dest_ip_connection_count'] = self.ip_frequency[dest_ip]
        else:
            features['dest_ip_connection_count'] = 1
        
        # Port-related features
        src_port = event.get('src_port')
        dest_port = event.get('dest_port')
        
        if src_port:
            features['src_port'] = src_port
            features['src_port_is_well_known'] = src_port < 1024
            features['src_port_is_registered'] = 1024 <= src_port <= 49151
            features['src_port_is_ephemeral'] = src_port > 49151
        
        if dest_port:
            features['dest_port'] = dest_port
            features['dest_port_is_well_known'] = dest_port < 1024
            features['dest_port_is_registered'] = 1024 <= dest_port <= 49151
            features['dest_port_is_ephemeral'] = dest_port > 49151
            
            # Check for common service ports
            features['dest_port_is_http'] = dest_port in [80, 8080]
            features['dest_port_is_https'] = dest_port in [443, 8443]
            features['dest_port_is_ssh'] = dest_port == 22
            features['dest_port_is_dns'] = dest_port == 53
            features['dest_port_is_smtp'] = dest_port in [25, 587]
            features['dest_port_is_sql'] = dest_port in [1433, 3306, 5432]
        
        # Protocol features
        proto = event.get('proto')
        if proto:
            features['proto_is_tcp'] = proto.lower() == 'tcp'
            features['proto_is_udp'] = proto.lower() == 'udp'
            features['proto_is_icmp'] = proto.lower() == 'icmp'
        
        # Time-related features
        timestamp = event.get('timestamp')
        if timestamp:
            dt = self._parse_timestamp(timestamp)
            if dt:
                features['hour_of_day'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['is_weekend'] = dt.weekday() >= 5  # 5=Saturday, 6=Sunday
                features['is_business_hours'] = 8 <= dt.hour <= 18 and dt.weekday() < 5
        
        return features
    
    def _extract_alert_features(self, event):
        """Extract features specific to alert events"""
        features = {}
        
        # Alert severity and category
        severity = event.get('alert', {}).get('severity')
        if severity is not None:
            features['alert_severity'] = severity
        
        category = event.get('alert', {}).get('category')
        if category:
            features['alert_category_scan'] = 'scan' in category.lower()
            features['alert_category_attack'] = 'attack' in category.lower()
            features['alert_category_malware'] = 'malware' in category.lower()
            features['alert_category_bad_traffic'] = 'bad traffic' in category.lower()
            
        # Signature ID info
        signature_id = event.get('alert', {}).get('signature_id')
        if signature_id:
            features['alert_has_signature_id'] = 1
            features['alert_signature_id'] = signature_id
            
        # Extract Suricata metadata features if available
        metadata = event.get('alert', {}).get('metadata', {})
        if metadata:
            if 'attack_target' in metadata:
                features['metadata_has_attack_target'] = 1
            
            # Extract tags info
            if 'tag' in metadata:
                tags = metadata['tag']
                features['metadata_has_cins_tag'] = 'CINS' in tags
                features['metadata_has_compromised_tag'] = 'COMPROMISED' in tags
                features['metadata_has_dshield_tag'] = 'Dshield' in tags
            
            # Extract severity info
            if 'signature_severity' in metadata:
                features['metadata_severity_is_major'] = 'Major' in metadata['signature_severity']
                
        # Flow statistics
        flow = event.get('flow', {})
        features['flow_pkts_toserver'] = flow.get('pkts_toserver', 0)
        features['flow_pkts_toclient'] = flow.get('pkts_toclient', 0)
        features['flow_bytes_toserver'] = flow.get('bytes_toserver', 0)
        features['flow_bytes_toclient'] = flow.get('bytes_toclient', 0)
        
        # Calculate packet and byte ratios
        total_pkts = features['flow_pkts_toserver'] + features['flow_pkts_toclient']
        if total_pkts > 0:
            features['flow_pkts_ratio'] = features['flow_pkts_toserver'] / total_pkts
        else:
            features['flow_pkts_ratio'] = 0
            
        total_bytes = features['flow_bytes_toserver'] + features['flow_bytes_toclient']
        if total_bytes > 0:
            features['flow_bytes_ratio'] = features['flow_bytes_toserver'] / total_bytes
        else:
            features['flow_bytes_ratio'] = 0
            
        # Check flow direction imbalance (potential C&C or data exfiltration)
        features['flow_direction_imbalance'] = abs(features['flow_pkts_ratio'] - 0.5)
        
        return features
    
    def _extract_dns_features(self, event):
        """Extract features specific to DNS events"""
        features = {}
        
        # DNS query type
        dns_type = event.get('dns', {}).get('type')
        if dns_type:
            features['dns_type_is_query'] = dns_type.lower() == 'query'
            features['dns_type_is_answer'] = dns_type.lower() == 'answer'
        
        # DNS record type
        dns_rrtype = event.get('dns', {}).get('rrtype')
        if dns_rrtype:
            features['dns_rrtype_is_a'] = dns_rrtype.upper() == 'A'
            features['dns_rrtype_is_aaaa'] = dns_rrtype.upper() == 'AAAA'
            features['dns_rrtype_is_txt'] = dns_rrtype.upper() == 'TXT'
            features['dns_rrtype_is_mx'] = dns_rrtype.upper() == 'MX'
            features['dns_rrtype_is_ns'] = dns_rrtype.upper() == 'NS'
        
        # DNS domain related features (useful for DGA detection)
        dns_rrname = event.get('dns', {}).get('rrname')
        if dns_rrname:
            features['dns_domain_length'] = len(dns_rrname)
            features['dns_domain_dot_count'] = dns_rrname.count('.')
            features['dns_domain_digit_count'] = sum(c.isdigit() for c in dns_rrname)
            features['dns_domain_digit_ratio'] = features['dns_domain_digit_count'] / len(dns_rrname) if len(dns_rrname) > 0 else 0
            features['dns_domain_is_ip'] = self._is_ip_as_domain(dns_rrname)
            
            # Calculate domain entropy (randomness measure, high for DGAs)
            features['dns_domain_entropy'] = self._calculate_entropy(dns_rrname)
            
            # Check for suspicious TLDs
            tld = dns_rrname.split('.')[-1].lower() if '.' in dns_rrname else ''
            features['dns_domain_has_suspicious_tld'] = tld in ['top', 'xyz', 'info', 'cc', 'tk']
            
            # Check for suspicious domain characteristics
            domain_part = dns_rrname.split('.')[0] if '.' in dns_rrname else dns_rrname
            features['dns_domain_consonant_ratio'] = self._consonant_ratio(domain_part)
        
        # DNS response features
        dns_answers = event.get('dns', {}).get('answers', [])
        if dns_answers:
            features['dns_answer_count'] = len(dns_answers)
            
            # Count different record types in answers
            a_count = 0
            cname_count = 0
            for answer in dns_answers:
                answer_type = answer.get('rrtype', '').upper()
                if answer_type == 'A':
                    a_count += 1
                elif answer_type == 'CNAME':
                    cname_count += 1
            
            features['dns_answer_a_count'] = a_count
            features['dns_answer_cname_count'] = cname_count
            
            # Check for multiple IP answers (potential fast-flux)
            features['dns_has_multiple_ips'] = a_count > 1
            
            # Check for CNAME chains (potential evasion)
            features['dns_has_cname_chain'] = cname_count > 1
        
        return features
    
    def _extract_flow_features(self, event):
        """Extract features specific to flow events"""
        features = {}
        
        # Flow statistics
        features['flow_pkts_toserver'] = event.get('flow', {}).get('pkts_toserver', 0)
        features['flow_pkts_toclient'] = event.get('flow', {}).get('pkts_toclient', 0)
        features['flow_bytes_toserver'] = event.get('flow', {}).get('bytes_toserver', 0)
        features['flow_bytes_toclient'] = event.get('flow', {}).get('bytes_toclient', 0)
        
        # Calculate ratios
        total_pkts = features['flow_pkts_toserver'] + features['flow_pkts_toclient']
        if total_pkts > 0:
            features['flow_pkts_ratio'] = features['flow_pkts_toserver'] / total_pkts
        else:
            features['flow_pkts_ratio'] = 0
            
        total_bytes = features['flow_bytes_toserver'] + features['flow_bytes_toclient']
        if total_bytes > 0:
            features['flow_bytes_ratio'] = features['flow_bytes_toserver'] / total_bytes
        else:
            features['flow_bytes_ratio'] = 0
        
        # Flow duration
        flow_start = event.get('flow', {}).get('start')
        flow_end = event.get('flow', {}).get('end')
        
        if flow_start and flow_end:
            start_dt = self._parse_timestamp(flow_start)
            end_dt = self._parse_timestamp(flow_end)
            
            if start_dt and end_dt:
                duration = (end_dt - start_dt).total_seconds()
                features['flow_duration'] = duration
                
                # Calculate bytes and packets per second
                if duration > 0:
                    features['flow_bytes_per_second'] = total_bytes / duration
                    features['flow_pkts_per_second'] = total_pkts / duration
                else:
                    features['flow_bytes_per_second'] = 0
                    features['flow_pkts_per_second'] = 0
        
        # Flow state (useful for scanning detection)
        flow_state = event.get('flow', {}).get('state')
        if flow_state:
            features['flow_state_is_established'] = flow_state.lower() == 'established'
            features['flow_state_is_new'] = flow_state.lower() == 'new'
            features['flow_state_is_closed'] = flow_state.lower() == 'closed'
        
        # App protocol
        app_proto = event.get('app_proto')
        if app_proto:
            features['app_proto_is_http'] = app_proto.lower() == 'http'
            features['app_proto_is_dns'] = app_proto.lower() == 'dns'
            features['app_proto_is_ssl'] = app_proto.lower() == 'ssl' or app_proto.lower() == 'tls'
            features['app_proto_is_ssh'] = app_proto.lower() == 'ssh'
            features['app_proto_is_smtp'] = app_proto.lower() == 'smtp'
            features['app_proto_is_ftp'] = app_proto.lower() == 'ftp'
        
        return features
    
    def _update_frequency_trackers(self, event):
        """Update IP and port frequency counters"""
        src_ip = event.get('src_ip')
        dest_ip = event.get('dest_ip')
        
        if src_ip:
            self.ip_frequency[src_ip] = self.ip_frequency.get(src_ip, 0) + 1
        
        if dest_ip:
            self.ip_frequency[dest_ip] = self.ip_frequency.get(dest_ip, 0) + 1
            
        src_port = event.get('src_port')
        dest_port = event.get('dest_port')
        
        if src_port:
            self.port_frequency[src_port] = self.port_frequency.get(src_port, 0) + 1
            
        if dest_port:
            self.port_frequency[dest_port] = self.port_frequency.get(dest_port, 0) + 1
    
    def _is_private_ip(self, ip_str):
        """Check if an IP address is private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False
    
    def _is_ip_as_domain(self, domain):
        """Check if a domain looks like an IP address (potential DNS tunneling)"""
        parts = domain.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of a string (useful for DGA detection)"""
        if not text:
            return 0
        
        entropy = 0
        text_len = len(text)
        char_counts = {}
        
        for char in text:
            if char in char_counts:
                char_counts[char] += 1
            else:
                char_counts[char] = 1
        
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
        
    def _consonant_ratio(self, text):
        """Calculate ratio of consonants to string length"""
        if not text:
            return 0
            
        vowels = set('aeiou')
        consonants = sum(1 for c in text.lower() if c.isalpha() and c not in vowels)
        return consonants / len(text) if len(text) > 0 else 0
    
    def _parse_timestamp(self, timestamp_str):
        """Parse a timestamp string into a datetime object"""
        try:
            # Handle Suricata timestamp format: "2021-06-06T15:59:46.457984+0200"
            return datetime.fromisoformat(timestamp_str)
        except:
            try:
                # Try another common format
                return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
            except:
                return None
