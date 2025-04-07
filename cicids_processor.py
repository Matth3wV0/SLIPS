#!/usr/bin/env python3
"""
CICIDS2017 CSV Processor for Suricata Analyzer
Processes CICIDS2017 CSV files and converts them to a format compatible with Suricata Analyzer.
"""
import os
import logging
import pandas as pd
import numpy as np
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
import re
import ipaddress
import math

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cicids_processor')

# Map CICIDS2017 protocols to Suricata protocols
PROTOCOL_MAP = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
    "igmp": "IGMP",
    "tcp-syn": "TCP",  # Specific TCP SYN flood
    "tcp-ack": "TCP",  # Specific TCP ACK flood
    "http": "HTTP",
    "https": "TLS",
    "ssh": "SSH",
    "ftp": "FTP",
    "smtp": "SMTP"
}

# Map CICIDS2017 attack labels to categories
ATTACK_CATEGORY_MAP = {
    "BENIGN": "normal",
    "Bot": "botnet",
    "FTP-Patator": "brute-force",
    "SSH-Patator": "brute-force",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "Heartbleed": "vulnerability",
    "Web Attack – Brute Force": "web-attack",
    "Web Attack – XSS": "web-attack", 
    "Web Attack – SQL Injection": "web-attack",
    "Infiltration": "infiltration",
    "PortScan": "scanning",
    # Add these additional labels that might appear in the dataset
    "DDoS": "dos",
    "Brute Force": "brute-force",
    "XSS": "web-attack",
    "SQL Injection": "web-attack",
    "Infiltration": "infiltration",
    "Port Scan": "scanning"
}

class CICIDSProcessor:
    """Processor for CICIDS2017 CSV files"""
    
    def __init__(self):
        """Initialize the CICIDS processor"""
        self.features = []
        self.label_to_alert_map = self._create_label_to_alert_map()
        
    def _create_label_to_alert_map(self) -> Dict[str, Dict[str, Any]]:
        """
        Create a mapping from CICIDS labels to Suricata alert format
        
        Returns:
            Dictionary mapping CICIDS labels to Suricata alert attributes
        """
        label_map = {}
        
        # Create alert templates for each attack category
        label_map["BENIGN"] = None  # No alert for benign traffic
        
        label_map["Bot"] = {
            "signature": "Potential Botnet Traffic Detected",
            "signature_id": 1000001,
            "category": "Malware Command and Control",
            "severity": 3
        }
        
        label_map["FTP-Patator"] = {
            "signature": "FTP Brute Force Attack",
            "signature_id": 1000002,
            "category": "Attempted Administrator Privilege Gain",
            "severity": 2
        }
        
        label_map["SSH-Patator"] = {
            "signature": "SSH Brute Force Attack",
            "signature_id": 1000003,
            "category": "Attempted Administrator Privilege Gain",
            "severity": 2
        }
        
        for dos_type in ["DoS slowloris", "DoS Slowhttptest", "DoS Hulk", "DoS GoldenEye", "DDoS"]:
            label_map[dos_type] = {
                "signature": f"DoS Attack Detected - {dos_type}",
                "signature_id": 1000004,
                "category": "Attempted Denial of Service",
                "severity": 3
            }
            
        label_map["Heartbleed"] = {
            "signature": "Heartbleed Vulnerability Exploit Attempt",
            "signature_id": 1000005,
            "category": "Attempted Information Leak",
            "severity": 3
        }
        
        for web_attack in ["Web Attack – Brute Force", "Brute Force"]:
            label_map[web_attack] = {
                "signature": "Web Brute Force Attack",
                "signature_id": 1000006,
                "category": "Web Application Attack",
                "severity": 2
            }
        
        for xss_attack in ["Web Attack – XSS", "XSS"]:
            label_map[xss_attack] = {
                "signature": "Cross-Site Scripting Attack",
                "signature_id": 1000007,
                "category": "Web Application Attack",
                "severity": 2
            }
        
        for sql_attack in ["Web Attack – SQL Injection", "SQL Injection"]:
            label_map[sql_attack] = {
                "signature": "SQL Injection Attack",
                "signature_id": 1000008,
                "category": "Web Application Attack",
                "severity": 3
            }
        
        label_map["Infiltration"] = {
            "signature": "Potential System Infiltration",
            "signature_id": 1000009,
            "category": "A Network Trojan was Detected",
            "severity": 3
        }
        
        for scan_attack in ["PortScan", "Port Scan"]:
            label_map[scan_attack] = {
                "signature": "Port Scanning Activity",
                "signature_id": 1000010,
                "category": "Potentially Bad Traffic",
                "severity": 1
            }
        
        return label_map
            
    def process_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Process a CICIDS2017 CSV file and convert to Suricata-compatible format
        
        Args:
            file_path: Path to the CICIDS2017 CSV file
            
        Returns:
            Tuple of (events list, stats dictionary)
        """
        logger.info(f"Processing CICIDS2017 file: {file_path}")
        
        # Check file existence
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return [], {"error": "File not found"}
            
        # Get file size
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
        logger.info(f"File size: {file_size:.2f} MB")
        
        # For very large files, we might want to use chunking
        use_chunking = file_size > 100  # If file is larger than 100 MB
        
        try:
            # Load CSV file
            all_attack_types = {}
            
            if use_chunking:
                logger.info("Using chunked processing for large file")
                events, all_attack_types = self._process_large_file(file_path)
            else:
                df = pd.read_csv(file_path, low_memory=False)
                events, all_attack_types = self._process_dataframe(df)
                
            # Collect stats
            benign_flows = sum(1 for e in events if not e.get("has_alert", False))
            attack_flows = sum(1 for e in events if e.get("has_alert", False))
            
            stats = {
                "total_flows": len(events),
                "benign_flows": benign_flows,
                "attack_flows": attack_flows,
                "file_size_mb": file_size,
                "attack_types": all_attack_types
            }
            
            logger.info(f"Processed {stats['total_flows']} flows "
                    f"({stats['benign_flows']} benign, {stats['attack_flows']} attack)")
            
            if all_attack_types:
                logger.info("Attack types detected:")
                for attack_type, count in all_attack_types.items():
                    logger.info(f"  - {attack_type}: {count}")
            
            return events, stats
            
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return [], {"error": str(e)}
            
    def _process_large_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Process a large CSV file in chunks
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Tuple of (list of processed events, dictionary of attack types)
        """
        all_events = []
        all_attack_types = {}
        chunk_size = 100000  # Process 100k rows at a time
        
        # Process file in chunks
        try:
            for chunk_idx, chunk in enumerate(pd.read_csv(file_path, chunksize=chunk_size, low_memory=False)):
                chunk_events, chunk_attack_types = self._process_dataframe(chunk)
                
                # Merge attack types
                for attack_type, count in chunk_attack_types.items():
                    if attack_type not in all_attack_types:
                        all_attack_types[attack_type] = 0
                    all_attack_types[attack_type] += count
                    
                all_events.extend(chunk_events)
                logger.info(f"Processed chunk {chunk_idx+1} with {len(chunk_events)} events")
        except Exception as e:
            logger.error(f"Error processing chunk: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
        return all_events, all_attack_types
    
    def _process_dataframe(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Process a DataFrame of CICIDS2017 data
        
        Args:
            df: DataFrame with CICIDS2017 data
            
        Returns:
            List of Suricata-compatible events
        """
        events = []
        attack_types = {}  # Track attack types for statistics
        
        # Debug: print the actual columns in the dataset
        logger.debug(f"Columns in dataset: {df.columns.tolist()}")
        
        # Clean up column names (remove whitespace)
        df.columns = [col.strip() for col in df.columns]
        
        # Handle different column naming conventions in CICIDS2017
        # Some files use 'Label' while others might use 'label' or ' Label'
        label_column = None
        for col in df.columns:
            if col.lower().strip() == 'label':
                label_column = col
                break
                
        if not label_column:
            # Try alternative names for the label column
            alt_label_names = ['Class', 'class', 'target', 'Target', 'attack_type', 'Attack_type']
            for alt_name in alt_label_names:
                if alt_name in df.columns:
                    label_column = alt_name
                    break
                    
        if not label_column:
            logger.warning("Label column not found, assuming all traffic is benign")
            df['Label'] = 'BENIGN'
            label_column = 'Label'
            
        # Generate synthetic network data since original network fields aren't available
        # This approach creates fictitious but consistent network data based on row indices
        # This allows the system to work even without the actual network information
        
        # Create synthetic IP addresses based on row indices
        row_indices = df.index.tolist()
        max_index = max(row_indices) if row_indices else 0
        
        # Use synthetic data directly
        src_ips = [f"10.0.0.{(i % 254) + 1}" for i in row_indices]
        dst_ips = [f"192.168.1.{(i % 254) + 1}" for i in row_indices]
        src_ports = [(i % 60000) + 1024 for i in row_indices]  # Dynamic ports
        dst_ports = [(i % 10) * 100 + 80 for i in row_indices]  # Common server ports
        protocols = ["TCP"] * len(row_indices)  # Default to TCP
        
        # Add synthetic columns to the dataframe
        df['src_ip'] = src_ips
        df['dst_ip'] = dst_ips
        df['src_port'] = src_ports
        df['dst_port'] = dst_ports
        df['protocol'] = protocols
        
        # Create synthetic flow durations and packet/byte counts if needed
        if 'flow_duration' not in df.columns:
            df['flow_duration'] = np.random.uniform(0.1, 10.0, size=len(df))
        
        for field in ['fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes']:
            if field not in df.columns:
                df[field] = np.random.randint(1, 1000, size=len(df))
        
        # Generate a timestamp if not present in the data
        if 'timestamp' not in df.columns:
            # Create a timestamp based on the current time
            current_time = datetime.now().isoformat()
            df['timestamp'] = current_time
        
        # Process each row
        for idx, row in df.iterrows():
            try:
                # Generate flow ID
                flow_id = self._generate_flow_id(row)
                
                # Normalize the label (remove spaces, convert to title case)
                raw_label = str(row[label_column]).strip()
                
                # Print some samples of the labels to debug
                if idx < 5 or (idx < 100 and idx % 20 == 0):
                    logger.debug(f"Sample label at row {idx}: '{raw_label}'")
                
                # Check for attack or benign
                # IMPORTANT: We're being much more aggressive about identifying attacks here
                is_attack = True  # Default to assuming it's an attack
                
                # Only set to benign if explicitly labeled as such
                if raw_label.upper() == 'BENIGN' or raw_label.lower() == 'normal' or raw_label == '0':
                    is_attack = False
                    label = 'BENIGN'
                else:
                    # It's an attack - try to normalize the label
                    if raw_label in ATTACK_CATEGORY_MAP:
                        label = raw_label
                    else:
                        # Try to match based on substring
                        matched = False
                        for known_label in ATTACK_CATEGORY_MAP.keys():
                            if (known_label.lower() in raw_label.lower() or 
                                raw_label.lower() in known_label.lower()):
                                label = known_label
                                matched = True
                                break
                        if not matched:
                            label = "Unknown Attack"
                    
                    # Count attack types for statistics
                    if label not in attack_types:
                        attack_types[label] = 0
                    attack_types[label] += 1
                
                # Map protocol
                protocol = self._map_protocol(row.get('protocol', 'TCP'))
                
                # Create Suricata-compatible event
                event = self._create_flow_event(row, flow_id, protocol)
                
                # Add alert if this is an attack
                if is_attack:
                    alert = self._create_alert_event(row, flow_id, label)
                    event["has_alert"] = True
                    events.append(alert)
                else:
                    event["has_alert"] = False
                
                events.append(event)
                
            except Exception as e:
                logger.error(f"Error processing row {idx}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                continue
        
        # Add attack types to stats
        if attack_types:
            logger.info(f"Attack types detected: {attack_types}")
            
        return events, attack_types

    
    def _safe_int(self, value, default=0):
        """Safely convert a value to int, handling NaN and None"""
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def _safe_float(self, value, default=0.0):
        """Safely convert a value to float, handling NaN and None"""
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
            
    def _safe_str(self, value, default=""):
        """Safely convert a value to string, handling NaN and None"""
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return default
        return str(value)
    
    def _generate_flow_id(self, row: pd.Series) -> str:
        """
        Generate a flow ID similar to Suricata flow IDs
        
        Args:
            row: DataFrame row
            
        Returns:
            Flow ID string
        """
        # Use source/destination IPs and ports to create a unique ID
        src_ip = self._safe_str(row.get('src_ip', '0.0.0.0'))
        dst_ip = self._safe_str(row.get('dst_ip', '0.0.0.0'))
        src_port = self._safe_int(row.get('src_port', 0))
        dst_port = self._safe_int(row.get('dst_port', 0))
        
        # Create a consistent flow ID format
        flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        
        # Hash the flow ID to make it more similar to Suricata format
        hashed_id = hashlib.md5(flow_id.encode()).hexdigest()[:8]
        
        return hashed_id
    
    def _map_protocol(self, protocol_value: Union[str, int]) -> str:
        """
        Map CICIDS2017 protocol values to Suricata protocol names
        
        Args:
            protocol_value: Protocol value from CICIDS2017
            
        Returns:
            Suricata protocol name
        """
        if protocol_value is None or (isinstance(protocol_value, float) and math.isnan(protocol_value)):
            return "TCP"  # Default to TCP for missing values
            
        if isinstance(protocol_value, int) or (isinstance(protocol_value, float) and not math.isnan(protocol_value)):
            # CICIDS2017 sometimes uses numeric protocol values
            protocol_int = int(protocol_value)
            if protocol_int == 6:
                return "TCP"
            elif protocol_int == 17:
                return "UDP"
            elif protocol_int == 1:
                return "ICMP"
            else:
                return f"PROTO:{protocol_int}"
        elif isinstance(protocol_value, str):
            # Convert to lowercase for consistent mapping
            proto_lower = protocol_value.lower()
            
            # Map to Suricata protocol name
            if proto_lower in PROTOCOL_MAP:
                return PROTOCOL_MAP[proto_lower]
            else:
                return protocol_value.upper()
        else:
            return "TCP"  # Default to TCP
    
    def _create_flow_event(self, row: pd.Series, flow_id: str, protocol: str) -> Dict[str, Any]:
        """
        Create a Suricata-compatible flow event
        
        Args:
            row: DataFrame row
            flow_id: Generated flow ID
            protocol: Mapped protocol name
            
        Returns:
            Suricata-compatible flow event
        """
        # Generate timestamp
        timestamp = row.get('timestamp', None)
        if timestamp is None or (isinstance(timestamp, float) and math.isnan(timestamp)):
            # Use current time if timestamp is not available
            timestamp = datetime.now().isoformat()
            
        # Create flow event
        flow_event = {
            "event_type": "flow",
            "flow_id": flow_id,
            "src_ip": self._safe_str(row.get('src_ip', '0.0.0.0')),
            "src_port": self._safe_int(row.get('src_port', 0)),
            "dst_ip": self._safe_str(row.get('dst_ip', '0.0.0.0')),
            "dst_port": self._safe_int(row.get('dst_port', 0)),
            "proto": protocol,
            "app_proto": self._guess_app_protocol(row),
            "flow": {
                "start": self._safe_str(timestamp),
                "end": self._safe_str(timestamp),  # We'll calculate this below
                "bytes_toserver": self._safe_int(row.get('fwd_bytes', 0)),
                "bytes_toclient": self._safe_int(row.get('bwd_bytes', 0)),
                "pkts_toserver": self._safe_int(row.get('fwd_pkts', 0)),
                "pkts_toclient": self._safe_int(row.get('bwd_pkts', 0)),
                "state": "established"
            },
            "uid": flow_id,
            "timestamp": self._safe_str(timestamp)
        }
        
        # Calculate end time based on duration
        duration = self._safe_float(row.get('flow_duration', 0))
        if duration > 0:
            # If duration is in microseconds (common in CICIDS2017)
            if duration > 1000000:
                duration /= 1000000  # Convert to seconds
                
            # Parse timestamp and add duration
            try:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp)
                    end_time = dt.timestamp() + duration
                    flow_event["flow"]["end"] = datetime.fromtimestamp(end_time).isoformat()
            except (ValueError, TypeError):
                # If timestamp isn't in ISO format, just use same value
                flow_event["flow"]["end"] = self._safe_str(timestamp)
                
        return flow_event
    
    def _guess_app_protocol(self, row: pd.Series) -> str:
        """
        Guess application protocol based on ports and other indicators
        
        Args:
            row: DataFrame row
            
        Returns:
            Guessed application protocol
        """
        dst_port = self._safe_int(row.get('dst_port', 0))
        
        # Map common ports to protocols
        if dst_port == 80:
            return "http"
        elif dst_port == 443:
            return "tls"
        elif dst_port == 22:
            return "ssh"
        elif dst_port == 21:
            return "ftp"
        elif dst_port == 25 or dst_port == 587:
            return "smtp"
        elif dst_port == 53:
            return "dns"
        else:
            return "failed"  # Suricata uses "failed" when app protocol isn't determined
    
    def _create_alert_event(self, row: pd.Series, flow_id: str, attack_label: str) -> Dict[str, Any]:
        """
        Create a Suricata-compatible alert event
        
        Args:
            row: DataFrame row
            flow_id: Generated flow ID
            attack_label: Attack label
            
        Returns:
            Suricata-compatible alert event
        """
        # Get alert template for this label
        alert_template = self.label_to_alert_map.get(attack_label)
        if not alert_template:
            # Default alert if no specific template exists
            alert_template = {
                "signature": f"Potential Attack: {attack_label}",
                "signature_id": 1000000,
                "category": "Potentially Bad Traffic",
                "severity": 2
            }
            
        # Create alert event
        alert_event = {
            "event_type": "alert",
            "flow_id": flow_id,
            "src_ip": self._safe_str(row.get('src_ip', '0.0.0.0')),
            "src_port": self._safe_int(row.get('src_port', 0)),
            "dst_ip": self._safe_str(row.get('dst_ip', '0.0.0.0')),
            "dst_port": self._safe_int(row.get('dst_port', 0)),
            "proto": self._map_protocol(row.get('protocol', 'TCP')),
            "alert": alert_template,
            "uid": flow_id,
            "timestamp": self._safe_str(row.get('timestamp', datetime.now().isoformat()))
        }
        
        return alert_event


# Helper function to convert CICIDS CSV file to Suricata format
def convert_cicids_to_suricata_json(input_file: str, output_file: str) -> Dict[str, Any]:
    """
    Convert a CICIDS2017 CSV file to Suricata JSON format
    
    Args:
        input_file: Path to CICIDS2017 CSV file
        output_file: Path to output Suricata JSON file
        
    Returns:
        Dictionary with conversion statistics
    """
    processor = CICIDSProcessor()
    
    # Process the file
    events, stats = processor.process_file(input_file)
    
    # Write events to output file
    with open(output_file, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
            
    logger.info(f"Converted {stats['total_flows']} flows to Suricata format in {output_file}")
    
    return stats


# Example usage
if __name__ == "__main__":
    import json
    import argparse
    
    parser = argparse.ArgumentParser(description='Convert CICIDS2017 CSV to Suricata JSON')
    parser.add_argument('input', help='Input CICIDS2017 CSV file')
    parser.add_argument('output', help='Output Suricata JSON file')
    
    args = parser.parse_args()
    
    stats = convert_cicids_to_suricata_json(args.input, args.output)
    print(json.dumps(stats, indent=2))
