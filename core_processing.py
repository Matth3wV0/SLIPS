#!/usr/bin/env python3
"""
Core processing module for Suricata JSON analysis
"""
import json
import os
import datetime
from typing import Dict, List, Union, Optional, Tuple, Any
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('suricata_analyzer')

@dataclass
class SuricataFlow:
    """Data class for Suricata flow events"""
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: Union[str, bool]
    starttime: str
    endtime: str
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    state: str
    dur: float = 0
    pkts: int = 0
    bytes: int = 0
    smac: str = ""
    dmac: str = ""
    dir_: str = "->"
    type_: str = "conn"
    flow_source: str = "suricata"

    def __post_init__(self):
        """Calculate derived fields after initialization"""
        if not self.dur:
            self.dur = (
                convert_to_datetime(self.endtime) - 
                convert_to_datetime(self.starttime)
            ).total_seconds() or 0
        self.pkts = self.dpkts + self.spkts
        self.bytes = self.dbytes + self.sbytes
        self.uid = str(self.uid)


@dataclass
class SuricataHTTP:
    """Data class for Suricata HTTP events"""
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    method: str
    host: str
    uri: str
    user_agent: str
    status_code: str
    version: str
    request_body_len: int
    response_body_len: int
    status_msg: str = ""
    resp_mime_types: str = ""
    resp_fuids: str = ""
    type_: str = "http"
    flow_source: str = "suricata"

    def __post_init__(self):
        self.uid = str(self.uid)


@dataclass
class SuricataDNS:
    """Data class for Suricata DNS events"""
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    query: str
    TTLs: str
    qtype_name: str
    answers: List[Dict[str, str]]
    qclass_name: str = ""
    rcode_name: str = ""
    type_: str = "dns"
    flow_source: str = "suricata"

    def __post_init__(self):
        self.uid = str(self.uid)


@dataclass
class SuricataTLS:
    """Data class for Suricata TLS events"""
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: str
    sslversion: str
    subject: str
    issuer: str
    server_name: str
    notbefore: str
    notafter: str
    type_: str = "ssl"
    flow_source: str = "suricata"

    def __post_init__(self):
        self.uid = str(self.uid)


@dataclass
class SuricataAlert:
    """Data class for Suricata Alert events"""
    starttime: str
    uid: str
    saddr: str
    sport: str
    daddr: str
    dport: str
    proto: str
    appproto: Union[str, bool]
    signature: str
    signature_id: int
    category: str
    severity: int
    raw_info: Dict = None
    type_: str = "alert"
    flow_source: str = "suricata"

    def __post_init__(self):
        self.uid = str(self.uid)
        if self.raw_info is None:
            self.raw_info = {}


# Improved datetime conversion function to handle more formats

def convert_to_datetime(time_str: str) -> datetime.datetime:
    """
    Convert various time string formats to datetime object
    Args:
        time_str: Time string in various formats

    Returns:
        datetime object
    """
    if isinstance(time_str, datetime.datetime):
        return time_str
    
    if isinstance(time_str, (int, float)):
        return datetime.datetime.fromtimestamp(time_str)
    
    # Try different formats
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f%z',  # ISO format with timezone and microseconds
        '%Y-%m-%dT%H:%M:%S%z',     # ISO format with timezone without microseconds
        '%Y-%m-%dT%H:%M:%S.%f',    # ISO format without timezone with microseconds
        '%Y-%m-%dT%H:%M:%S',       # ISO format without timezone without microseconds
        '%Y-%m-%d %H:%M:%S.%f',    # Standard format with microseconds
        '%Y-%m-%d %H:%M:%S',       # Standard format without microseconds
        '%Y/%m/%d %H:%M:%S',       # Alternative date format with slash
        '%d/%m/%Y %H:%M:%S',       # Day-first format
        '%m/%d/%Y %H:%M:%S',       # Month-first format
    ]
    
    for fmt in formats:
        try:
            return datetime.datetime.strptime(time_str, fmt)
        except ValueError:
            continue
    
    # Try to handle partial ISO format (some CICIDS files might have this)
    try:
        # For format like "2025-04-07T04:07:11" (missing seconds/microseconds)
        if isinstance(time_str, str) and 'T' in time_str:
            parts = time_str.split('T')
            date_part = parts[0]
            time_part = parts[1]
            
            # Try to parse with different time formats
            time_formats = ['%H:%M:%S.%f', '%H:%M:%S', '%H:%M']
            for time_fmt in time_formats:
                try:
                    time_obj = datetime.datetime.strptime(time_part, time_fmt).time()
                    date_obj = datetime.datetime.strptime(date_part, '%Y-%m-%d').date()
                    return datetime.datetime.combine(date_obj, time_obj)
                except ValueError:
                    continue
    except Exception:
        pass
    
    # Last resort: current time
    logger.warning(f"Could not parse time string: {time_str}. Using current time instead.")
    return datetime.datetime.now()


def convert_format(time_value, format_type="unixtimestamp"):
    """
    Convert time values between different formats
    Args:
        time_value: Time value to convert
        format_type: Target format type

    Returns:
        Converted time string
    """
    if not time_value:
        return None

    if format_type == "unixtimestamp":
        if isinstance(time_value, (int, float)):
            dt = datetime.datetime.fromtimestamp(time_value)
            return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')
        return time_value
    return time_value


class SuricataParser:
    """Parser for Suricata JSON files and streams"""
    
    def __init__(self):
        """Initialize the Suricata parser"""
        self.events = []
        self.flows = {}  # Storing flows by flow_id
        self.alerts = []
        self.http_events = []
        self.dns_events = []
        self.tls_events = []
        
    def parse_line(self, line: Union[str, Dict]) -> Optional[Any]:
        """
        Parse a single line of Suricata JSON
        
        Args:
            line: JSON string or dictionary representing a Suricata event
            
        Returns:
            Parsed event object or None if parsing fails
        """
        # Convert to dict if it's a string
        if isinstance(line, str):
            try:
                line = json.loads(line)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON: {line[:100]}...")
                return None
        elif isinstance(line, dict) and "data" in line:
            # Handle dict with 'data' key
            try:
                line = json.loads(line.get("data", "{}"))
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON from data field: {line.get('data', '{}')[:100]}...")
                return None
        
        if not line:
            return None
            
        # Extract common fields from the event
        try:
            event_type = line.get("event_type")
            flow_id = line.get("flow_id", "")
            saddr = line.get("src_ip", "")
            sport = line.get("src_port", "")
            daddr = line.get("dest_ip", "")
            dport = line.get("dest_port", "")
            proto = line.get("proto", "")
            appproto = line.get("app_proto", False)
            
            # Get timestamp
            try:
                timestamp = line.get("timestamp", "")
                if timestamp:
                    timestamp = convert_to_datetime(timestamp)
            except ValueError:
                logger.warning(f"Invalid timestamp in event: {line.get('timestamp', '')}")
                timestamp = datetime.datetime.now()
        except KeyError as e:
            logger.error(f"Missing required field in Suricata event: {e}")
            return None
        
        # Helper function to extract nested values
        def get_value_at(field, subfield, default_=False):
            try:
                val = line[field][subfield]
                return val or default_
            except (IndexError, KeyError):
                return default_
        
        # Process based on event type
        result = None
        
        if event_type == "flow":
            try:
                starttime = convert_format(get_value_at("flow", "start"), "unixtimestamp")
                endtime = convert_format(get_value_at("flow", "end"), "unixtimestamp")
                
                flow = SuricataFlow(
                    flow_id,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    proto,
                    appproto,
                    starttime,
                    endtime,
                    int(get_value_at("flow", "pkts_toserver", 0)),
                    int(get_value_at("flow", "pkts_toclient", 0)),
                    int(get_value_at("flow", "bytes_toserver", 0)),
                    int(get_value_at("flow", "bytes_toclient", 0)),
                    get_value_at("flow", "state", ""),
                )
                
                self.flows[flow_id] = flow
                result = flow
                
            except (KeyError, ValueError) as e:
                logger.error(f"Error processing flow event: {e}")
                
        elif event_type == "http":
            try:
                http = SuricataHTTP(
                    timestamp,
                    flow_id,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    proto,
                    appproto,
                    get_value_at("http", "http_method", ""),
                    get_value_at("http", "hostname", ""),
                    get_value_at("http", "url", ""),
                    get_value_at("http", "http_user_agent", ""),
                    get_value_at("http", "status", ""),
                    get_value_at("http", "protocol", ""),
                    int(get_value_at("http", "request_body_len", 0)),
                    int(get_value_at("http", "length", 0)),
                )
                
                self.http_events.append(http)
                result = http
                
            except (KeyError, ValueError) as e:
                logger.error(f"Error processing HTTP event: {e}")
                
        elif event_type == "dns":
            try:
                # Get DNS answers
                answers = []
                dns_data = line.get("dns", {})
                if "grouped" in dns_data:
                    grouped = dns_data["grouped"]
                    cnames = grouped.get("CNAME", [])
                    ips = grouped.get("A", [])
                    answers = cnames + ips
                    
                dns = SuricataDNS(
                    timestamp,
                    flow_id,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    proto,
                    appproto,
                    get_value_at("dns", "rrname", ""),
                    get_value_at("dns", "ttl", ""),
                    get_value_at("dns", "rrtype", ""),
                    answers,
                )
                
                self.dns_events.append(dns)
                result = dns
                
            except (KeyError, ValueError) as e:
                logger.error(f"Error processing DNS event: {e}")
                
        elif event_type == "tls":
            try:
                tls = SuricataTLS(
                    timestamp,
                    flow_id,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    proto,
                    appproto,
                    get_value_at("tls", "version", ""),
                    get_value_at("tls", "subject", ""),
                    get_value_at("tls", "issuerdn", ""),
                    get_value_at("tls", "sni", ""),
                    get_value_at("tls", "notbefore", ""),
                    get_value_at("tls", "notafter", ""),
                )
                
                self.tls_events.append(tls)
                result = tls
                
            except (KeyError, ValueError) as e:
                logger.error(f"Error processing TLS event: {e}")
                
        elif event_type == "alert":
            try:
                alert = SuricataAlert(
                    timestamp,
                    flow_id,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    proto,
                    appproto,
                    line.get("alert", {}).get("signature", ""),
                    int(line.get("alert", {}).get("signature_id", 0)),
                    line.get("alert", {}).get("category", ""),
                    int(line.get("alert", {}).get("severity", 0)),
                    line.get("alert", {}),
                )
                
                self.alerts.append(alert)
                result = alert
                
            except (KeyError, ValueError) as e:
                logger.error(f"Error processing Alert event: {e}")
        
        # Add event to the general events list if we successfully parsed it
        if result:
            self.events.append(result)
            
        return result
    
    def parse_file(self, file_path: str) -> List:
        """
        Parse a Suricata JSON file
        
        Args:
            file_path: Path to the Suricata JSON file
            
        Returns:
            List of parsed events
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []
        
        # Reset state
        self.events = []
        self.flows = {}
        self.alerts = []
        self.http_events = []
        self.dns_events = []
        self.tls_events = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    self.parse_line(line)
                    
            logger.info(f"Parsed {len(self.events)} events from {file_path}")
            return self.events
            
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """
        Get statistics about parsed events
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_events": len(self.events),
            "flows": len(self.flows),
            "alerts": len(self.alerts),
            "http_events": len(self.http_events),
            "dns_events": len(self.dns_events),
            "tls_events": len(self.tls_events),
        }


# Example usage
if __name__ == "__main__":
    parser = SuricataParser()
    events = parser.parse_file("example.json")
    print(f"Parsed {len(events)} events")
    print(parser.get_stats())
