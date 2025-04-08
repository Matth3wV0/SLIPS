#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flow Classifier module for SLIPS Simplified
Classifies and converts network flows
"""

import time
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, NamedTuple


class Flow(NamedTuple):
    """Flow data structure"""
    uid: str
    saddr: str
    sport: int
    daddr: str
    dport: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    conn_state: str
    starttime: float
    endtime: float
    

class FlowClassifier:
    """Classifies and converts network flows"""
    
    def __init__(self):
        """Initialize the flow classifier"""
        pass
        
    def convert_to_flow_obj(self, flow_dict: Dict) -> Optional[Flow]:
        """
        Convert a flow dictionary to a Flow object
        
        Args:
            flow_dict: Flow dictionary
            
        Returns:
            Flow object or None if conversion fails
        """
        try:
            # Extract required fields
            uid = flow_dict.get('uid', '')
            
            # Handle different field naming schemes (Zeek vs Suricata)
            if 'id.orig_h' in flow_dict:
                # Zeek-style fields
                saddr = flow_dict.get('id.orig_h', '')
                sport = int(flow_dict.get('id.orig_p', 0))
                daddr = flow_dict.get('id.resp_h', '')
                dport = int(flow_dict.get('id.resp_p', 0))
            else:
                # Suricata-style fields
                saddr = flow_dict.get('src_ip', '')
                sport = int(flow_dict.get('src_port', 0))
                daddr = flow_dict.get('dest_ip', '')
                dport = int(flow_dict.get('dest_port', 0))
                
            proto = flow_dict.get('proto', '').lower()
            service = flow_dict.get('service', '')
            
            # Duration
            duration = float(flow_dict.get('duration', 0))
            
            # Bytes and packets
            orig_bytes = int(flow_dict.get('orig_bytes', 0))
            resp_bytes = int(flow_dict.get('resp_bytes', 0))
            orig_pkts = int(flow_dict.get('orig_pkts', 0))
            resp_pkts = int(flow_dict.get('resp_pkts', 0))
            
            # Connection state
            conn_state = flow_dict.get('conn_state', '')
            
            # Timestamps
            starttime = float(flow_dict.get('ts', flow_dict.get('timestamp', time.time())))
            endtime = starttime + duration
            
            return Flow(
                uid=uid,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                conn_state=conn_state,
                starttime=starttime,
                endtime=endtime
            )
            
        except Exception as e:
            print(f"Error converting flow: {str(e)}")
            return None
            
    def is_internal_ip(self, ip: str) -> bool:
        """
        Check if an IP is internal (private)
        
        Args:
            ip: IP address
            
        Returns:
            True if internal, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ValueError, TypeError):
            return False
            
    def get_flow_key(self, flow: Flow) -> str:
        """
        Get a unique key for a flow
        
        Args:
            flow: Flow object
            
        Returns:
            Unique flow key
        """
        return f"{flow.saddr}:{flow.sport}-{flow.daddr}:{flow.dport}-{flow.proto}"
        
    def get_bilateral_flow_key(self, flow: Flow) -> str:
        """
        Get a bilateral flow key (direction-agnostic)
        
        Args:
            flow: Flow object
            
        Returns:
            Bilateral flow key
        """
        # Sort IPs and ports to make key direction-agnostic
        if flow.saddr < flow.daddr or (flow.saddr == flow.daddr and flow.sport < flow.dport):
            return f"{flow.saddr}:{flow.sport}-{flow.daddr}:{flow.dport}-{flow.proto}"
        else:
            return f"{flow.daddr}:{flow.dport}-{flow.saddr}:{flow.sport}-{flow.proto}"
            
    def classify_port(self, port: int, proto: str) -> str:
        """
        Classify a port based on its number and protocol
        
        Args:
            port: Port number
            proto: Protocol (tcp, udp)
            
        Returns:
            Port classification
        """
        proto = proto.lower()
        
        # Well-known ports
        if port <= 1023:
            if proto == 'tcp':
                if port == 80:
                    return 'http'
                elif port == 443:
                    return 'https'
                elif port == 21:
                    return 'ftp'
                elif port == 22:
                    return 'ssh'
                elif port == 23:
                    return 'telnet'
                elif port == 25:
                    return 'smtp'
                elif port == 143:
                    return 'imap'
                elif port == 993:
                    return 'imaps'
                elif port == 110:
                    return 'pop3'
                elif port == 995:
                    return 'pop3s'
                return 'tcp-well-known'
            elif proto == 'udp':
                if port == 53:
                    return 'dns'
                elif port == 123:
                    return 'ntp'
                elif port == 161:
                    return 'snmp'
                return 'udp-well-known'
                
        # Registered ports
        elif port <= 49151:
            if proto == 'tcp':
                if port == 3306:
                    return 'mysql'
                elif port == 5432:
                    return 'postgresql'
                elif port == 8080:
                    return 'http-alt'
                elif port == 8443:
                    return 'https-alt'
                return 'tcp-registered'
            elif proto == 'udp':
                return 'udp-registered'
                
        # Dynamic/private ports
        else:
            if proto == 'tcp':
                return 'tcp-dynamic'
            elif proto == 'udp':
                return 'udp-dynamic'
                
        return 'unknown'
        
    def is_horizontal_scan(self, flows: List[Flow], threshold: int = 5) -> bool:
        """
        Check if a set of flows represents a horizontal scan
        
        Args:
            flows: List of Flow objects
            threshold: Minimum number of unique destination IPs to consider as a scan
            
        Returns:
            True if flows represent a horizontal scan, False otherwise
        """
        # Group flows by source IP, destination port, and protocol
        scan_groups = {}
        
        for flow in flows:
            key = (flow.saddr, flow.dport, flow.proto)
            if key not in scan_groups:
                scan_groups[key] = set()
            scan_groups[key].add(flow.daddr)
            
        # Check if any group has more unique destinations than the threshold
        for key, daddrs in scan_groups.items():
            if len(daddrs) >= threshold:
                return True
                
        return False
        
    def is_vertical_scan(self, flows: List[Flow], threshold: int = 5) -> bool:
        """
        Check if a set of flows represents a vertical scan
        
        Args:
            flows: List of Flow objects
            threshold: Minimum number of unique destination ports to consider as a scan
            
        Returns:
            True if flows represent a vertical scan, False otherwise
        """
        # Group flows by source IP and destination IP
        scan_groups = {}
        
        for flow in flows:
            key = (flow.saddr, flow.daddr)
            if key not in scan_groups:
                scan_groups[key] = set()
            scan_groups[key].add((flow.dport, flow.proto))
            
        # Check if any group has more unique ports than the threshold
        for key, ports in scan_groups.items():
            if len(ports) >= threshold:
                return True
                
        return False
