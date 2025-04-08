#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Profiler module for SLIPS Simplified
Creates and manages IP profiles and timewindows
"""

import time
import json
import logging
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from multiprocessing.managers import ValueProxy


class Profiler:
    """Create and manage IP profiles and timewindows"""
    
    def __init__(self, db, config: Dict, should_stop: ValueProxy):
        """
        Initialize the profiler
        
        Args:
            db: Database instance
            config: Configuration dictionary
            should_stop: Shared value to indicate when to stop processing
        """
        self.logger = logging.getLogger('Profiler')
        self.db = db
        self.config = config
        self.should_stop = should_stop
        
        # Profile settings
        self.timewindow_width = config.get('timewindow_width', 3600)  # 1 hour in seconds
        self.analysis_direction = config.get('analysis_direction', 'all')  # 'all' or 'out'
        
        # Initialize state
        self.pubsub = None
        
    def start(self) -> None:
        """Start the profiler process"""
        self.logger.info("Starting Profiler")
        
        try:
            # Subscribe to new flows
            self.pubsub = self.db.subscribe('new_flow')
            
            # Main processing loop
            while not self.should_stop.value:
                self._process_messages()
                time.sleep(0.01)  # Small sleep to avoid CPU hogging
                
        except Exception as e:
            self.logger.error(f"Error in profiler: {str(e)}")
            self.should_stop.value = True
        finally:
            self.logger.info("Profiler shutting down")

    def _process_messages(self) -> None:
        """Process messages from Redis channels"""
        message = self.db.get_message()
        
        if not message:
            return
            
        channel = message.get('channel', b'').decode('utf-8')
        data = message.get('data')
        
        if channel == 'new_flow':
            try:
                if isinstance(data, bytes):
                    data = json.loads(data.decode('utf-8'))
                    
                # Process the flow
                self._process_flow(data)
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"Error parsing flow data: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error processing flow: {str(e)}")

    def _process_flow(self, data: Dict) -> None:
        """
        Process a flow message
        
        Args:
            data: Flow data dictionary with 'flow' and 'timestamp' keys
        """
        if 'flow' not in data:
            self.logger.warning("Flow data missing 'flow' key")
            return
            
        flow = data['flow']
        timestamp = float(data.get('timestamp', time.time()))
        
        # Get source and destination IPs
        src_ip = flow.get('id.orig_h')
        dst_ip = flow.get('id.resp_h')
        
        if not src_ip or not dst_ip:
            self.logger.warning("Flow missing source or destination IP")
            return
            
        # Determine if we should process both directions or just outgoing
        if self.analysis_direction == 'out':
            # Process only outgoing traffic from internal IPs
            if self._is_internal_ip(src_ip):
                self._update_profile(src_ip, flow, timestamp)
        else:
            # Process both source and destination IPs
            self._update_profile(src_ip, flow, timestamp)
            self._update_profile(dst_ip, flow, timestamp)

    def _is_internal_ip(self, ip: str) -> bool:
        """
        Check if an IP is internal (private)
        
        Args:
            ip: IP address to check
            
        Returns:
            True if internal, False otherwise
        """
        try:
            # Handle IPv6 addresses
            if ':' in ip:
                ip_obj = ipaddress.IPv6Address(ip)
                return ip_obj.is_private or ip_obj.is_link_local
            else:
                ip_obj = ipaddress.IPv4Address(ip)
                return ip_obj.is_private
        except (ValueError, TypeError):
            return False

    def _update_profile(self, ip: str, flow: Dict, timestamp: float) -> None:
        """
        Update profile for an IP with new flow data
        
        Args:
            ip: IP address
            flow: Flow data dictionary
            timestamp: Flow timestamp
        """
        # Get or create profile
        profile = self._get_or_create_profile(ip)
        
        # Get appropriate timewindow
        tw_id, timewindow = self._get_or_create_timewindow(ip, timestamp)
        
        # Add flow to timewindow
        self.db.add_flow_to_timewindow(ip, tw_id, flow)
        
        # Update timewindow stats
        self._update_timewindow_stats(ip, tw_id, timewindow, flow)
        
        # Update profile stats
        self._update_profile_stats(ip, profile, flow)

    def _get_or_create_profile(self, ip: str) -> Dict:
        """
        Get existing profile or create a new one
        
        Args:
            ip: IP address
            
        Returns:
            Profile dictionary
        """
        profile = self.db.get_profile(ip)
        
        if not profile:
            # Create new profile
            profile = {
                'ip': ip,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'flow_count': 0,
                'bytes_in': 0,
                'bytes_out': 0,
                'protocols': {},
                'ports': {},
                'connected_ips': [],  # Initialize as list, not set
                'threat_level': 'info',
                'confidence': 0.0,
                'is_internal': self._is_internal_ip(ip)
            }
            
            self.db.set_profile(ip, profile)
            self.logger.debug(f"Created new profile for IP: {ip}")
            
            # Publish new profile event
            self.db.publish('new_profile', {'ip': ip})
            
        return profile

    def _get_or_create_timewindow(self, ip: str, timestamp: float) -> Tuple[str, Dict]:
        """
        Get appropriate timewindow or create a new one
        
        Args:
            ip: IP address
            timestamp: Flow timestamp
            
        Returns:
            Tuple of (timewindow_id, timewindow_data)
        """
        # Calculate timewindow ID based on timestamp
        # Ensure timestamp is a float before division
        timestamp_float = float(timestamp)
        tw_number = int(timestamp_float // self.timewindow_width)
        tw_id = f"timewindow{tw_number}"
        
        # Try to get existing timewindow
        timewindow = self.db.get_timewindow(ip, tw_id)
        
        if not timewindow:
            # Create new timewindow
            start_time = tw_number * self.timewindow_width
            end_time = start_time + self.timewindow_width
            
            timewindow = {
                'id': tw_id,
                'start_time': start_time,
                'end_time': end_time,
                'flow_count': 0,
                'bytes_in': 0,
                'bytes_out': 0,
                'protocols': {},
                'ports': {},
                'connected_ips': [],  # Initialize as list, not set
                'threat_level': 'info',
                'confidence': 0.0
            }
            
            self.db.set_timewindow(ip, tw_id, timewindow)
            self.logger.debug(f"Created new timewindow {tw_id} for IP: {ip}")
            
        return tw_id, timewindow

    def _update_timewindow_stats(self, ip: str, tw_id: str, timewindow: Dict, flow: Dict) -> None:
        """
        Update statistics for a timewindow
        
        Args:
            ip: IP address
            tw_id: Timewindow ID
            timewindow: Timewindow data dictionary
            flow: Flow data dictionary
        """
        # Increment flow count
        timewindow['flow_count'] += 1
        
        # Update bytes
        orig_bytes = int(flow.get('orig_bytes', 0))
        resp_bytes = int(flow.get('resp_bytes', 0))
        
        if ip == flow.get('id.orig_h'):
            # IP is source
            timewindow['bytes_out'] += orig_bytes
            timewindow['bytes_in'] += resp_bytes
        else:
            # IP is destination
            timewindow['bytes_in'] += orig_bytes
            timewindow['bytes_out'] += resp_bytes
        
        # Update protocols
        proto = flow.get('proto', '').lower()
        if proto:
            if proto not in timewindow['protocols']:
                timewindow['protocols'][proto] = 0
            timewindow['protocols'][proto] += 1
        
        # Update ports
        if ip == flow.get('id.orig_h'):
            # IP is source, track destination port
            port = flow.get('id.resp_p')
        else:
            # IP is destination, track source port
            port = flow.get('id.orig_p')
            
        if port:
            port_str = f"{proto}/{port}"
            if port_str not in timewindow['ports']:
                timewindow['ports'][port_str] = 0
            timewindow['ports'][port_str] += 1
        
        # Update connected IPs
        if ip == flow.get('id.orig_h'):
            connected_ip = flow.get('id.resp_h')
        else:
            connected_ip = flow.get('id.orig_h')
            
        if connected_ip and connected_ip not in timewindow['connected_ips']:
            timewindow['connected_ips'].append(connected_ip)
        
        # Update timewindow in database
        self.db.set_timewindow(ip, tw_id, timewindow)

    def _update_profile_stats(self, ip: str, profile: Dict, flow: Dict) -> None:
        """
        Update statistics for a profile
        
        Args:
            ip: IP address
            profile: Profile data dictionary
            flow: Flow data dictionary
        """
        # Update last seen time
        profile['last_seen'] = time.time()
        
        # Increment flow count
        profile['flow_count'] += 1
        
        # Update bytes
        orig_bytes = int(flow.get('orig_bytes', 0))
        resp_bytes = int(flow.get('resp_bytes', 0))
        
        if ip == flow.get('id.orig_h'):
            # IP is source
            profile['bytes_out'] += orig_bytes
            profile['bytes_in'] += resp_bytes
        else:
            # IP is destination
            profile['bytes_in'] += orig_bytes
            profile['bytes_out'] += resp_bytes
        
        # Update protocols
        proto = flow.get('proto', '').lower()
        if proto:
            if 'protocols' not in profile:
                profile['protocols'] = {}
            if proto not in profile['protocols']:
                profile['protocols'][proto] = 0
            profile['protocols'][proto] += 1
        
        # Update ports
        if ip == flow.get('id.orig_h'):
            # IP is source, track destination port
            port = flow.get('id.resp_p')
        else:
            # IP is destination, track source port
            port = flow.get('id.orig_p')
            
        if port:
            if 'ports' not in profile:
                profile['ports'] = {}
            port_str = f"{proto}/{port}"
            if port_str not in profile['ports']:
                profile['ports'][port_str] = 0
            profile['ports'][port_str] += 1
        
        # Update connected IPs
        if ip == flow.get('id.orig_h'):
            connected_ip = flow.get('id.resp_h')
        else:
            connected_ip = flow.get('id.orig_h')
            
        if connected_ip:
            if 'connected_ips' not in profile:
                profile['connected_ips'] = []
            if connected_ip not in profile['connected_ips']:  # Check before adding
                profile['connected_ips'].append(connected_ip)
        
        # Update profile in database
        self.db.set_profile(ip, profile)