#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Threat Intelligence module for SLIPS Simplified
Checks IPs and domains against threat intelligence feeds
"""

import os
import re
import csv
import time
import json
import ipaddress
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple

from modules.module_interface import IModule


class ThreatIntelligence(IModule):
    """Threat intelligence module for checking IPs and domains against threat feeds"""
    
    def __init__(self, db, config, should_stop):
        """
        Initialize the threat intelligence module
        
        Args:
            db: Database instance
            config: Module configuration dictionary
            should_stop: Shared value to indicate when to stop processing
        """
        # Set module metadata
        self.name = "ThreatIntelligence"
        self.description = "Checks IPs and domains against threat intelligence feeds"
        self.authors = ["SLIPS Simplified"]
        
        # Call parent constructor
        super().__init__(db, config, should_stop)
        
    def init(self) -> None:
        """Initialize module-specific resources and state"""
        # Subscribe to channels
        self.subscribe('new_flow')
        
        # Load feeds configuration
        self.feeds_file = self.config.get('feeds_file', 'config/threat_intel_feeds.yaml')
        self.feeds = self._load_feeds_config()
        
        # Initialize databases
        self.ip_blocklist = set()
        self.ip_ranges = []  # List of (ipaddress.IPv4Network, threat_level, source) tuples
        self.domain_blocklist = {}  # domain -> (threat_level, source)
        
        # Settings
        self.update_interval = self.config.get('update_interval', 86400)  # 24 hours
        self.last_update_time = 0
        self.download_dir = self.config.get('download_dir', 'data/threat_intel')
        
        # User agent for requests
        self.user_agent = 'SLIPS-Simplified/1.0'
        
        # Create download directory
        os.makedirs(self.download_dir, exist_ok=True)
        
        # Initialize feeds
        self._update_feeds()
        
        self.logger.info("Threat Intelligence module initialized")
        
    def shutdown(self) -> None:
        """Clean up module resources before shutting down"""
        self.logger.info("Threat Intelligence module shutdown")
        
    def process_flow(self, flow: Dict) -> None:
        """
        Process a network flow
        
        Args:
            flow: Flow dictionary
        """
        # Extract IPs and domains from flow
        src_ip = flow.get('id.orig_h')
        dst_ip = flow.get('id.resp_h')
        
        # Check if update is needed
        current_time = time.time()
        if current_time - self.last_update_time > self.update_interval:
            self._update_feeds()
            
        # Check IPs against blocklists
        if src_ip:
            self._check_ip(src_ip, flow)
            
        if dst_ip:
            self._check_ip(dst_ip, flow)
            
        # Extract and check any domains
        domains = self._extract_domains_from_flow(flow)
        for domain in domains:
            self._check_domain(domain, flow)
            
    def _load_feeds_config(self) -> Dict:
        """
        Load feeds configuration from YAML file
        
        Returns:
            Feeds configuration dictionary
        """
        try:
            import yaml
            
            if os.path.exists(self.feeds_file):
                with open(self.feeds_file, 'r') as f:
                    feeds = yaml.safe_load(f)
                self.logger.info(f"Loaded feeds configuration from {self.feeds_file}")
                return feeds
            else:
                self.logger.warning(f"Feeds file {self.feeds_file} not found, using default configuration")
                return {
                    'ip_feeds': [
                        {
                            'name': 'Blocklist.de Blocklist',
                            'url': 'https://lists.blocklist.de/lists/all.txt',
                            'type': 'ip',
                            'threat_level': 0.6,
                            'enabled': True
                        }
                    ],
                    'domain_feeds': [
                        {
                            'name': 'Malware Domains',
                            'url': 'https://mirror1.malwaredomains.com/files/justdomains',
                            'type': 'domain',
                            'threat_level': 0.7,
                            'enabled': True
                        }
                    ]
                }
        except Exception as e:
            self.logger.error(f"Error loading feeds configuration: {str(e)}")
            return {
                'ip_feeds': [],
                'domain_feeds': []
            }
            
    def _update_feeds(self) -> None:
        """Update all enabled threat intelligence feeds"""
        self.logger.info("Updating threat intelligence feeds")
        
        # Clear existing data
        self.ip_blocklist = set()
        self.ip_ranges = []
        self.domain_blocklist = {}
        
        # Update IP feeds
        for feed in self.feeds.get('ip_feeds', []):
            if feed.get('enabled', True):
                self._update_ip_feed(feed)
                
        # Update domain feeds
        for feed in self.feeds.get('domain_feeds', []):
            if feed.get('enabled', True):
                self._update_domain_feed(feed)
                
        self.last_update_time = time.time()
        self.logger.info(f"Feeds updated: {len(self.ip_blocklist)} IPs, {len(self.ip_ranges)} IP ranges, {len(self.domain_blocklist)} domains")
        
    def _update_ip_feed(self, feed: Dict) -> None:
        """
        Update an IP feed
        
        Args:
            feed: Feed configuration dictionary
        """
        name = feed.get('name', 'Unknown')
        url = feed.get('url')
        threat_level = float(feed.get('threat_level', 0.5))
        
        if not url:
            self.logger.warning(f"Feed {name} has no URL")
            return
            
        try:
            # Download feed
            response = requests.get(
                url, 
                headers={'User-Agent': self.user_agent},
                timeout=30
            )
            
            if response.status_code != 200:
                self.logger.warning(f"Failed to download feed {name}: HTTP {response.status_code}")
                return
                
            # Parse and process the feed
            content = response.text
            
            # Save to file
            file_path = os.path.join(self.download_dir, f"{name.replace(' ', '_')}.txt")
            with open(file_path, 'w') as f:
                f.write(content)
                
            # Process each line
            for line in content.splitlines():
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                    
                # Try to parse as IP or range
                try:
                    # Check if it's an IP range (CIDR notation)
                    if '/' in line:
                        ip_range = ipaddress.IPv4Network(line, strict=False)
                        self.ip_ranges.append((ip_range, threat_level, name))
                    else:
                        # Single IP
                        ip = ipaddress.IPv4Address(line)
                        self.ip_blocklist.add((str(ip), threat_level, name))
                except ValueError:
                    # Not a valid IP or range
                    continue
                    
            self.logger.info(f"Updated IP feed {name}")
            
        except Exception as e:
            self.logger.error(f"Error updating IP feed {name}: {str(e)}")
            
    def _update_domain_feed(self, feed: Dict) -> None:
        """
        Update a domain feed
        
        Args:
            feed: Feed configuration dictionary
        """
        name = feed.get('name', 'Unknown')
        url = feed.get('url')
        threat_level = float(feed.get('threat_level', 0.5))
        
        if not url:
            self.logger.warning(f"Feed {name} has no URL")
            return
            
        try:
            # Download feed
            response = requests.get(
                url, 
                headers={'User-Agent': self.user_agent},
                timeout=30
            )
            
            if response.status_code != 200:
                self.logger.warning(f"Failed to download feed {name}: HTTP {response.status_code}")
                return
                
            # Parse and process the feed
            content = response.text
            
            # Save to file
            file_path = os.path.join(self.download_dir, f"{name.replace(' ', '_')}.txt")
            with open(file_path, 'w') as f:
                f.write(content)
                
            # Process each line
            for line in content.splitlines():
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                    
                # Normalize domain (lowercase)
                domain = line.lower()
                
                # Add to domain blocklist
                self.domain_blocklist[domain] = (threat_level, name)
                    
            self.logger.info(f"Updated domain feed {name}")
            
        except Exception as e:
            self.logger.error(f"Error updating domain feed {name}: {str(e)}")
            
    def _check_ip(self, ip: str, flow: Dict) -> None:
        """
        Check if an IP is in any blocklist
        
        Args:
            ip: IP address to check
            flow: Flow dictionary
        """
        try:
            # Check exact match
            for blocked_ip, threat_level, source in self.ip_blocklist:
                if ip == blocked_ip:
                    self._set_ip_evidence(ip, threat_level, source, flow)
                    return
                    
            # Check IP ranges
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                for network, threat_level, source in self.ip_ranges:
                    if ip_obj in network:
                        self._set_ip_evidence(ip, threat_level, source, flow)
                        return
            except ValueError:
                # Not a valid IPv4 address
                pass
                
        except Exception as e:
            self.logger.error(f"Error checking IP {ip}: {str(e)}")
            
    def _check_domain(self, domain: str, flow: Dict) -> None:
        """
        Check if a domain is in any blocklist
        
        Args:
            domain: Domain to check
            flow: Flow dictionary
        """
        try:
            # Normalize domain
            domain = domain.lower()
            
            # Check exact match
            if domain in self.domain_blocklist:
                threat_level, source = self.domain_blocklist[domain]
                self._set_domain_evidence(domain, threat_level, source, flow)
                return
                
            # Check if it's a subdomain of a blocked domain
            parts = domain.split('.')
            for i in range(1, len(parts)):
                parent_domain = '.'.join(parts[i:])
                if parent_domain in self.domain_blocklist:
                    threat_level, source = self.domain_blocklist[parent_domain]
                    self._set_domain_evidence(domain, threat_level, source, flow)
                    return
                    
        except Exception as e:
            self.logger.error(f"Error checking domain {domain}: {str(e)}")
            
    def _set_ip_evidence(self, ip: str, threat_level: float, source: str, flow: Dict) -> None:
        """
        Set evidence for a blocked IP
        
        Args:
            ip: IP address
            threat_level: Threat level
            source: Source feed name
            flow: Flow dictionary
        """
        # Determine if IP is source or destination
        is_source = ip == flow.get('id.orig_h')
        
        # Create evidence
        evidence = {
            'ip': ip,
            'type': 'ThreatIntelligenceBlacklistIP',
            'description': f"IP {ip} found in threat intelligence feed: {source}",
            'threat_level': threat_level,
            'confidence': 0.9,  # High confidence for TI matches
            'timestamp': time.time(),
            'details': {
                'source': source,
                'is_source': is_source,
                'flow': flow
            }
        }
        
        self.set_evidence(evidence)
        
    def _set_domain_evidence(self, domain: str, threat_level: float, source: str, flow: Dict) -> None:
        """
        Set evidence for a blocked domain
        
        Args:
            domain: Domain
            threat_level: Threat level
            source: Source feed name
            flow: Flow dictionary
        """
        # Determine IP associated with the domain
        src_ip = flow.get('id.orig_h')
        dst_ip = flow.get('id.resp_h')
        
        # Use the IP that's most likely associated with the domain
        ip = dst_ip if src_ip else src_ip
        
        # Create evidence
        evidence = {
            'ip': ip,
            'type': 'ThreatIntelligenceBlacklistDomain',
            'description': f"Domain {domain} found in threat intelligence feed: {source}",
            'threat_level': threat_level,
            'confidence': 0.9,  # High confidence for TI matches
            'timestamp': time.time(),
            'details': {
                'domain': domain,
                'source': source,
                'flow': flow
            }
        }
        
        self.set_evidence(evidence)
        
    def _extract_domains_from_flow(self, flow: Dict) -> List[str]:
        """
        Extract domains from a flow
        
        Args:
            flow: Flow dictionary
            
        Returns:
            List of domains
        """
        domains = []
        
        # Check if this is a DNS flow
        if flow.get('service', '').lower() == 'dns':
            # In a real implementation, we would extract the domain from DNS query
            # This is a simplified version
            if 'dns' in flow:
                query = flow['dns'].get('query', '')
                if query:
                    domains.append(query)
                    
        # Check for HTTP host
        if flow.get('service', '').lower() == 'http':
            # In a real implementation, we would extract the host from HTTP header
            # This is a simplified version
            if 'http' in flow:
                host = flow['http'].get('host', '')
                if host:
                    domains.append(host)
                    
        # Check for TLS SNI
        if flow.get('service', '').lower() == 'ssl' or flow.get('service', '').lower() == 'tls':
            # In a real implementation, we would extract the SNI from TLS handshake
            # This is a simplified version
            if 'ssl' in flow:
                server_name = flow['ssl'].get('server_name', '')
                if server_name:
                    domains.append(server_name)
                    
        return domains
