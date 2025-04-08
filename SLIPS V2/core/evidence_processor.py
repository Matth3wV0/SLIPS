#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Evidence Processor module for SLIPS Simplified
Collects and processes evidence from detection modules
"""

import os
import json
import time
import logging
import subprocess
from typing import Dict, List, Any, Optional
from multiprocessing.managers import ValueProxy


class EvidenceProcessor:
    """Collect and process evidence from detection modules"""
    
    def __init__(self, db, config: Dict, output_dir: str, should_stop: ValueProxy, blocking_enabled: bool = False):
        """
        Initialize the evidence processor
        
        Args:
            db: Database instance
            config: Configuration dictionary
            output_dir: Output directory path
            should_stop: Shared value to indicate when to stop processing
            blocking_enabled: Whether to enable traffic blocking
        """
        self.logger = logging.getLogger('EvidenceProcessor')
        self.db = db
        self.config = config
        self.output_dir = output_dir
        self.should_stop = should_stop
        self.blocking_enabled = blocking_enabled
        
        # Evidence settings
        self.evidence_threshold = config.get('evidence_threshold', 0.25)
        self.min_confidence = config.get('min_confidence', 0.5)
        
        # Initialize state
        self.pubsub = None
        self.alert_file = os.path.join(output_dir, 'alerts.json')
        self.alert_log = os.path.join(output_dir, 'alerts.log')
        self.blocked_ips = set()
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize alert files
        self._init_alert_files()
        
        # Initialize blocking if enabled
        if blocking_enabled:
            self._init_blocking()
        
    def start(self) -> None:
        """Start the evidence processor"""
        self.logger.info("Starting Evidence Processor")
        
        try:
            # Subscribe to new evidence
            self.pubsub = self.db.subscribe('new_evidence')
            
            # Main processing loop
            while not self.should_stop.value:
                self._process_messages()
                time.sleep(0.01)  # Small sleep to avoid CPU hogging
                
        except Exception as e:
            self.logger.error(f"Error in evidence processor: {str(e)}")
            self.should_stop.value = True
        finally:
            # Clean up blocking rules if enabled
            if self.blocking_enabled:
                self._cleanup_blocking()
            self.logger.info("Evidence Processor shutting down")

    def _init_alert_files(self) -> None:
        """Initialize alert output files"""
        # Create JSON alerts file with empty array
        with open(self.alert_file, 'w') as f:
            f.write('[]')
            
        # Create log file with header
        with open(self.alert_log, 'w') as f:
            f.write(f"SLIPS Simplified Alerts - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
        self.logger.info(f"Alert files initialized at {self.output_dir}")

    def _init_blocking(self) -> None:
        """Initialize traffic blocking (iptables)"""
        try:
            # Check if we're running as root (required for iptables)
            if os.geteuid() != 0:
                self.logger.warning("Blocking enabled but not running as root. Blocking will be disabled.")
                self.blocking_enabled = False
                return
                
            # Create iptables chain for SLIPS
            subprocess.run(
                ['iptables', '-N', 'slipsBlocking'],
                stderr=subprocess.PIPE,
                check=False
            )
            
            # Link the chain to INPUT and FORWARD chains
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-j', 'slipsBlocking'],
                check=True
            )
            subprocess.run(
                ['iptables', '-I', 'FORWARD', '-j', 'slipsBlocking'],
                check=True
            )
            
            self.logger.info("Blocking initialized successfully")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error initializing blocking: {e.stderr.decode() if e.stderr else str(e)}")
            self.blocking_enabled = False
        except Exception as e:
            self.logger.error(f"Error initializing blocking: {str(e)}")
            self.blocking_enabled = False

    def _cleanup_blocking(self) -> None:
        """Clean up iptables rules on shutdown"""
        if not self.blocking_enabled:
            return
            
        try:
            # Remove chain links
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-j', 'slipsBlocking'],
                stderr=subprocess.PIPE,
                check=False
            )
            subprocess.run(
                ['iptables', '-D', 'FORWARD', '-j', 'slipsBlocking'],
                stderr=subprocess.PIPE,
                check=False
            )
            
            # Flush and delete the chain
            subprocess.run(
                ['iptables', '-F', 'slipsBlocking'],
                check=True
            )
            subprocess.run(
                ['iptables', '-X', 'slipsBlocking'],
                check=True
            )
            
            self.logger.info("Blocking rules cleaned up")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error cleaning up blocking rules: {e.stderr.decode() if e.stderr else str(e)}")
        except Exception as e:
            self.logger.error(f"Error cleaning up blocking rules: {str(e)}")

    def _process_messages(self) -> None:
        """Process messages from Redis channels"""
        message = self.db.get_message()
        
        if not message:
            return
            
        channel = message.get('channel', b'').decode('utf-8')
        data = message.get('data')
        
        if channel == 'new_evidence':
            try:
                if isinstance(data, bytes):
                    data = json.loads(data.decode('utf-8'))
                    
                # Process the evidence
                self._process_evidence(data)
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"Error parsing evidence data: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error processing evidence: {str(e)}")

    def _process_evidence(self, evidence: Dict) -> None:
        """
        Process a piece of evidence
        
        Args:
            evidence: Evidence data dictionary
        """
        # Basic validation
        if 'ip' not in evidence:
            self.logger.warning("Evidence missing 'ip' key")
            return
            
        ip = evidence['ip']
        
        # Get all evidence for this IP
        all_evidence = self.db.get_evidence_for_ip(ip)
        
        # Calculate total threat score
        total_score = 0.0
        evidence_count = 0
        
        for ev in all_evidence:
            threat_level = ev.get('threat_level', 0.0)
            confidence = ev.get('confidence', 0.0)
            
            # Weight evidence by confidence
            score = threat_level * confidence
            total_score += score
            evidence_count += 1
            
        # Check if we should generate an alert
        if total_score >= self.evidence_threshold and evidence_count > 0:
            average_confidence = total_score / evidence_count
            
            if average_confidence >= self.min_confidence:
                # Generate alert
                self._generate_alert(ip, all_evidence, total_score, average_confidence)
                
                # Block IP if enabled and not already blocked
                if self.blocking_enabled and ip not in self.blocked_ips:
                    self._block_ip(ip)

    def _generate_alert(self, ip: str, evidence_list: List[Dict], total_score: float, confidence: float) -> None:
        """
        Generate an alert for an IP
        
        Args:
            ip: IP address
            evidence_list: List of evidence dictionaries
            total_score: Total threat score
            confidence: Average confidence level
        """
        # Create alert structure
        alert = {
            'id': f"alert_{int(time.time())}_{ip}",
            'timestamp': time.time(),
            'ip': ip,
            'evidence_count': len(evidence_list),
            'total_score': total_score,
            'confidence': confidence,
            'threat_level': self._get_threat_level(total_score),
            'evidence': evidence_list
        }
        
        # Add profile information if available
        profile = self.db.get_profile(ip)
        if profile:
            alert['profile'] = {
                'first_seen': profile.get('first_seen'),
                'last_seen': profile.get('last_seen'),
                'flow_count': profile.get('flow_count'),
                'bytes_in': profile.get('bytes_in'),
                'bytes_out': profile.get('bytes_out'),
                'is_internal': profile.get('is_internal', False)
            }
        
        # Store alert in database
        self.db.add_alert(alert)
        
        # Write to alert files
        self._write_alert_to_files(alert)
        
        self.logger.info(f"Generated alert for IP {ip} with threat level {alert['threat_level']}")

    def _get_threat_level(self, score: float) -> str:
        """
        Convert numerical score to threat level string
        
        Args:
            score: Threat score
            
        Returns:
            Threat level string
        """
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'info'

    def _write_alert_to_files(self, alert: Dict) -> None:
        """
        Write alert to output files
        
        Args:
            alert: Alert dictionary
        """
        try:
            # Write to JSON file
            with open(self.alert_file, 'r') as f:
                alerts = json.load(f)
                
            alerts.append(alert)
            
            with open(self.alert_file, 'w') as f:
                json.dump(alerts, f, indent=2)
                
            # Write to log file
            with open(self.alert_log, 'a') as f:
                timestamp = time.strftime('%Y/%m/%d-%H:%M:%S', time.localtime(alert['timestamp']))
                f.write(f"{timestamp}: IP {alert['ip']} - {alert['threat_level'].upper()} - Evidence count: {alert['evidence_count']}\n")
                
                # Write evidence details
                for i, evidence in enumerate(alert['evidence']):
                    description = evidence.get('description', 'No description')
                    evidence_type = evidence.get('type', 'Unknown')
                    f.write(f"    {i+1}. {evidence_type}: {description}\n")
                    
                f.write("\n")
                
        except Exception as e:
            self.logger.error(f"Error writing alert to files: {str(e)}")

    def _block_ip(self, ip: str) -> None:
        """
        Block an IP using iptables
        
        Args:
            ip: IP address to block
        """
        if not self.blocking_enabled:
            return
            
        try:
            # Add blocking rule
            subprocess.run(
                ['iptables', '-A', 'slipsBlocking', '-s', ip, '-j', 'DROP'],
                check=True
            )
            
            # Also block incoming connections
            subprocess.run(
                ['iptables', '-A', 'slipsBlocking', '-d', ip, '-j', 'DROP'],
                check=True
            )
            
            # Add to blocked IPs set
            self.blocked_ips.add(ip)
            
            self.logger.info(f"Blocked IP: {ip}")
            
            # Write to alert log
            with open(self.alert_log, 'a') as f:
                timestamp = time.strftime('%Y/%m/%d-%H:%M:%S')
                f.write(f"{timestamp}: BLOCKED IP {ip}\n\n")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error blocking IP {ip}: {e.stderr.decode() if e.stderr else str(e)}")
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip}: {str(e)}")
