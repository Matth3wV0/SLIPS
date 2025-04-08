#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abstract Module Interface for SLIPS Simplified
Provides a common interface for all detection modules
"""

import time
import json
import logging
import abc
from typing import Dict, List, Any, Optional, Union


class IModule(abc.ABC):
    """Abstract interface for SLIPS detection modules"""
    
    def __init__(self, db, config: Dict, should_stop):
        """
        Initialize the module
        
        Args:
            db: Database instance
            config: Module configuration dictionary
            should_stop: Shared value to indicate when to stop processing
        """
        # Set module metadata
        self.name = self.__class__.__name__
        self.description = "Base module interface"
        self.authors = ["SLIPS Simplified"]
        
        # Initialize module
        self.logger = logging.getLogger(self.name)
        self.db = db
        self.config = config
        self.should_stop = should_stop
        
        # Initialize subscribed channels
        self.channels = {}
        
        # Initialize module state
        self.is_running = False
        self.processed_messages = 0
        
        # Call module init
        self.init()
        
    @abc.abstractmethod
    def init(self) -> None:
        """Initialize module-specific resources and state"""
        pass
        
    @abc.abstractmethod
    def shutdown(self) -> None:
        """Clean up module resources before shutting down"""
        pass
        
    @abc.abstractmethod
    def process_flow(self, flow: Dict) -> None:
        """
        Process a network flow
        
        Args:
            flow: Flow dictionary
        """
        pass
        
    def start(self) -> None:
        """Start the module's main processing loop"""
        self.logger.info(f"Starting module: {self.name}")
        self.is_running = True
        
        try:
            # Main processing loop
            while self.is_running and not self.should_stop.value:
                try:
                    self.main_loop()
                except Exception as e:
                    self.logger.error(f"Error in main loop: {str(e)}")
                    time.sleep(1)  # Avoid tight loop on persistent errors
        finally:
            self.shutdown()
            self.logger.info(f"Module {self.name} shutdown complete")
            
    def main_loop(self) -> None:
        """Main processing loop implementation"""
        # Process messages from subscribed channels
        for channel_name, pubsub in self.channels.items():
            message = self.get_message(channel_name)
            if message:
                self.process_message(channel_name, message)
                self.processed_messages += 1
                
        # Avoid tight loop
        time.sleep(0.01)
        
    def subscribe(self, channel: str) -> None:
        """
        Subscribe to a Redis channel
        
        Args:
            channel: Channel name
        """
        if channel in self.channels:
            self.logger.warning(f"Already subscribed to channel: {channel}")
            return
            
        pubsub = self.db.subscribe(channel)
        self.channels[channel] = pubsub
        self.logger.debug(f"Subscribed to channel: {channel}")
        
    def get_message(self, channel: str) -> Optional[Dict]:
        """
        Get a message from a subscribed channel
        
        Args:
            channel: Channel name
            
        Returns:
            Message dictionary or None
        """
        if channel not in self.channels:
            self.logger.warning(f"Not subscribed to channel: {channel}")
            return None
            
        message = self.db.get_message(timeout=0.01)
        return message
        
    def process_message(self, channel: str, message: Dict) -> None:
        """
        Process a message from a channel
        
        Args:
            channel: Channel name
            message: Message dictionary
        """
        if channel == 'new_flow':
            try:
                data = message.get('data')
                if isinstance(data, bytes):
                    data = json.loads(data.decode('utf-8'))
                
                if 'flow' in data:
                    self.process_flow(data['flow'])
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"Error parsing flow data: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error processing flow: {str(e)}")
                
    def set_evidence(self, evidence: Dict) -> None:
        """
        Set evidence for an IP
        
        Args:
            evidence: Evidence dictionary with required fields:
                      - ip: IP address
                      - type: Evidence type
                      - description: Evidence description
                      - threat_level: Threat level (0.0-1.0)
                      - confidence: Confidence level (0.0-1.0)
        """
        # Validate required fields
        required_fields = ['ip', 'type', 'description', 'threat_level', 'confidence']
        for field in required_fields:
            if field not in evidence:
                self.logger.error(f"Missing required field in evidence: {field}")
                return
                
        # Add metadata
        evidence['timestamp'] = evidence.get('timestamp', time.time())
        evidence['module'] = evidence.get('module', self.name)
        evidence['id'] = evidence.get('id', f"{self.name}_{int(time.time())}_{evidence['ip']}")
        
        # Store and publish
        self.db.add_evidence(evidence)
        self.logger.info(f"Set evidence for IP {evidence['ip']}: {evidence['description']}")
        
    def stop(self) -> None:
        """Signal the module to stop processing"""
        self.logger.info(f"Stopping module: {self.name}")
        self.is_running = False
