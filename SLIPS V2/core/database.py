#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database module for SLIPS Simplified
Handles Redis database operations
"""

import json
import time
import logging
import redis
import subprocess
import os
from typing import Dict, List, Any, Optional, Union

class Database:
    """Redis database interface for SLIPS Simplified"""
    
    def __init__(self, port: int = 6379, db_name: int = 0):
        """
        Initialize the database connection
        
        Args:
            port: Redis port number
            db_name: Redis database name/number
        """
        self.logger = logging.getLogger('Database')
        self.port = port
        self.db_name = db_name
        self.redis_client = None
        self.pubsub = None
        self.supported_channels = [
            'new_flow',
            'new_evidence',
            'new_alert',
            'new_profile',
            'shutdown'
        ]
        
        # First, try to fix or restart an existing problematic Redis server
        self._fix_redis_server()
        
        # Connect to Redis
        self._connect()

    def _fix_redis_server(self) -> None:
        """Attempt to fix a potentially problematic Redis server"""
        try:
            # First try to connect
            test_client = redis.Redis(
                host='localhost',
                port=self.port,
                db=self.db_name,
                socket_timeout=2
            )
            
            try:
                # Try a ping - if this succeeds, Redis is running
                test_client.ping()
                # Try to fix the configuration
                try:
                    test_client.config_set('stop-writes-on-bgsave-error', 'no')
                    self.logger.info("Successfully configured existing Redis server")
                    test_client.close()
                    return
                except Exception:
                    # Can't reconfigure, need to restart
                    self.logger.info("Couldn't reconfigure Redis, attempting restart")
            except Exception:
                # Redis is not responding, may need to be started
                self.logger.info("Redis server not responding, will start a new one")
            
            # Try to gracefully shut down any existing Redis instance
            try:
                subprocess.run(
                    ['redis-cli', '-p', str(self.port), 'shutdown'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=3
                )
                time.sleep(1)  # Give Redis time to shut down
                self.logger.info("Successfully shut down existing Redis server")
            except Exception as e:
                self.logger.warning(f"Could not shut down Redis: {str(e)}")
            
            # Force kill any remaining Redis processes on this port
            try:
                # Find any process listening on our port
                cmd = f"lsof -i :{self.port} -t"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                pids = result.stdout.strip().split("\n")
                
                for pid in pids:
                    if pid:
                        try:
                            # Kill the process
                            subprocess.run(['kill', '-9', pid], check=False)
                            self.logger.info(f"Killed Redis process with PID {pid}")
                        except Exception:
                            pass
                time.sleep(1)  # Give processes time to die
            except Exception as e:
                self.logger.warning(f"Error killing Redis processes: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Error fixing Redis server: {str(e)}")

    def _connect(self) -> None:
        """Connect to Redis database, start server if not running"""
        try:
            # Start a new Redis server with correct configuration
            self._start_redis_server()
            
            # Try to connect again
            self.redis_client = redis.Redis(
                host='localhost',
                port=self.port,
                db=self.db_name,
                socket_timeout=5
            )
            self.redis_client.ping()  # Test connection
            self.logger.info(f"Connected to Redis server on port {self.port}")
                
            # Initialize pubsub client
            self.pubsub = self.redis_client.pubsub(ignore_subscribe_messages=True)
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {str(e)}")
            raise
            
    def _start_redis_server(self) -> None:
        """Start a Redis server instance"""
        try:
            # Create a temporary Redis config file
            temp_config = f"/tmp/redis_{self.port}.conf"
            with open(temp_config, 'w') as f:
                f.write(f"""
                port {self.port}
                daemonize yes
                save ""
                stop-writes-on-bgsave-error no
                """)
            
            # Start Redis with our config file
            cmd = ['redis-server', temp_config]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for server to start
            max_retries = 5
            for i in range(max_retries):
                try:
                    client = redis.Redis(
                        host='localhost',
                        port=self.port,
                        db=self.db_name,
                        socket_timeout=2
                    )
                    client.ping()
                    client.close()
                    self.logger.info(f"Redis server started on port {self.port}")
                    
                    # Clean up config file
                    os.remove(temp_config)
                    return
                except (redis.ConnectionError, redis.TimeoutError):
                    time.sleep(1)
                    
            raise Exception(f"Failed to start Redis server on port {self.port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start Redis server: {str(e)}")
            raise

    def publish(self, channel: str, message: Any) -> None:
        """
        Publish a message to a Redis channel
        
        Args:
            channel: The channel name
            message: The message to publish (will be converted to JSON)
        """
        if channel not in self.supported_channels:
            self.logger.warning(f"Publishing to unsupported channel: {channel}")
            
        try:
            if isinstance(message, (dict, list)):
                message = json.dumps(message)
            self.redis_client.publish(channel, message)
        except Exception as e:
            self.logger.error(f"Error publishing to channel {channel}: {str(e)}")

    def subscribe(self, channel: str) -> redis.client.PubSub:
        """
        Subscribe to a Redis channel
        
        Args:
            channel: The channel name
            
        Returns:
            Redis PubSub client
        """
        if channel not in self.supported_channels:
            self.logger.warning(f"Subscribing to unsupported channel: {channel}")
            
        try:
            self.pubsub.subscribe(channel)
            return self.pubsub
        except Exception as e:
            self.logger.error(f"Error subscribing to channel {channel}: {str(e)}")
            return None

    def get_message(self, timeout: float = 0.01) -> Optional[Dict]:
        """
        Get a message from subscribed channels
        
        Args:
            timeout: Time to wait for a message
            
        Returns:
            Message or None if no message is available
        """
        try:
            return self.pubsub.get_message(timeout=timeout)
        except Exception as e:
            self.logger.error(f"Error getting message: {str(e)}")
            return None

    def set(self, key: str, value: Any) -> None:
        """
        Set a key-value pair in Redis
        
        Args:
            key: The key
            value: The value (will be converted to JSON if dict/list)
        """
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            self.redis_client.set(key, value)
        except Exception as e:
            self.logger.error(f"Error setting key {key}: {str(e)}")

    def get(self, key: str) -> Any:
        """
        Get a value from Redis
        
        Args:
            key: The key
            
        Returns:
            The value or None if key doesn't exist
        """
        try:
            value = self.redis_client.get(key)
            if value:
                try:
                    # Try to decode as JSON
                    return json.loads(value)
                except json.JSONDecodeError:
                    # Return as string if not JSON
                    return value.decode('utf-8')
            return None
        except Exception as e:
            self.logger.error(f"Error getting key {key}: {str(e)}")
            return None

    def set_profile(self, ip: str, profile_data: Dict) -> None:
        """
        Store a profile for an IP
        
        Args:
            ip: The IP address
            profile_data: Profile data dictionary
        """
        key = f"profile:{ip}"
        self.set(key, profile_data)

    def get_profile(self, ip: str) -> Optional[Dict]:
        """
        Get profile data for an IP
        
        Args:
            ip: The IP address
            
        Returns:
            Profile data dictionary or None
        """
        key = f"profile:{ip}"
        return self.get(key)

    def add_flow_to_timewindow(self, ip: str, tw_id: str, flow: Dict) -> None:
        """
        Add a flow to a specific timewindow of an IP profile
        
        Args:
            ip: The IP address
            tw_id: Timewindow ID
            flow: Flow data dictionary
        """
        key = f"profile:{ip}:{tw_id}:flows"
        try:
            flow_json = json.dumps(flow)
            self.redis_client.rpush(key, flow_json)
        except Exception as e:
            self.logger.error(f"Error adding flow to timewindow: {str(e)}")

    def get_flows_in_timewindow(self, ip: str, tw_id: str) -> List[Dict]:
        """
        Get all flows in a specific timewindow
        
        Args:
            ip: The IP address
            tw_id: Timewindow ID
            
        Returns:
            List of flow dictionaries
        """
        key = f"profile:{ip}:{tw_id}:flows"
        try:
            flows_json = self.redis_client.lrange(key, 0, -1)
            return [json.loads(flow) for flow in flows_json]
        except Exception as e:
            self.logger.error(f"Error getting flows from timewindow: {str(e)}")
            return []

    def add_evidence(self, evidence: Dict) -> None:
        """
        Add evidence to the database
        
        Args:
            evidence: Evidence data dictionary
        """
        # Store evidence with timestamp as ID
        evidence_id = evidence.get('id', str(time.time()))
        key = f"evidence:{evidence_id}"
        self.set(key, evidence)
        
        # Add to IP's evidence list
        ip = evidence.get('ip')
        if ip:
            ip_evidence_key = f"ip:{ip}:evidence"
            self.redis_client.sadd(ip_evidence_key, evidence_id)
        
        # Publish event
        self.publish('new_evidence', evidence)

    def get_evidence_for_ip(self, ip: str) -> List[Dict]:
        """
        Get all evidence for an IP
        
        Args:
            ip: The IP address
            
        Returns:
            List of evidence dictionaries
        """
        ip_evidence_key = f"ip:{ip}:evidence"
        try:
            evidence_ids = self.redis_client.smembers(ip_evidence_key)
            evidence_list = []
            
            for ev_id in evidence_ids:
                ev_key = f"evidence:{ev_id.decode('utf-8')}"
                evidence = self.get(ev_key)
                if evidence:
                    evidence_list.append(evidence)
                    
            return evidence_list
        except Exception as e:
            self.logger.error(f"Error getting evidence for IP {ip}: {str(e)}")
            return []

    def set_timewindow(self, ip: str, tw_id: str, tw_data: Dict) -> None:
        """
        Set timewindow data for an IP
        
        Args:
            ip: The IP address
            tw_id: Timewindow ID
            tw_data: Timewindow data dictionary
        """
        key = f"profile:{ip}:{tw_id}"
        self.set(key, tw_data)
        
        # Add timewindow to IP's timewindow list
        ip_tw_key = f"profile:{ip}:timewindows"
        self.redis_client.sadd(ip_tw_key, tw_id)

    def get_timewindow(self, ip: str, tw_id: str) -> Optional[Dict]:
        """
        Get timewindow data for an IP
        
        Args:
            ip: The IP address
            tw_id: Timewindow ID
            
        Returns:
            Timewindow data dictionary or None
        """
        key = f"profile:{ip}:{tw_id}"
        return self.get(key)

    def get_timewindows_for_ip(self, ip: str) -> List[str]:
        """
        Get all timewindow IDs for an IP
        
        Args:
            ip: The IP address
            
        Returns:
            List of timewindow IDs
        """
        ip_tw_key = f"profile:{ip}:timewindows"
        try:
            tw_ids = self.redis_client.smembers(ip_tw_key)
            return [tw_id.decode('utf-8') for tw_id in tw_ids]
        except Exception as e:
            self.logger.error(f"Error getting timewindows for IP {ip}: {str(e)}")
            return []

    def add_alert(self, alert: Dict) -> None:
        """
        Add an alert to the database
        
        Args:
            alert: Alert data dictionary
        """
        # Store alert with timestamp as ID
        alert_id = alert.get('id', str(time.time()))
        key = f"alert:{alert_id}"
        self.set(key, alert)
        
        # Add to IP's alert list
        ip = alert.get('ip')
        if ip:
            ip_alert_key = f"ip:{ip}:alerts"
            self.redis_client.sadd(ip_alert_key, alert_id)
        
        # Publish event
        self.publish('new_alert', alert)

    def get_alerts_for_ip(self, ip: str) -> List[Dict]:
        """
        Get all alerts for an IP
        
        Args:
            ip: The IP address
            
        Returns:
            List of alert dictionaries
        """
        ip_alert_key = f"ip:{ip}:alerts"
        try:
            alert_ids = self.redis_client.smembers(ip_alert_key)
            alert_list = []
            
            for alert_id in alert_ids:
                alert_key = f"alert:{alert_id.decode('utf-8')}"
                alert = self.get(alert_key)
                if alert:
                    alert_list.append(alert)
                    
            return alert_list
        except Exception as e:
            self.logger.error(f"Error getting alerts for IP {ip}: {str(e)}")
            return []

    def shutdown(self) -> None:
        """Shutdown database connection"""
        try:
            if self.pubsub:
                self.pubsub.unsubscribe()
                self.pubsub.close()
                
            if self.redis_client:
                self.redis_client.close()
                
            self.logger.info("Database connection closed")
        except Exception as e:
            self.logger.error(f"Error closing database connection: {str(e)}")