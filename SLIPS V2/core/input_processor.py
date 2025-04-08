#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Input Processor module for SLIPS Simplified
Handles reading and processing Suricata.json files
"""

import os
import json
import time
import logging
from typing import Dict, List, Any, Optional
from multiprocessing.managers import ValueProxy


class InputProcessor:
    """Process Suricata.json input files and convert to flows"""
    
    def __init__(self, db, input_file: str, config: Dict, should_stop: ValueProxy):
        """
        Initialize the input processor
        
        Args:
            db: Database instance
            input_file: Path to Suricata.json file
            config: Configuration dictionary
            should_stop: Shared value to indicate when to stop processing
        """
        self.logger = logging.getLogger('InputProcessor')
        self.db = db
        self.input_file = input_file
        self.config = config
        self.should_stop = should_stop
        
        # Initialize state
        self.file_handle = None
        self.processed_lines = 0
        self.current_position = 0
        self.last_check_time = time.time()
        self.check_interval = config.get('check_interval', 1.0)  # seconds
        
    def start(self) -> None:
        """Start processing the input file"""
        self.logger.info(f"Starting to process {self.input_file}")
        
        try:
            self._open_file()
            self._process_file()
        except Exception as e:
            self.logger.error(f"Error processing file: {str(e)}")
            self.should_stop.value = True
        finally:
            self._close_file()

    def _open_file(self) -> None:
        """Open the input file for reading"""
        try:
            self.file_handle = open(self.input_file, 'r')
            self.logger.info(f"Opened file: {self.input_file}")
        except Exception as e:
            self.logger.error(f"Error opening file {self.input_file}: {str(e)}")
            raise

    def _close_file(self) -> None:
        """Close the input file if open"""
        if self.file_handle:
            self.file_handle.close()
            self.logger.info(f"Closed file: {self.input_file}")

    def _process_file(self) -> None:
        """Process the Suricata.json file"""
        if not self.file_handle:
            self.logger.error("No file handle available")
            return
            
        self.logger.info("Processing Suricata.json file")
        
        line_buffer = []
        current_line = ""
        
        while not self.should_stop.value:
            # Read a chunk of data
            chunk = self.file_handle.read(8192)
            
            if not chunk:
                # End of file reached
                if line_buffer:
                    # Process remaining complete lines
                    for line in line_buffer:
                        self._process_line(line)
                        self.processed_lines += 1
                    line_buffer = []
                
                # If still more in current_line, process it
                if current_line.strip():
                    self._process_line(current_line)
                    self.processed_lines += 1
                    current_line = ""
                
                # Check if file has grown
                if self._check_file_growth():
                    # File has grown, continue reading
                    continue
                else:
                    # No more data and file hasn't grown
                    # If this is a real-time processing setup, wait and check again
                    time.sleep(self.check_interval)
                    if not self._check_file_growth():
                        # Still no new data, assume we're done
                        self.logger.info(f"Processed {self.processed_lines} flows")
                        break
            
            # Process the chunk
            data = current_line + chunk
            lines = data.split('\n')
            
            # The last line might be incomplete
            current_line = lines[-1]
            
            # Process complete lines
            for line in lines[:-1]:
                if line.strip():
                    self._process_line(line)
                    self.processed_lines += 1
                    
            # Periodically check if we should stop
            if self.processed_lines % 1000 == 0:
                self.logger.info(f"Processed {self.processed_lines} flows so far")

    def _check_file_growth(self) -> bool:
        """
        Check if the file has grown since last read
        
        Returns:
            True if file has grown, False otherwise
        """
        current_time = time.time()
        
        # Only check periodically to reduce file stats calls
        if current_time - self.last_check_time < self.check_interval:
            return False
            
        self.last_check_time = current_time
        
        try:
            # Get current file size
            file_size = os.path.getsize(self.input_file)
            
            # Check if file has grown
            if file_size > self.current_position:
                # File has grown, update position
                self.current_position = self.file_handle.tell()
                return True
                
            return False
        except Exception as e:
            self.logger.error(f"Error checking file growth: {str(e)}")
            return False

    def _process_line(self, line: str) -> None:
        """
        Process a single line from the Suricata.json file
        
        Args:
            line: JSON line to process
        """
        try:
            # Parse JSON
            event = json.loads(line)
            
            # Skip non-flow events
            if event.get('event_type') not in ['flow', 'netflow']:
                return
                
            # Convert to our internal flow format
            flow = self._convert_to_flow(event)
            
            if flow:
                # Publish the flow to Redis
                self.db.publish('new_flow', {
                    'flow': flow,
                    'timestamp': flow.get('timestamp', time.time()),
                    'twid': f"timewindow{int(float(flow.get('timestamp', time.time())) // 3600)}"
                })
                
        except json.JSONDecodeError:
            self.logger.warning(f"Invalid JSON line: {line[:100]}...")
        except Exception as e:
            self.logger.error(f"Error processing line: {str(e)}")

    def _convert_to_flow(self, event: Dict) -> Optional[Dict]:
        """
        Convert Suricata event to internal flow format
        
        Args:
            event: Suricata event dictionary
            
        Returns:
            Flow dictionary in internal format or None if invalid
        """
        # Basic validation
        if 'src_ip' not in event or 'dest_ip' not in event:
            return None
            
        try:
            # Extract required fields
            flow = {
                'uid': event.get('flow_id', ''),
                'id.orig_h': event.get('src_ip'),
                'id.orig_p': event.get('src_port', 0),
                'id.resp_h': event.get('dest_ip'),
                'id.resp_p': event.get('dest_port', 0),
                'proto': event.get('proto', '').lower(),
                'service': event.get('app_proto', ''),
                'duration': float(event.get('flow', {}).get('duration', 0)),
                'orig_bytes': int(event.get('flow', {}).get('bytes_toserver', 0)),
                'resp_bytes': int(event.get('flow', {}).get('bytes_toclient', 0)),
                'conn_state': event.get('flow', {}).get('state', ''),
                'timestamp': float(event.get('timestamp', time.time()))
            }
            
            # Add additional fields if available
            if 'tcp' in event:
                flow['tcp_flags'] = event['tcp'].get('tcp_flags', '')
                flow['tcp_flags_ts'] = event['tcp'].get('tcp_flags_ts', '')
                flow['tcp_flags_tc'] = event['tcp'].get('tcp_flags_tc', '')
                
            # Convert Suricata state to Zeek-like conn_state
            state_map = {
                'new': 'S0',
                'established': 'SF',
                'closed': 'SF',
                'reset': 'REJ'
            }
            
            if flow['conn_state'] in state_map:
                flow['conn_state'] = state_map[flow['conn_state']]
                
            return flow
            
        except Exception as e:
            self.logger.error(f"Error converting event to flow: {str(e)}")
            return None