#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RNN C&C Detection module for SLIPS Simplified
Uses recurrent neural networks to detect command and control channels
"""

import os
import time
import math
import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple

try:
    import tensorflow as tf
    from tensorflow.keras.models import load_model
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from modules.module_interface import IModule


class RNNCCDetection(IModule):
    """RNN-based Command and Control detection module"""
    
    def __init__(self, db, config, should_stop):
        """
        Initialize the RNN C&C detection module
        
        Args:
            db: Database instance
            config: Module configuration dictionary
            should_stop: Shared value to indicate when to stop processing
        """
        # Set module metadata
        self.name = "RNNCCDetection"
        self.description = "RNN-based Command and Control channel detection"
        self.authors = ["SLIPS Simplified"]
        
        # Call parent constructor
        super().__init__(db, config, should_stop)
        
    def init(self) -> None:
        """Initialize module-specific resources and state"""
        if not TF_AVAILABLE:
            self.logger.error("TensorFlow not available. Module will not function properly.")
            return
            
        # Subscribe to channels
        self.subscribe('new_flow')
        
        # Load RNN model
        self.model = None
        self.max_sequence_length = 20  # Maximum stratoletters sequence length
        
        model_path = self.config.get('model_path', 'models/rnn_model.h5')
        self._load_model(model_path)
        
        # Detection settings
        self.prediction_threshold = self.config.get('prediction_threshold', 0.7)
        self.min_confidence = self.config.get('min_confidence', 0.5)
        self.min_sequence_length = self.config.get('min_sequence_length', 5)
        
        # State for tracking flows by IP pairs
        self.flow_sequences = {}  # (src_ip, dst_ip, dst_port) -> list of stratoletters
        self.last_flow_times = {}  # (src_ip, dst_ip, dst_port) -> last flow timestamp
        
        # Stratoletter generation settings
        self.periodicity_threshold = self.config.get('periodicity_threshold', 0.3)
        
        self.logger.info("RNN C&C Detection module initialized")
        
    def shutdown(self) -> None:
        """Clean up module resources before shutting down"""
        # Check all remaining sequences for C&C patterns
        self._check_remaining_sequences()
        
        self.logger.info("RNN C&C Detection module shutdown")
        
    def _load_model(self, model_path: str) -> None:
        """
        Load RNN model from file
        
        Args:
            model_path: Path to model file
        """
        try:
            if os.path.exists(model_path):
                self.model = load_model(model_path)
                self.logger.info(f"Model loaded from {model_path}")
            else:
                self.logger.warning(f"Model file not found at {model_path}")
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            
    def process_flow(self, flow: Dict) -> None:
        """
        Process a network flow
        
        Args:
            flow: Flow dictionary
        """
        # Skip if model not available
        if not TF_AVAILABLE or self.model is None:
            return
            
        # Extract relevant data from flow
        src_ip = flow.get('id.orig_h')
        dst_ip = flow.get('id.resp_h')
        dst_port = flow.get('id.resp_p')
        proto = flow.get('proto', '').lower()
        timestamp = flow.get('timestamp', time.time())
        
        # Skip non-TCP/UDP flows and flows without required fields
        if not (proto in ['tcp', 'udp'] and src_ip and dst_ip and dst_port):
            return
            
        # Create flow identifier
        flow_id = (src_ip, dst_ip, f"{dst_port}/{proto}")
        
        # Get flow characteristics
        duration = float(flow.get('duration', 0))
        orig_bytes = int(flow.get('orig_bytes', 0))
        resp_bytes = int(flow.get('resp_bytes', 0))
        
        # Generate stratoletter for this flow
        stratoletter = self._generate_stratoletter(
            flow_id, timestamp, duration, orig_bytes, resp_bytes
        )
        
        if stratoletter:
            # Add stratoletter to sequence
            if flow_id not in self.flow_sequences:
                self.flow_sequences[flow_id] = []
                
            self.flow_sequences[flow_id].append(stratoletter)
            self.last_flow_times[flow_id] = timestamp
            
            # Trim sequence if too long
            if len(self.flow_sequences[flow_id]) > self.max_sequence_length:
                self.flow_sequences[flow_id] = self.flow_sequences[flow_id][-self.max_sequence_length:]
                
            # Check for C&C pattern if sequence is long enough
            if len(self.flow_sequences[flow_id]) >= self.min_sequence_length:
                self._check_for_cc_pattern(flow_id)
                
        # Clean up old sequences
        self._cleanup_old_sequences()
        
    def _generate_stratoletter(self, flow_id: Tuple, timestamp: float, 
                               duration: float, orig_bytes: int, 
                               resp_bytes: int) -> Optional[str]:
        """
        Generate a Stratosphere letter for a flow
        
        Args:
            flow_id: Flow identifier tuple (src_ip, dst_ip, dst_port/proto)
            timestamp: Flow timestamp
            duration: Flow duration
            orig_bytes: Bytes sent by originator
            resp_bytes: Bytes sent by responder
            
        Returns:
            Stratosphere letter or None if can't be generated
        """
        # Calculate hours since last flow for this ID
        hours_since_last = 0
        if flow_id in self.last_flow_times:
            time_diff = timestamp - self.last_flow_times[flow_id]
            hours_since_last = time_diff / 3600  # Convert to hours
            
        # Calculate periodicity
        periodicity = 4  # Default: Strongly not periodic (1-4 scale)
        if flow_id in self.last_flow_times and len(self.flow_sequences[flow_id]) >= 2:
            # Simple periodicity calculation based on time differences
            prev_timestamps = [self.last_flow_times[flow_id]]
            time_diffs = [timestamp - prev_timestamps[-1]]
            
            if len(time_diffs) > 1:
                # Calculate variation in time differences
                mean_diff = sum(time_diffs) / len(time_diffs)
                variance = sum((diff - mean_diff) ** 2 for diff in time_diffs) / len(time_diffs)
                std_dev = math.sqrt(variance)
                
                # Calculate coefficient of variation (normalized std dev)
                if mean_diff > 0:
                    cv = std_dev / mean_diff
                    
                    # Map CV to periodicity scale (lower CV = more periodic)
                    if cv < self.periodicity_threshold:
                        periodicity = 1  # Strongly periodic
                    elif cv < self.periodicity_threshold * 2:
                        periodicity = 2  # Weakly periodic
                    elif cv < self.periodicity_threshold * 3:
                        periodicity = 3  # Weakly not periodic
                    else:
                        periodicity = 4  # Strongly not periodic
        
        # Determine size category (1-3 scale)
        total_bytes = orig_bytes + resp_bytes
        if total_bytes < 1000:  # Less than 1KB
            size = 1  # Small
        elif total_bytes < 10000:  # Less than 10KB
            size = 2  # Medium
        else:  # 10KB or larger
            size = 3  # Large
            
        # Determine duration category (1-3 scale)
        if duration < 1:  # Less than 1 second
            dur = 1  # Short
        elif duration < 10:  # Less than 10 seconds
            dur = 2  # Medium
        else:  # 10 seconds or longer
            dur = 3  # Long
            
        # Generate the letter based on periodicity, size, and duration
        letter = self._get_letter(periodicity, size, dur)
        
        # Add time prefix (zeroes for each full hour since last flow)
        time_prefix = '0' * int(hours_since_last)
        
        # Add time suffix
        time_suffix = ''
        fractional_hour = hours_since_last - int(hours_since_last)
        if fractional_hour < 0.25:
            time_suffix = ''  # No suffix for very recent flows
        elif fractional_hour < 0.5:
            time_suffix = '.'
        elif fractional_hour < 0.75:
            time_suffix = ','
        else:
            time_suffix = '+'
            
        # Combine to create the stratoletter
        return f"{time_prefix}{letter}{time_suffix}"
        
    def _get_letter(self, periodicity: int, size: int, duration: int) -> str:
        """
        Get Stratosphere letter based on periodicity, size, and duration
        
        Args:
            periodicity: Periodicity category (1-4)
            size: Size category (1-3)
            duration: Duration category (1-3)
            
        Returns:
            Stratosphere letter
        """
        # Define letter mapping
        letter_map = {
            # Strongly periodic (1)
            (1, 1, 1): 'a', (1, 1, 2): 'b', (1, 1, 3): 'c',
            (1, 2, 1): 'd', (1, 2, 2): 'e', (1, 2, 3): 'f',
            (1, 3, 1): 'g', (1, 3, 2): 'h', (1, 3, 3): 'i',
            
            # Weakly periodic (2)
            (2, 1, 1): 'A', (2, 1, 2): 'B', (2, 1, 3): 'C',
            (2, 2, 1): 'D', (2, 2, 2): 'E', (2, 2, 3): 'F',
            (2, 3, 1): 'G', (2, 3, 2): 'H', (2, 3, 3): 'I',
            
            # Weakly not periodic (3)
            (3, 1, 1): 'j', (3, 1, 2): 'k', (3, 1, 3): 'l',
            (3, 2, 1): 'm', (3, 2, 2): 'n', (3, 2, 3): 'o',
            (3, 3, 1): 'p', (3, 3, 2): 'q', (3, 3, 3): 'r',
            
            # Strongly not periodic (4)
            (4, 1, 1): 'J', (4, 1, 2): 'K', (4, 1, 3): 'L',
            (4, 2, 1): 'M', (4, 2, 2): 'N', (4, 2, 3): 'O',
            (4, 3, 1): 'P', (4, 3, 2): 'Q', (4, 3, 3): 'R',
        }
        
        # Ensure values are in correct range
        periodicity = max(1, min(4, periodicity))
        size = max(1, min(3, size))
        duration = max(1, min(3, duration))
        
        # Return mapped letter
        return letter_map.get((periodicity, size, duration), 'X')  # X is used for unknown combinations
        
    def _check_for_cc_pattern(self, flow_id: Tuple) -> None:
        """
        Check if a flow sequence matches a C&C pattern
        
        Args:
            flow_id: Flow identifier tuple (src_ip, dst_ip, dst_port/proto)
        """
        if flow_id not in self.flow_sequences or len(self.flow_sequences[flow_id]) < self.min_sequence_length:
            return
            
        # Get sequence
        sequence = self.flow_sequences[flow_id]
        
        # Prepare sequence for model input
        sequence_encoded = self._encode_sequence(sequence)
        
        # Make prediction
        prediction = self.model.predict(np.array([sequence_encoded]), verbose=0)[0][0]
        
        # Calculate confidence based on prediction certainty
        confidence = abs(prediction - 0.5) * 2  # Scale to 0-1
        
        # Set evidence if probability exceeds threshold with sufficient confidence
        if prediction >= self.prediction_threshold and confidence >= self.min_confidence:
            src_ip, dst_ip, dst_port_proto = flow_id
            
            # Create evidence
            evidence = {
                'ip': src_ip,  # Source IP is potentially infected
                'type': 'Command-and-Control-channels-detection',
                'description': f"Detected C&C channel, destination IP: {dst_ip} port: {dst_port_proto} score: {prediction:.4f}",
                'threat_level': prediction,
                'confidence': confidence,
                'timestamp': time.time(),
                'details': {
                    'sequence': ''.join(sequence),
                    'dst_ip': dst_ip,
                    'dst_port_proto': dst_port_proto
                }
            }
            
            self.set_evidence(evidence)
            
            # Reset sequence after detection to avoid repeated alerts
            self.flow_sequences[flow_id] = []
            
    def _encode_sequence(self, sequence: List[str]) -> List[float]:
        """
        Encode a stratoletter sequence for RNN input
        
        Args:
            sequence: List of stratoletters
            
        Returns:
            Encoded sequence as a list of float values
        """
        # Simple encoding for demonstration - in a real implementation,
        # this would use a proper encoding scheme
        
        # Pad sequence to max length
        padded_seq = sequence.copy()
        while len(padded_seq) < self.max_sequence_length:
            padded_seq.append('')  # Empty string for padding
            
        # Truncate to max length
        padded_seq = padded_seq[-self.max_sequence_length:]
        
        # Encode each letter
        encoded_seq = []
        for letter in padded_seq:
            # Extract actual letter (ignore time prefixes/suffixes)
            actual_letter = ''
            for char in letter:
                if char.isalpha() or char.isdigit():
                    actual_letter = char
                    break
                    
            # Encode the letter
            if not actual_letter:
                encoded_seq.append(0.0)  # Padding
            elif actual_letter.isalpha():
                if actual_letter.isupper():
                    # Uppercase letters (A-Z) map to 27-52
                    encoded_seq.append((ord(actual_letter) - ord('A') + 27) / 100.0)
                else:
                    # Lowercase letters (a-z) map to 1-26
                    encoded_seq.append((ord(actual_letter) - ord('a') + 1) / 100.0)
            elif actual_letter.isdigit():
                # Digits (0-9) map to 53-62
                encoded_seq.append((int(actual_letter) + 53) / 100.0)
            else:
                encoded_seq.append(0.0)  # Unknown character
                
        return encoded_seq
        
    def _cleanup_old_sequences(self) -> None:
        """Clean up sequences that haven't been updated recently"""
        current_time = time.time()
        timeout = 3600  # 1 hour timeout
        
        to_remove = []
        for flow_id, last_time in self.last_flow_times.items():
            if current_time - last_time > timeout:
                to_remove.append(flow_id)
                
        for flow_id in to_remove:
            if flow_id in self.flow_sequences:
                del self.flow_sequences[flow_id]
            del self.last_flow_times[flow_id]
            
    def _check_remaining_sequences(self) -> None:
        """Check all remaining sequences for C&C patterns"""
        for flow_id in list(self.flow_sequences.keys()):
            if len(self.flow_sequences[flow_id]) >= self.min_sequence_length:
                self._check_for_cc_pattern(flow_id)
