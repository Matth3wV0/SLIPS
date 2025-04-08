#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flow ML Detection module for SLIPS Simplified
Uses machine learning to detect malicious flows
"""

import os
import time
import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional

try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from modules.module_interface import IModule


class FlowMLDetection(IModule):
    """Machine learning-based flow detection module"""
    
    def __init__(self, db, config, should_stop):
        """
        Initialize the flow ML detection module
        
        Args:
            db: Database instance
            config: Module configuration dictionary
            should_stop: Shared value to indicate when to stop processing
        """
        # Set module metadata
        self.name = "FlowMLDetection"
        self.description = "Machine learning-based flow detection"
        self.authors = ["SLIPS Simplified"]
        
        # Call parent constructor
        super().__init__(db, config, should_stop)
        
    def init(self) -> None:
        """Initialize module-specific resources and state"""
        if not SKLEARN_AVAILABLE:
            self.logger.error("sklearn not available. Module will not function properly.")
            return
            
        # Subscribe to new flows
        self.subscribe('new_flow')
        
        # Initialize model and scaler
        self.model = None
        self.scaler = None
        self.feature_names = None
        
        # Load model if available
        model_path = self.config.get('model_path', 'models/flow_model.joblib')
        scaler_path = self.config.get('scaler_path', 'models/flow_scaler.joblib')
        
        self._load_model(model_path, scaler_path)
        
        # If model not available, train a basic one if in training mode
        if self.model is None and self.config.get('mode') == 'train':
            self._initialize_model()
            
        # Detection thresholds
        self.prediction_threshold = self.config.get('prediction_threshold', 0.7)
        self.min_confidence = self.config.get('min_confidence', 0.5)
        
        # Feature extraction settings
        self.continuous_features = [
            'duration', 'orig_bytes', 'resp_bytes', 
            'missing_bytes', 'orig_pkts', 'orig_ip_bytes',
            'resp_pkts', 'resp_ip_bytes'
        ]
        
        self.categorical_features = [
            'proto', 'service', 'conn_state'
        ]
        
        # Pre-defined feature dictionary for known protocols and services
        self.proto_dict = {'tcp': 0, 'udp': 1, 'icmp': 2}
        self.service_dict = {
            'http': 0, 'dns': 1, 'ssl': 2, 'ssh': 3, 
            'smtp': 4, 'ftp': 5, 'dhcp': 6, 'ntp': 7
        }
        self.conn_state_dict = {
            'S0': 0, 'S1': 1, 'SF': 2, 'REJ': 3, 
            'S2': 4, 'S3': 5, 'RSTO': 6, 'RSTR': 7,
            'RSTOS0': 8, 'RSTRH': 9, 'SH': 10, 'SHR': 11,
            'OTH': 12
        }
        
        self.logger.info("Flow ML Detection module initialized")
        
    def shutdown(self) -> None:
        """Clean up module resources before shutting down"""
        # Save model if in training mode
        if self.config.get('mode') == 'train' and self.model is not None:
            model_path = self.config.get('model_path', 'models/flow_model.joblib')
            scaler_path = self.config.get('scaler_path', 'models/flow_scaler.joblib')
            
            # Create models directory if it doesn't exist
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            # Save model and scaler
            try:
                joblib.dump(self.model, model_path)
                joblib.dump(self.scaler, scaler_path)
                self.logger.info(f"Model saved to {model_path}")
            except Exception as e:
                self.logger.error(f"Error saving model: {str(e)}")
                
        self.logger.info("Flow ML Detection module shutdown")
        
    def _load_model(self, model_path: str, scaler_path: str) -> None:
        """
        Load ML model and scaler from files
        
        Args:
            model_path: Path to model file
            scaler_path: Path to scaler file
        """
        try:
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.logger.info(f"Model loaded from {model_path}")
            else:
                self.logger.warning(f"Model files not found at {model_path} and {scaler_path}")
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            
    def _initialize_model(self) -> None:
        """Initialize a new ML model and scaler"""
        self.logger.info("Initializing new ML model")
        
        # Initialize a RandomForest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Initialize a standard scaler
        self.scaler = StandardScaler()
        
        # Define feature names
        self.feature_names = self.continuous_features + self.categorical_features
        
    def process_flow(self, flow: Dict) -> None:
        """
        Process a network flow
        
        Args:
            flow: Flow dictionary
        """
        # Skip if model not available
        if not SKLEARN_AVAILABLE or self.model is None:
            return
        
        # Extract features
        features = self._extract_features(flow)
        
        if features is None:
            return
            
        # Normalize features
        features_scaled = self.scaler.transform([features])
        
        # Get prediction
        predictions = self.model.predict_proba(features_scaled)
        
        # Get malicious class probability (assuming binary classification)
        if len(predictions[0]) >= 2:
            malicious_prob = predictions[0][1]  # Probability of malicious class
        else:
            malicious_prob = predictions[0][0]  # Only one class, use its probability
            
        # Calculate confidence based on prediction certainty
        confidence = abs(malicious_prob - 0.5) * 2  # Scale to 0-1
        
        # Set evidence if probability exceeds threshold with sufficient confidence
        if malicious_prob >= self.prediction_threshold and confidence >= self.min_confidence:
            src_ip = flow.get('id.orig_h')
            dest_ip = flow.get('id.resp_h')
            
            # Create evidence
            evidence = {
                'ip': src_ip,  # Consider source IP as potentially malicious
                'type': 'MaliciousFlow',
                'description': f"Detected potentially malicious flow to {dest_ip}:{flow.get('id.resp_p')} with {malicious_prob:.2f} probability",
                'threat_level': malicious_prob,
                'confidence': confidence,
                'timestamp': time.time(),
                'flow': flow
            }
            
            self.set_evidence(evidence)
            
    def _extract_features(self, flow: Dict) -> Optional[List[float]]:
        """
        Extract features from a flow
        
        Args:
            flow: Flow dictionary
            
        Returns:
            List of numerical features or None if features could not be extracted
        """
        try:
            features = []
            
            # Extract continuous features
            for feature in self.continuous_features:
                # Map Zeek fields to our feature names
                zeek_field = self._map_feature_to_zeek_field(feature)
                value = float(flow.get(zeek_field, 0))
                features.append(value)
                
            # Extract categorical features
            for feature in self.categorical_features:
                zeek_field = self._map_feature_to_zeek_field(feature)
                value = flow.get(zeek_field, '')
                
                # Convert categorical values to numeric using pre-defined dictionaries
                if feature == 'proto':
                    features.append(float(self.proto_dict.get(value.lower(), -1)))
                elif feature == 'service':
                    features.append(float(self.service_dict.get(value.lower(), -1)))
                elif feature == 'conn_state':
                    features.append(float(self.conn_state_dict.get(value, -1)))
                else:
                    features.append(-1.0)  # Unknown category
                    
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return None
            
    def _map_feature_to_zeek_field(self, feature: str) -> str:
        """
        Map feature name to Zeek field name
        
        Args:
            feature: Feature name
            
        Returns:
            Zeek field name
        """
        # Define mappings from our feature names to Zeek fields
        mappings = {
            'duration': 'duration',
            'orig_bytes': 'orig_bytes',
            'resp_bytes': 'resp_bytes',
            'missing_bytes': 'missing_bytes',
            'orig_pkts': 'orig_pkts',
            'orig_ip_bytes': 'orig_ip_bytes',
            'resp_pkts': 'resp_pkts',
            'resp_ip_bytes': 'resp_ip_bytes',
            'proto': 'proto',
            'service': 'service',
            'conn_state': 'conn_state'
        }
        
        return mappings.get(feature, feature)
