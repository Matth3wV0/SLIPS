# main.py

import os
import sys
import argparse
import time
import signal
import logging
import pandas as pd
import numpy as np
from datetime import datetime

# Import configuration
from config import Config, create_default_config_files

# Import input modules
from input.file_reader import SuricataFileReader
from input.stream_reader import SuricataStreamReader

# Import feature extraction
from features.extractor import FeatureExtractor

# Import ML models
from models.unsupervised import VAEAnomalyDetector, IsolationForestDetector
from models.supervised import RandomForestModel
from models.ensemble import EnsembleDetector

# Import alert modules
from alerts.generator import AlertGenerator
from alerts.telegram import TelegramNotifier

class SlipsSuricata:
    """
    Main SLIPS-Suricata application
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the application
        
        Args:
            config_path (str): Path to configuration file
        """
        # Create default config files if they don't exist
        create_default_config_files()
        
        # Load configuration
        self.config = Config(config_path or 'config/config.yaml')
        
        # Set up logging
        self.logger = self.config.setup_logging()
        
        # Create required directories
        self.paths = self.config.create_paths()
        
        # Initialize components to None
        self.telegram_notifier = None
        self.alert_generator = None
        self.feature_extractor = None
        self.file_reader = None
        self.stream_reader = None
        self.vae_model = None
        self.isolation_forest_model = None
        self.random_forest_model = None
        self.ensemble_model = None
        
        # Runtime state
        self.running = True
        self.feature_cache = {}
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def initialize(self):
        """
        Initialize all components
        
        Returns:
            bool: Whether initialization was successful
        """
        try:
            # Validate configuration
            valid, errors = self.config.validate()
            if not valid:
                for error in errors:
                    self.logger.error(f"Configuration error: {error}")
                return False
            
            # Initialize Telegram notifier if enabled
            if self.config.get('telegram.enabled'):
                self.telegram_notifier = TelegramNotifier(
                    bot_token=self.config.get('telegram.bot_token'),
                    chat_id=self.config.get('telegram.chat_id'),
                    log_callback=self._log_callback,
                    min_severity=self.config.get('telegram.min_severity'),
                    rate_limit=self.config.get('telegram.rate_limit')
                )
            
            # Initialize alert generator
            self.alert_generator = AlertGenerator(
                output_dir=self.paths['alert_dir'],
                log_callback=self._log_callback,
                telegram_notifier=self.telegram_notifier
            )
            
            # Initialize feature extractor
            self.feature_extractor = FeatureExtractor()
            
            # Initialize input readers
            self.file_reader = SuricataFileReader(log_callback=self._log_callback)
            self.stream_reader = SuricataStreamReader(log_callback=self._log_callback)
            
            # Log initialization status
            self.logger.info("SLIPS-Suricata initialized successfully")
            self.logger.info(f"Running in {self.config.get('input.mode')} mode")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization error: {str(e)}")
            return False
    
    def run(self):
        """
        Run the main application loop
        
        Returns:
            int: Exit code
        """
        try:
            # Initialize components
            if not self.initialize():
                return 1
            
            # Load or train ML models
            if not self.load_models():
                self.logger.info("No pre-trained models found, will train models")
            
            # Run in appropriate mode
            input_mode = self.config.get('input.mode')
            if input_mode == 'file':
                return self._run_file_mode()
            elif input_mode == 'stream':
                return self._run_stream_mode()
            else:
                self.logger.error(f"Unsupported input mode: {input_mode}")
                return 1
                
        except Exception as e:
            self.logger.error(f"Runtime error: {str(e)}")
            return 1
        finally:
            self.shutdown()
    
    def load_models(self):
        """
        Load pre-trained ML models
        
        Returns:
            bool: Whether any models were loaded
        """
        models_loaded = False
        model_dir = self.paths['model_dir']
        
        # Try to load unsupervised models
        if self.config.get('ml.use_unsupervised'):
            # Try to load VAE model
            vae_path = os.path.join(model_dir, 'vae')
            if os.path.exists(f"{vae_path}_metadata.pkl"):
                try:
                    self.vae_model = VAEAnomalyDetector.load(vae_path)
                    self.logger.info("Loaded VAE model")
                    models_loaded = True
                except Exception as e:
                    self.logger.warning(f"Failed to load VAE model: {str(e)}")
            
            # Try to load Isolation Forest model
            if_path = os.path.join(model_dir, 'isolation_forest.pkl')
            if os.path.exists(if_path):
                try:
                    self.isolation_forest_model = IsolationForestDetector.load(if_path)
                    self.logger.info("Loaded Isolation Forest model")
                    models_loaded = True
                except Exception as e:
                    self.logger.warning(f"Failed to load Isolation Forest model: {str(e)}")
        
        # Try to load supervised model
        if self.config.get('ml.use_supervised'):
            # Try to load Random Forest model
            rf_path = os.path.join(model_dir, 'random_forest.pkl')
            if os.path.exists(rf_path):
                try:
                    self.random_forest_model = RandomForestModel.load(rf_path)
                    self.logger.info("Loaded Random Forest model")
                    models_loaded = True
                except Exception as e:
                    self.logger.warning(f"Failed to load Random Forest model: {str(e)}")
        
        # Try to load ensemble model
        ensemble_path = os.path.join(model_dir, 'ensemble.pkl')
        if os.path.exists(ensemble_path):
            try:
                # Create a list of loaded models
                models = []
                if self.vae_model:
                    models.append(self.vae_model)
                if self.isolation_forest_model:
                    models.append(self.isolation_forest_model)
                if self.random_forest_model:
                    models.append(self.random_forest_model)
                
                # Load ensemble
                self.ensemble_model = EnsembleDetector.load(ensemble_path, models)
                self.logger.info("Loaded ensemble model")
                models_loaded = True
            except Exception as e:
                self.logger.warning(f"Failed to load ensemble model: {str(e)}")
        
        return models_loaded
    
    def save_models(self):
        """
        Save ML models
        
        Returns:
            bool: Whether any models were saved
        """
        models_saved = False
        model_dir = self.paths['model_dir']
        
        # Save VAE model
        if self.vae_model:
            try:
                vae_path = os.path.join(model_dir, 'vae')
                self.vae_model.save(vae_path)
                self.logger.info(f"Saved VAE model to {vae_path}")
                models_saved = True
            except Exception as e:
                self.logger.error(f"Failed to save VAE model: {str(e)}")
        
        # Save Isolation Forest model
        if self.isolation_forest_model:
            try:
                if_path = os.path.join(model_dir, 'isolation_forest.pkl')
                self.isolation_forest_model.save(if_path)
                self.logger.info(f"Saved Isolation Forest model to {if_path}")
                models_saved = True
            except Exception as e:
                self.logger.error(f"Failed to save Isolation Forest model: {str(e)}")
        
        # Save Random Forest model
        if self.random_forest_model:
            try:
                rf_path = os.path.join(model_dir, 'random_forest.pkl')
                self.random_forest_model.save(rf_path)
                self.logger.info(f"Saved Random Forest model to {rf_path}")
                models_saved = True
            except Exception as e:
                self.logger.error(f"Failed to save Random Forest model: {str(e)}")
        
        # Save ensemble model
        if self.ensemble_model:
            try:
                ensemble_path = os.path.join(model_dir, 'ensemble.pkl')
                self.ensemble_model.save(ensemble_path)
                self.logger.info(f"Saved ensemble model to {ensemble_path}")
                models_saved = True
            except Exception as e:
                self.logger.error(f"Failed to save ensemble model: {str(e)}")
        
        return models_saved
    
    def shutdown(self):
        """Perform cleanup and shutdown"""
        self.logger.info("Shutting down SLIPS-Suricata...")
        
        # Stop stream reader if active
        if self.stream_reader:
            self.stream_reader.stop_monitoring()
        
        # Save models if they exist
        self.save_models()
        
        # Log alert statistics
        if self.alert_generator:
            stats = self.alert_generator.get_stats()
            self.logger.info(f"Alert statistics: {stats}")
        
        self.logger.info("Shutdown complete")
    
    def _run_file_mode(self):
        """
        Run in file mode (static analysis)
        
        Returns:
            int: Exit code
        """
        file_path = self.config.get('input.file_path')
        if not file_path:
            self.logger.error("File path not specified")
            return 1
        
        self.logger.info(f"Processing file: {file_path}")
        
        # Process the file
        events = list(self.file_reader.read_file(file_path))
        if not events:
            self.logger.error(f"No events found in file: {file_path}")
            return 1
        
        self.logger.info(f"Found {len(events)} events in file")
        
        # Extract features
        features_df = self._extract_features_batch(events)
        if features_df.empty:
            self.logger.error("No features extracted from events")
            return 1
        
        self.logger.info(f"Extracted {len(features_df)} feature sets")
        
        # Split into training and validation sets
        train_ratio = self.config.get('ml.train_ratio')
        validation_ratio = self.config.get('ml.validation_ratio')
        
        # Find alerts for possible labels
        alert_events = [event for event in events if event.get('event_type') == 'alert']
        alert_ips = set()
        for event in alert_events:
            alert_ips.add(event.get('src_ip'))
            alert_ips.add(event.get('dest_ip'))
        
        # Create labels based on IPs seen in alerts
        labels = []
        for index, row in features_df.iterrows():
            src_ip = row.get('src_ip')
            dest_ip = row.get('dest_ip')
            if src_ip in alert_ips or dest_ip in alert_ips:
                labels.append(1)  # Malicious
            else:
                labels.append(0)  # Benign
        
        labels = pd.Series(labels, index=features_df.index)
        self.logger.info(f"Created labels: {sum(labels)} malicious, {len(labels) - sum(labels)} benign")
        
        # Split data
        msk_train = np.random.rand(len(features_df)) < train_ratio
        msk_val = np.logical_and(np.random.rand(len(features_df)) < (train_ratio + validation_ratio), ~msk_train)
        msk_test = ~np.logical_or(msk_train, msk_val)
        
        train_features = features_df[msk_train]
        val_features = features_df[msk_val]
        test_features = features_df[msk_test]
        
        train_labels = labels[msk_train]
        val_labels = labels[msk_val]
        test_labels = labels[msk_test]
        
        self.logger.info(f"Split data: {len(train_features)} train, {len(val_features)} validation, {len(test_features)} test")
        
        # Train models
        if self.config.get('ml.use_unsupervised'):
            self._train_unsupervised_models(train_features, val_features)
        
        if self.config.get('ml.use_supervised'):
            self._train_supervised_models(train_features, train_labels, val_features, val_labels)
        
        # Create ensemble if multiple models are available
        self._create_ensemble()
        
        # Evaluate on test set
        self._evaluate_models(test_features, test_labels)
        
        # Process all events for alerts
        self._process_events_for_alerts(events)
        
        return 0
    
    def _run_stream_mode(self):
        """
        Run in stream mode (real-time monitoring)
        
        Returns:
            int: Exit code
        """
        # Get Suricata configuration
        suricata_eve_path = self.config.get('input.suricata_eve_path')
        suricata_command = self.config.get('input.suricata_command')
        
        # Start monitoring
        if not self.stream_reader.start_monitoring(
            filepath=suricata_eve_path,
            suricata_command=suricata_command
        ):
            self.logger.error("Failed to start Suricata monitoring")
            return 1
        
        self.logger.info("Started real-time monitoring")
        
        # Main monitoring loop
        batch_size = self.config.get('ml.batch_size', 1000)
        events_processed = 0
        
        while self.running:
            # Get a batch of events
            events = self.stream_reader.get_events_batch(
                max_batch_size=batch_size,
                timeout=1.0
            )
            
            # Process events if any
            if events:
                start_time = time.time()
                self._process_events_for_alerts(events)
                
                events_processed += len(events)
                batch_duration = time.time() - start_time
                
                # Generate batch summary
                anomaly_count = sum(1 for event in events if event.get('event_type') == 'alert')
                self.alert_generator.generate_batch_summary(
                    total_events=len(events),
                    anomaly_count=anomaly_count,
                    batch_duration=batch_duration
                )
                
                # Periodically log progress
                if events_processed % (10 * batch_size) == 0:
                    self.logger.info(f"Processed {events_processed} events so far")
            
            # Short sleep to prevent CPU spinning
            time.sleep(0.01)
        
        return 0
    
    def _train_unsupervised_models(self, train_features, val_features):
        """
        Train unsupervised models
        
        Args:
            train_features (pd.DataFrame): Training features
            val_features (pd.DataFrame): Validation features
        """
        # Get only numerical features for training
        numeric_cols = train_features.select_dtypes(include=['number']).columns
        X_train = train_features[numeric_cols]
        X_val = val_features[numeric_cols]
        
        self.logger.info(f"Training unsupervised models with {len(X_train)} samples and {len(numeric_cols)} features")
        
        # Train VAE model
        if 'vae' in self.config.get('ml.unsupervised.model_type', ''):
            self.logger.info("Training VAE model...")
            
            # Initialize model
            self.vae_model = VAEAnomalyDetector(
                input_dim=len(numeric_cols),
                latent_dim=self.config.get('ml.unsupervised.vae_latent_dim', 10),
                hidden_layers=self.config.get('ml.unsupervised.vae_hidden_layers', [64, 32])
            )
            
            # Train model
            self.vae_model.fit(
                X_train,
                validation_split=0.1,
                batch_size=32,
                epochs=50
            )
            
            self.logger.info("VAE model training complete")
        
        # Train Isolation Forest model
        if 'isolation_forest' in self.config.get('ml.unsupervised.model_type', ''):
            self.logger.info("Training Isolation Forest model...")
            
            # Initialize model
            self.isolation_forest_model = IsolationForestDetector(
                contamination=self.config.get('ml.unsupervised.contamination', 0.01)
            )
            
            # Train model
            self.isolation_forest_model.fit(X_train, use_pca=True)
            
            self.logger.info("Isolation Forest model training complete")
    
    def _train_supervised_models(self, train_features, train_labels, val_features, val_labels):
        """
        Train supervised models
        
        Args:
            train_features (pd.DataFrame): Training features
            train_labels (pd.Series): Training labels
            val_features (pd.DataFrame): Validation features
            val_labels (pd.Series): Validation labels
        """
        # Get only numerical features for training
        numeric_cols = train_features.select_dtypes(include=['number']).columns
        X_train = train_features[numeric_cols]
        X_val = val_features[numeric_cols]
        
        self.logger.info(f"Training supervised models with {len(X_train)} samples, {sum(train_labels)} positive, {len(train_labels) - sum(train_labels)} negative")
        
        # Train Random Forest model
        if self.config.get('ml.supervised.model_type') == 'random_forest':
            self.logger.info("Training Random Forest model...")
            
            # Initialize model
            self.random_forest_model = RandomForestModel(
                n_estimators=self.config.get('ml.supervised.n_estimators', 100),
                max_depth=self.config.get('ml.supervised.max_depth')
            )
            
            # Train model
            self.random_forest_model.fit(X_train, train_labels)
            
            # Evaluate on validation set
            val_preds = self.random_forest_model.predict(X_val)
            accuracy = sum(val_preds == val_labels) / len(val_labels)
            
            self.logger.info(f"Random Forest model training complete, validation accuracy: {accuracy:.4f}")
            
            # Get top features
            top_features = self.random_forest_model.get_top_features(10)
            if top_features is not None:
                top_features_str = ", ".join([f"{name}" for name in top_features.index])
                self.logger.info(f"Top features: {top_features_str}")
    
    def _create_ensemble(self):
        """Create an ensemble of available models"""
        if not (self.vae_model or self.isolation_forest_model or self.random_forest_model):
            return
        
        self.logger.info("Creating ensemble model...")
        
        # Initialize ensemble
        self.ensemble_model = EnsembleDetector()
        
        # Add unsupervised models
        if self.vae_model:
            weight = self.config.get('ml.ensembling.weights.vae', 1.0)
            self.ensemble_model.add_model(self.vae_model, weight)
            self.logger.info(f"Added VAE model to ensemble with weight {weight}")
        
        if self.isolation_forest_model:
            weight = self.config.get('ml.ensembling.weights.isolation_forest', 1.0)
            self.ensemble_model.add_model(self.isolation_forest_model, weight)
            self.logger.info(f"Added Isolation Forest model to ensemble with weight {weight}")
        
        if self.random_forest_model:
            weight = self.config.get('ml.ensembling.weights.supervised', 1.0)
            self.ensemble_model.add_model(self.random_forest_model, weight)
            self.logger.info(f"Added Random Forest model to ensemble with weight {weight}")
        
        self.logger.info("Ensemble model created")
    
    def _evaluate_models(self, test_features, test_labels):
        """
        Evaluate trained models
        
        Args:
            test_features (pd.DataFrame): Test features
            test_labels (pd.Series): Test labels (0=normal, 1=anomaly)
        """
        # Get only numerical features
        numeric_cols = test_features.select_dtypes(include=['number']).columns
        X_test = test_features[numeric_cols]
        
        self.logger.info(f"Evaluating models on {len(X_test)} test samples, {sum(test_labels)} positive, {len(test_labels) - sum(test_labels)} negative")
        
        # Evaluate VAE model
        if self.vae_model:
            self._evaluate_model("VAE", self.vae_model, X_test, test_labels)
        
        # Evaluate Isolation Forest model
        if self.isolation_forest_model:
            self._evaluate_model("Isolation Forest", self.isolation_forest_model, X_test, test_labels)
        
        # Evaluate Random Forest model
        if self.random_forest_model:
            self._evaluate_model("Random Forest", self.random_forest_model, X_test, test_labels)
        
        # Evaluate ensemble model
        if self.ensemble_model:
            self._evaluate_model("Ensemble", self.ensemble_model, X_test, test_labels)
    
    def _evaluate_model(self, name, model, X_test, test_labels):
        """
        Evaluate a single model
        
        Args:
            name (str): Model name
            model: Model object
            X_test (pd.DataFrame): Test features
            test_labels (pd.Series): Test labels
        """
        try:
            # Get predictions
            if hasattr(model, 'predict_proba'):
                # Supervised model
                y_pred_proba = model.predict_proba(X_test)[:, 1]
                y_pred = np.where(y_pred_proba >= 0.5, 1, 0)
            else:
                # Unsupervised model
                y_pred = np.where(model.predict(X_test) < 0, 1, 0)
                y_pred_proba = model.decision_function(X_test)
            
            # Calculate metrics
            accuracy = sum(y_pred == test_labels) / len(test_labels)
            
            # True positives, false positives, etc.
            tp = sum((y_pred == 1) & (test_labels == 1))
            fp = sum((y_pred == 1) & (test_labels == 0))
            tn = sum((y_pred == 0) & (test_labels == 0))
            fn = sum((y_pred == 0) & (test_labels == 1))
            
            # Calculate metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # Log results
            self.logger.info(f"{name} model evaluation results:")
            self.logger.info(f"  Accuracy: {accuracy:.4f}")
            self.logger.info(f"  Precision: {precision:.4f}")
            self.logger.info(f"  Recall: {recall:.4f}")
            self.logger.info(f"  F1 Score: {f1:.4f}")
            self.logger.info(f"  TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
            
        except Exception as e:
            self.logger.error(f"Error evaluating {name} model: {str(e)}")
    
    def _extract_features_batch(self, events):
        """
        Extract features from a batch of events
        
        Args:
            events (list): List of Suricata events
            
        Returns:
            pd.DataFrame: Extracted features
        """
        all_features = []
        
        for event in events:
            try:
                # Extract features
                features = self.feature_extractor.extract_features(event)
                
                # Add original source IP and destination IP for reference
                features['src_ip'] = event.get('src_ip')
                features['dest_ip'] = event.get('dest_ip')
                
                # Add to list
                all_features.append(features)
            except Exception as e:
                self.logger.error(f"Error extracting features: {str(e)}")
        
        # Convert to DataFrame if we have features
        if all_features:
            df = pd.DataFrame(all_features)
            
            # Cache feature names
            self.feature_cache['names'] = df.columns.tolist()
            
            return df
        else:
            return pd.DataFrame()
    
    def _process_events_for_alerts(self, events):
        """
        Process events for alerts
        
        Args:
            events (list): List of Suricata events
        """
        # Track already alerted events to avoid duplicates
        alerted_events = set()
        
        # First pass: process Suricata alerts directly
        for event in events:
            event_type = event.get('event_type')
            
            if event_type == 'alert' and event.get('flow_id') not in alerted_events:
                # This is a Suricata alert
                self.alert_generator.generate_alert(
                    source_event=event,
                    detection_source='suricata'
                )
                
                # Mark as alerted
                alerted_events.add(event.get('flow_id'))
        
        # Second pass: ML-based detection
        if self.vae_model or self.isolation_forest_model or self.random_forest_model or self.ensemble_model:
            # Extract features
            features_df = self._extract_features_batch(events)
            
            if not features_df.empty:
                # Get numerical features
                numeric_cols = features_df.select_dtypes(include=['number']).columns
                X = features_df[numeric_cols]
                
                # Use ensemble model if available
                if self.ensemble_model:
                    # Get scores
                    scores = self.ensemble_model.decision_function(X)
                    
                    # Predict anomalies
                    threshold = self.config.get('ml.anomaly_threshold', 0.7)
                    predictions = scores >= threshold
                    
                    # Generate alerts for anomalies
                    for i, (is_anomaly, score) in enumerate(zip(predictions, scores)):
                        if is_anomaly and events[i].get('flow_id') not in alerted_events:
                            # Get top features
                            top_features = self._get_top_features_for_event(events[i], features_df.iloc[i])
                            
                            # Generate alert
                            self.alert_generator.generate_alert(
                                source_event=events[i],
                                detection_source='ml_anomaly',
                                ml_score=score,
                                ml_features=top_features,
                                severity=self._get_severity_from_score(score)
                            )
                            
                            # Mark as alerted
                            alerted_events.add(events[i].get('flow_id'))
                
                # Use supervised model if available
                elif self.random_forest_model:
                    # Get probabilities
                    probs = self.random_forest_model.predict_proba(X)[:, 1]
                    
                    # Predict malicious
                    threshold = 0.5
                    predictions = probs >= threshold
                    
                    # Generate alerts for malicious
                    for i, (is_malicious, prob) in enumerate(zip(predictions, probs)):
                        if is_malicious and events[i].get('flow_id') not in alerted_events:
                            # Get top features
                            top_features = self._get_top_features_for_event(events[i], features_df.iloc[i])
                            
                            # Generate alert
                            self.alert_generator.generate_alert(
                                source_event=events[i],
                                detection_source='ml_classification',
                                ml_score=prob,
                                ml_features=top_features,
                                severity=self._get_severity_from_score(prob)
                            )
                            
                            # Mark as alerted
                            alerted_events.add(events[i].get('flow_id'))
                
                # Use unsupervised models if available
                elif self.vae_model:
                    # Get anomaly scores
                    scores = self.vae_model.decision_function(X)
                    
                    # Predict anomalies
                    threshold = self.config.get('ml.anomaly_threshold', 0.7)
                    predictions = scores >= threshold
                    
                    # Generate alerts for anomalies
                    for i, (is_anomaly, score) in enumerate(zip(predictions, scores)):
                        if is_anomaly and events[i].get('flow_id') not in alerted_events:
                            # Get top features
                            top_features = self._get_top_features_for_event(events[i], features_df.iloc[i])
                            
                            # Generate alert
                            self.alert_generator.generate_alert(
                                source_event=events[i],
                                detection_source='ml_anomaly',
                                ml_score=score,
                                ml_features=top_features,
                                severity=self._get_severity_from_score(score)
                            )
                            
                            # Mark as alerted
                            alerted_events.add(events[i].get('flow_id'))
                
                elif self.isolation_forest_model:
                    # Get anomaly scores
                    scores = self.isolation_forest_model.decision_function(X)
                    
                    # Predict anomalies
                    threshold = self.config.get('ml.anomaly_threshold', 0.7)
                    predictions = scores >= threshold
                    
                    # Generate alerts for anomalies
                    for i, (is_anomaly, score) in enumerate(zip(predictions, scores)):
                        if is_anomaly and events[i].get('flow_id') not in alerted_events:
                            # Get top features
                            top_features = self._get_top_features_for_event(events[i], features_df.iloc[i])
                            
                            # Generate alert
                            self.alert_generator.generate_alert(
                                source_event=events[i],
                                detection_source='ml_anomaly',
                                ml_score=score,
                                ml_features=top_features,
                                severity=self._get_severity_from_score(score)
                            )
                            
                            # Mark as alerted
                            alerted_events.add(events[i].get('flow_id'))
    
    def _get_top_features_for_event(self, event, features_row):
        """
        Get top contributing features for an event
        
        Args:
            event (dict): Suricata event
            features_row (pd.Series): Extracted features
            
        Returns:
            list: Top feature names
        """
        # For now, just return some common suspicious features
        all_features = []
        
        # Check for port scans
        if 'dest_port_is_well_known' in features_row and features_row['dest_port_is_well_known']:
            all_features.append('dest_port_is_well_known')
        
        # Check for suspicious ports
        if 'dest_port' in features_row:
            dest_port = features_row['dest_port']
            if dest_port in [22, 23, 3389, 5900]:
                all_features.append(f'dest_port_{dest_port}')
        
        # Check for protocol
        if 'proto_is_tcp' in features_row and features_row['proto_is_tcp']:
            all_features.append('proto_is_tcp')
        
        # Check for DNS features
        if 'dns_domain_entropy' in features_row and features_row['dns_domain_entropy'] > 4.0:
            all_features.append('high_dns_entropy')
        
        # Check flow features
        if 'flow_direction_imbalance' in features_row and features_row['flow_direction_imbalance'] > 0.8:
            all_features.append('flow_direction_imbalance')
        
        # Return top features or defaults
        return all_features[:5] if all_features else ['unknown']
    
    def _get_severity_from_score(self, score):
        """
        Determine severity based on ML score
        
        Args:
            score (float): ML score (0-1)
            
        Returns:
            str: Severity ('low', 'medium', 'high')
        """
        if score >= 0.8:
            return 'high'
        elif score >= 0.6:
            return 'medium'
        else:
            return 'low'
    
    def _log_callback(self, message, level='info'):
        """
        Callback for logging from other components
        
        Args:
            message (str): Log message
            level (str): Log level
        """
        if level == 'info':
            self.logger.info(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        else:
            self.logger.debug(message)
    
    def _signal_handler(self, sig, frame):
        """
        Handle signals
        
        Args:
            sig: Signal number
            frame: Frame
        """
        self.logger.info(f"Received signal {sig}, shutting down...")
        self.running = False

def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='SLIPS-Suricata: ML-Enhanced Network Intrusion Detection')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-f', '--file', help='Path to Suricata JSON file for analysis')
    parser.add_argument('-m', '--mode', choices=['file', 'stream'], help='Processing mode')
    parser.add_argument('-t', '--telegram', action='store_true', help='Enable Telegram notifications')
    parser.add_argument('--bot-token', help='Telegram bot token')
    parser.add_argument('--chat-id', help='Telegram chat ID')
    args = parser.parse_args()
    
    # Create application
    app = SlipsSuricata(config_path=args.config)
    
    # Override configuration from command line
    if args.file:
        app.config.set('input.mode', 'file')
        app.config.set('input.file_path', args.file)
    
    if args.mode:
        app.config.set('input.mode', args.mode)
    
    if args.telegram:
        app.config.set('telegram.enabled', True)
    
    if args.bot_token:
        app.config.set('telegram.bot_token', args.bot_token)
    
    if args.chat_id:
        app.config.set('telegram.chat_id', args.chat_id)
    
    # Run the application
    return app.run()

if __name__ == '__main__':
    sys.exit(main())
