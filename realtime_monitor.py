#!/usr/bin/env python3
"""
Real-time monitoring component for Suricata JSON analysis
"""
import os
import time
import json
import logging
import threading
import queue
import datetime
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import numpy as np
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Local imports
from ml_module import MLModel
from core_processing import SuricataParser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('realtime_monitor')


class AlertManager:
    """Manage and process alerts"""
    
    def __init__(self, telegram_token: str = None, chat_id: str = None):
        """
        Initialize the alert manager
        
        Args:
            telegram_token: Telegram bot token for sending alerts
            chat_id: Telegram chat ID to receive alerts
        """
        self.telegram_token = telegram_token
        self.chat_id = chat_id
        self.alert_queue = queue.Queue()
        self.alert_history = []
        self.alert_thread = None
        self.running = False
        
    def start(self):
        """Start the alert processing thread"""
        if self.alert_thread is None or not self.alert_thread.is_alive():
            self.running = True
            self.alert_thread = threading.Thread(target=self._process_alerts)
            self.alert_thread.daemon = True
            self.alert_thread.start()
            logger.info("Alert manager started")
            
    def stop(self):
        """Stop the alert processing thread"""
        self.running = False
        if self.alert_thread and self.alert_thread.is_alive():
            self.alert_thread.join(timeout=2.0)
            logger.info("Alert manager stopped")
            
    def add_alert(self, alert: Dict[str, Any]):
        """
        Add an alert to the queue
        
        Args:
            alert: Alert data dictionary
        """
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.datetime.now().isoformat()
            
        self.alert_queue.put(alert)
        
    def _process_alerts(self):
        """Process alerts from the queue"""
        while self.running:
            try:
                # Get alert with a timeout to allow checking running flag
                try:
                    alert = self.alert_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Add to history
                self.alert_history.append(alert)
                
                # Send to Telegram if configured
                if self.telegram_token and self.chat_id:
                    self._send_telegram_alert(alert)
                    
                # Mark as processed
                self.alert_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
                
    def _send_telegram_alert(self, alert: Dict[str, Any]):
        """
        Send an alert to Telegram
        
        Args:
            alert: Alert data dictionary
        """
        try:
            import requests
            
            # Format message
            message = self._format_alert_message(alert)
            
            # Send to Telegram
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, data=data)
            
            if response.status_code != 200:
                logger.error(f"Failed to send Telegram alert: {response.text}")
                
        except Exception as e:
            logger.error(f"Error sending Telegram alert: {e}")
            
    def _format_alert_message(self, alert: Dict[str, Any]) -> str:
        """
        Format an alert as a message
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Formatted message string
        """
        # Basic alert formatting
        message = "*NETWORK SECURITY ALERT*\n\n"
        
        # Add alert type
        if 'type' in alert:
            message += f"*Type:* {alert['type']}\n"
            
        # Add severity
        if 'severity' in alert:
            message += f"*Severity:* {alert['severity']}\n"
            
        # Add source/destination
        if 'src_ip' in alert and 'dst_ip' in alert:
            message += f"*Source:* {alert['src_ip']}:{alert.get('src_port', 'N/A')}\n"
            message += f"*Destination:* {alert['dst_ip']}:{alert.get('dst_port', 'N/A')}\n"
            
        # Add protocol
        if 'protocol' in alert:
            message += f"*Protocol:* {alert['protocol']}\n"
            
        # Add timestamp
        if 'timestamp' in alert:
            message += f"*Time:* {alert['timestamp']}\n"
            
        # Add description
        if 'description' in alert:
            message += f"\n{alert['description']}\n"
            
        # Add any additional details
        if 'details' in alert and isinstance(alert['details'], dict):
            message += "\n*Additional Details:*\n"
            for key, value in alert['details'].items():
                message += f"- {key}: {value}\n"
                
        return message
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent alerts
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of recent alerts
        """
        return self.alert_history[-limit:] if self.alert_history else []


class SuricataLogWatcher(FileSystemEventHandler):
    """Watch Suricata log files for changes and process new entries"""
    
    def __init__(self, log_file: str, ml_model: MLModel, alert_manager: AlertManager):
        """
        Initialize the log watcher
        
        Args:
            log_file: Path to the Suricata log file to watch
            ml_model: MLModel instance for analysis
            alert_manager: AlertManager for handling alerts
        """
        super().__init__()
        self.log_file = log_file
        self.ml_model = ml_model
        self.alert_manager = alert_manager
        self.parser = SuricataParser()
        self.last_position = 0
        self.buffer = ""
        
    def on_modified(self, event):
        """
        Handle file modification events
        
        Args:
            event: File system event
        """
        if not event.is_directory and event.src_path == self.log_file:
            self.process_new_lines()
            
    def process_new_lines(self):
        """Process new lines in the log file"""
        try:
            # Open file and seek to last position
            with open(self.log_file, 'r') as f:
                f.seek(self.last_position)
                new_data = f.read()
                self.last_position = f.tell()
                
            if not new_data:
                return
                
            # Process new data
            self.buffer += new_data
            lines = self.buffer.split('\n')
            
            # Keep last line in buffer if it's not complete
            if not self.buffer.endswith('\n'):
                self.buffer = lines[-1]
                lines = lines[:-1]
            else:
                self.buffer = ""
                
            # Process complete lines
            for line in lines:
                if not line.strip():
                    continue
                    
                self.process_line(line)
                
        except Exception as e:
            logger.error(f"Error processing new lines: {e}")
            
    def process_line(self, line: str):
        """
        Process a single line of Suricata JSON
        
        Args:
            line: JSON log line
        """
        try:
            # Parse the line
            event = self.parser.parse_line(line)
            
            if not event:
                return
                
            # Check if it's an alert from Suricata
            is_suricata_alert = False
            signature = ""
            signature_id = 0
            category = ""
            severity = 0
            
            if hasattr(event, 'type_') and event.type_ == 'alert':
                is_suricata_alert = True
                signature = getattr(event, 'signature', "")
                signature_id = getattr(event, 'signature_id', 0)
                category = getattr(event, 'category', "")
                severity = getattr(event, 'severity', 0)
                
            # Extract features for ML analysis
            feature_dict = {}
            
            if hasattr(event, 'uid'):
                # Create a small DataFrame with just this event
                feature_dict = {
                    'uid': event.uid,
                    'src_ip': event.saddr,
                    'dst_ip': event.daddr,
                    'src_port': event.sport,
                    'dst_port': event.dport,
                    'protocol': event.proto,
                }
                
                # Add protocol-specific fields
                if hasattr(event, 'dur'):
                    feature_dict['duration'] = event.dur
                    feature_dict['total_bytes'] = event.bytes
                    feature_dict['total_packets'] = event.pkts
                    
                # Create DataFrame
                df = pd.DataFrame([feature_dict])
                
                # Extract features
                feature_df = self.ml_model.feature_extractor.process_events([event])
                
                # Analyze with ML models
                if feature_df:
                    # Get flow identifiers
                    flow_id = list(feature_df.keys())[0]
                    flow_features = feature_df[flow_id]
                    
                    # Prepare feature vector
                    feature_vector = np.array([list(flow_features.values())])
                    
                    # Make predictions
                    try:
                        results = self.ml_model.predict(feature_vector)
                        
                        # Check for ML-detected anomalies
                        is_ml_alert = False
                        alert_type = ""
                        alert_score = 0.0
                        
                        if (results['supervised'] is not None and 
                            results['supervised']['prediction'][0] == 1):
                            is_ml_alert = True
                            alert_type = "supervised"
                            alert_score = float(results['supervised']['probability'][0][1])
                            
                        elif (results['anomaly'] is not None and 
                              results['anomaly']['prediction'][0] == 1):
                            is_ml_alert = True
                            alert_type = "anomaly"
                            alert_score = float(results['anomaly']['scores'][0])
                            
                        # Create and send alert if needed
                        if is_suricata_alert or is_ml_alert:
                            alert = {
                                'timestamp': datetime.datetime.now().isoformat(),
                                'src_ip': event.saddr,
                                'src_port': event.sport,
                                'dst_ip': event.daddr,
                                'dst_port': event.dport,
                                'protocol': event.proto,
                            }
                            
                            if is_suricata_alert:
                                alert.update({
                                    'type': 'Suricata Signature Alert',
                                    'signature': signature,
                                    'signature_id': signature_id,
                                    'category': category,
                                    'severity': severity,
                                    'description': f"Suricata detected: {signature}"
                                })
                                
                            elif is_ml_alert:
                                alert.update({
                                    'type': 'ML-Based Anomaly Detection',
                                    'alert_type': alert_type,
                                    'score': alert_score,
                                    'severity': 'High' if alert_score > 0.8 else 'Medium',
                                    'description': f"Behavioral anomaly detected ({alert_type})"
                                })
                                
                            # Add alert to manager
                            self.alert_manager.add_alert(alert)
                            
                    except Exception as e:
                        logger.error(f"Error making predictions: {e}")
                        
        except Exception as e:
            logger.error(f"Error processing line: {e}")


class RealTimeMonitor:
    """Real-time monitoring of Suricata logs"""
    
    def __init__(self, log_file: str, model_dir: str = 'models', 
                 telegram_token: str = None, chat_id: str = None):
        """
        Initialize the real-time monitor
        
        Args:
            log_file: Path to the Suricata log file to monitor
            model_dir: Directory containing ML models
            telegram_token: Telegram bot token for sending alerts
            chat_id: Telegram chat ID to receive alerts
        """
        self.log_file = log_file
        self.model_dir = model_dir
        self.telegram_token = telegram_token
        self.chat_id = chat_id
        
        # Initialize components
        self.ml_model = MLModel(model_dir)
        self.ml_model.load_models()
        
        self.alert_manager = AlertManager(telegram_token, chat_id)
        
        self.log_watcher = SuricataLogWatcher(log_file, self.ml_model, self.alert_manager)
        self.observer = None
        
    def start(self):
        """Start monitoring"""
        # Start alert manager
        self.alert_manager.start()
        
        # Check if log file exists, create it if not
        if not os.path.exists(self.log_file):
            logger.info(f"Log file {self.log_file} does not exist, creating empty file")
            with open(self.log_file, 'w') as f:
                pass
                
        # Process any existing content
        self.log_watcher.process_new_lines()
        
        # Start file system observer
        self.observer = Observer()
        self.observer.schedule(self.log_watcher, os.path.dirname(self.log_file), recursive=False)
        self.observer.start()
        
        logger.info(f"Started monitoring Suricata log file: {self.log_file}")
        
    def stop(self):
        """Stop monitoring"""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            
        self.alert_manager.stop()
        
        logger.info("Stopped monitoring")
        
    def analyze_static_file(self, file_path: str) -> pd.DataFrame:
        """
        Analyze a static Suricata JSON file
        
        Args:
            file_path: Path to the Suricata JSON file
            
        Returns:
            DataFrame with analysis results
        """
        return self.ml_model.analyze_file(file_path)


# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time Suricata log monitor')
    parser.add_argument('--log-file', type=str, default='/var/log/suricata/eve.json',
                        help='Path to Suricata eve.json log file')
    parser.add_argument('--model-dir', type=str, default='models',
                        help='Directory containing ML models')
    parser.add_argument('--telegram-token', type=str, help='Telegram bot token')
    parser.add_argument('--telegram-chat-id', type=str, help='Telegram chat ID')
    parser.add_argument('--static-file', type=str, help='Analyze a static file instead of monitoring')
    
    args = parser.parse_args()
    
    # Create monitor
    monitor = RealTimeMonitor(
        args.log_file,
        args.model_dir,
        args.telegram_token,
        args.telegram_chat_id
    )
    
    if args.static_file:
        # Analyze static file
        logger.info(f"Analyzing static file: {args.static_file}")
        results = monitor.analyze_static_file(args.static_file)
        
        # Print results summary
        alert_count = results.get('has_alert', 0).sum() if 'has_alert' in results.columns else 0
        total_flows = len(results)
        
        logger.info(f"Analysis complete: {alert_count} alerts in {total_flows} flows")
        
        # Save results to CSV
        output_file = f"analysis_results_{os.path.basename(args.static_file)}.csv"
        results.to_csv(output_file, index=False)
        logger.info(f"Results saved to {output_file}")
        
    else:
        # Start monitoring
        try:
            monitor.start()
            
            # Keep running until interrupted
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            
        finally:
            monitor.stop()
