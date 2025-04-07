# alerts/generator.py

import json
import os
from datetime import datetime
import logging

class AlertGenerator:
    """
    Generate and format alerts from Suricata events and ML detections
    """
    
    def __init__(self, output_dir="alerts", log_callback=None, telegram_notifier=None):
        """
        Initialize the alert generator
        
        Args:
            output_dir (str): Directory to save alerts to
            log_callback (callable): Optional callback for logging
            telegram_notifier (TelegramNotifier): Optional Telegram notifier
        """
        self.logger = logging.getLogger('AlertGenerator')
        self.log_callback = log_callback
        self.telegram_notifier = telegram_notifier
        self.output_dir = output_dir
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize alert file
        self.alert_file = os.path.join(output_dir, f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        # Track alert statistics
        self.alert_counts = {
            'suricata': 0,
            'ml_anomaly': 0,
            'ml_classification': 0,
            'total': 0
        }
    
    def generate_alert(self, source_event, detection_source, ml_score=None, ml_features=None, 
                       additional_info=None, severity=None):
        """
        Generate and save an alert
        
        Args:
            source_event (dict): Original Suricata event that triggered the alert
            detection_source (str): 'suricata', 'ml_anomaly', or 'ml_classification'
            ml_score (float): ML score (0-1 range, higher = more anomalous/malicious)
            ml_features (list): Top features that contributed to the detection
            additional_info (dict): Additional information to include
            severity (str): Alert severity (high, medium, low)
            
        Returns:
            dict: The generated alert
        """
        # Create alert structure
        alert = {
            'timestamp': datetime.now().isoformat(),
            'source_event_time': source_event.get('timestamp'),
            'detection_source': detection_source,
            'source_ip': source_event.get('src_ip'),
            'dest_ip': source_event.get('dest_ip'),
            'src_port': source_event.get('src_port'),
            'dest_port': source_event.get('dest_port'),
            'proto': source_event.get('proto'),
            'event_type': source_event.get('event_type')
        }
        
        # Add ML information if available
        if ml_score is not None:
            alert['ml_score'] = ml_score
        
        if ml_features:
            alert['ml_features'] = ml_features
        
        # Add additional info
        if additional_info:
            alert.update(additional_info)
        
        # Determine severity if not provided
        if severity is None:
            if detection_source == 'suricata':
                # Use Suricata severity if available
                suricata_severity = source_event.get('alert', {}).get('severity')
                if suricata_severity == 1:
                    severity = 'high'
                elif suricata_severity == 2:
                    severity = 'medium'
                else:
                    severity = 'low'
            elif ml_score is not None:
                # Use ML score to determine severity
                if ml_score >= 0.8:
                    severity = 'high'
                elif ml_score >= 0.6:
                    severity = 'medium'
                else:
                    severity = 'low'
            else:
                severity = 'low'
        
        alert['severity'] = severity
        
        # Generate alert description
        alert['description'] = self._generate_description(alert, source_event)
        
        # Write alert to file
        self._write_alert(alert)
        
        # Update statistics
        self.alert_counts[detection_source] += 1
        self.alert_counts['total'] += 1
        
        # Log the alert
        self._log_alert(alert)
        
        # Send to Telegram if configured
        if self.telegram_notifier:
            self.telegram_notifier.send_alert(alert)
        
        return alert
    
    def generate_batch_summary(self, total_events, anomaly_count, batch_duration):
        """
        Generate a summary of processed events
        
        Args:
            total_events (int): Total number of events processed
            anomaly_count (int): Number of anomalies detected
            batch_duration (float): Processing time in seconds
        """
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_events': total_events,
            'anomaly_count': anomaly_count,
            'processing_time': batch_duration,
            'events_per_second': total_events / batch_duration if batch_duration > 0 else 0
        }
        
        # Log summary
        self._log_info(
            f"Batch summary: {total_events} events, {anomaly_count} anomalies "
            f"in {batch_duration:.2f}s ({summary['events_per_second']:.2f} events/s)"
        )
        
        return summary
    
    def _generate_description(self, alert, source_event):
        """
        Generate human-readable alert description
        
        Args:
            alert (dict): The alert structure
            source_event (dict): Original Suricata event
            
        Returns:
            str: Alert description
        """
        description_parts = []
        
        # Detection source specific parts
        if alert['detection_source'] == 'suricata':
            signature = source_event.get('alert', {}).get('signature', 'Unknown signature')
            category = source_event.get('alert', {}).get('category', 'Unknown category')
            description_parts.append(f"Suricata alert: {signature}")
            description_parts.append(f"Category: {category}")
            
        elif alert['detection_source'] == 'ml_anomaly':
            score = alert.get('ml_score', 0)
            description_parts.append(f"ML anomaly detection with score: {score:.3f}")
            
            # Add top contributing features if available
            features = alert.get('ml_features', [])
            if features:
                feature_str = ", ".join([f"{name}" for name in features[:3]])
                description_parts.append(f"Top features: {feature_str}")
                
        elif alert['detection_source'] == 'ml_classification':
            score = alert.get('ml_score', 0)
            description_parts.append(f"ML classification detected malicious traffic with score: {score:.3f}")
            
            # Add top contributing features if available
            features = alert.get('ml_features', [])
            if features:
                feature_str = ", ".join([f"{name}" for name in features[:3]])
                description_parts.append(f"Top features: {feature_str}")
        
        # Add connection information
        proto = alert.get('proto', 'unknown')
        src_ip = alert.get('source_ip', 'unknown')
        src_port = alert.get('src_port', 'unknown')
        dest_ip = alert.get('dest_ip', 'unknown')
        dest_port = alert.get('dest_port', 'unknown')
        
        conn_info = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port} ({proto})"
        description_parts.append(f"Connection: {conn_info}")
        
        # Add severity
        severity = alert.get('severity', 'unknown')
        description_parts.append(f"Severity: {severity}")
        
        return " | ".join(description_parts)
    
    def _write_alert(self, alert):
        """
        Write alert to JSON file
        
        Args:
            alert (dict): The alert to write
        """
        try:
            with open(self.alert_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            self._log_error(f"Error writing alert to file: {str(e)}")
    
    def _log_alert(self, alert):
        """
        Log an alert
        
        Args:
            alert (dict): The alert to log
        """
        severity = alert.get('severity', 'unknown')
        source = alert.get('detection_source', 'unknown')
        description = alert.get('description', 'No description')
        
        # Format for visual distinction
        if severity == 'high':
            prefix = "🔴 HIGH SEVERITY"
        elif severity == 'medium':
            prefix = "🟠 MEDIUM SEVERITY"
        else:
            prefix = "🟡 LOW SEVERITY"
        
        message = f"{prefix} | {source.upper()} | {description}"
        self._log_warning(message)
    
    def get_stats(self):
        """
        Get alert statistics
        
        Returns:
            dict: Alert statistics
        """
        return self.alert_counts
    
    def _log_info(self, message):
        """Log an info message"""
        self.logger.info(message)
        if self.log_callback:
            self.log_callback(message, 'info')
    
    def _log_warning(self, message):
        """Log a warning message"""
        self.logger.warning(message)
        if self.log_callback:
            self.log_callback(message, 'warning')
    
    def _log_error(self, message):
        """Log an error message"""
        self.logger.error(message)
        if self.log_callback:
            self.log_callback(message, 'error')

# alerts/telegram.py

import requests
import logging
import json
import time
from datetime import datetime

class TelegramNotifier:
    """
    Send alert notifications to Telegram
    """
    
    def __init__(self, bot_token, chat_id, log_callback=None, min_severity='low', rate_limit=10):
        """
        Initialize the Telegram notifier
        
        Args:
            bot_token (str): Telegram bot token
            chat_id (str): Telegram chat ID to send messages to
            log_callback (callable): Optional callback for logging
            min_severity (str): Minimum severity to notify ('low', 'medium', 'high')
            rate_limit (int): Maximum notifications per minute
        """
        self.logger = logging.getLogger('TelegramNotifier')
        self.log_callback = log_callback
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.min_severity = min_severity
        self.rate_limit = rate_limit
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        # Alert count and timestamps for rate limiting
        self.alert_timestamps = []
        
        # Test connection
        self.test_connection()
    
    def test_connection(self):
        """Test the Telegram connection"""
        try:
            message = f"🔔 SLIPS-Suricata monitoring started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            self.send_message(message)
            self._log_info("Telegram connection successful")
            return True
        except Exception as e:
            self._log_error(f"Telegram connection failed: {str(e)}")
            return False
    
    def send_alert(self, alert):
        """
        Send alert notification to Telegram
        
        Args:
            alert (dict): Alert data
            
        Returns:
            bool: Whether the notification was sent
        """
        # Check if we should send this alert based on severity
        severity = alert.get('severity', 'low')
        if not self._should_send_alert(severity):
            return False
        
        # Apply rate limiting
        if not self._check_rate_limit():
            self._log_warning("Rate limit exceeded, skipping Telegram notification")
            return False
        
        # Format alert message
        message = self._format_alert(alert)
        
        # Send notification
        return self.send_message(message)
    
    def send_message(self, message):
        """
        Send a message to Telegram
        
        Args:
            message (str): Message to send
            
        Returns:
            bool: Whether the message was sent successfully
        """
        try:
            # Prepare request data
            data = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            # Send request
            response = requests.post(self.api_url, data=data)
            response.raise_for_status()
            
            # Check response
            result = response.json()
            if result.get('ok'):
                # Update rate limiting tracker
                self.alert_timestamps.append(time.time())
                return True
            else:
                self._log_error(f"Failed to send Telegram message: {result}")
                return False
                
        except Exception as e:
            self._log_error(f"Error sending Telegram notification: {str(e)}")
            return False
    
    def _format_alert(self, alert):
        """
        Format alert for Telegram
        
        Args:
            alert (dict): Alert data
            
        Returns:
            str: Formatted message
        """
        # Get alert details
        severity = alert.get('severity', 'low')
        source = alert.get('detection_source', 'unknown')
        description = alert.get('description', 'No description')
        source_ip = alert.get('source_ip', 'unknown')
        dest_ip = alert.get('dest_ip', 'unknown')
        src_port = alert.get('src_port', 'unknown')
        dest_port = alert.get('dest_port', 'unknown')
        proto = alert.get('proto', 'unknown')
        event_time = alert.get('source_event_time', 'unknown')
        
        # Format severity emoji
        if severity == 'high':
            emoji = '🔴'
        elif severity == 'medium':
            emoji = '🟠'
        else:
            emoji = '🟡'
        
        # Construct message
        message = (
            f"{emoji} <b>SECURITY ALERT</b> {emoji}\n\n"
            f"<b>Source:</b> {source.upper()}\n"
            f"<b>Severity:</b> {severity.upper()}\n"
            f"<b>Time:</b> {event_time}\n\n"
            f"<b>Details:</b> {description}\n\n"
            f"<b>Connection:</b>\n"
            f"{source_ip}:{src_port} → {dest_ip}:{dest_port} ({proto})"
        )
        
        # Add ML details if available
        ml_score = alert.get('ml_score')
        if ml_score is not None:
            message += f"\n\n<b>ML Score:</b> {ml_score:.3f}"
        
        ml_features = alert.get('ml_features')
        if ml_features:
            feature_str = ", ".join([f"{name}" for name in ml_features[:3]])
            message += f"\n<b>Top Features:</b> {feature_str}"
        
        return message
    
    def _should_send_alert(self, severity):
        """
        Check if an alert should be sent based on severity
        
        Args:
            severity (str): Alert severity
            
        Returns:
            bool: Whether to send the alert
        """
        severity_order = {
            'low': 0,
            'medium': 1,
            'high': 2
        }
        
        alert_level = severity_order.get(severity.lower(), 0)
        min_level = severity_order.get(self.min_severity.lower(), 0)
        
        return alert_level >= min_level
    
    def _check_rate_limit(self):
        """
        Check if we're within rate limits
        
        Returns:
            bool: Whether we can send a message
        """
        # Clean up old timestamps
        current_time = time.time()
        self.alert_timestamps = [t for t in self.alert_timestamps if current_time - t < 60]
        
        # Check if we're within the limit
        return len(self.alert_timestamps) < self.rate_limit
    
    def _log_info(self, message):
        """Log an info message"""
        self.logger.info(message)
        if self.log_callback:
            self.log_callback(message, 'info')
    
    def _log_warning(self, message):
        """Log a warning message"""
        self.logger.warning(message)
        if self.log_callback:
            self.log_callback(message, 'warning')
    
    def _log_error(self, message):
        """Log an error message"""
        self.logger.error(message)
        if self.log_callback:
            self.log_callback(message, 'error')
