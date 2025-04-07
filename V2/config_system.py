# config.py

import os
import json
import logging
import yaml
from datetime import datetime

class Config:
    """
    Configuration manager for SLIPS-Suricata
    """
    
    DEFAULT_CONFIG = {
        # Input configuration
        'input': {
            'mode': 'file',  # 'file' or 'stream'
            'file_path': None,
            'suricata_eve_path': '/var/log/suricata/eve.json',
            'suricata_command': None,
            'polling_interval': 0.1  # Seconds between checks for new data
        },
        
        # ML configuration
        'ml': {
            'use_unsupervised': True,
            'use_supervised': True,
            'batch_size': 1000,  # Events to process in a batch
            'anomaly_threshold': 0.7,  # Score threshold for anomalies
            'train_ratio': 0.8,  # Portion of data to use for training
            'validation_ratio': 0.1,  # Portion of data to use for validation
            'unsupervised': {
                'model_type': 'ensemble',  # 'vae', 'isolation_forest', or 'ensemble'
                'contamination': 0.01,  # Expected ratio of anomalies
                'vae_latent_dim': 10,
                'vae_hidden_layers': [64, 32]
            },
            'supervised': {
                'model_type': 'random_forest',
                'n_estimators': 100,
                'max_depth': None
            },
            'ensembling': {
                'weights': {
                    'vae': 1.0,
                    'isolation_forest': 1.0,
                    'supervised': 1.0
                }
            }
        },
        
        # Output configuration
        'output': {
            'output_dir': 'output',
            'alert_dir': 'alerts',
            'model_dir': 'models',
            'log_file': 'slips_suricata.log',
            'console_log_level': 'INFO',
            'file_log_level': 'DEBUG'
        },
        
        # Telegram configuration
        'telegram': {
            'enabled': False,
            'bot_token': None,
            'chat_id': None,
            'min_severity': 'medium',  # 'low', 'medium', 'high'
            'rate_limit': 10  # Maximum messages per minute
        }
    }
    
    def __init__(self, config_path=None):
        """
        Initialize configuration
        
        Args:
            config_path (str): Path to configuration file
        """
        self.logger = logging.getLogger('Config')
        self.config = self.DEFAULT_CONFIG.copy()
        
        # Load configuration file if provided
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
    
    def load_config(self, config_path):
        """
        Load configuration from file
        
        Args:
            config_path (str): Path to configuration file
            
        Returns:
            bool: Whether loading was successful
        """
        try:
            # Determine file format from extension
            ext = os.path.splitext(config_path)[1].lower()
            
            if ext == '.json':
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
            elif ext in ['.yaml', '.yml']:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
            else:
                self.logger.error(f"Unsupported config file format: {ext}")
                return False
            
            # Update configuration
            self._update_config(self.config, user_config)
            self.logger.info(f"Configuration loaded from {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            return False
    
    def save_config(self, config_path):
        """
        Save configuration to file
        
        Args:
            config_path (str): Path to save configuration to
            
        Returns:
            bool: Whether saving was successful
        """
        try:
            # Determine file format from extension
            ext = os.path.splitext(config_path)[1].lower()
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
            
            if ext == '.json':
                with open(config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)
            elif ext in ['.yaml', '.yml']:
                with open(config_path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False)
            else:
                self.logger.error(f"Unsupported config file format: {ext}")
                return False
            
            self.logger.info(f"Configuration saved to {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def get(self, path, default=None):
        """
        Get a configuration value
        
        Args:
            path (str): Path to value (e.g., 'ml.batch_size')
            default: Default value if path not found
            
        Returns:
            The configuration value or default
        """
        parts = path.split('.')
        value = self.config
        
        try:
            for part in parts:
                value = value[part]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, path, value):
        """
        Set a configuration value
        
        Args:
            path (str): Path to value (e.g., 'ml.batch_size')
            value: Value to set
            
        Returns:
            bool: Whether setting was successful
        """
        parts = path.split('.')
        config = self.config
        
        try:
            # Navigate to the parent object
            for part in parts[:-1]:
                if part not in config:
                    config[part] = {}
                config = config[part]
            
            # Set the value
            config[parts[-1]] = value
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting configuration value: {str(e)}")
            return False
    
    def validate(self):
        """
        Validate configuration
        
        Returns:
            tuple: (bool, list of errors)
        """
        errors = []
        
        # Validate input configuration
        input_mode = self.get('input.mode')
        if input_mode not in ['file', 'stream']:
            errors.append(f"Invalid input mode: {input_mode}. Must be 'file' or 'stream'.")
        
        if input_mode == 'file' and not self.get('input.file_path'):
            errors.append("Input file path is required for file mode.")
        
        if input_mode == 'stream':
            if not self.get('input.suricata_eve_path') and not self.get('input.suricata_command'):
                errors.append("Either Suricata eve path or command is required for stream mode.")
        
        # Validate ML configuration
        if self.get('ml.use_supervised') and not self.get('ml.use_unsupervised'):
            # We need labeled data for supervised learning
            if not os.path.exists(self.get('ml.labeled_data_path', '')):
                errors.append("Labeled data path is required for supervised learning.")
        
        # Validate Telegram configuration
        if self.get('telegram.enabled'):
            if not self.get('telegram.bot_token'):
                errors.append("Telegram bot token is required when Telegram is enabled.")
            if not self.get('telegram.chat_id'):
                errors.append("Telegram chat ID is required when Telegram is enabled.")
        
        # Validate output paths
        output_dir = self.get('output.output_dir')
        if not output_dir:
            errors.append("Output directory is required.")
        
        return len(errors) == 0, errors
    
    def _update_config(self, target, source):
        """
        Recursively update configuration
        
        Args:
            target (dict): Target configuration
            source (dict): Source configuration
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_config(target[key], value)
            else:
                target[key] = value
    
    def setup_logging(self):
        """
        Set up logging based on configuration
        
        Returns:
            logging.Logger: The root logger
        """
        # Create output directory if it doesn't exist
        output_dir = self.get('output.output_dir')
        os.makedirs(output_dir, exist_ok=True)
        
        # Set up logging
        log_file = os.path.join(output_dir, self.get('output.log_file'))
        
        # Get log levels
        console_level = getattr(logging, self.get('output.console_log_level', 'INFO').upper())
        file_level = getattr(logging, self.get('output.file_log_level', 'DEBUG').upper())
        
        # Configure root logger
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(file_level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        logger.info(f"Logging initialized, log file: {log_file}")
        return logger
    
    def create_paths(self):
        """
        Create all necessary directories
        
        Returns:
            dict: Paths created
        """
        paths = {}
        
        # Create output directory
        output_dir = self.get('output.output_dir')
        os.makedirs(output_dir, exist_ok=True)
        paths['output_dir'] = output_dir
        
        # Create alert directory
        alert_dir = os.path.join(output_dir, self.get('output.alert_dir'))
        os.makedirs(alert_dir, exist_ok=True)
        paths['alert_dir'] = alert_dir
        
        # Create model directory
        model_dir = os.path.join(output_dir, self.get('output.model_dir'))
        os.makedirs(model_dir, exist_ok=True)
        paths['model_dir'] = model_dir
        
        return paths

# Create default config files

DEFAULT_CONFIG_YAML = """
# SLIPS-Suricata Configuration

# Input configuration
input:
  # Mode: 'file' for static analysis, 'stream' for real-time monitoring
  mode: file
  
  # Path to Suricata JSON file for static analysis
  file_path: test6-malicious.suricata.json
  
  # Path to Suricata's eve.json for real-time monitoring
  suricata_eve_path: /var/log/suricata/eve.json
  
  # Optional Suricata command to run for monitoring
  # Example: "suricata -c /etc/suricata/suricata.yaml -i eth0 -l /var/log/suricata"
  suricata_command: null
  
  # Interval in seconds to check for new data
  polling_interval: 0.1

# Machine Learning configuration
ml:
  # Whether to use unsupervised learning
  use_unsupervised: true
  
  # Whether to use supervised learning
  use_supervised: true
  
  # Number of events to process in a batch
  batch_size: 1000
  
  # Score threshold for anomalies (0-1, higher = more anomalous)
  anomaly_threshold: 0.7
  
  # Portion of data to use for training
  train_ratio: 0.8
  
  # Portion of data to use for validation
  validation_ratio: 0.1
  
  # Unsupervised learning configuration
  unsupervised:
    # Model type: 'vae', 'isolation_forest', or 'ensemble'
    model_type: ensemble
    
    # Expected ratio of anomalies in the data
    contamination: 0.01
    
    # VAE latent dimension
    vae_latent_dim: 10
    
    # VAE hidden layers
    vae_hidden_layers: [64, 32]
  
  # Supervised learning configuration
  supervised:
    # Model type: 'random_forest'
    model_type: random_forest
    
    # Number of trees in random forest
    n_estimators: 100
    
    # Maximum depth of trees (null for unlimited)
    max_depth: null
  
  # Ensembling configuration
  ensembling:
    # Weights for ensemble components
    weights:
      vae: 1.0
      isolation_forest: 1.0
      supervised: 1.0

# Output configuration
output:
  # Base output directory
  output_dir: output
  
  # Alert directory (relative to output_dir)
  alert_dir: alerts
  
  # Model directory (relative to output_dir)
  model_dir: models
  
  # Log file name
  log_file: slips_suricata.log
  
  # Console log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  console_log_level: INFO
  
  # File log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  file_log_level: DEBUG

# Telegram notification configuration
telegram:
  # Whether to enable Telegram notifications
  enabled: false
  
  # Telegram bot token
  bot_token: null
  
  # Telegram chat ID
  chat_id: null
  
  # Minimum severity to notify: 'low', 'medium', 'high'
  min_severity: medium
  
  # Maximum messages per minute
  rate_limit: 10
"""

def create_default_config_files():
    """Create default configuration files if they don't exist"""
    # Create config directory if it doesn't exist
    os.makedirs('config', exist_ok=True)
    
    # Create YAML config
    yaml_path = os.path.join('config', 'config.yaml')
    if not os.path.exists(yaml_path):
        with open(yaml_path, 'w') as f:
            f.write(DEFAULT_CONFIG_YAML)
        print(f"Created default YAML configuration: {yaml_path}")
