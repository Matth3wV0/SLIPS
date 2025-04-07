#!/usr/bin/env python3
"""
Main application script for Suricata Analyzer
This script provides a unified interface for all components of the system.
"""

import os
import sys
import logging
import argparse
import json
import time
from typing import Dict, List, Any, Optional
import pandas as pd

# Import local modules
from core_processing import SuricataParser
from feature_extraction import FeatureExtractor
from ml_module import MLModel, ModelTrainer
from realtime_monitor import RealTimeMonitor
import web_dashboard  # Import the web dashboard module

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('suricata_analyzer.log')
    ]
)
logger = logging.getLogger('suricata_analyzer')


class SuricataAnalyzer:
    """Main application class for Suricata Analyzer"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Suricata Analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Set up directories
        self.setup_directories()
        
        # Initialize components
        self.parser = SuricataParser()
        self.feature_extractor = FeatureExtractor()
        self.ml_model = MLModel(self.config['model_dir'])
        self.monitor = None  # Initialize only when needed
        
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.config['data_dir'],
            os.path.join(self.config['data_dir'], 'normal'),
            os.path.join(self.config['data_dir'], 'attack'),
            os.path.join(self.config['data_dir'], 'test'),
            os.path.join(self.config['data_dir'], 'uploads'),
            self.config['model_dir'],
            'logs',
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
        logger.info(f"Set up directories: {directories}")
        
    def analyze_file(self, file_path: str, output_path: Optional[str] = None) -> pd.DataFrame:
        """
        Analyze a Suricata JSON file
        
        Args:
            file_path: Path to the Suricata JSON file
            output_path: Optional path to save results
            
        Returns:
            DataFrame with analysis results
        """
        logger.info(f"Analyzing file: {file_path}")
        
        # Load models
        self.ml_model.load_models()
        
        # Analyze file
        results_df = self.ml_model.analyze_file(file_path)
        
        # Display summary
        self._display_analysis_summary(results_df)
        
        # Save results if output path is provided
        if output_path and not results_df.empty:
            results_df.to_csv(output_path, index=False)
            logger.info(f"Saved results to {output_path}")
            
        return results_df
    
    def _display_analysis_summary(self, df: pd.DataFrame):
        """
        Display summary of analysis results
        
        Args:
            df: Results DataFrame
        """
        if df.empty:
            logger.warning("No results to display")
            return
            
        print("\n===== ANALYSIS SUMMARY =====")
        print(f"Total flows: {len(df)}")
        
        # Check for alerts
        if 'has_alert' in df.columns:
            alert_count = df['has_alert'].sum()
            print(f"Suricata alerts: {alert_count} ({alert_count/len(df)*100:.2f}%)")
            
        # Check for ML-detected anomalies
        if 'anomaly_prediction' in df.columns:
            anomaly_count = df['anomaly_prediction'].sum()
            print(f"ML-detected anomalies: {anomaly_count} ({anomaly_count/len(df)*100:.2f}%)")
            
        # Protocol distribution
        if 'protocol' in df.columns:
            proto_counts = df['protocol'].value_counts()
            print("\nProtocol distribution:")
            for proto, count in proto_counts.items():
                print(f"  {proto}: {count} ({count/len(df)*100:.2f}%)")
                
        # Traffic volume
        if 'total_bytes' in df.columns:
            total_bytes = df['total_bytes'].sum()
            print(f"\nTotal traffic volume: {self._format_bytes(total_bytes)}")
            
        print("=============================\n")
            
    def _format_bytes(self, bytes: int) -> str:
        """
        Format bytes into human-readable format
        
        Args:
            bytes: Number of bytes
            
        Returns:
            Formatted string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"
    
    def train_models(self, normal_dir: Optional[str] = None, attack_dir: Optional[str] = None):
        """
        Train ML models
        
        Args:
            normal_dir: Directory containing normal traffic files
            attack_dir: Directory containing attack traffic files
        """
        # Use default directories if not specified
        if normal_dir is None:
            normal_dir = os.path.join(self.config['data_dir'], 'normal')
        if attack_dir is None:
            attack_dir = os.path.join(self.config['data_dir'], 'attack')
            
        logger.info(f"Training models using normal data from {normal_dir} and attack data from {attack_dir}")
        
        # Create model trainer
        trainer = ModelTrainer(self.config['data_dir'], self.config['model_dir'])
        
        # Train models
        trainer.train_from_directories(normal_dir, attack_dir)
        
        logger.info("Model training complete")
        
    def evaluate_models(self, test_dir: Optional[str] = None):
        """
        Evaluate ML models
        
        Args:
            test_dir: Directory containing test data
        """
        # Use default directory if not specified
        if test_dir is None:
            test_dir = os.path.join(self.config['data_dir'], 'test')
            
        logger.info(f"Evaluating models using test data from {test_dir}")
        
        # Create model trainer
        trainer = ModelTrainer(self.config['data_dir'], self.config['model_dir'])
        
        # Evaluate models
        results = trainer.evaluate_model(test_dir)
        
        # Display results
        self._display_evaluation_results(results)
        
    def _display_evaluation_results(self, results: Dict[str, Any]):
        """
        Display model evaluation results
        
        Args:
            results: Evaluation results dictionary
        """
        if not results:
            logger.warning("No evaluation results to display")
            return
            
        print("\n===== MODEL EVALUATION =====")
        
        for model_type, metrics in results.items():
            print(f"\n{model_type.upper()} MODEL:")
            print(f"Accuracy: {metrics['accuracy']:.4f}")
            
            if 'report' in metrics:
                report = metrics['report']
                print("\nClassification Report:")
                print(f"              precision    recall  f1-score   support")
                
                for label in sorted(report.keys()):
                    if label in ['0', '1', 0, 1]:
                        label_str = "Normal" if str(label) == "0" else "Attack"
                        metrics_dict = report[label]
                        print(f"{label_str:14} {metrics_dict['precision']:.4f}    {metrics_dict['recall']:.4f}    {metrics_dict['f1-score']:.4f}   {metrics_dict['support']}")
                
                if 'accuracy' in report:
                    print(f"\nAccuracy: {report['accuracy']:.4f}")
                if 'macro avg' in report:
                    print(f"Macro Avg: {report['macro avg']['precision']:.4f}    {report['macro avg']['recall']:.4f}    {report['macro avg']['f1-score']:.4f}")
                if 'weighted avg' in report:
                    print(f"Weighted Avg: {report['weighted avg']['precision']:.4f}    {report['weighted avg']['recall']:.4f}    {report['weighted avg']['f1-score']:.4f}")
            
            if 'confusion_matrix' in metrics:
                cm = metrics['confusion_matrix']
                print("\nConfusion Matrix:")
                print(f"            Predicted")
                print(f"            Normal  Attack")
                print(f"Actual Normal  {cm[0][0]:6d}  {cm[0][1]:6d}")
                print(f"       Attack  {cm[1][0]:6d}  {cm[1][1]:6d}")
                
        print("=============================\n")
        
    def start_monitoring(self, log_file: Optional[str] = None):
        """
        Start real-time monitoring
        
        Args:
            log_file: Path to the Suricata log file to monitor
        """
        # Use default log file if not specified
        if log_file is None:
            log_file = self.config['log_file']
            
        logger.info(f"Starting real-time monitoring of {log_file}")
        
        # Create monitor if not already created
        if self.monitor is None:
            self.monitor = RealTimeMonitor(
                log_file,
                self.config['model_dir'],
                self.config.get('telegram_token'),
                self.config.get('telegram_chat_id')
            )
            
        # Start monitoring
        self.monitor.start()
        
        logger.info("Monitoring started")
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Monitoring interrupted by user")
        finally:
            self.stop_monitoring()
            
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if self.monitor:
            self.monitor.stop()
            logger.info("Monitoring stopped")
            
    def start_dashboard(self, host: str = '0.0.0.0', port: int = 5000):
        """
        Start web dashboard
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        logger.info(f"Starting web dashboard on {host}:{port}")
        
        # Update config for dashboard
        web_dashboard.config.update(self.config)
        
        # Start dashboard
        web_dashboard.main()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Suricata Analyzer - ML-based Intrusion Detection System')
    
    # Main command argument
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a Suricata JSON file')
    analyze_parser.add_argument('file', help='Path to the Suricata JSON file')
    analyze_parser.add_argument('--output', '-o', help='Path to save results')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train ML models')
    train_parser.add_argument('--normal', help='Directory containing normal traffic files')
    train_parser.add_argument('--attack', help='Directory containing attack traffic files')
    
    # Evaluate command
    evaluate_parser = subparsers.add_parser('evaluate', help='Evaluate ML models')
    evaluate_parser.add_argument('--test', help='Directory containing test data')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start real-time monitoring')
    monitor_parser.add_argument('--log-file', help='Path to the Suricata log file to monitor')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dashboard_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    dashboard_parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    
    # Configuration options
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--data-dir', default='data', help='Path to data directory')
    parser.add_argument('--model-dir', default='models', help='Path to model directory')
    parser.add_argument('--log-file', default='/var/log/suricata/eve.json', help='Path to Suricata log file')
    parser.add_argument('--telegram-token', help='Telegram bot token for alerts')
    parser.add_argument('--telegram-chat-id', help='Telegram chat ID for alerts')
    
    return parser.parse_args()


def main():
    """Main function"""
    # Parse arguments
    args = parse_arguments()
    
    # Load configuration from file if provided
    config = {
        'data_dir': args.data_dir,
        'model_dir': args.model_dir,
        'log_file': args.log_file,
        'telegram_token': args.telegram_token,
        'telegram_chat_id': args.telegram_chat_id,
    }
    
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            file_config = json.load(f)
            config.update(file_config)
            
    # Create analyzer
    analyzer = SuricataAnalyzer(config)
    
    # Execute command
    if args.command == 'analyze':
        analyzer.analyze_file(args.file, args.output)
        
    elif args.command == 'train':
        analyzer.train_models(args.normal, args.attack)
        
    elif args.command == 'evaluate':
        analyzer.evaluate_models(args.test)
        
    elif args.command == 'monitor':
        analyzer.start_monitoring(args.log_file)
        
    elif args.command == 'dashboard':
        analyzer.start_dashboard(args.host, args.port)
        
    else:
        # Default: print help
        print("Please specify a command. Use --help for more information.")
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
