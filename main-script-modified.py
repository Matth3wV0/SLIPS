#!/usr/bin/env python3
"""
Main application script for Suricata Analyzer
This script provides a unified interface for all components of the system.
With added support for CICIDS2017 CSV dataset.
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
from cicids_processor import CICIDSProcessor, convert_cicids_to_suricata_json
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
        self.cicids_processor = CICIDSProcessor()
        self.monitor = None  # Initialize only when needed
        
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.config['data_dir'],
            os.path.join(self.config['data_dir'], 'normal'),
            os.path.join(self.config['data_dir'], 'attack'),
            os.path.join(self.config['data_dir'], 'test'),
            os.path.join(self.config['data_dir'], 'uploads'),
            os.path.join(self.config['data_dir'], 'cicids'),
            os.path.join(self.config['data_dir'], 'cicids', 'processed'),
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
            
    def process_cicids_dataset(self, input_dir: str, output_dir: Optional[str] = None,
                        split_ratio: float = 0.7):
        """
        Process CICIDS2017 CSV files and convert to Suricata JSON format
        
        Args:
            input_dir: Directory containing CICIDS2017 CSV files
            output_dir: Directory to save processed files (default: data/cicids/processed)
            split_ratio: Ratio for splitting data into train/test sets (default: 0.7)
        """
        # Use default output directory if not specified
        if output_dir is None:
            output_dir = os.path.join(self.config['data_dir'], 'cicids', 'processed')
            
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'normal'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'attack'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'test'), exist_ok=True)
        
        logger.info(f"Processing CICIDS2017 CSV files from {input_dir}")
        
        # Find all CSV files in the input directory
        csv_files = []
        for root, _, files in os.walk(input_dir):
            for file in files:
                if file.endswith('.csv'):
                    csv_files.append(os.path.join(root, file))
                    
        if not csv_files:
            logger.error(f"No CSV files found in {input_dir}")
            return
            
        logger.info(f"Found {len(csv_files)} CSV files")
        
        # Dictionary to track attack/normal counts
        attack_normal_counts = {
            "normal_files": 0,
            "attack_files": 0,
            "attack_by_type": {}
        }
        
        # Set a lower threshold for attack ratio to ensure we capture attack files
        # Even if a file has 10% attacks, we'll consider it an attack file
        attack_threshold = 0.1
        
        # Process each CSV file
        for csv_file in csv_files:
            file_name = os.path.basename(csv_file)
            logger.info(f"Processing {file_name}")
            
            # Output file path
            json_file = os.path.join(output_dir, f"{os.path.splitext(file_name)[0]}.json")
            
            try:
                # Convert CICIDS CSV to Suricata JSON
                stats = convert_cicids_to_suricata_json(csv_file, json_file)
                
                # Skip if no flows were processed
                if stats.get('total_flows', 0) == 0:
                    logger.warning(f"No flows processed in {file_name}")
                    continue
                    
                # Determine if this file contains mostly attacks or benign traffic
                attack_count = stats.get('attack_flows', 0)
                total_count = stats.get('total_flows', 1)
                attack_ratio = attack_count / total_count
                
                logger.info(f"File {file_name}: {attack_count} attacks out of {total_count} flows ({attack_ratio:.2%})")
                
                # Split the output file into normal and attack dirs based on content
                if attack_ratio > attack_threshold:
                    # Contains significant attacks - put in attack directory
                    category = 'attack'
                    attack_normal_counts["attack_files"] += 1
                    
                    # Log attack types if available
                    if 'attack_types' in stats:
                        for attack_type, count in stats['attack_types'].items():
                            if attack_type not in attack_normal_counts["attack_by_type"]:
                                attack_normal_counts["attack_by_type"][attack_type] = 0
                            attack_normal_counts["attack_by_type"][attack_type] += count
                else:
                    # Mostly benign - put in normal directory
                    category = 'normal'
                    attack_normal_counts["normal_files"] += 1
                    
                # Create symlinks or copies for training and testing
                # For training (split_ratio of the data)
                train_file = os.path.join(output_dir, category, f"train_{file_name}.json")
                
                # For testing (1-split_ratio of the data)
                test_file = os.path.join(output_dir, 'test', f"test_{file_name}.json")
                
                # Split the file
                self._split_json_file(json_file, train_file, test_file, split_ratio)
                
                logger.info(f"Processed {file_name} - {stats['total_flows']} flows "
                        f"({stats['benign_flows']} benign, {stats['attack_flows']} attack) - Categorized as {category}")
                
            except Exception as e:
                logger.error(f"Error processing {file_name}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                
        logger.info("CICIDS2017 dataset processing complete")
        logger.info(f"Summary: {attack_normal_counts['normal_files']} normal files, {attack_normal_counts['attack_files']} attack files")
        if attack_normal_counts["attack_by_type"]:
            logger.info("Attack types detected:")
            for attack_type, count in attack_normal_counts["attack_by_type"].items():
                logger.info(f"  - {attack_type}: {count}")
        
        # Ensure we have both normal and attack files
        if attack_normal_counts["attack_files"] == 0:
            logger.warning("No attack files were detected! Creating a special attack file from attack records.")
            self._create_attack_file_from_mixed(output_dir)
        
        # Create consolidated files
        self._consolidate_files(output_dir)
        
    def _create_attack_file_from_mixed(self, output_dir: str):
        """
        Create an attack file by extracting attack records from all files
        
        Args:
            output_dir: Directory containing processed files
        """
        # Find all JSON files
        all_json_files = []
        for root, _, files in os.walk(output_dir):
            for file in files:
                if file.endswith('.json') and not file.startswith('all_'):
                    all_json_files.append(os.path.join(root, file))
        
        # Create output attack file
        attack_output = os.path.join(output_dir, 'attack', 'extracted_attacks.json')
        attack_count = 0
        
        with open(attack_output, 'w') as f_out:
            for json_file in all_json_files:
                try:
                    with open(json_file, 'r') as f_in:
                        for line in f_in:
                            try:
                                event = json.loads(line)
                                # Check if this is an attack event
                                if event.get('has_alert', False) or (event.get('event_type') == 'alert'):
                                    f_out.write(line)
                                    attack_count += 1
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.error(f"Error processing {json_file}: {e}")
        
        logger.info(f"Created attack file with {attack_count} attack events: {attack_output}")
        
        # Create a training file copy
        train_attack = os.path.join(output_dir, 'attack', 'train_extracted_attacks.json')
        try:
            with open(attack_output, 'r') as f_in:
                with open(train_attack, 'w') as f_out:
                    f_out.write(f_in.read())
            logger.info(f"Created training attack file: {train_attack}")
        except Exception as e:
            logger.error(f"Error creating training attack file: {e}")
        
    def _split_json_file(self, input_file: str, train_file: str, test_file: str, split_ratio: float):
        """
        Split a JSON file into training and testing sets
        
        Args:
            input_file: Input JSON file
            train_file: Output training file
            test_file: Output testing file
            split_ratio: Ratio for splitting data (0.0-1.0)
        """
        try:
            # Count lines in file
            with open(input_file, 'r') as f:
                total_lines = sum(1 for _ in f)
                
            # Calculate split
            train_lines = int(total_lines * split_ratio)
            
            # Open files
            with open(input_file, 'r') as f_in, \
                 open(train_file, 'w') as f_train, \
                 open(test_file, 'w') as f_test:
                
                # Process each line
                for i, line in enumerate(f_in):
                    if i < train_lines:
                        f_train.write(line)
                    else:
                        f_test.write(line)
                        
            logger.info(f"Split {input_file} into {train_lines} training and "
                       f"{total_lines - train_lines} testing samples")
            
        except Exception as e:
            logger.error(f"Error splitting file {input_file}: {e}")
            
    def _consolidate_files(self, output_dir: str):
        """
        Consolidate processed files into combined training and testing files
        
        Args:
            output_dir: Directory containing processed files
        """
        # Create consolidated files
        normal_train = os.path.join(output_dir, 'normal', 'all_normal_train.json')
        attack_train = os.path.join(output_dir, 'attack', 'all_attack_train.json')
        test_all = os.path.join(output_dir, 'test', 'all_test.json')
        
        # Consolidate normal training files
        with open(normal_train, 'w') as f_out:
            for root, _, files in os.walk(os.path.join(output_dir, 'normal')):
                for file in files:
                    if file != 'all_normal_train.json' and file.endswith('.json'):
                        with open(os.path.join(root, file), 'r') as f_in:
                            f_out.write(f_in.read())
                            
        # Consolidate attack training files
        with open(attack_train, 'w') as f_out:
            for root, _, files in os.walk(os.path.join(output_dir, 'attack')):
                for file in files:
                    if file != 'all_attack_train.json' and file.endswith('.json'):
                        with open(os.path.join(root, file), 'r') as f_in:
                            f_out.write(f_in.read())
                            
        # Consolidate test files
        with open(test_all, 'w') as f_out:
            for root, _, files in os.walk(os.path.join(output_dir, 'test')):
                for file in files:
                    if file != 'all_test.json' and file.endswith('.json'):
                        with open(os.path.join(root, file), 'r') as f_in:
                            f_out.write(f_in.read())
                            
        logger.info("Created consolidated files for training and testing")
        
    def train_with_cicids(self, cicids_dir: Optional[str] = None):
        """
        Train models with processed CICIDS2017 data
        
        Args:
            cicids_dir: Directory containing processed CICIDS2017 files
        """
        # Use default directory if not specified
        if cicids_dir is None:
            cicids_dir = os.path.join(self.config['data_dir'], 'cicids', 'processed')
            
        # Check if processed files exist
        normal_train = os.path.join(cicids_dir, 'normal', 'all_normal_train.json')
        attack_train = os.path.join(cicids_dir, 'attack', 'all_attack_train.json')
        
        if not os.path.exists(normal_train) or not os.path.exists(attack_train):
            logger.error("Processed CICIDS2017 files not found. Run 'process-cicids' command first.")
            return
            
        logger.info("Training models with CICIDS2017 dataset")
        
        # Train models
        self.train_models(
            normal_dir=os.path.join(cicids_dir, 'normal'),
            attack_dir=os.path.join(cicids_dir, 'attack')
        )
        
    def evaluate_with_cicids(self, cicids_dir: Optional[str] = None):
        """
        Evaluate models with processed CICIDS2017 test data
        
        Args:
            cicids_dir: Directory containing processed CICIDS2017 files
        """
        # Use default directory if not specified
        if cicids_dir is None:
            cicids_dir = os.path.join(self.config['data_dir'], 'cicids', 'processed')
            
        # Check if processed test files exist
        test_dir = os.path.join(cicids_dir, 'test')
        test_all = os.path.join(test_dir, 'all_test.json')
        
        if not os.path.exists(test_all):
            logger.error("Processed CICIDS2017 test files not found. Run 'process-cicids' command first.")
            return
            
        logger.info("Evaluating models with CICIDS2017 dataset")
        
        # Evaluate models
        self.evaluate_models(test_dir=test_dir)


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
    
    # CICIDS2017 specific commands
    cicids_parser = subparsers.add_parser('process-cicids', help='Process CICIDS2017 CSV files')
    cicids_parser.add_argument('input_dir', help='Directory containing CICIDS2017 CSV files')
    cicids_parser.add_argument('--output-dir', help='Directory to save processed files')
    cicids_parser.add_argument('--split-ratio', type=float, default=0.7, help='Train/test split ratio')
    
    cicids_train_parser = subparsers.add_parser('train-cicids', help='Train models with CICIDS2017 data')
    cicids_train_parser.add_argument('--cicids-dir', help='Directory containing processed CICIDS2017 files')
    
    cicids_eval_parser = subparsers.add_parser('evaluate-cicids', help='Evaluate models with CICIDS2017 data')
    cicids_eval_parser.add_argument('--cicids-dir', help='Directory containing processed CICIDS2017 files')
    
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
        
    elif args.command == 'process-cicids':
        analyzer.process_cicids_dataset(args.input_dir, args.output_dir, args.split_ratio)
        
    elif args.command == 'train-cicids':
        analyzer.train_with_cicids(args.cicids_dir)
        
    elif args.command == 'evaluate-cicids':
        analyzer.evaluate_with_cicids(args.cicids_dir)
        
    else:
        # Default: print help
        print("Please specify a command. Use --help for more information.")
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
