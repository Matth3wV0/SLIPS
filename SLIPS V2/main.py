#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SLIPS Simplified - Based on Stratosphere Linux IPS
Entry point for the application
Focused on Suricata.json input processing
"""

import os
import sys
import argparse
import yaml
import time
import signal
from multiprocessing import Process, Manager

from core.database import Database
from core.input_processor import InputProcessor
from core.profiler import Profiler
from core.evidence_processor import EvidenceProcessor
from utils.logger import setup_logger


class Main:
    """Main class for SLIPS Simplified"""
    
    def __init__(self):
        """Initialize the main application"""
        self.processes = []
        self.args = self.parse_args()
        self.config = self.load_config()
        self.logger = setup_logger(self.config.get('logging', {}))
        self.logger.info("Starting SLIPS Simplified")
        
        # Initialize database
        self.db = Database(
            port=self.args.port, 
            db_name=self.config.get('database', {}).get('db_name', 0)
        )
        
        # Setup manager for process communication
        self.manager = Manager()
        self.should_stop = self.manager.Value('b', False)
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def parse_args(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(description='SLIPS Simplified - Network Security Monitoring')
        parser.add_argument('-f', '--file', help='Suricata.json file to analyze')
        parser.add_argument('-o', '--output', default='output', help='Output directory')
        parser.add_argument('-c', '--config', default='config/config.yaml', help='Configuration file')
        parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity level')
        parser.add_argument('-e', '--debug', action='count', default=0, help='Debug level')
        parser.add_argument('-p', '--blocking', action='store_true', help='Enable traffic blocking')
        parser.add_argument('-P', '--port', type=int, default=6379, help='Redis port')
        
        args = parser.parse_args()
        
        # Check if file exists
        if args.file and not os.path.isfile(args.file):
            print(f"Error: File {args.file} not found.")
            sys.exit(1)
            
        # Create output directory if it doesn't exist
        if not os.path.exists(args.output):
            os.makedirs(args.output)
            
        return args

    def load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.args.config, 'r') as f:
                return yaml.safe_load(f)
        except (FileNotFoundError, yaml.YAMLError) as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)

    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        self.logger.info("Termination signal received. Shutting down...")
        self.should_stop.value = True
        
        # Give processes time to shut down gracefully
        time.sleep(1)
        self.shutdown()

    def load_modules(self):
        """Load and initialize detection modules"""
        modules = []
        
        # Get enabled modules from config
        enabled_modules = self.config.get('modules', {}).get('enabled', [])
        disabled_modules = self.config.get('modules', {}).get('disabled', [])
        
        # For now, we're just creating a placeholder
        # In a real implementation, we would dynamically load modules
        self.logger.info("Loading detection modules")
        
        return modules
        
    def start_processes(self):
        """Start all necessary processes"""
        # Create processes
        input_processor = Process(
            target=self.start_input_processor,
            name="InputProcessor"
        )
        
        profiler = Process(
            target=self.start_profiler,
            name="Profiler"
        )
        
        evidence_processor = Process(
            target=self.start_evidence_processor,
            name="EvidenceProcessor"
        )
        
        # Start processes
        input_processor.start()
        profiler.start()
        evidence_processor.start()
        
        # Store references
        self.processes.extend([
            input_processor,
            profiler,
            evidence_processor
        ])
        
        # Start detection modules
        self.start_detection_modules()
        
    def start_input_processor(self):
        """Start the input processor process"""
        input_proc = InputProcessor(
            self.db, 
            self.args.file, 
            self.config.get('input_processor', {}),
            self.should_stop
        )
        input_proc.start()
        
    def start_profiler(self):
        """Start the profiler process"""
        profiler = Profiler(
            self.db,
            self.config.get('profiler', {}),
            self.should_stop
        )
        profiler.start()
        
    def start_evidence_processor(self):
        """Start the evidence processor process"""
        evidence_proc = EvidenceProcessor(
            self.db,
            self.config.get('evidence_processor', {}),
            self.args.output,
            self.should_stop,
            self.args.blocking
        )
        evidence_proc.start()
        
    def start_detection_modules(self):
        """Start all detection module processes"""
        modules = self.load_modules()
        
        for module in modules:
            module_process = Process(
                target=module.start,
                name=module.name
            )
            module_process.start()
            self.processes.append(module_process)
            
    def shutdown(self):
        """Shutdown all processes and clean up"""
        self.logger.info("Shutting down SLIPS Simplified...")
        
        # Stop all processes
        for process in self.processes:
            if process.is_alive():
                self.logger.debug(f"Terminating process: {process.name}")
                process.terminate()
                process.join(timeout=3)
                
                # Force kill if it didn't terminate gracefully
                if process.is_alive():
                    self.logger.warning(f"Force killing process: {process.name}")
                    process.kill()
                    process.join()
        
        # Close database connection
        self.db.shutdown()
        
        self.logger.info("SLIPS Simplified shutdown complete")
        sys.exit(0)
        
    def run(self):
        """Run the application"""
        self.logger.info(f"Analyzing file: {self.args.file}")
        
        try:
            self.start_processes()
            
            # Main loop - keep running until termination
            while not self.should_stop.value:
                time.sleep(1)
                
                # Check if all processes are still running
                for process in self.processes:
                    if not process.is_alive():
                        self.logger.error(f"Process {process.name} died unexpectedly")
                        self.should_stop.value = True
                        break
                        
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.should_stop.value = True
        finally:
            self.shutdown()
            

if __name__ == "__main__":
    main = Main()
    main.run()
