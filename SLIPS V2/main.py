#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SLIPS Simplified - Based on Stratosphere Linux IPS
Entry point for the application
Focused on Suricata.json input processing
"""
import logging
import os
import sys
import argparse
import yaml
import time
import signal
from multiprocessing import Process, Manager
import random
import json
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

    # Replace the load_modules method in your main.py file

    def load_modules(self):
        """Load and initialize detection modules"""
        modules = []
        
        # Get enabled modules from config
        enabled_modules = self.config.get('modules', {}).get('enabled', [])
        disabled_modules = self.config.get('modules', {}).get('disabled', [])
        
        # Simplified: Create basic detection modules
        self.logger.info("Loading detection modules")
        
        # Add a simple flow alert module for demonstration
        class SimpleFlowAlertModule:
            def __init__(self, db, config, should_stop):
                self.name = "SimpleFlowAlert"
                self.db = db
                self.config = config
                self.should_stop = should_stop
                self.pubsub = db.subscribe('new_flow')
                self.logger = logging.getLogger(self.name)
                self.logger.info(f"Initialized {self.name} module")
                
            def start(self):
                self.logger.info(f"Starting {self.name} module")
                try:
                    while not self.should_stop.value:
                        # Process messages
                        message = self.db.get_message()
                        if message:
                            channel = message.get('channel', b'').decode('utf-8')
                            if channel == 'new_flow':
                                try:
                                    data = message.get('data')
                                    if isinstance(data, bytes):
                                        data = json.loads(data.decode('utf-8'))
                                        
                                    if 'flow' in data:
                                        flow = data['flow']
                                        # Simple detection: Check for SSH brute force attempts
                                        self._detect_ssh_brute_force(flow)
                                        # Check for port scans
                                        self._detect_port_scan(flow)
                                        # Check for DNS issues
                                        self._detect_dns_issues(flow)
                                        # Check for HTTP issues
                                        self._detect_http_issues(flow)
                                except Exception as e:
                                    self.logger.error(f"Error processing flow: {str(e)}")
                        
                        time.sleep(0.01)  # Small sleep to prevent CPU hogging
                except Exception as e:
                    self.logger.error(f"Error in {self.name}: {str(e)}")
                self.logger.info(f"{self.name} shutting down")
                    
            def _detect_ssh_brute_force(self, flow):
                """Detect SSH brute force attempts"""
                # Simple SSH brute force detection: SSH on port 22 with small packets
                dest_port = flow.get('id.resp_p')
                proto = flow.get('proto', '').lower()
                service = flow.get('service', '').lower()
                conn_state = flow.get('conn_state', '')
                orig_bytes = int(flow.get('orig_bytes', 0))
                
                if proto == 'tcp' and dest_port == 22 and (service == 'ssh' or service == ''):
                    # Potential SSH connection
                    if conn_state in ['REJ', 'S0', 'S1'] and orig_bytes < 1000:
                        # Failed or rejected SSH connection with small packet size
                        evidence = {
                            'ip': flow.get('id.orig_h'),
                            'type': 'SSHBruteForceAttempt',
                            'description': f"Possible SSH brute force attempt to {flow.get('id.resp_h')}",
                            'threat_level': 0.7,
                            'confidence': 0.6,
                            'timestamp': time.time(),
                            'flow': flow
                        }
                        self.db.add_evidence(evidence)
                        self.logger.info(f"Detected possible SSH brute force: {flow.get('id.orig_h')} -> {flow.get('id.resp_h')}")
                        
            def _detect_port_scan(self, flow):
                """Detect potential port scans"""
                conn_state = flow.get('conn_state', '')
                proto = flow.get('proto', '').lower()
                orig_pkts = int(flow.get('orig_pkts', 0))
                
                # Look for rejected connections or connection attempts with few packets
                if conn_state in ['REJ', 'S0'] and proto == 'tcp' and orig_pkts <= 3:
                    evidence = {
                        'ip': flow.get('id.orig_h'),
                        'type': 'PotentialPortScan',
                        'description': f"Possible port scan to {flow.get('id.resp_h')}:{flow.get('id.resp_p')}",
                        'threat_level': 0.6,
                        'confidence': 0.5,
                        'timestamp': time.time(),
                        'flow': flow
                    }
                    self.db.add_evidence(evidence)
                    self.logger.info(f"Detected potential port scan: {flow.get('id.orig_h')} -> {flow.get('id.resp_h')}:{flow.get('id.resp_p')}")
                    
            def _detect_dns_issues(self, flow):
                """Detect DNS issues"""
                service = flow.get('service', '').lower()
                proto = flow.get('proto', '').lower()
                dest_port = flow.get('id.resp_p')
                
                if proto == 'udp' and dest_port == 53 and service == 'dns':
                    # This is a DNS query - in a real implementation we would check for DGA, etc.
                    # For demonstration, let's just detect high DNS query rates
                    # (this is very simplified)
                    
                    # In a real implementation, we would track DNS queries over time
                    if random.random() < 0.01:  # Simulate finding a suspicious DNS query (1% chance)
                        evidence = {
                            'ip': flow.get('id.orig_h'),
                            'type': 'SuspiciousDNSActivity',
                            'description': f"Suspicious DNS activity detected",
                            'threat_level': 0.5,
                            'confidence': 0.4,
                            'timestamp': time.time(),
                            'flow': flow
                        }
                        self.db.add_evidence(evidence)
                        self.logger.info(f"Detected suspicious DNS activity: {flow.get('id.orig_h')}")
                        
            def _detect_http_issues(self, flow):
                """Detect HTTP issues"""
                service = flow.get('service', '').lower()
                proto = flow.get('proto', '').lower()
                dest_port = flow.get('id.resp_p')
                
                if proto == 'tcp' and (service == 'http' or dest_port == 80):
                    # This is an HTTP connection - check for suspicious patterns
                    # For demonstration, let's detect unusual ports for HTTP
                    if dest_port != 80 and dest_port != 8080 and dest_port != 8000:
                        evidence = {
                            'ip': flow.get('id.orig_h'),
                            'type': 'UnusualHTTPPort',
                            'description': f"HTTP traffic on unusual port {dest_port}",
                            'threat_level': 0.4,
                            'confidence': 0.5,
                            'timestamp': time.time(),
                            'flow': flow
                        }
                        self.db.add_evidence(evidence)
                        self.logger.info(f"Detected HTTP on unusual port: {flow.get('id.orig_h')} -> {flow.get('id.resp_h')}:{dest_port}")
        
        # Create and add the module
        flow_alert_module = SimpleFlowAlertModule(self.db, self.config.get('flowalerts', {}), self.should_stop)
        modules.append(flow_alert_module)
        
        self.logger.info(f"Loaded {len(modules)} detection modules")
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
        
    # Replace this section in your main.py file

    def run(self):
        """Run the application"""
        self.logger.info(f"Analyzing file: {self.args.file}")
        
        try:
            self.start_processes()
            
            # Main loop - keep running until termination
            while not self.should_stop.value:
                time.sleep(1)
                
                # Check if all processes are still running
                all_processes_alive = True
                for process in self.processes:
                    if not process.is_alive():
                        # If the InputProcessor died but finished processing, this is normal
                        if process.name == "InputProcessor":
                            # Check if we're analyzing a file (not an interface)
                            if self.args.file and not self.args.interface:
                                self.logger.info(f"InputProcessor finished processing file: {self.args.file}")
                                continue  # Skip this process, don't trigger shutdown
                        
                        # For other processes dying, this is an error
                        self.logger.error(f"Process {process.name} died unexpectedly")
                        all_processes_alive = False
                        self.should_stop.value = True
                        break
                
                # Check if input processing is done but we should keep running for detection
                if self.args.file and not self.args.interface:
                    input_proc_alive = any(p.name == "InputProcessor" and p.is_alive() for p in self.processes)
                    if not input_proc_alive:
                        # After 30 seconds of processing with no input, shut down gracefully
                        if hasattr(self, 'input_finished_time'):
                            if time.time() - self.input_finished_time > 30:
                                self.logger.info("Processing complete, shutting down...")
                                self.should_stop.value = True
                        else:
                            self.input_finished_time = time.time()
                            self.logger.info("Input processing complete, waiting for detections to finish...")
                        
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.should_stop.value = True
        finally:
            self.shutdown()
            

if __name__ == "__main__":
    main = Main()
    main.run()
