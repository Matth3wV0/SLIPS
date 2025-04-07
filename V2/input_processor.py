# input/file_reader.py

import json
import os
from datetime import datetime
import logging

class SuricataFileReader:
    """
    Process static Suricata JSON files for analysis
    """
    
    def __init__(self, log_callback=None):
        """
        Initialize the file reader
        
        Args:
            log_callback (callable): Optional callback function for logging
        """
        self.logger = logging.getLogger('SuricataFileReader')
        self.log_callback = log_callback
        
    def read_file(self, filepath):
        """
        Read a static Suricata JSON file and yield events
        
        Args:
            filepath (str): Path to Suricata JSON file
            
        Yields:
            dict: Parsed Suricata event
        """
        self._log_info(f"Processing Suricata file: {filepath}")
        
        # Check if file exists
        if not os.path.exists(filepath):
            self._log_error(f"File not found: {filepath}")
            return
        
        # Count for progress reporting
        line_count = 0
        event_count = 0
        alert_count = 0
        dns_count = 0
        flow_count = 0
        other_count = 0
        
        # Track start time for performance reporting
        start_time = datetime.now()
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line_count += 1
                    
                    # Process the line as JSON
                    try:
                        event = json.loads(line.strip())
                        event_count += 1
                        
                        # Track event types
                        if event.get('event_type') == 'alert':
                            alert_count += 1
                        elif event.get('event_type') == 'dns':
                            dns_count += 1
                        elif event.get('event_type') == 'flow':
                            flow_count += 1
                        else:
                            other_count += 1
                        
                        # Report progress every 1000 events
                        if event_count % 1000 == 0:
                            self._log_info(f"Processed {event_count} events...")
                        
                        yield event
                    except json.JSONDecodeError:
                        self._log_warning(f"Invalid JSON at line {line_count}: {line[:50]}...")
        
        except Exception as e:
            self._log_error(f"Error processing file {filepath}: {str(e)}")
        
        # Report final statistics
        duration = (datetime.now() - start_time).total_seconds()
        self._log_info(f"File processing complete. Stats:")
        self._log_info(f"- Total events: {event_count}")
        self._log_info(f"- Alerts: {alert_count}")
        self._log_info(f"- DNS: {dns_count}")
        self._log_info(f"- Flows: {flow_count}")
        self._log_info(f"- Other: {other_count}")
        self._log_info(f"- Processing time: {duration:.2f} seconds")
    
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

# input/stream_reader.py

import json
import time
import os
import queue
import threading
import subprocess
from datetime import datetime
import logging

class SuricataStreamReader:
    """
    Monitor and process Suricata JSON output in real-time
    """
    
    def __init__(self, log_callback=None, buffer_size=1000, polling_interval=0.1):
        """
        Initialize the stream reader
        
        Args:
            log_callback (callable): Optional callback for logging
            buffer_size (int): Maximum number of events to buffer
            polling_interval (float): Seconds to wait between file checks
        """
        self.logger = logging.getLogger('SuricataStreamReader')
        self.log_callback = log_callback
        self.buffer_size = buffer_size
        self.polling_interval = polling_interval
        self.event_queue = queue.Queue(maxsize=buffer_size)
        self.stop_event = threading.Event()
        self.reader_thread = None
        
    def start_monitoring(self, filepath=None, suricata_command=None):
        """
        Start monitoring Suricata output
        
        Args:
            filepath (str): Path to Suricata JSON log file to monitor
            suricata_command (str): Optional Suricata command to execute
            
        Returns:
            bool: Whether monitoring started successfully
        """
        # Check input
        if not filepath and not suricata_command:
            self._log_error("Either filepath or suricata_command must be provided")
            return False
        
        # Start Suricata if command is provided
        if suricata_command:
            try:
                # Run Suricata in the background
                self._log_info(f"Starting Suricata with command: {suricata_command}")
                process = subprocess.Popen(
                    suricata_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Wait a bit to ensure Suricata starts
                time.sleep(2)
                
                # Check if process is running
                if process.poll() is not None:
                    stderr = process.stderr.read().decode('utf-8')
                    self._log_error(f"Suricata failed to start: {stderr}")
                    return False
                
                self._log_info("Suricata started successfully")
            except Exception as e:
                self._log_error(f"Error starting Suricata: {str(e)}")
                return False
        
        # Start the reader thread
        self.stop_event.clear()
        self.reader_thread = threading.Thread(
            target=self._read_loop,
            args=(filepath,),
            daemon=True
        )
        self.reader_thread.start()
        self._log_info(f"Started monitoring Suricata output at {filepath}")
        return True
    
    def stop_monitoring(self):
        """Stop monitoring Suricata output"""
        if self.reader_thread and self.reader_thread.is_alive():
            self._log_info("Stopping Suricata monitoring...")
            self.stop_event.set()
            self.reader_thread.join(timeout=5)
            self._log_info("Suricata monitoring stopped")
    
    def get_event(self, timeout=None):
        """
        Get the next event from the queue
        
        Args:
            timeout (float): Maximum time to wait for an event
            
        Returns:
            dict: Next Suricata event or None if timeout
        """
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_events_batch(self, max_batch_size=100, timeout=0.1):
        """
        Get a batch of events from the queue
        
        Args:
            max_batch_size (int): Maximum number of events to return
            timeout (float): Maximum time to wait for first event
            
        Returns:
            list: List of Suricata events
        """
        events = []
        
        # Try to get the first event with timeout
        try:
            events.append(self.event_queue.get(timeout=timeout))
        except queue.Empty:
            return events
        
        # Get additional events without blocking
        for _ in range(max_batch_size - 1):
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        
        return events
    
    def _read_loop(self, filepath):
        """
        Main file reading loop
        
        Args:
            filepath (str): Path to Suricata log file
        """
        last_position = 0
        file_check_count = 0
        
        # Wait for file to be created if it doesn't exist
        while not self.stop_event.is_set():
            if os.path.exists(filepath):
                break
            
            file_check_count += 1
            if file_check_count % 10 == 0:
                self._log_info(f"Waiting for file to be created: {filepath}")
            
            time.sleep(self.polling_interval)
        
        # Main reading loop
        while not self.stop_event.is_set():
            try:
                # Open file and seek to last position
                with open(filepath, 'r') as f:
                    f.seek(last_position)
                    
                    # Read and process new lines
                    new_lines = f.readlines()
                    if new_lines:
                        for line in new_lines:
                            try:
                                # Parse JSON and add to queue
                                event = json.loads(line.strip())
                                
                                # Add to queue with a timeout to prevent blocking forever
                                # if queue is full and stop event is set
                                try:
                                    self.event_queue.put(event, timeout=1)
                                except queue.Full:
                                    self._log_warning("Event queue is full, discarding event")
                                    
                            except json.JSONDecodeError:
                                pass  # Ignore invalid JSON
                    
                    # Update last position
                    last_position = f.tell()
                
            except Exception as e:
                self._log_error(f"Error reading file: {str(e)}")
            
            # Sleep before next check
            time.sleep(self.polling_interval)
    
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
