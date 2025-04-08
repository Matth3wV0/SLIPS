#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logger module for SLIPS Simplified
Sets up logging with proper formatting and output
"""

import os
import logging
import logging.handlers
from typing import Dict, Optional


def setup_logger(config: Dict) -> logging.Logger:
    """
    Setup and configure the logger
    
    Args:
        config: Logger configuration dictionary
        
    Returns:
        Configured logger
    """
    # Get configuration
    log_level_str = config.get('level', 'INFO')
    log_format = config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_file = config.get('file')
    log_dir = config.get('dir', 'logs')
    max_bytes = config.get('max_bytes', 10 * 1024 * 1024)  # 10 MB
    backup_count = config.get('backup_count', 5)
    
    # Convert log level string to constant
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    log_level = log_level_map.get(log_level_str.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if specified
    if log_file:
        try:
            # Create log directory if it doesn't exist
            os.makedirs(log_dir, exist_ok=True)
            
            # Full path to log file
            log_path = os.path.join(log_dir, log_file)
            
            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            print(f"Logging to file: {log_path}")
        except Exception as e:
            print(f"Error setting up file logger: {str(e)}")
    
    return logger


def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get a logger for a specific module
    
    Args:
        module_name: Name of the module
        
    Returns:
        Module-specific logger
    """
    return logging.getLogger(module_name)


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter with extra context"""
    
    def __init__(self, logger, extra=None):
        """
        Initialize the logger adapter
        
        Args:
            logger: Logger instance
            extra: Extra context dictionary
        """
        super().__init__(logger, extra or {})
        
    def process(self, msg, kwargs):
        """
        Process the log message
        
        Args:
            msg: Log message
            kwargs: Keyword arguments
            
        Returns:
            Processed message and kwargs
        """
        extra = kwargs.get('extra', {})
        extra.update(self.extra)
        kwargs['extra'] = extra
        return msg, kwargs


def setup_colored_logger(config: Dict) -> logging.Logger:
    """
    Setup a logger with colored output
    
    Args:
        config: Logger configuration dictionary
        
    Returns:
        Configured logger with colored output
    """
    try:
        import colorama
        from colorama import Fore, Style
        
        colorama.init()
        
        # Color mapping
        colors = {
            'DEBUG': Fore.BLUE,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }
        
        # Custom formatter with colors
        class ColoredFormatter(logging.Formatter):
            def format(self, record):
                levelname = record.levelname
                record.levelname = f"{colors.get(levelname, '')}{levelname}{Style.RESET_ALL}"
                return super().format(record)
                
        # Setup basic logger
        logger = setup_logger(config)
        
        # Replace formatters with colored ones
        formatter = ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setFormatter(formatter)
                
        return logger
        
    except ImportError:
        # Fall back to regular logger if colorama not available
        return setup_logger(config)
