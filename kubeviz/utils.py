"""
Utility functions for KubeViz.
"""

import logging
import sys
from typing import Optional

def setup_logging(log_level: int = logging.INFO):
    """
    Set up logging for KubeViz.
    
    Args:
        log_level: Logging level (INFO, DEBUG, etc.)
    """
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    if not root_logger.handlers:
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        
        # Create formatter
        if log_level == logging.DEBUG:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            formatter = logging.Formatter('%(levelname)s: %(message)s')
        
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
