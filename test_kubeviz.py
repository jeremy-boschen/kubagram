
#!/usr/bin/env python3

import os
import sys
import logging
from kubeviz.utils import setup_logging
from kubeviz.collector import KubernetesResourceCollector
from kubeviz.mermaid import MermaidRenderer

# Set up logging with more detail
setup_logging(logging.DEBUG)
logger = logging.getLogger(__name__)

try:
    logger.info("Starting test connection to Kubernetes...")
    logger.debug(f"KUBECONFIG env var: {os.getenv('KUBECONFIG')}")
    
    # Try to create a collector and see how far we get
    collector = KubernetesResourceCollector(
        include_system=True
    )
    
    # Try to get a single namespace to test connection
    logger.info("Testing Kubernetes connection by listing namespaces...")
    namespaces = collector._collect_namespaces()
    
    if namespaces:
        logger.info(f"Successfully connected to Kubernetes. Found {len(namespaces)} namespaces.")
        for ns in namespaces[:5]:  # Show first 5 only
            logger.info(f" - {ns['name']}")
    else:
        logger.warning("Connection established but no namespaces found.")
        
except Exception as e:
    logger.error(f"Error connecting to Kubernetes: {str(e)}")
    logger.debug("Check if kubectl is configured correctly:")
    logger.debug("1. Run 'kubectl config view' to verify configuration")
    logger.debug("2. Make sure you have access to a Kubernetes cluster")
    logger.exception("Detailed error information:")
    sys.exit(1)
