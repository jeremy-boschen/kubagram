"""
Command-line interface for the KubeViz kubectl plugin.
"""

import os
import sys
import argparse
import logging
from typing import Optional, List

from kubeviz.collector import KubernetesResourceCollector
from kubeviz.renderer import DiagramRenderer
from kubeviz.mermaid import MermaidRenderer
from kubeviz.svg import SVGRenderer
from kubeviz.server import start_preview_server
from kubeviz.utils import setup_logging

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Visualize Kubernetes cluster resources and their relationships."
    )
    
    # Output format
    parser.add_argument(
        "--output", "-o",
        choices=["svg", "mermaid", "preview"],
        default="svg",
        help="Output format (svg, mermaid, or preview in browser)"
    )
    
    # Output file
    parser.add_argument(
        "--file", "-f",
        help="Output file path (default: kubeviz_output.[svg|md])"
    )
    
    # Filtering options
    parser.add_argument(
        "--namespace", "-n",
        help="Filter resources by namespace"
    )
    
    parser.add_argument(
        "--selector", "-l",
        help="Filter resources by label selector (e.g. app=nginx)"
    )
    
    parser.add_argument(
        "--include-resources",
        help="Comma-separated list of resource types to include (e.g. pods,services,deployments)"
    )
    
    parser.add_argument(
        "--exclude-resources",
        help="Comma-separated list of resource types to exclude"
    )
    
    # Preview options
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't open browser when using preview mode"
    )
    
    # Diagram options
    parser.add_argument(
        "--direction",
        choices=["TB", "BT", "LR", "RL"],
        default="TB",
        help="Diagram direction: TB (top-bottom), BT (bottom-top), LR (left-right), RL (right-left)"
    )
    
    parser.add_argument(
        "--show-labels",
        action="store_true",
        help="Show resource labels in the diagram"
    )
    
    parser.add_argument(
        "--show-system",
        action="store_true",
        help="Show system resources (kube-system, etc.)"
    )
    
    # Debug/verbosity
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    parser.add_argument(
        "--kubeconfig",
        help="Path to kubeconfig file"
    )
    
    return parser.parse_args()

def main():
    """Main entrypoint for the KubeViz kubectl plugin."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        # Set kubeconfig from args or environment
        kubeconfig = args.kubeconfig
        if kubeconfig:
            os.environ["KUBECONFIG"] = kubeconfig
        
        # Parse resource inclusions/exclusions
        include_resources = None
        if args.include_resources:
            include_resources = args.include_resources.split(',')
        
        exclude_resources = None
        if args.exclude_resources:
            exclude_resources = args.exclude_resources.split(',')
        
        # Collect Kubernetes resources
        logger.info("Collecting Kubernetes resources...")
        collector = KubernetesResourceCollector(
            namespace=args.namespace,
            label_selector=args.selector,
            include_resources=include_resources,
            exclude_resources=exclude_resources,
            include_system=args.show_system
        )
        resources = collector.collect()
        
        # If no resources found, display a message and exit
        if not resources:
            logger.warning("No resources found matching the specified criteria")
            sys.exit(0)
        
        # Choose renderer based on output format
        logger.info(f"Generating {args.output} diagram...")
        if args.output == "mermaid":
            renderer = MermaidRenderer(
                resources=resources,
                direction=args.direction,
                show_labels=args.show_labels
            )
            extension = "md"
        else:  # svg is default
            renderer = SVGRenderer(
                resources=resources,
                direction=args.direction,
                show_labels=args.show_labels
            )
            extension = "svg"
        
        # Generate the diagram
        diagram_content = renderer.render()
        
        # Handle output
        if args.output == "preview":
            logger.info("Starting preview server...")
            start_preview_server(
                diagram_content, 
                format_type="svg" if isinstance(renderer, SVGRenderer) else "mermaid",
                open_browser=not args.no_browser
            )
        else:
            # Determine output file path
            output_file = args.file
            if not output_file:
                output_file = f"kubeviz_output.{extension}"
            
            # Write output to file
            with open(output_file, 'w') as f:
                f.write(diagram_content)
            
            logger.info(f"Diagram saved to: {output_file}")
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.debug:
            logger.exception("Detailed error information:")
        sys.exit(1)

if __name__ == "__main__":
    main()
