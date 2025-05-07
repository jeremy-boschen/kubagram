"""
Base class for diagram renderers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

class DiagramRenderer(ABC):
    """Base class for diagram renderers."""
    
    def __init__(
        self,
        resources: Dict[str, List[Dict[str, Any]]],
        direction: str = "TB",
        show_labels: bool = False
    ):
        """
        Initialize the diagram renderer.
        
        Args:
            resources: Dictionary of resources by type
            direction: Diagram direction (TB, BT, LR, RL)
            show_labels: Whether to show resource labels in the diagram
        """
        self.resources = resources
        self.direction = direction
        self.show_labels = show_labels
    
    @abstractmethod
    def render(self) -> str:
        """
        Render the diagram.
        
        Returns:
            The rendered diagram as a string
        """
        pass
    
    def get_node_id(self, resource: Dict[str, Any]) -> str:
        """
        Get a unique ID for a resource node.
        
        Args:
            resource: Resource dictionary
            
        Returns:
            Unique node ID
        """
        # Create a node ID based on kind, namespace, and name
        kind = resource["kind"]
        namespace = resource["namespace"] or "global"
        name = resource["name"]
        
        # Clean any characters that might cause issues in node IDs
        namespace = namespace.replace("-", "_").replace(":", "_")
        name = name.replace("-", "_").replace(":", "_")
        
        return f"{kind}_{namespace}_{name}"
    
    def get_resource_label(self, resource: Dict[str, Any]) -> str:
        """
        Get a label for a resource node.
        
        Args:
            resource: Resource dictionary
            
        Returns:
            Node label
        """
        # Basic label includes kind and name
        kind = resource["kind"]
        name = resource["name"]
        label = f"{kind}: {name}"
        
        # Add namespace for resources that have one
        if resource["namespace"]:
            label = f"{label}\n(ns: {resource['namespace']})"
        
        # Add labels if requested
        if self.show_labels and "labels" in resource and resource["labels"]:
            # Limit to a few important labels
            important_labels = ["app", "component", "tier", "part-of", "name"]
            label_str = ""
            for key, value in resource["labels"].items():
                if key in important_labels:
                    label_str += f"\n{key}: {value}"
            if label_str:
                label = f"{label}{label_str}"
        
        # Add cloud load balancer info if available
        if "cloud_load_balancer" in resource:
            lb_type = resource["cloud_load_balancer"]["type"]
            provider = resource["cloud_load_balancer"]["provider"]
            label = f"{label}\n({provider} {lb_type})"
        
        # Add ingress controller type if available
        if "ingress_controller_type" in resource:
            label = f"{label}\n({resource['ingress_controller_type']})"
        
        return label
    
    def get_node_style(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get style attributes for a resource node.
        
        Args:
            resource: Resource dictionary
            
        Returns:
            Style attributes
        """
        kind = resource["kind"]
        
        # Default styles
        style = {
            "shape": "box",
            "style": "filled",
            "color": "#000000",
            "fillcolor": "#FFFFFF",
            "fontname": "Arial",
            "fontsize": "10"
        }
        
        # Style by resource kind
        if kind == "Pod":
            style["fillcolor"] = "#ADD8E6"  # Light blue
            style["shape"] = "circle"
        elif kind == "Service":
            style["fillcolor"] = "#98FB98"  # Pale green
            style["shape"] = "hexagon"
            # Special styling for external load balancers
            if resource.get("service_type") == "LoadBalancer":
                style["fillcolor"] = "#FFAEBC"  # Light pink
                style["shape"] = "doubleoctagon"
        elif kind == "Deployment":
            style["fillcolor"] = "#FFA07A"  # Light salmon
        elif kind == "StatefulSet":
            style["fillcolor"] = "#FFDAB9"  # Peach puff
        elif kind == "DaemonSet":
            style["fillcolor"] = "#D8BFD8"  # Thistle
        elif kind == "ReplicaSet":
            style["fillcolor"] = "#F0E68C"  # Khaki
        elif kind == "Ingress":
            style["fillcolor"] = "#87CEFA"  # Light sky blue
            style["shape"] = "invhouse"
        elif kind == "Job":
            style["fillcolor"] = "#B0C4DE"  # Light steel blue
        elif kind == "CronJob":
            style["fillcolor"] = "#20B2AA"  # Light sea green
        elif kind == "PersistentVolumeClaim":
            style["fillcolor"] = "#DDA0DD"  # Plum
            style["shape"] = "cylinder"
        elif kind == "ConfigMap":
            style["fillcolor"] = "#D3D3D3"  # Light gray
            style["shape"] = "note"
        elif kind == "Secret":
            style["fillcolor"] = "#FA8072"  # Salmon
            style["shape"] = "note"
        elif kind == "Namespace":
            style["fillcolor"] = "#E6E6FA"  # Lavender
            style["shape"] = "doubleoctagon"
        elif kind == "Node":
            style["fillcolor"] = "#FFFACD"  # Lemon chiffon
            style["shape"] = "box3d"
        elif kind == "Endpoints":
            style["fillcolor"] = "#E0FFFF"  # Light cyan
        
        # Cloud-specific styling
        if "cloud_load_balancer" in resource:
            provider = resource["cloud_load_balancer"]["provider"]
            if provider == "AWS":
                style["color"] = "#FF9900"  # AWS orange
                style["penwidth"] = "2"
            elif provider == "Azure":
                style["color"] = "#0089D6"  # Azure blue
                style["penwidth"] = "2"
            elif provider == "GCP":
                style["color"] = "#4285F4"  # GCP blue
                style["penwidth"] = "2"
        
        return style
    
    def get_edge_style(self, source: Dict[str, Any], target: Dict[str, Any], relationship_type: str) -> Dict[str, Any]:
        """
        Get style attributes for a relationship edge.
        
        Args:
            source: Source resource dictionary
            target: Target resource dictionary
            relationship_type: Type of relationship
            
        Returns:
            Style attributes
        """
        # Default style
        style = {
            "color": "#000000",
            "fontname": "Arial",
            "fontsize": "8",
            "style": "solid"
        }
        
        # Style by relationship type
        if relationship_type == "owns" or relationship_type == "owned-by":
            style["color"] = "#000000"
            style["style"] = "solid"
            style["penwidth"] = "2"
            style["arrowhead"] = "normal"
        elif relationship_type == "selects" or relationship_type == "selected-by":
            style["color"] = "#0000FF"  # Blue
            style["style"] = "dashed"
        elif relationship_type == "routes-to" or relationship_type == "routed-from":
            style["color"] = "#FF00FF"  # Magenta
            style["style"] = "bold"
        elif relationship_type == "creates" or relationship_type == "created-by":
            style["color"] = "#008000"  # Green
            style["style"] = "dotted"
        elif relationship_type == "runs-on":
            style["color"] = "#FFA500"  # Orange
            style["style"] = "dashed"
        
        return style
    
    def get_edge_label(self, relationship_type: str) -> str:
        """
        Get a label for a relationship edge.
        
        Args:
            relationship_type: Type of relationship
            
        Returns:
            Edge label
        """
        # Simplify the relationship type for display
        if relationship_type == "owned-by" or relationship_type == "owns":
            return "owns"
        elif relationship_type == "selected-by" or relationship_type == "selects":
            return "selects"
        elif relationship_type == "routed-from" or relationship_type == "routes-to":
            return "routes to"
        elif relationship_type == "created-by" or relationship_type == "creates":
            return "creates"
        elif relationship_type == "runs-on":
            return "runs on"
        else:
            return relationship_type.replace("-", " ")
