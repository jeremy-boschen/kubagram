"""
Mermaid diagram renderer.
"""

import logging
from typing import Dict, List, Any, Set, Tuple

from kubeviz.renderer import DiagramRenderer

logger = logging.getLogger(__name__)

class MermaidRenderer(DiagramRenderer):
    """Renders diagrams in Mermaid format."""
    
    def render(self) -> str:
        """
        Render the diagram in Mermaid format.
        
        Returns:
            Mermaid diagram string
        """
        # Start with the Mermaid graph definition
        lines = [
            "```mermaid",
            f"graph {self.direction}"
        ]
        
        # Keep track of nodes and edges we've already added
        added_nodes = set()
        added_edges = set()
        
        # Process all resource types
        for resource_type, resources in self.resources.items():
            # Add nodes for all resources of this type
            for resource in resources:
                node_id = self.get_node_id(resource)
                if node_id not in added_nodes:
                    node_label = self.get_resource_label(resource)
                    node_style = self.get_mermaid_node_style(resource)
                    lines.append(f"    {node_id}{node_style}[\"{node_label}\"]")
                    added_nodes.add(node_id)
        
        # Add edges for relationships
        for resource_type, resources in self.resources.items():
            for resource in resources:
                source_id = self.get_node_id(resource)
                
                # Add edges for all relationships
                for relationship in resource.get("relationships", []):
                    target_kind = relationship["kind"]
                    target_name = relationship["name"]
                    target_namespace = relationship["namespace"]
                    relationship_type = relationship["relationship_type"]
                    
                    # Construct target node ID
                    target_namespace = target_namespace or "global"
                    target_namespace = target_namespace.replace("-", "_").replace(":", "_")
                    target_name = target_name.replace("-", "_").replace(":", "_")
                    target_id = f"{target_kind}_{target_namespace}_{target_name}"
                    
                    if target_id in added_nodes:
                        # Determine if it's an incoming or outgoing relationship
                        # so we draw the arrow in the correct direction
                        if relationship_type in ["owned-by", "selected-by", "routed-from", "created-by", "runs-on"]:
                            from_id, to_id = source_id, target_id
                        else:
                            from_id, to_id = target_id, source_id
                        
                        # Only add an edge if it doesn't already exist
                        edge_key = f"{from_id}|{to_id}|{relationship_type}"
                        if edge_key not in added_edges:
                            edge_style = self.get_mermaid_edge_style(relationship_type)
                            edge_label = self.get_edge_label(relationship_type)
                            
                            lines.append(f"    {from_id} {edge_style} |{edge_label}| {to_id}")
                            added_edges.add(edge_key)
        
        # Add legend
        lines.extend(self._render_legend())
        
        # Close the Mermaid code block
        lines.append("```")
        
        return "\n".join(lines)
    
    def get_mermaid_node_style(self, resource: Dict[str, Any]) -> str:
        """
        Convert node style to Mermaid format.
        
        Args:
            resource: Resource dictionary
            
        Returns:
            Mermaid node style string
        """
        kind = resource["kind"]
        
        # Define style based on kind
        if kind == "Pod":
            return "(()"  # Circle
        elif kind == "Service":
            if resource.get("service_type") == "LoadBalancer":
                return "{{{"  # Hexagon with double border
            return "{{" # Hexagon
        elif kind == "Ingress":
            return ">]"  # Flag shape
        elif kind == "PersistentVolumeClaim":
            return "[("  # Cylindrical shape
        elif kind == "ConfigMap" or kind == "Secret":
            return "[\\"  # Note shape
        elif kind == "Namespace":
            return "[/\\"  # Trapezoid shape
        elif kind == "Node":
            return "[/]"  # Parallelogram shape
        else:
            return ""  # Default rectangle shape
    
    def get_mermaid_edge_style(self, relationship_type: str) -> str:
        """
        Convert edge style to Mermaid format.
        
        Args:
            relationship_type: Type of relationship
            
        Returns:
            Mermaid edge style string
        """
        if relationship_type in ["owns", "owned-by"]:
            return "-->"  # Solid arrow
        elif relationship_type in ["selects", "selected-by"]:
            return "-.->"  # Dashed arrow
        elif relationship_type in ["routes-to", "routed-from"]:
            return "==>"  # Bold arrow
        elif relationship_type in ["creates", "created-by"]:
            return "-..->"  # Dotted arrow
        elif relationship_type == "runs-on":
            return "-.->"  # Dashed arrow
        else:
            return "-->"  # Default solid arrow
    
    def _render_legend(self) -> List[str]:
        """
        Render a legend for the diagram.
        
        Returns:
            List of strings for the legend
        """
        legend_lines = [
            "    %% Legend",
            "    subgraph Legend",
            "    legend_pod((Pod))",
            "    legend_service{{Service}}",
            "    legend_loadbalancer{{{LoadBalancer}}}",
            "    legend_ingress>Ingress]",
            "    legend_deployment[Deployment]",
            "    legend_pvc[(PVC)]",
            "    legend_config[\ConfigMap\]",
            "    legend_namespace[/Namespace\]",
            "    legend_node[/Node/]",
            "    end"
        ]
        
        return legend_lines
