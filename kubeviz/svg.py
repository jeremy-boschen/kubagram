"""
SVG diagram renderer using Graphviz.
"""

import logging
import tempfile
import os
from typing import Dict, List, Any, Set, Tuple

try:
    import graphviz
except ImportError:
    graphviz = None

from kubeviz.renderer import DiagramRenderer

logger = logging.getLogger(__name__)

class SVGRenderer(DiagramRenderer):
    """Renders diagrams in SVG format using Graphviz."""
    
    def render(self) -> str:
        """
        Render the diagram in SVG format.
        
        Returns:
            SVG diagram string
        """
        if graphviz is None:
            raise ImportError("The 'graphviz' package is required for SVG rendering. "
                              "Install it using: pip install graphviz")
        
        # Create a new Graphviz digraph
        graph = graphviz.Digraph(
            format='svg',
            engine='dot',
            graph_attr={
                'rankdir': self.direction,
                'splines': 'ortho',
                'nodesep': '0.5',
                'ranksep': '0.5',
                'fontname': 'Arial',
                'bgcolor': 'transparent',
                'style': 'filled',
                'margin': '0'
            }
        )
        
        # Add cluster for each namespace if we have multiple namespaces
        namespaces = set()
        for resource_type, resources in self.resources.items():
            for resource in resources:
                if resource["namespace"]:
                    namespaces.add(resource["namespace"])
        
        # If there are multiple namespaces and not too many, group by namespace
        namespace_subgraphs = {}
        if len(namespaces) > 1 and len(namespaces) <= 10:
            for namespace in namespaces:
                namespace_subgraph = graphviz.Digraph(
                    name=f"cluster_{namespace.replace('-', '_')}",
                    graph_attr={
                        'label': f"Namespace: {namespace}",
                        'style': 'filled',
                        'color': '#E6E6FA',
                        'fontname': 'Arial',
                        'fontsize': '12'
                    }
                )
                namespace_subgraphs[namespace] = namespace_subgraph
        
        # Keep track of nodes and edges we've already added
        added_nodes = set()
        added_edges = set()
        
        # Add nodes for all resources
        for resource_type, resources in self.resources.items():
            for resource in resources:
                node_id = self.get_node_id(resource)
                if node_id not in added_nodes:
                    node_label = self.get_resource_label(resource)
                    node_style = self.get_node_style(resource)
                    
                    # Add node to appropriate namespace subgraph or main graph
                    namespace = resource["namespace"]
                    if namespace and namespace in namespace_subgraphs:
                        namespace_subgraphs[namespace].node(
                            node_id,
                            label=node_label,
                            **node_style
                        )
                    else:
                        graph.node(
                            node_id,
                            label=node_label,
                            **node_style
                        )
                    
                    added_nodes.add(node_id)
        
        # Add all namespace subgraphs to the main graph
        for namespace, subgraph in namespace_subgraphs.items():
            graph.subgraph(subgraph)
        
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
                            # Get edge style
                            source_resource = next(r for r in self.resources[resource_type] if self.get_node_id(r) == source_id)
                            target_resource_type = next(rt for rt, resources in self.resources.items() 
                                                     for r in resources if self.get_node_id(r) == target_id)
                            target_resource = next(r for r in self.resources[target_resource_type] if self.get_node_id(r) == target_id)
                            
                            edge_style = self.get_edge_style(source_resource, target_resource, relationship_type)
                            edge_label = self.get_edge_label(relationship_type)
                            
                            graph.edge(
                                from_id,
                                to_id,
                                label=edge_label,
                                **edge_style
                            )
                            
                            added_edges.add(edge_key)
        
        # Generate legend
        self._add_legend(graph)
        
        # Render the SVG
        with tempfile.TemporaryDirectory() as tmpdirname:
            # Render to a temporary file
            graph_path = os.path.join(tmpdirname, "k8s_diagram")
            try:
                rendered_graph = graph.render(filename=graph_path, cleanup=True)
                with open(rendered_graph, 'r') as f:
                    svg_content = f.read()
                return svg_content
            except Exception as e:
                logger.error(f"Error rendering SVG: {str(e)}")
                # Return simple error SVG
                return f"""<?xml version="1.0" encoding="UTF-8" standalone="no"?>
                <svg xmlns="http://www.w3.org/2000/svg" width="500" height="200">
                    <rect width="500" height="200" fill="#f8f9fa" />
                    <text x="50" y="100" font-family="Arial" font-size="14" fill="#dc3545">
                        Error rendering diagram: {str(e)}
                    </text>
                </svg>
                """
    
    def _add_legend(self, graph: 'graphviz.Digraph'):
        """
        Add a legend to the graph.
        
        Args:
            graph: Graphviz digraph
        """
        with graph.subgraph(name='cluster_legend') as legend:
            legend.attr(label='Legend', fontname='Arial', fontsize='12', style='filled', color='#f5f5f5')
            
            # Add nodes for each resource type
            legend.node('legend_pod', 'Pod', shape='circle', style='filled', fillcolor='#ADD8E6', fontname='Arial', fontsize='10')
            legend.node('legend_service', 'Service', shape='hexagon', style='filled', fillcolor='#98FB98', fontname='Arial', fontsize='10')
            legend.node('legend_loadbalancer', 'LoadBalancer', shape='doubleoctagon', style='filled', fillcolor='#FFAEBC', fontname='Arial', fontsize='10')
            legend.node('legend_deployment', 'Deployment', shape='box', style='filled', fillcolor='#FFA07A', fontname='Arial', fontsize='10')
            legend.node('legend_ingress', 'Ingress', shape='invhouse', style='filled', fillcolor='#87CEFA', fontname='Arial', fontsize='10')
            legend.node('legend_pvc', 'PersistentVolumeClaim', shape='cylinder', style='filled', fillcolor='#DDA0DD', fontname='Arial', fontsize='10')
            legend.node('legend_config', 'ConfigMap', shape='note', style='filled', fillcolor='#D3D3D3', fontname='Arial', fontsize='10')
            legend.node('legend_secret', 'Secret', shape='note', style='filled', fillcolor='#FA8072', fontname='Arial', fontsize='10')
            
            # Add relationship types
            legend.edge('legend_deployment', 'legend_pod', label='creates', style='dotted', color='#008000', fontname='Arial', fontsize='8')
            legend.edge('legend_service', 'legend_pod', label='selects', style='dashed', color='#0000FF', fontname='Arial', fontsize='8')
            legend.edge('legend_ingress', 'legend_service', label='routes to', style='bold', color='#FF00FF', fontname='Arial', fontsize='8')
