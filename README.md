# KubeViz - Kubernetes Cluster Visualization

KubeViz is a kubectl plugin that visualizes Kubernetes cluster resources and their relationships as SVG or Mermaid diagrams with smart detection of key components.

![KubeViz Example](https://via.placeholder.com/800x400?text=KubeViz+Example+Diagram)

## Features

- Generate cluster visualization diagrams in SVG and Mermaid formats
- Support filtering by namespace or label selectors
- Default to visualizing the entire cluster if no filters provided
- Detect and visualize Kubernetes resources (pods, services, deployments, etc.)
- Smart detection of ingress resources and external load balancers (like AWS ALB)
- Show relationships between resources (connections, dependencies)
- Interactive preview mode with zooming and export capabilities

## Installation

### Prerequisites

- Kubernetes cluster and `kubectl` configured
- Python 3.6 or later
- Graphviz (for SVG output)

### Install using Krew

```bash
kubectl krew install kubeviz
