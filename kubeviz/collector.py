"""
Collects Kubernetes resources from the cluster.
"""

import logging
import re
from typing import Dict, List, Optional, Set, Any, Tuple

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

class KubernetesResourceCollector:
    """Collects Kubernetes resources from the cluster."""
    
    def __init__(
        self,
        namespace: Optional[str] = None,
        label_selector: Optional[str] = None,
        include_resources: Optional[List[str]] = None,
        exclude_resources: Optional[List[str]] = None,
        include_system: bool = False
    ):
        """
        Initialize the resource collector.
        
        Args:
            namespace: Namespace to filter resources by
            label_selector: Label selector to filter resources by
            include_resources: List of resource types to include
            exclude_resources: List of resource types to exclude
            include_system: Whether to include system resources
        """
        self.namespace = namespace
        self.label_selector = label_selector
        self.include_resources = include_resources
        self.exclude_resources = exclude_resources
        self.include_system = include_system
        
        # Initialize Kubernetes client
        try:
            config.load_kube_config()
        except Exception:
            try:
                # Fallback to in-cluster config
                config.load_incluster_config()
            except Exception as e:
                logger.error("Failed to load Kubernetes configuration: %s", str(e))
                raise
        
        # Initialize API clients
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.batch_v1 = client.BatchV1Api()
        self.custom_api = client.CustomObjectsApi()
        
        # System namespaces to exclude
        self.system_namespaces = {
            "kube-system", "kube-public", "kube-node-lease"
        }
        
        # Default resource types to collect
        self.default_resources = {
            "pods", "services", "deployments", "statefulsets", 
            "daemonsets", "replicasets", "ingresses", "jobs",
            "cronjobs", "persistentvolumeclaims", "configmaps",
            "secrets", "endpoints", "namespaces", "nodes"
        }
        
        # Initialize the resource types to collect
        self._initialize_resource_types()

    def _initialize_resource_types(self):
        """Initialize the set of resource types to collect."""
        if self.include_resources:
            # If include_resources is specified, only collect those
            self.resource_types = set(res.lower() for res in self.include_resources)
        else:
            # Otherwise, use default resources
            self.resource_types = self.default_resources.copy()
            
        # Apply exclusions
        if self.exclude_resources:
            exclude_set = set(res.lower() for res in self.exclude_resources)
            self.resource_types -= exclude_set

    def _should_include_namespace(self, namespace: str) -> bool:
        """Determine if a namespace should be included in the collection."""
        if self.namespace:
            # If namespace filter is specified, only include that namespace
            return namespace == self.namespace
            
        # If no namespace filter, include all non-system namespaces
        # or include system namespaces if include_system is True
        return self.include_system or namespace not in self.system_namespaces

    def collect(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect Kubernetes resources from the cluster.
        
        Returns:
            Dictionary of resources by type
        """
        result = {}
        
        # Namespaces
        if "namespaces" in self.resource_types:
            result["namespaces"] = self._collect_namespaces()
        
        # Nodes
        if "nodes" in self.resource_types:
            result["nodes"] = self._collect_nodes()
        
        # Pods
        if "pods" in self.resource_types:
            result["pods"] = self._collect_pods()
        
        # Services
        if "services" in self.resource_types:
            result["services"] = self._collect_services()
        
        # Deployments
        if "deployments" in self.resource_types:
            result["deployments"] = self._collect_deployments()
        
        # StatefulSets
        if "statefulsets" in self.resource_types:
            result["statefulsets"] = self._collect_statefulsets()
        
        # DaemonSets
        if "daemonsets" in self.resource_types:
            result["daemonsets"] = self._collect_daemonsets()
        
        # ReplicaSets
        if "replicasets" in self.resource_types:
            result["replicasets"] = self._collect_replicasets()
        
        # Ingresses
        if "ingresses" in self.resource_types:
            result["ingresses"] = self._collect_ingresses()
        
        # Jobs
        if "jobs" in self.resource_types:
            result["jobs"] = self._collect_jobs()
        
        # CronJobs
        if "cronjobs" in self.resource_types:
            result["cronjobs"] = self._collect_cronjobs()
        
        # PersistentVolumeClaims
        if "persistentvolumeclaims" in self.resource_types:
            result["persistentvolumeclaims"] = self._collect_pvcs()
        
        # ConfigMaps
        if "configmaps" in self.resource_types:
            result["configmaps"] = self._collect_configmaps()
        
        # Secrets
        if "secrets" in self.resource_types:
            result["secrets"] = self._collect_secrets()
        
        # Endpoints
        if "endpoints" in self.resource_types:
            result["endpoints"] = self._collect_endpoints()
        
        # Add relationships between resources
        self._add_relationships(result)
        
        # Detect external load balancers
        self._detect_external_load_balancers(result)
        
        return result

    def _collect_namespaces(self) -> List[Dict[str, Any]]:
        """Collect namespaces."""
        try:
            namespaces = self.core_v1.list_namespace().items
            result = []
            
            for ns in namespaces:
                if self._should_include_namespace(ns.metadata.name):
                    result.append(self._process_resource(ns))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting namespaces: {str(e)}")
            return []

    def _collect_nodes(self) -> List[Dict[str, Any]]:
        """Collect nodes."""
        try:
            nodes = self.core_v1.list_node().items
            return [self._process_resource(node) for node in nodes]
        except ApiException as e:
            logger.error(f"Error collecting nodes: {str(e)}")
            return []

    def _collect_pods(self) -> List[Dict[str, Any]]:
        """Collect pods."""
        try:
            if self.namespace:
                pods = self.core_v1.list_namespaced_pod(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                pods = self.core_v1.list_pod_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for pod in pods:
                if self._should_include_namespace(pod.metadata.namespace):
                    result.append(self._process_resource(pod))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting pods: {str(e)}")
            return []

    def _collect_services(self) -> List[Dict[str, Any]]:
        """Collect services."""
        try:
            if self.namespace:
                services = self.core_v1.list_namespaced_service(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                services = self.core_v1.list_service_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for svc in services:
                if self._should_include_namespace(svc.metadata.namespace):
                    result.append(self._process_resource(svc))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting services: {str(e)}")
            return []

    def _collect_deployments(self) -> List[Dict[str, Any]]:
        """Collect deployments."""
        try:
            if self.namespace:
                deployments = self.apps_v1.list_namespaced_deployment(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                deployments = self.apps_v1.list_deployment_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for deployment in deployments:
                if self._should_include_namespace(deployment.metadata.namespace):
                    result.append(self._process_resource(deployment))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting deployments: {str(e)}")
            return []

    def _collect_statefulsets(self) -> List[Dict[str, Any]]:
        """Collect statefulsets."""
        try:
            if self.namespace:
                statefulsets = self.apps_v1.list_namespaced_stateful_set(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                statefulsets = self.apps_v1.list_stateful_set_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for statefulset in statefulsets:
                if self._should_include_namespace(statefulset.metadata.namespace):
                    result.append(self._process_resource(statefulset))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting statefulsets: {str(e)}")
            return []

    def _collect_daemonsets(self) -> List[Dict[str, Any]]:
        """Collect daemonsets."""
        try:
            if self.namespace:
                daemonsets = self.apps_v1.list_namespaced_daemon_set(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                daemonsets = self.apps_v1.list_daemon_set_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for daemonset in daemonsets:
                if self._should_include_namespace(daemonset.metadata.namespace):
                    result.append(self._process_resource(daemonset))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting daemonsets: {str(e)}")
            return []

    def _collect_replicasets(self) -> List[Dict[str, Any]]:
        """Collect replicasets."""
        try:
            if self.namespace:
                replicasets = self.apps_v1.list_namespaced_replica_set(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                replicasets = self.apps_v1.list_replica_set_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for replicaset in replicasets:
                if self._should_include_namespace(replicaset.metadata.namespace):
                    result.append(self._process_resource(replicaset))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting replicasets: {str(e)}")
            return []

    def _collect_ingresses(self) -> List[Dict[str, Any]]:
        """Collect ingresses."""
        try:
            if self.namespace:
                ingresses = self.networking_v1.list_namespaced_ingress(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                ingresses = self.networking_v1.list_ingress_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for ingress in ingresses:
                if self._should_include_namespace(ingress.metadata.namespace):
                    resource = self._process_resource(ingress)
                    # Add ingress-specific information
                    resource["ingress_rules"] = []
                    if ingress.spec.rules:
                        for rule in ingress.spec.rules:
                            ingress_rule = {
                                "host": rule.host,
                                "http": []
                            }
                            if rule.http and rule.http.paths:
                                for path in rule.http.paths:
                                    ingress_rule["http"].append({
                                        "path": path.path,
                                        "path_type": path.path_type,
                                        "backend_service_name": path.backend.service.name if path.backend.service else None,
                                        "backend_service_port": path.backend.service.port.number if path.backend.service and path.backend.service.port else None
                                    })
                            resource["ingress_rules"].append(ingress_rule)
                    result.append(resource)
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting ingresses: {str(e)}")
            return []

    def _collect_jobs(self) -> List[Dict[str, Any]]:
        """Collect jobs."""
        try:
            if self.namespace:
                jobs = self.batch_v1.list_namespaced_job(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                jobs = self.batch_v1.list_job_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for job in jobs:
                if self._should_include_namespace(job.metadata.namespace):
                    result.append(self._process_resource(job))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting jobs: {str(e)}")
            return []

    def _collect_cronjobs(self) -> List[Dict[str, Any]]:
        """Collect cronjobs."""
        try:
            if self.namespace:
                cronjobs = self.batch_v1.list_namespaced_cron_job(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                cronjobs = self.batch_v1.list_cron_job_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for cronjob in cronjobs:
                if self._should_include_namespace(cronjob.metadata.namespace):
                    result.append(self._process_resource(cronjob))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting cronjobs: {str(e)}")
            return []

    def _collect_pvcs(self) -> List[Dict[str, Any]]:
        """Collect persistent volume claims."""
        try:
            if self.namespace:
                pvcs = self.core_v1.list_namespaced_persistent_volume_claim(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                pvcs = self.core_v1.list_persistent_volume_claim_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for pvc in pvcs:
                if self._should_include_namespace(pvc.metadata.namespace):
                    result.append(self._process_resource(pvc))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting persistent volume claims: {str(e)}")
            return []

    def _collect_configmaps(self) -> List[Dict[str, Any]]:
        """Collect configmaps."""
        try:
            if self.namespace:
                configmaps = self.core_v1.list_namespaced_config_map(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                configmaps = self.core_v1.list_config_map_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for configmap in configmaps:
                if self._should_include_namespace(configmap.metadata.namespace):
                    result.append(self._process_resource(configmap))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting configmaps: {str(e)}")
            return []

    def _collect_secrets(self) -> List[Dict[str, Any]]:
        """Collect secrets."""
        try:
            if self.namespace:
                secrets = self.core_v1.list_namespaced_secret(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                secrets = self.core_v1.list_secret_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for secret in secrets:
                if self._should_include_namespace(secret.metadata.namespace):
                    # Skip service account tokens and other auto-generated secrets
                    if (secret.type != "kubernetes.io/service-account-token" and
                        not secret.metadata.name.startswith("default-token-")):
                        result.append(self._process_resource(secret))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting secrets: {str(e)}")
            return []

    def _collect_endpoints(self) -> List[Dict[str, Any]]:
        """Collect endpoints."""
        try:
            if self.namespace:
                endpoints = self.core_v1.list_namespaced_endpoints(
                    namespace=self.namespace,
                    label_selector=self.label_selector
                ).items
            else:
                endpoints = self.core_v1.list_endpoints_for_all_namespaces(
                    label_selector=self.label_selector
                ).items
            
            result = []
            for endpoint in endpoints:
                if self._should_include_namespace(endpoint.metadata.namespace):
                    result.append(self._process_resource(endpoint))
            
            return result
        except ApiException as e:
            logger.error(f"Error collecting endpoints: {str(e)}")
            return []

    def _process_resource(self, resource) -> Dict[str, Any]:
        """Process a Kubernetes resource into a dictionary with needed attributes."""
        result = {
            "kind": resource.kind,
            "name": resource.metadata.name,
            "namespace": resource.metadata.namespace,
            "uid": resource.metadata.uid,
        }
        
        # Add labels if present
        if resource.metadata.labels:
            result["labels"] = resource.metadata.labels
        else:
            result["labels"] = {}
        
        # Add owner references if present
        if resource.metadata.owner_references:
            result["owner_references"] = []
            for ref in resource.metadata.owner_references:
                result["owner_references"].append({
                    "kind": ref.kind,
                    "name": ref.name,
                    "uid": ref.uid
                })
        
        # Process Pod-specific information
        if resource.kind == "Pod" and hasattr(resource, "spec"):
            # Add node name for pods
            if hasattr(resource.spec, "node_name") and resource.spec.node_name:
                result["node_name"] = resource.spec.node_name
            
            # Add volumes for pods
            if hasattr(resource.spec, "volumes") and resource.spec.volumes:
                result["volumes"] = []
                for volume in resource.spec.volumes:
                    volume_info = {"name": volume.name}
                    
                    # PVC
                    if hasattr(volume, "persistent_volume_claim") and volume.persistent_volume_claim:
                        volume_info["persistent_volume_claim"] = volume.persistent_volume_claim.claim_name
                    
                    # ConfigMap
                    if hasattr(volume, "config_map") and volume.config_map:
                        volume_info["config_map"] = volume.config_map.name
                    
                    # Secret
                    if hasattr(volume, "secret") and volume.secret:
                        volume_info["secret"] = volume.secret.secret_name
                    
                    result["volumes"].append(volume_info)
            
            # Add container information
            if hasattr(resource.spec, "containers") and resource.spec.containers:
                result["containers"] = []
                for container in resource.spec.containers:
                    container_info = {"name": container.name}
                    
                    # Add environment variables that reference configmaps or secrets
                    if hasattr(container, "env") and container.env:
                        container_info["env_from"] = []
                        for env in container.env:
                            if hasattr(env, "value_from"):
                                if hasattr(env.value_from, "config_map_key_ref") and env.value_from.config_map_key_ref:
                                    container_info["env_from"].append({
                                        "type": "ConfigMap",
                                        "name": env.value_from.config_map_key_ref.name
                                    })
                                elif hasattr(env.value_from, "secret_key_ref") and env.value_from.secret_key_ref:
                                    container_info["env_from"].append({
                                        "type": "Secret",
                                        "name": env.value_from.secret_key_ref.name
                                    })
                    
                    # Add volume mounts
                    if hasattr(container, "volume_mounts") and container.volume_mounts:
                        container_info["volume_mounts"] = [vm.name for vm in container.volume_mounts]
                    
                    result["containers"].append(container_info)
        
        # Add selector if present (for deployments, services, etc.)
        if hasattr(resource, "spec") and hasattr(resource.spec, "selector"):
            if hasattr(resource.spec.selector, "match_labels") and resource.spec.selector.match_labels:
                # For deployments, statefulsets, etc. that use matchLabels
                result["selector"] = resource.spec.selector.match_labels
            else:
                # For services that use a simple selector
                result["selector"] = resource.spec.selector
        
        # Add service type for services
        if resource.kind == "Service" and hasattr(resource, "spec"):
            result["service_type"] = resource.spec.type
            if resource.spec.type == "LoadBalancer" and hasattr(resource.status, "load_balancer") and hasattr(resource.status.load_balancer, "ingress"):
                result["load_balancer"] = []
                for ingress in resource.status.load_balancer.ingress:
                    lb_entry = {}
                    if hasattr(ingress, "ip") and ingress.ip:
                        lb_entry["ip"] = ingress.ip
                    if hasattr(ingress, "hostname") and ingress.hostname:
                        lb_entry["hostname"] = ingress.hostname
                    result["load_balancer"].append(lb_entry)
        
        # Add pod template labels for controllers
        if (resource.kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"] and 
            hasattr(resource, "spec") and 
            hasattr(resource.spec, "template") and 
            hasattr(resource.spec.template, "metadata") and 
            hasattr(resource.spec.template.metadata, "labels")):
            result["pod_template_labels"] = resource.spec.template.metadata.labels
        
        # Add custom relationships to track
        result["relationships"] = []
        
        return result

    def _add_relationships(self, resources: Dict[str, List[Dict[str, Any]]]):
        """Add relationships between resources."""
        logger.debug("Adding relationships between resources")
        
        # Add pod-to-node relationships
        if "pods" in resources and "nodes" in resources:
            logger.debug(f"Found {len(resources['pods'])} pods and {len(resources['nodes'])} nodes")
            for pod in resources["pods"]:
                # Find the node that the pod is running on
                node_name = pod.get("node_name")
                if node_name:
                    logger.debug(f"Pod {pod['name']} runs on node {node_name}")
                    for node in resources["nodes"]:
                        if node["name"] == node_name:
                            pod["relationships"].append({
                                "kind": "Node",
                                "name": node_name,
                                "namespace": None,
                                "relationship_type": "runs-on"
                            })
                            node["relationships"].append({
                                "kind": "Pod",
                                "name": pod["name"],
                                "namespace": pod["namespace"],
                                "relationship_type": "hosts"
                            })
                            break
        
        # Add service-to-pod relationships (via selectors)
        if "services" in resources and "pods" in resources:
            logger.debug(f"Found {len(resources['services'])} services")
            for service in resources["services"]:
                selector = service.get("selector", {})
                if selector and isinstance(selector, dict):
                    logger.debug(f"Service {service['name']} has selector {selector}")
                    matching_pods = []
                    for pod in resources["pods"]:
                        pod_labels = pod.get("labels", {})
                        if self._matches_selector(pod_labels, selector):
                            matching_pods.append(pod)
                            service["relationships"].append({
                                "kind": "Pod",
                                "name": pod["name"],
                                "namespace": pod["namespace"],
                                "relationship_type": "selects"
                            })
                            pod["relationships"].append({
                                "kind": "Service",
                                "name": service["name"],
                                "namespace": service["namespace"],
                                "relationship_type": "selected-by"
                            })
                    logger.debug(f"Service {service['name']} selects {len(matching_pods)} pods")
        
        # Add owner relationships (e.g., deployments own replicasets, which own pods)
        owner_count = 0
        for resource_type, resource_list in resources.items():
            for resource in resource_list:
                if "owner_references" in resource and resource["owner_references"]:
                    for owner_ref in resource["owner_references"]:
                        found_owner = False
                        # Find the owner in our resources
                        for owner_type, owner_list in resources.items():
                            if not found_owner:  # Stop once we find one
                                for potential_owner in owner_list:
                                    if (potential_owner["kind"] == owner_ref["kind"] and 
                                        potential_owner["name"] == owner_ref["name"]):
                                        # Add relationship in both directions
                                        resource["relationships"].append({
                                            "kind": potential_owner["kind"],
                                            "name": potential_owner["name"],
                                            "namespace": potential_owner["namespace"],
                                            "relationship_type": "owned-by"
                                        })
                                        potential_owner["relationships"].append({
                                            "kind": resource["kind"],
                                            "name": resource["name"],
                                            "namespace": resource["namespace"],
                                            "relationship_type": "owns"
                                        })
                                        found_owner = True
                                        owner_count += 1
                                        break
        logger.debug(f"Added {owner_count} owner relationships")
        
        # Add controller-to-pod relationships (via pod template labels)
        controller_count = 0
        if "pods" in resources:
            # For each controller type that would create pods
            for controller_type in ["deployments", "statefulsets", "daemonsets", "replicasets"]:
                if controller_type in resources:
                    logger.debug(f"Found {len(resources[controller_type])} {controller_type}")
                    for controller in resources[controller_type]:
                        pod_template_labels = controller.get("pod_template_labels", {})
                        if pod_template_labels:
                            # Find pods that match this controller's pod template labels
                            for pod in resources["pods"]:
                                pod_labels = pod.get("labels", {})
                                
                                # Check if this pod is already owned by another resource
                                already_owned = False
                                for rel in pod.get("relationships", []):
                                    if rel["relationship_type"] == "owned-by":
                                        already_owned = True
                                        break
                                
                                # If it's not already owned, or if it's owned but we need to ensure the controller relationship
                                if not already_owned and self._matches_selector(pod_labels, pod_template_labels):
                                    # Check if we already have this relationship
                                    already_has_relationship = False
                                    for rel in pod.get("relationships", []):
                                        if (rel["kind"] == controller["kind"] and 
                                            rel["name"] == controller["name"] and 
                                            rel["namespace"] == controller["namespace"]):
                                            already_has_relationship = True
                                            break
                                    
                                    if not already_has_relationship:
                                        pod["relationships"].append({
                                            "kind": controller["kind"],
                                            "name": controller["name"],
                                            "namespace": controller["namespace"],
                                            "relationship_type": "created-by"
                                        })
                                        controller["relationships"].append({
                                            "kind": "Pod",
                                            "name": pod["name"],
                                            "namespace": pod["namespace"],
                                            "relationship_type": "creates"
                                        })
                                        controller_count += 1
        logger.debug(f"Added {controller_count} controller-pod relationships")
        
        # Add POD volume mount relationships
        vol_mount_count = 0
        if "pods" in resources:
            # Check for PVCs
            if "persistentvolumeclaims" in resources:
                for pod in resources["pods"]:
                    pod_volumes = pod.get("volumes", [])
                    for volume in pod_volumes:
                        if volume.get("persistent_volume_claim"):
                            pvc_name = volume.get("persistent_volume_claim")
                            for pvc in resources["persistentvolumeclaims"]:
                                if pvc["name"] == pvc_name and pvc["namespace"] == pod["namespace"]:
                                    pod["relationships"].append({
                                        "kind": "PersistentVolumeClaim",
                                        "name": pvc["name"],
                                        "namespace": pvc["namespace"],
                                        "relationship_type": "uses"
                                    })
                                    pvc["relationships"].append({
                                        "kind": "Pod",
                                        "name": pod["name"],
                                        "namespace": pod["namespace"],
                                        "relationship_type": "used-by"
                                    })
                                    vol_mount_count += 1
            
            # Check for ConfigMap volumes
            if "configmaps" in resources:
                for pod in resources["pods"]:
                    pod_volumes = pod.get("volumes", [])
                    for volume in pod_volumes:
                        if volume.get("config_map"):
                            cm_name = volume.get("config_map")
                            for cm in resources["configmaps"]:
                                if cm["name"] == cm_name and cm["namespace"] == pod["namespace"]:
                                    pod["relationships"].append({
                                        "kind": "ConfigMap",
                                        "name": cm["name"],
                                        "namespace": cm["namespace"],
                                        "relationship_type": "mounts"
                                    })
                                    cm["relationships"].append({
                                        "kind": "Pod",
                                        "name": pod["name"],
                                        "namespace": pod["namespace"],
                                        "relationship_type": "mounted-by"
                                    })
                                    vol_mount_count += 1
            
            # Check for Secret volumes
            if "secrets" in resources:
                for pod in resources["pods"]:
                    pod_volumes = pod.get("volumes", [])
                    for volume in pod_volumes:
                        if volume.get("secret"):
                            secret_name = volume.get("secret")
                            for secret in resources["secrets"]:
                                if secret["name"] == secret_name and secret["namespace"] == pod["namespace"]:
                                    pod["relationships"].append({
                                        "kind": "Secret",
                                        "name": secret["name"],
                                        "namespace": secret["namespace"],
                                        "relationship_type": "mounts"
                                    })
                                    secret["relationships"].append({
                                        "kind": "Pod",
                                        "name": pod["name"],
                                        "namespace": pod["namespace"],
                                        "relationship_type": "mounted-by"
                                    })
                                    vol_mount_count += 1
        logger.debug(f"Added {vol_mount_count} volume mount relationships")
        
        # Add ingress-to-service relationships
        ingress_count = 0
        if "ingresses" in resources and "services" in resources:
            logger.debug(f"Found {len(resources['ingresses'])} ingresses")
            for ingress in resources["ingresses"]:
                if "ingress_rules" in ingress:
                    for rule in ingress["ingress_rules"]:
                        for http_path in rule.get("http", []):
                            if http_path.get("backend_service_name"):
                                # Find the service that this ingress points to
                                service_name = http_path["backend_service_name"]
                                for service in resources["services"]:
                                    if service["name"] == service_name and service["namespace"] == ingress["namespace"]:
                                        logger.debug(f"Ingress {ingress['name']} routes to Service {service['name']}")
                                        
                                        # Check if the relationship already exists
                                        already_has_relationship = False
                                        for rel in ingress.get("relationships", []):
                                            if (rel["kind"] == "Service" and 
                                                rel["name"] == service["name"] and 
                                                rel["namespace"] == service["namespace"]):
                                                already_has_relationship = True
                                                break
                                        
                                        if not already_has_relationship:
                                            ingress["relationships"].append({
                                                "kind": "Service",
                                                "name": service["name"],
                                                "namespace": service["namespace"],
                                                "relationship_type": "routes-to"
                                            })
                                            service["relationships"].append({
                                                "kind": "Ingress",
                                                "name": ingress["name"],
                                                "namespace": ingress["namespace"],
                                                "relationship_type": "routed-from"
                                            })
                                            ingress_count += 1
            
            # Extra check for Kubernetes 1.19+ style ingresses that might not have been processed
            try:
                # Add a check for newer Kubernetes API versions (1.19+) with Ingress format changes
                logger.debug("Checking for additional ingress-service relationships using newer API format")
                
                # Process ingresses again to find potential backend services
                for ingress_resource in resources["ingresses"]:
                    # Check for backend links that may have been missed
                    backends_found = 0
                    
                    # Try to find services targeted by this ingress
                    for service in resources["services"]:
                        # Look for standard naming convention where service name might be embedded in ingress name
                        ingress_name_lower = ingress_resource["name"].lower()
                        service_name_lower = service["name"].lower()
                        
                        # Check if ingress contains service name or vice versa
                        if (service_name_lower in ingress_name_lower or 
                            ingress_name_lower.startswith(service_name_lower) or
                            ingress_name_lower.endswith(service_name_lower)):
                            
                            # Only add if they're in the same namespace
                            if service["namespace"] == ingress_resource["namespace"]:
                                # Check if relationship already exists
                                already_has_relationship = False
                                for rel in ingress_resource.get("relationships", []):
                                    if (rel["kind"] == "Service" and 
                                        rel["name"] == service["name"] and 
                                        rel["namespace"] == service["namespace"]):
                                        already_has_relationship = True
                                        break
                                
                                if not already_has_relationship:
                                    logger.debug(f"Found potential service match: Ingress {ingress_resource['name']} -> Service {service['name']}")
                                    ingress_resource["relationships"].append({
                                        "kind": "Service",
                                        "name": service["name"],
                                        "namespace": service["namespace"],
                                        "relationship_type": "routes-to"
                                    })
                                    service["relationships"].append({
                                        "kind": "Ingress",
                                        "name": ingress_resource["name"],
                                        "namespace": ingress_resource["namespace"],
                                        "relationship_type": "routed-from"
                                    })
                                    ingress_count += 1
                                    backends_found += 1
                    
                    logger.debug(f"Found {backends_found} potential additional backend services for ingress {ingress_resource['name']}")
            except Exception as e:
                logger.warning(f"Error checking for additional ingress-service relationships: {str(e)}")
        
        logger.debug(f"Added {ingress_count} ingress-service relationships")

    def _detect_external_load_balancers(self, resources: Dict[str, List[Dict[str, Any]]]):
        """
        Detect external load balancers like AWS ALB/ELB, and add them to the resources.
        """
        lb_count = 0
        logger.debug("Detecting external load balancers")
        
        # Check for services with type LoadBalancer and add cloud-specific information
        if "services" in resources:
            for service in resources["services"]:
                if service.get("service_type") == "LoadBalancer" and "load_balancer" in service:
                    for lb in service["load_balancer"]:
                        detected = False
                        
                        # Check for AWS ELB/ALB
                        if "hostname" in lb and (".elb.amazonaws.com" in lb["hostname"] or 
                                                ".amazonaws.com" in lb["hostname"]):
                            # Detect if it's an ALB or ELB
                            lb_type = "ALB" if "amazonaws.com/alb" in lb["hostname"] else "ELB"
                            service["cloud_load_balancer"] = {
                                "type": lb_type,
                                "provider": "AWS",
                                "hostname": lb["hostname"]
                            }
                            detected = True
                            logger.debug(f"Detected AWS {lb_type} for service {service['name']}")
                            
                            # Add a synthetic resource for the load balancer
                            lb_name = f"{service['name']}-aws-{lb_type.lower()}"
                            lb_resource = {
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "uid": f"{service['uid']}-lb",  # Generate a synthetic UID
                                "provider": "AWS",
                                "type": lb_type,
                                "hostname": lb["hostname"],
                                "relationships": [{
                                    "kind": "Service",
                                    "name": service["name"],
                                    "namespace": service["namespace"],
                                    "relationship_type": "routes-to"
                                }]
                            }
                            
                            # Add to resources if not already there
                            if "loadbalancers" not in resources:
                                resources["loadbalancers"] = []
                            resources["loadbalancers"].append(lb_resource)
                            
                            # Add relationship from service to load balancer
                            service["relationships"].append({
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "relationship_type": "exposed-by"
                            })
                            lb_count += 1
                            
                        # Check for Azure Load Balancer
                        elif "ip" in lb and "hostname" in lb and ".cloudapp.azure.com" in lb.get("hostname", ""):
                            service["cloud_load_balancer"] = {
                                "type": "LoadBalancer",
                                "provider": "Azure",
                                "hostname": lb["hostname"],
                                "ip": lb["ip"]
                            }
                            detected = True
                            logger.debug(f"Detected Azure Load Balancer for service {service['name']}")
                            
                            # Add a synthetic resource for the load balancer
                            lb_name = f"{service['name']}-azure-lb"
                            lb_resource = {
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "uid": f"{service['uid']}-lb",  # Generate a synthetic UID
                                "provider": "Azure",
                                "type": "LoadBalancer",
                                "hostname": lb["hostname"],
                                "ip": lb["ip"],
                                "relationships": [{
                                    "kind": "Service",
                                    "name": service["name"],
                                    "namespace": service["namespace"],
                                    "relationship_type": "routes-to"
                                }]
                            }
                            
                            # Add to resources if not already there
                            if "loadbalancers" not in resources:
                                resources["loadbalancers"] = []
                            resources["loadbalancers"].append(lb_resource)
                            
                            # Add relationship from service to load balancer
                            service["relationships"].append({
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "relationship_type": "exposed-by"
                            })
                            lb_count += 1
                            
                        # Check for GCP Load Balancer (detect by annotation)
                        elif "labels" in service and service["labels"].get("cloud.google.com/load-balancer-type"):
                            lb_type = service["labels"]["cloud.google.com/load-balancer-type"]
                            service["cloud_load_balancer"] = {
                                "type": lb_type,
                                "provider": "GCP",
                                "ip": lb.get("ip")
                            }
                            detected = True
                            logger.debug(f"Detected GCP {lb_type} for service {service['name']}")
                            
                            # Add a synthetic resource for the load balancer
                            lb_name = f"{service['name']}-gcp-{lb_type.lower().replace(' ', '-')}"
                            lb_resource = {
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "uid": f"{service['uid']}-lb",  # Generate a synthetic UID
                                "provider": "GCP",
                                "type": lb_type,
                                "ip": lb.get("ip"),
                                "relationships": [{
                                    "kind": "Service",
                                    "name": service["name"],
                                    "namespace": service["namespace"],
                                    "relationship_type": "routes-to"
                                }]
                            }
                            
                            # Add to resources if not already there
                            if "loadbalancers" not in resources:
                                resources["loadbalancers"] = []
                            resources["loadbalancers"].append(lb_resource)
                            
                            # Add relationship from service to load balancer
                            service["relationships"].append({
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "relationship_type": "exposed-by"
                            })
                            lb_count += 1
                        
                        # Generic load balancer if we couldn't detect a specific cloud provider
                        elif not detected and service.get("service_type") == "LoadBalancer":
                            logger.debug(f"Detected generic Load Balancer for service {service['name']}")
                            
                            # Add a synthetic resource for the load balancer
                            lb_name = f"{service['name']}-external-lb"
                            lb_resource = {
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "uid": f"{service['uid']}-lb",  # Generate a synthetic UID
                                "provider": "Unknown",
                                "type": "LoadBalancer",
                                "ip": lb.get("ip", ""),
                                "hostname": lb.get("hostname", ""),
                                "relationships": [{
                                    "kind": "Service",
                                    "name": service["name"],
                                    "namespace": service["namespace"],
                                    "relationship_type": "routes-to"
                                }]
                            }
                            
                            # Add to resources if not already there
                            if "loadbalancers" not in resources:
                                resources["loadbalancers"] = []
                            resources["loadbalancers"].append(lb_resource)
                            
                            # Add relationship from service to load balancer
                            service["relationships"].append({
                                "kind": "LoadBalancer",
                                "name": lb_name,
                                "namespace": service["namespace"],
                                "relationship_type": "exposed-by"
                            })
                            lb_count += 1
        
        # Check for Ingress controllers and add their relationships
        ingress_controller_count = 0
        if "ingresses" in resources and "services" in resources:
            # Try to detect ingress controller type based on annotations or labels
            for ingress in resources["ingresses"]:
                labels = ingress.get("labels", {})
                controller_type = None
                
                # Check for specific ingress controller types based on annotations or labels
                if "kubernetes.io/ingress.class" in labels:
                    ingress_class = labels["kubernetes.io/ingress.class"]
                    if ingress_class == "nginx":
                        controller_type = "NGINX"
                    elif ingress_class == "traefik":
                        controller_type = "Traefik"
                    elif ingress_class == "alb":
                        controller_type = "AWS ALB"
                    elif ingress_class == "istio":
                        controller_type = "Istio"
                    else:
                        controller_type = ingress_class.capitalize()
                elif labels.get("app.kubernetes.io/name") == "ingress-nginx":
                    controller_type = "NGINX"
                elif "traefik" in labels.get("app.kubernetes.io/name", ""):
                    controller_type = "Traefik"
                elif "aws-alb" in labels.get("app.kubernetes.io/name", ""):
                    controller_type = "AWS ALB"
                
                if controller_type:
                    ingress["ingress_controller_type"] = controller_type
                    logger.debug(f"Detected {controller_type} ingress controller for ingress {ingress['name']}")
                    
                    # Add synthetic resource for ingress controller if it doesn't exist already
                    controller_name = f"{controller_type.lower()}-ingress-controller"
                    
                    # Check if this controller already exists
                    exists = False
                    if "ingresscontrollers" in resources:
                        for controller in resources["ingresscontrollers"]:
                            if controller["name"] == controller_name:
                                exists = True
                                # Add relationship to this ingress
                                controller["relationships"].append({
                                    "kind": "Ingress",
                                    "name": ingress["name"],
                                    "namespace": ingress["namespace"],
                                    "relationship_type": "manages"
                                })
                                break
                    
                    if not exists:
                        # Create a new synthetic resource for the ingress controller
                        controller_resource = {
                            "kind": "IngressController",
                            "name": controller_name,
                            "namespace": "kube-system",  # Typically ingress controllers run in kube-system
                            "uid": f"ic-{controller_type.lower()}",  # Synthetic UID
                            "type": controller_type,
                            "relationships": [{
                                "kind": "Ingress",
                                "name": ingress["name"],
                                "namespace": ingress["namespace"],
                                "relationship_type": "manages"
                            }]
                        }
                        
                        # Add to resources
                        if "ingresscontrollers" not in resources:
                            resources["ingresscontrollers"] = []
                        resources["ingresscontrollers"].append(controller_resource)
                    
                    # Add relationship from ingress to controller
                    ingress["relationships"].append({
                        "kind": "IngressController",
                        "name": controller_name,
                        "namespace": "kube-system",
                        "relationship_type": "managed-by"
                    })
                    ingress_controller_count += 1
        
        logger.debug(f"Detected {lb_count} load balancers and {ingress_controller_count} ingress controllers")

    def _matches_selector(self, labels: Dict[str, str], selector: Dict[str, str]) -> bool:
        """Check if labels match the given selector."""
        if not selector:
            return False
        
        for key, value in selector.items():
            if key not in labels or labels[key] != value:
                return False
        
        return True
