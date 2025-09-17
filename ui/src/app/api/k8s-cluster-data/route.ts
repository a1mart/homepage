/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-unused-vars */


// app/api/k8s-cluster-data/route.ts
import { NextRequest, NextResponse } from 'next/server';
import * as k8s from '@kubernetes/client-node';

interface NodeInfo {
  name: string;
  status: string;
  version: string;
  os: string;
  architecture: string;
  containerRuntime: string;
  capacity: {
    cpu: string;
    memory: string;
    pods: string;
  };
  allocatable: {
    cpu: string;
    memory: string;
    pods: string;
  };
  conditions: Array<{
    type: string;
    status: string;
    reason?: string;
    message?: string;
  }>;
  creationTimestamp: string;
  addresses: Array<{
    type: string;
    address: string;
  }>;
}

interface ClusterInfo {
  totalNodes: number;
  healthyNodes: number;
  totalPods: number;
  runningPods: number;
  namespaces: number;
  version: string;
}

interface ExposedService {
  name: string;
  namespace: string;
  type: 'LoadBalancer' | 'NodePort' | 'Ingress';
  urls: string[];
  ports: Array<{
    name?: string;
    port: number;
    targetPort?: number | string;
    protocol: string;
  }>;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  category?: string;
}

interface ResourceMetrics {
  nodes: Array<{
    name: string;
    cpu: { usage: string; capacity: string; percentage: number };
    memory: { usage: string; capacity: string; percentage: number };
  }>;
  pods: Array<{
    name: string;
    namespace: string;
    cpu: string;
    memory: string;
  }>;
}

interface StorageInfo {
  persistentVolumes: Array<{
    name: string;
    status: string;
    capacity: string;
    storageClass?: string;
    accessModes: string[];
    reclaimPolicy: string;
  }>;
  persistentVolumeClaims: Array<{
    name: string;
    namespace: string;
    status: string;
    volumeName?: string;
    capacity: string;
    storageClass?: string;
  }>;
  storageClasses: Array<{
    name: string;
    provisioner: string;
    reclaimPolicy: string;
    allowVolumeExpansion: boolean;
  }>;
}

interface ClusterEvent {
  type: string;
  reason: string;
  message: string;
  count: number;
  firstTime: string;
  lastTime: string;
  source: string;
  object: string;
  namespace?: string;
}

interface ClusterIssue {
  severity: 'critical' | 'warning' | 'info';
  category: string;
  message: string;
  object?: string;
  namespace?: string;
  suggestion?: string;
}

interface CertificateInfo {
  name: string;
  namespace: string;
  type: string;
  issuer?: string;
  dnsNames?: string[];
  expirationDate?: string;
  status?: string;
  daysUntilExpiration?: number;
}

class KubernetesClusterMonitor {
  private kc: k8s.KubeConfig;
  private k8sApi: k8s.CoreV1Api;
  private networkingApi: k8s.NetworkingV1Api;
  private appsApi: k8s.AppsV1Api;
  private storageApi: k8s.StorageV1Api;
  private metricsApi?: k8s.Metrics;

  constructor() {
    this.kc = new k8s.KubeConfig();

    // Check if we're running in-cluster
    if (process.env.KUBERNETES_SERVICE_HOST && process.env.KUBERNETES_SERVICE_PORT) {
      console.log('Loading in-cluster configuration');
      this.kc.loadFromCluster();
    } else {
      console.log('Loading from default kubeconfig');
      try {
        // Try to load from KUBECONFIG environment variable first
        if (process.env.KUBECONFIG) {
          this.kc.loadFromFile(process.env.KUBECONFIG);
        } else {
          // Manually construct the path to avoid ~ expansion issues
          const os = require('os');
          const path = require('path');
          const kubeconfigPath = path.join(os.homedir(), '.kube', 'config');
          this.kc.loadFromFile(kubeconfigPath);
        }
      } catch (error) {
        console.error('Failed to load kubeconfig:', error);
        // Fallback to loadFromDefault which tries multiple locations
        this.kc.loadFromDefault();
      }
    }

    this.k8sApi = this.kc.makeApiClient(k8s.CoreV1Api);
    this.networkingApi = this.kc.makeApiClient(k8s.NetworkingV1Api);
    this.appsApi = this.kc.makeApiClient(k8s.AppsV1Api);
    this.storageApi = this.kc.makeApiClient(k8s.StorageV1Api);

    try {
      this.metricsApi = new k8s.Metrics(this.kc);
    } catch (error) {
      console.warn('Metrics server not available');
    }
  }

  async getClusterInfo(): Promise<ClusterInfo> {
    try {
      const [nodesResponse, podsResponse, namespacesResponse] = await Promise.all([
        this.k8sApi.listNode(),
        this.k8sApi.listPodForAllNamespaces(),
        this.k8sApi.listNamespace(),
      ]);

      const nodes = (nodesResponse as any).items || (nodesResponse as any).body?.items || [];
      const pods = (podsResponse as any).items || (podsResponse as any).body?.items || [];
      const namespaces =
        (namespacesResponse as any).items || (namespacesResponse as any).body?.items || [];

      const healthyNodes = nodes.filter((node: any) => {
        const readyCondition = node.status?.conditions?.find((c: any) => c.type === 'Ready');
        return readyCondition?.status === 'True';
      }).length;

      const runningPods = pods.filter((pod: any) => pod.status?.phase === 'Running').length;
      const version = nodes[0]?.status?.nodeInfo?.kubeletVersion || 'Unknown';

      return {
        totalNodes: nodes.length,
        healthyNodes,
        totalPods: pods.length,
        runningPods,
        namespaces: namespaces.length,
        version,
      };
    } catch (error) {
      console.error('Error fetching cluster info:', error);
      throw error;
    }
  }

  async getNodeDetails(): Promise<NodeInfo[]> {
    try {
      const response = await this.k8sApi.listNode();
      const nodes = (response as any).items || (response as any).body?.items || [];

      return nodes.map((node: any) => {
        const nodeInfo = node.status?.nodeInfo;
        const addresses = node.status?.addresses || [];
        const conditions = node.status?.conditions || [];

        const readyCondition = conditions.find((c: any) => c.type === 'Ready');
        const status = readyCondition?.status === 'True' ? 'Ready' : 'Not Ready';

        return {
          name: node.metadata?.name || 'Unknown',
          status,
          version: nodeInfo?.kubeletVersion || 'Unknown',
          os: `${nodeInfo?.operatingSystem || 'Unknown'} ${nodeInfo?.osImage || ''}`.trim(),
          architecture: nodeInfo?.architecture || 'Unknown',
          containerRuntime: nodeInfo?.containerRuntimeVersion || 'Unknown',
          capacity: {
            cpu: node.status?.capacity?.cpu || '0',
            memory: this.formatMemory(node.status?.capacity?.memory || '0'),
            pods: node.status?.capacity?.pods || '0',
          },
          allocatable: {
            cpu: node.status?.allocatable?.cpu || '0',
            memory: this.formatMemory(node.status?.allocatable?.memory || '0'),
            pods: node.status?.allocatable?.pods || '0',
          },
          conditions: conditions.map((condition: any) => ({
            type: condition.type || '',
            status: condition.status || '',
            reason: condition.reason,
            message: condition.message,
          })),
          creationTimestamp: node.metadata?.creationTimestamp?.toISOString() || '',
          addresses: addresses.map((addr: any) => ({
            type: addr.type || '',
            address: addr.address || '',
          })),
        };
      });
    } catch (error) {
      console.error('Error fetching node details:', error);
      throw error;
    }
  }

  async getResourceMetrics(): Promise<ResourceMetrics> {
    try {
      if (!this.metricsApi) {
        throw new Error('Metrics server not available');
      }

      const [nodeMetrics, podMetrics] = await Promise.all([
        this.metricsApi.getNodeMetrics(),
        this.metricsApi.getPodMetrics(),
      ]);

      const nodes = await this.k8sApi.listNode();
      const nodeItems = (nodes as any).items || (nodes as any).body?.items || [];

      const processedNodeMetrics = (nodeMetrics.items || []).map((nodeMetric: any) => {
        const nodeName = nodeMetric.metadata.name;
        const node = nodeItems.find((n: any) => n.metadata.name === nodeName);

        const cpuUsage = this.parseCpuValue(nodeMetric.usage.cpu);
        const memoryUsage = this.parseMemoryValue(nodeMetric.usage.memory);
        const cpuCapacity = this.parseCpuValue(node?.status?.capacity?.cpu || '0');
        const memoryCapacity = this.parseMemoryValue(node?.status?.capacity?.memory || '0Ki');

        return {
          name: nodeName,
          cpu: {
            usage: this.formatCpuUsage(nodeMetric.usage.cpu), // Add this helper
            capacity: node?.status?.capacity?.cpu || '0',
            percentage: cpuCapacity > 0 ? Math.round((cpuUsage / cpuCapacity) * 100) : 0,
          },
          memory: {
            usage: this.formatMemory(nodeMetric.usage.memory),
            capacity: this.formatMemory(node?.status?.capacity?.memory || '0Ki'),
            percentage: memoryCapacity > 0 ? Math.round((memoryUsage / memoryCapacity) * 100) : 0,
          },
        };
      });

      const processedPodMetrics = (podMetrics.items || []).map((podMetric: any) => {
        // Sum CPU usage across all containers in the pod
        const totalCpuRaw = (podMetric.containers || []).reduce((sum: number, container: any) => {
          return sum + this.parseCpuValue(container.usage?.cpu || '0');
        }, 0);

        // Sum memory usage across all containers in the pod
        const totalMemoryRaw = (podMetric.containers || []).reduce(
          (sum: number, container: any) => {
            return sum + this.parseMemoryValue(container.usage?.memory || '0Ki');
          },
          0,
        );

        return {
          name: podMetric.metadata.name,
          namespace: podMetric.metadata.namespace,
          cpu:
            totalCpuRaw >= 1
              ? `${totalCpuRaw.toFixed(2)} cores`
              : `${(totalCpuRaw * 1000).toFixed(0)}m`,
          memory: this.formatMemoryFromBytes(totalMemoryRaw),
        };
      });

      return {
        nodes: processedNodeMetrics,
        pods: processedPodMetrics,
      };
    } catch (error) {
      console.error('Error fetching metrics:', error);
      return { nodes: [], pods: [] };
    }
  }

  async getStorageInfo(): Promise<StorageInfo> {
    try {
      const [pvsResponse, pvcsResponse, storageClassesResponse] = await Promise.all([
        this.k8sApi.listPersistentVolume(),
        this.k8sApi.listPersistentVolumeClaimForAllNamespaces(),
        this.storageApi.listStorageClass(),
      ]);

      const pvs = (pvsResponse as any).items || (pvsResponse as any).body?.items || [];
      const pvcs = (pvcsResponse as any).items || (pvcsResponse as any).body?.items || [];
      const storageClasses =
        (storageClassesResponse as any).items || (storageClassesResponse as any).body?.items || [];

      return {
        persistentVolumes: pvs.map((pv: any) => ({
          name: pv.metadata?.name || 'unknown',
          status: pv.status?.phase || 'Unknown',
          capacity: pv.spec?.capacity?.storage || '0',
          storageClass: pv.spec?.storageClassName,
          accessModes: pv.spec?.accessModes || [],
          reclaimPolicy: pv.spec?.persistentVolumeReclaimPolicy || 'Unknown',
        })),
        persistentVolumeClaims: pvcs.map((pvc: any) => ({
          name: pvc.metadata?.name || 'unknown',
          namespace: pvc.metadata?.namespace || 'default',
          status: pvc.status?.phase || 'Unknown',
          volumeName: pvc.spec?.volumeName,
          capacity: pvc.status?.capacity?.storage || pvc.spec?.resources?.requests?.storage || '0',
          storageClass: pvc.spec?.storageClassName,
        })),
        storageClasses: storageClasses.map((sc: any) => ({
          name: sc.metadata?.name || 'unknown',
          provisioner: sc.provisioner || 'Unknown',
          reclaimPolicy: sc.reclaimPolicy || 'Delete',
          allowVolumeExpansion: sc.allowVolumeExpansion || false,
        })),
      };
    } catch (error) {
      console.error('Error fetching storage info:', error);
      throw error;
    }
  }

  async getClusterEvents(): Promise<ClusterEvent[]> {
    try {
      const response = await this.k8sApi.listEventForAllNamespaces();
      const events = (response as any).items || (response as any).body?.items || [];

      // Sort by last timestamp, most recent first
      const sortedEvents = events
        .sort((a: any, b: any) => {
          const timeA = new Date(a.lastTimestamp || a.eventTime || 0).getTime();
          const timeB = new Date(b.lastTimestamp || b.eventTime || 0).getTime();
          return timeB - timeA;
        })
        .slice(0, 50); // Limit to most recent 50 events

      return sortedEvents.map((event: any) => ({
        type: event.type || 'Normal',
        reason: event.reason || 'Unknown',
        message: event.message || '',
        count: event.count || 1,
        firstTime: event.firstTimestamp || event.eventTime || '',
        lastTime: event.lastTimestamp || event.eventTime || '',
        source: event.source?.component || event.reportingComponent || 'Unknown',
        object: `${event.involvedObject?.kind || 'Unknown'}/${event.involvedObject?.name || 'unknown'}`,
        namespace: event.namespace,
      }));
    } catch (error) {
      console.error('Error fetching events:', error);
      throw error;
    }
  }

  async detectClusterIssues(): Promise<ClusterIssue[]> {
    const issues: ClusterIssue[] = [];

    try {
      // Check node health
      const nodes = await this.getNodeDetails();
      nodes.forEach((node) => {
        if (node.status !== 'Ready') {
          issues.push({
            severity: 'critical',
            category: 'Node Health',
            message: `Node ${node.name} is not ready`,
            object: node.name,
            suggestion: 'Check node logs and system resources',
          });
        }

        // Check for pressure conditions
        node.conditions.forEach((condition) => {
          if (
            ['DiskPressure', 'MemoryPressure', 'PIDPressure'].includes(condition.type) &&
            condition.status === 'True'
          ) {
            issues.push({
              severity: 'warning',
              category: 'Resource Pressure',
              message: `${condition.type} detected on node ${node.name}`,
              object: node.name,
              suggestion: `Investigate ${condition.type.toLowerCase()} on node`,
            });
          }
        });
      });

      // Check for failed pods
      const podsResponse = await this.k8sApi.listPodForAllNamespaces();
      const pods = (podsResponse as any).items || (podsResponse as any).body?.items || [];

      pods.forEach((pod: any) => {
        const phase = pod.status?.phase;
        const podName = pod.metadata?.name;
        const namespace = pod.metadata?.namespace;

        if (phase === 'Failed') {
          issues.push({
            severity: 'critical',
            category: 'Pod Failure',
            message: `Pod ${podName} in namespace ${namespace} is in Failed state`,
            object: podName,
            namespace: namespace,
            suggestion: 'Check pod logs and events',
          });
        } else if (phase === 'Pending') {
          const containerStatuses = pod.status?.containerStatuses || [];
          const hasImagePullError = containerStatuses.some(
            (cs: any) =>
              cs.state?.waiting?.reason === 'ImagePullBackOff' ||
              cs.state?.waiting?.reason === 'ErrImagePull',
          );

          if (hasImagePullError) {
            issues.push({
              severity: 'warning',
              category: 'Image Pull Error',
              message: `Pod ${podName} cannot pull container image`,
              object: podName,
              namespace: namespace,
              suggestion: 'Check image name and registry accessibility',
            });
          }
        }
      });

      // Check recent error events
      const events = await this.getClusterEvents();
      const recentErrorEvents = events
        .filter((event) => event.type === 'Warning' || event.type === 'Error')
        .slice(0, 10);

      recentErrorEvents.forEach((event) => {
        issues.push({
          severity: event.type === 'Error' ? 'critical' : 'warning',
          category: 'Cluster Events',
          message: `${event.reason}: ${event.message}`,
          object: event.object,
          namespace: event.namespace,
          suggestion: 'Review event details and affected resources',
        });
      });
    } catch (error) {
      console.error('Error detecting issues:', error);
    }

    return issues.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  async getCertificateInfo(): Promise<CertificateInfo[]> {
    const certificates: CertificateInfo[] = [];

    try {
      // Check TLS secrets
      const secretsResponse = await this.k8sApi.listSecretForAllNamespaces();
      const secrets = (secretsResponse as any).items || (secretsResponse as any).body?.items || [];

      const tlsSecrets = secrets.filter((secret: any) => secret.type === 'kubernetes.io/tls');

      for (const secret of tlsSecrets) {
        const certData = secret.data?.['tls.crt'];
        if (certData) {
          try {
            const certPem = Buffer.from(certData, 'base64').toString('utf-8');
            const certInfo = this.parseCertificate(certPem);

            certificates.push({
              name: secret.metadata?.name || 'unknown',
              namespace: secret.metadata?.namespace || 'default',
              type: 'TLS Secret',
              ...certInfo,
            });
          } catch (error) {
            certificates.push({
              name: secret.metadata?.name || 'unknown',
              namespace: secret.metadata?.namespace || 'default',
              type: 'TLS Secret',
              status: 'Parse Error',
            });
          }
        }
      }

      // Try to get cert-manager certificates if available
      try {
        const customObjectsApi = this.kc.makeApiClient(k8s.CustomObjectsApi);
        const certManagerCerts = await customObjectsApi.listClusterCustomObject(
          { group: 'cert-manager.io', version: 'v1', plural: 'certificates' }
        );

        const certs = (certManagerCerts as any).body?.items || [];
        certs.forEach((cert: any) => {
          const status = cert.status?.conditions?.find((c: any) => c.type === 'Ready');
          certificates.push({
            name: cert.metadata?.name || 'unknown',
            namespace: cert.metadata?.namespace || 'default',
            type: 'cert-manager Certificate',
            issuer: cert.spec?.issuerRef?.name,
            dnsNames: cert.spec?.dnsNames || [],
            status: status?.status === 'True' ? 'Ready' : 'Not Ready',
          });
        });
      } catch (error) {
        // cert-manager not available or no permissions
      }
    } catch (error) {
      console.error('Error fetching certificate info:', error);
    }

    return certificates;
  }

  private parseCertificate(pemCert: string): Partial<CertificateInfo> {
    try {
      // This is a simplified certificate parser
      // In a real implementation, you'd use a proper X.509 parser
      const certMatch = pemCert.match(/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/);
      if (!certMatch) return { status: 'Invalid Format' };

      // For demo purposes, return placeholder info
      // In practice, you'd decode the base64 and parse the ASN.1 structure
      return {
        status: 'Active',
        dnsNames: ['example.com'], // Would parse from certificate
        expirationDate: '2024-12-31T23:59:59Z', // Would parse from certificate
        daysUntilExpiration: 365, // Would calculate from actual expiration
      };
    } catch (error) {
      return { status: 'Parse Error' };
    }
  }

  async getPodsByNamespace(): Promise<Record<string, number>> {
    try {
      const response = await this.k8sApi.listPodForAllNamespaces();
      const pods = (response as any).items || (response as any).body?.items || [];

      const podsByNamespace: Record<string, number> = {};

      pods.forEach((pod: any) => {
        const namespace = pod.metadata?.namespace || 'default';
        podsByNamespace[namespace] = (podsByNamespace[namespace] || 0) + 1;
      });

      return podsByNamespace;
    } catch (error) {
      console.error('Error fetching pods by namespace:', error);
      throw error;
    }
  }

  async getExposedServices(): Promise<ExposedService[]> {
    try {
      const [servicesResponse, ingressResponse] = await Promise.all([
        this.k8sApi.listServiceForAllNamespaces(),
        this.networkingApi.listIngressForAllNamespaces().catch(() => ({ body: { items: [] } })),
      ]);

      const services =
        (servicesResponse as any).items || (servicesResponse as any).body?.items || [];
      const ingresses =
        (ingressResponse as any).items || (ingressResponse as any).body?.items || [];

      const exposedServices: ExposedService[] = [];

      services.forEach((service: any) => {
        const serviceType = service.spec?.type;

        if (serviceType === 'LoadBalancer' || serviceType === 'NodePort') {
          const urls = this.buildServiceUrls(service, serviceType);

          if (urls.length > 0) {
            exposedServices.push({
              name: service.metadata?.name || 'unknown',
              namespace: service.metadata?.namespace || 'default',
              type: serviceType,
              urls,
              ports: (service.spec?.ports || []).map((port: any) => ({
                name: port.name,
                port: port.port,
                targetPort: port.targetPort,
                protocol: port.protocol || 'TCP',
              })),
              labels: service.metadata?.labels || {},
              annotations: service.metadata?.annotations || {},
              category: this.categorizeService(service.metadata?.name, service.metadata?.labels),
            });
          }
        }
      });

      ingresses.forEach((ingress: any) => {
        const ingressName = ingress.metadata?.name || 'unknown';
        const namespace = ingress.metadata?.namespace || 'default';
        const urls: string[] = [];

        (ingress.spec?.rules || []).forEach((rule: any) => {
          const host = rule.host;
          const protocol = ingress.spec?.tls?.some((tls: any) => tls.hosts?.includes(host))
            ? 'https'
            : 'http';

          if (host) {
            if (rule.http?.paths) {
              rule.http.paths.forEach((path: any) => {
                const pathStr = path.path || '/';
                urls.push(`${protocol}://${host}${pathStr}`);
              });
            } else {
              urls.push(`${protocol}://${host}`);
            }
          }
        });

        if (urls.length > 0) {
          exposedServices.push({
            name: ingressName,
            namespace,
            type: 'Ingress',
            urls,
            ports: [],
            labels: ingress.metadata?.labels || {},
            annotations: ingress.metadata?.annotations || {},
            category: this.categorizeService(ingressName, ingress.metadata?.labels),
          });
        }
      });

      return exposedServices.sort((a, b) => {
        const categoryOrder = ['monitoring', 'ci-cd', 'storage', 'networking', 'security', 'other'];
        const aCategoryIndex = categoryOrder.indexOf(a.category || 'other');
        const bCategoryIndex = categoryOrder.indexOf(b.category || 'other');

        if (aCategoryIndex !== bCategoryIndex) {
          return aCategoryIndex - bCategoryIndex;
        }

        return a.name.localeCompare(b.name);
      });
    } catch (error) {
      console.error('Error fetching exposed services:', error);
      throw error;
    }
  }

  async getCustomResources(): Promise<any[]> {
    try {
      const customObjectsApi = this.kc.makeApiClient(k8s.CustomObjectsApi);

      // Get available CRDs
      const apiExtensionsApi = this.kc.makeApiClient(k8s.ApiextensionsV1Api);
      const crdsResponse = await apiExtensionsApi.listCustomResourceDefinition();
      const crds = (crdsResponse as any).items || (crdsResponse as any).body?.items || [];

      const customResources: any[] = [];

      // Sample a few common CRDs
      const commonCRDs = crds
        .filter((crd: any) => {
          const name = crd.metadata?.name || '';
          return (
            name.includes('prometheus') ||
            name.includes('grafana') ||
            name.includes('cert-manager') ||
            name.includes('traefik') ||
            name.includes('argocd')
          );
        })
        .slice(0, 5); // Limit to prevent too many API calls

      for (const crd of commonCRDs) {
        try {
          const group = crd.spec?.group;
          const version = crd.spec?.versions?.[0]?.name;
          const plural = crd.spec?.names?.plural;

          if (group && version && plural) {
            const resources = await customObjectsApi.listClusterCustomObject({
              group,
              version,
              plural,
            });   
            const items = (resources as any).body?.items || [];

            customResources.push({
              apiVersion: `${group}/${version}`,
              kind: crd.spec?.names?.kind,
              plural: plural,
              count: items.length,
              items: items.slice(0, 3).map((item: any) => ({
                name: item.metadata?.name,
                namespace: item.metadata?.namespace,
                status: item.status || {},
              })),
            });
          }
        } catch (error) {
          // Skip if we can't access this resource
        }
      }

      return customResources;
    } catch (error) {
      console.error('Error fetching custom resources:', error);
      return [];
    }
  }

  async getInfrastructureOverview(): Promise<any> {
    try {
      const [clusterInfo, nodes, storageInfo, customResources] = await Promise.all([
        this.getClusterInfo(),
        this.getNodeDetails(),
        this.getStorageInfo(),
        this.getCustomResources(),
      ]);

      // Calculate resource totals
      const totalCPU = nodes.reduce((sum, node) => {
        return sum + this.parseCpuValue(node.capacity.cpu);
      }, 0);

      const totalMemory = nodes.reduce((sum, node) => {
        return sum + this.parseMemoryValue(node.capacity.memory + 'i');
      }, 0);

      const totalStorage = storageInfo.persistentVolumes.reduce((sum, pv) => {
        return sum + this.parseStorageValue(pv.capacity);
      }, 0);

      return {
        cluster: clusterInfo,
        resources: {
          totalCPUCores: totalCPU,
          totalMemoryGB: Math.round(totalMemory / (1024 * 1024 * 1024)),
          totalStorageGB: Math.round(totalStorage / (1024 * 1024 * 1024)),
          nodeCount: nodes.length,
          storageClasses: storageInfo.storageClasses.length,
        },
        nodeDistribution: nodes.reduce((dist: any, node) => {
          const os = node.os.split(' ')[0];
          dist[os] = (dist[os] || 0) + 1;
          return dist;
        }, {}),
        customResources: customResources.map((cr) => ({
          kind: cr.kind,
          count: cr.count,
        })),
      };
    } catch (error) {
      console.error('Error getting infrastructure overview:', error);
      throw error;
    }
  }

  // Helper methods
  private buildServiceUrls(service: any, serviceType: string): string[] {
    const urls: string[] = [];
    const ports = service.spec?.ports || [];

    if (serviceType === 'LoadBalancer') {
      const loadBalancerIngress = service.status?.loadBalancer?.ingress || [];

      loadBalancerIngress.forEach((lb: any) => {
        const host = lb.ip || lb.hostname;
        if (host) {
          ports.forEach((port: any) => {
            const protocol = this.getProtocolForPort(port.port, port.name);
            urls.push(`${protocol}://${host}:${port.port}`);
          });
        }
      });
    } else if (serviceType === 'NodePort') {
      ports.forEach((port: any) => {
        if (port.nodePort) {
          const protocol = this.getProtocolForPort(port.port, port.name);
          urls.push(`${protocol}://<node-ip>:${port.nodePort}`);
        }
      });
    }

    return urls;
  }

  private getProtocolForPort(port: number, portName?: string): string {
    const httpsIndicators = [443, 8443, 9443];
    const httpIndicators = [80, 8080, 3000, 9090, 9093, 9091];

    if (httpsIndicators.includes(port)) return 'https';
    if (httpIndicators.includes(port)) return 'http';

    if (portName) {
      const name = portName.toLowerCase();
      if (name.includes('https') || name.includes('tls') || name.includes('ssl')) return 'https';
      if (name.includes('http') || name.includes('web')) return 'http';
    }

    return port === 80 || port < 1024 ? 'http' : 'https';
  }

  private categorizeService(serviceName: string, labels: Record<string, string> = {}): string {
    const name = serviceName.toLowerCase();
    const labelValues = Object.values(labels).join(' ').toLowerCase();
    const searchText = `${name} ${labelValues}`;

    // Monitoring tools
    if (/grafana|prometheus|alertmanager|jaeger|zipkin|kiali|metrics/.test(searchText)) {
      return 'monitoring';
    }

    // CI/CD tools
    if (/argocd|jenkins|gitlab|drone|tekton|flux|harbor|registry/.test(searchText)) {
      return 'ci-cd';
    }

    // Storage
    if (/minio|ceph|rook|longhorn|nfs|storage/.test(searchText)) {
      return 'storage';
    }

    // Networking
    if (/traefik|nginx|istio|linkerd|ingress|gateway/.test(searchText)) {
      return 'networking';
    }

    // Security
    if (/vault|keycloak|oauth|auth|security|cert-manager/.test(searchText)) {
      return 'security';
    }

    return 'other';
  }

  private formatCpuUsage(cpuString: string): string {
    const cores = this.parseCpuValue(cpuString);

    if (cores >= 1) {
      return `${cores.toFixed(2)} cores`;
    } else {
      return `${(cores * 1000).toFixed(0)}m`;
    }
  }

  private formatMemory(memoryString: string): string {
    if (memoryString.endsWith('Ki')) {
      const value = parseInt(memoryString.replace('Ki', ''));
      const gb = value / (1024 * 1024);
      const mb = value / 1024;

      if (gb >= 1) {
        return `${gb.toFixed(2)} GB`;
      } else {
        return `${mb.toFixed(0)} MB`;
      }
    }
    return memoryString;
  }

  private formatMemoryFromBytes(bytes: number): string {
    if (bytes >= 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    } else if (bytes >= 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
    } else {
      return `${(bytes / 1024).toFixed(0)} KB`;
    }
  }

  private parseCpuValue(cpuString: string): number {
    // Handle nanoseconds (n) - Kubernetes metrics often use nanoseconds
    if (cpuString.endsWith('n')) {
      const nanoValue = parseInt(cpuString.replace('n', ''));
      return nanoValue / 1_000_000_000; // Convert nanoseconds to cores
    }

    // Handle microseconds (u)
    if (cpuString.endsWith('u')) {
      const microValue = parseInt(cpuString.replace('u', ''));
      return microValue / 1_000_000; // Convert microseconds to cores
    }

    // Handle millicores (m)
    if (cpuString.endsWith('m')) {
      return parseInt(cpuString.replace('m', '')) / 1000;
    }

    // Handle whole cores (no suffix)
    return parseFloat(cpuString) || 0;
  }

  private parseMemoryValue(memoryString: string): number {
    const units: Record<string, number> = {
      Ki: 1024,
      Mi: 1024 * 1024,
      Gi: 1024 * 1024 * 1024,
      Ti: 1024 * 1024 * 1024 * 1024,
      K: 1000,
      M: 1000 * 1000,
      G: 1000 * 1000 * 1000,
      T: 1000 * 1000 * 1000 * 1000,
    };

    for (const [unit, multiplier] of Object.entries(units)) {
      if (memoryString.endsWith(unit)) {
        return parseInt(memoryString.replace(unit, '')) * multiplier;
      }
    }

    return parseInt(memoryString) || 0;
  }

  private parseStorageValue(storageString: string): number {
    return this.parseMemoryValue(storageString);
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.k8sApi.listNamespace();
      return true;
    } catch (error) {
      console.error('Connection test failed:', error);
      return false;
    }
  }

  // Export data as JSON for use in Next.js
  async exportClusterData(): Promise<{
    clusterInfo: ClusterInfo;
    nodes: NodeInfo[];
    podsByNamespace: Record<string, number>;
    exposedServices: ExposedService[];
    storageInfo: StorageInfo;
    events: ClusterEvent[];
    issues: ClusterIssue[];
    certificates: CertificateInfo[];
    customResources: any[];
    infrastructure: any;
    metrics?: ResourceMetrics;
  }> {
    const [
      clusterInfo,
      nodes,
      podsByNamespace,
      exposedServices,
      storageInfo,
      events,
      issues,
      certificates,
      customResources,
      infrastructure,
    ] = await Promise.all([
      this.getClusterInfo(),
      this.getNodeDetails(),
      this.getPodsByNamespace(),
      this.getExposedServices(),
      this.getStorageInfo(),
      this.getClusterEvents(),
      this.detectClusterIssues(),
      this.getCertificateInfo(),
      this.getCustomResources(),
      this.getInfrastructureOverview(),
    ]);

    let metrics: ResourceMetrics | undefined;
    try {
      metrics = await this.getResourceMetrics();
    } catch (error) {
      console.warn('Metrics not available:', error);
      metrics = undefined;
    }

    return {
      clusterInfo,
      nodes,
      podsByNamespace,
      exposedServices,
      storageInfo,
      events,
      issues,
      certificates,
      customResources,
      infrastructure,
      metrics,
    };
  }
}

// Next.js API Route Handler
export async function GET(request: NextRequest) {
  try {
    const monitor = new KubernetesClusterMonitor();

    // Test connection first
    const connected = await monitor.testConnection();
    if (!connected) {
      return NextResponse.json(
        { error: 'Failed to connect to Kubernetes cluster' },
        { status: 500 },
      );
    }

    const data = await monitor.exportClusterData();
    return NextResponse.json(data);
  } catch (error) {
    console.error('API Error:', error);
    return NextResponse.json(
      {
        error: 'Failed to fetch cluster data',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 },
    );
  }
}
