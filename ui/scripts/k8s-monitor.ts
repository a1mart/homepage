#!/usr/bin/env node

// scripts/k8s-monitor.ts
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
    this.kc.loadFromDefault();
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
        this.k8sApi.listNamespace()
      ]);

      const nodes = (nodesResponse as any).items || (nodesResponse as any).body?.items || [];
      const pods = (podsResponse as any).items || (podsResponse as any).body?.items || [];
      const namespaces = (namespacesResponse as any).items || (namespacesResponse as any).body?.items || [];

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
        version
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
            pods: node.status?.capacity?.pods || '0'
          },
          allocatable: {
            cpu: node.status?.allocatable?.cpu || '0',
            memory: this.formatMemory(node.status?.allocatable?.memory || '0'),
            pods: node.status?.allocatable?.pods || '0'
          },
          conditions: conditions.map((condition: any) => ({
            type: condition.type || '',
            status: condition.status || '',
            reason: condition.reason,
            message: condition.message
          })),
          creationTimestamp: node.metadata?.creationTimestamp?.toISOString() || '',
          addresses: addresses.map((addr: any) => ({
            type: addr.type || '',
            address: addr.address || ''
          }))
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
        this.metricsApi.getPodMetrics()
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
            usage: nodeMetric.usage.cpu,
            capacity: node?.status?.capacity?.cpu || '0',
            percentage: cpuCapacity > 0 ? Math.round((cpuUsage / cpuCapacity) * 100) : 0
          },
          memory: {
            usage: this.formatMemory(nodeMetric.usage.memory),
            capacity: this.formatMemory(node?.status?.capacity?.memory || '0Ki'),
            percentage: memoryCapacity > 0 ? Math.round((memoryUsage / memoryCapacity) * 100) : 0
          }
        };
      });

      const processedPodMetrics = (podMetrics.items || []).map((podMetric: any) => ({
        name: podMetric.metadata.name,
        namespace: podMetric.metadata.namespace,
        cpu: podMetric.containers?.[0]?.usage?.cpu || '0',
        memory: this.formatMemory(podMetric.containers?.[0]?.usage?.memory || '0Ki')
      }));

      return {
        nodes: processedNodeMetrics,
        pods: processedPodMetrics
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
        this.storageApi.listStorageClass()
      ]);

      const pvs = (pvsResponse as any).items || (pvsResponse as any).body?.items || [];
      const pvcs = (pvcsResponse as any).items || (pvcsResponse as any).body?.items || [];
      const storageClasses = (storageClassesResponse as any).items || (storageClassesResponse as any).body?.items || [];

      return {
        persistentVolumes: pvs.map((pv: any) => ({
          name: pv.metadata?.name || 'unknown',
          status: pv.status?.phase || 'Unknown',
          capacity: pv.spec?.capacity?.storage || '0',
          storageClass: pv.spec?.storageClassName,
          accessModes: pv.spec?.accessModes || [],
          reclaimPolicy: pv.spec?.persistentVolumeReclaimPolicy || 'Unknown'
        })),
        persistentVolumeClaims: pvcs.map((pvc: any) => ({
          name: pvc.metadata?.name || 'unknown',
          namespace: pvc.metadata?.namespace || 'default',
          status: pvc.status?.phase || 'Unknown',
          volumeName: pvc.spec?.volumeName,
          capacity: pvc.status?.capacity?.storage || pvc.spec?.resources?.requests?.storage || '0',
          storageClass: pvc.spec?.storageClassName
        })),
        storageClasses: storageClasses.map((sc: any) => ({
          name: sc.metadata?.name || 'unknown',
          provisioner: sc.provisioner || 'Unknown',
          reclaimPolicy: sc.reclaimPolicy || 'Delete',
          allowVolumeExpansion: sc.allowVolumeExpansion || false
        }))
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
        namespace: event.namespace
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
      nodes.forEach(node => {
        if (node.status !== 'Ready') {
          issues.push({
            severity: 'critical',
            category: 'Node Health',
            message: `Node ${node.name} is not ready`,
            object: node.name,
            suggestion: 'Check node logs and system resources'
          });
        }

        // Check for pressure conditions
        node.conditions.forEach(condition => {
          if (['DiskPressure', 'MemoryPressure', 'PIDPressure'].includes(condition.type) && condition.status === 'True') {
            issues.push({
              severity: 'warning',
              category: 'Resource Pressure',
              message: `${condition.type} detected on node ${node.name}`,
              object: node.name,
              suggestion: `Investigate ${condition.type.toLowerCase()} on node`
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
            suggestion: 'Check pod logs and events'
          });
        } else if (phase === 'Pending') {
          const containerStatuses = pod.status?.containerStatuses || [];
          const hasImagePullError = containerStatuses.some((cs: any) => 
            cs.state?.waiting?.reason === 'ImagePullBackOff' || 
            cs.state?.waiting?.reason === 'ErrImagePull'
          );
          
          if (hasImagePullError) {
            issues.push({
              severity: 'warning',
              category: 'Image Pull Error',
              message: `Pod ${podName} cannot pull container image`,
              object: podName,
              namespace: namespace,
              suggestion: 'Check image name and registry accessibility'
            });
          }
        }
      });

      // Check recent error events
      const events = await this.getClusterEvents();
      const recentErrorEvents = events
        .filter(event => event.type === 'Warning' || event.type === 'Error')
        .slice(0, 10);

      recentErrorEvents.forEach(event => {
        issues.push({
          severity: event.type === 'Error' ? 'critical' : 'warning',
          category: 'Cluster Events',
          message: `${event.reason}: ${event.message}`,
          object: event.object,
          namespace: event.namespace,
          suggestion: 'Review event details and affected resources'
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
              ...certInfo
            });
          } catch (error) {
            certificates.push({
              name: secret.metadata?.name || 'unknown',
              namespace: secret.metadata?.namespace || 'default',
              type: 'TLS Secret',
              status: 'Parse Error'
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
            status: status?.status === 'True' ? 'Ready' : 'Not Ready'
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
      const certMatch = pemCert.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
      if (!certMatch) return { status: 'Invalid Format' };

      // For demo purposes, return placeholder info
      // In practice, you'd decode the base64 and parse the ASN.1 structure
      return {
        status: 'Active',
        dnsNames: ['example.com'], // Would parse from certificate
        expirationDate: '2024-12-31T23:59:59Z', // Would parse from certificate
        daysUntilExpiration: 365 // Would calculate from actual expiration
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
        this.networkingApi.listIngressForAllNamespaces().catch(() => ({ items: [] }))
      ]);

      const services = (servicesResponse as any).items || (servicesResponse as any).body?.items || [];
      const ingresses = (ingressResponse as any).items || (ingressResponse as any).body?.items || [];
      
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
                protocol: port.protocol || 'TCP'
              })),
              labels: service.metadata?.labels || {},
              annotations: service.metadata?.annotations || {},
              category: this.categorizeService(service.metadata?.name, service.metadata?.labels)
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
          const protocol = ingress.spec?.tls?.some((tls: any) => 
            tls.hosts?.includes(host)
          ) ? 'https' : 'http';
          
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
            category: this.categorizeService(ingressName, ingress.metadata?.labels)
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
      const commonCRDs = crds.filter((crd: any) => {
        const name = crd.metadata?.name || '';
        return name.includes('prometheus') || 
               name.includes('grafana') || 
               name.includes('cert-manager') ||
               name.includes('traefik') ||
               name.includes('argocd');
      }).slice(0, 5); // Limit to prevent too many API calls

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
                status: item.status || {}
              }))
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
      const [
        clusterInfo,
        nodes,
        storageInfo,
        customResources
      ] = await Promise.all([
        this.getClusterInfo(),
        this.getNodeDetails(),
        this.getStorageInfo(),
        this.getCustomResources()
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
          storageClasses: storageInfo.storageClasses.length
        },
        nodeDistribution: nodes.reduce((dist: any, node) => {
          const os = node.os.split(' ')[0];
          dist[os] = (dist[os] || 0) + 1;
          return dist;
        }, {}),
        customResources: customResources.map(cr => ({
          kind: cr.kind,
          count: cr.count
        }))
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
    
    return (port === 80 || port < 1024) ? 'http' : 'https';
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

  private parseCpuValue(cpuString: string): number {
    if (cpuString.endsWith('m')) {
      return parseInt(cpuString.replace('m', '')) / 1000;
    }
    return parseFloat(cpuString) || 0;
  }

  private parseMemoryValue(memoryString: string): number {
    const units: Record<string, number> = {
      'Ki': 1024,
      'Mi': 1024 * 1024,
      'Gi': 1024 * 1024 * 1024,
      'Ti': 1024 * 1024 * 1024 * 1024,
      'K': 1000,
      'M': 1000 * 1000,
      'G': 1000 * 1000 * 1000,
      'T': 1000 * 1000 * 1000 * 1000
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
      infrastructure
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
      this.getInfrastructureOverview()
    ]);

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
      infrastructure
    };
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'status';
  
  const monitor = new KubernetesClusterMonitor();

  try {
    // Test connection first
    const connected = await monitor.testConnection();
    if (!connected) {
      console.log('❌ Failed to connect to Kubernetes cluster');
      process.exit(1);
    }

    switch (command) {
      case 'status':
      case 'overview':
        console.log('✅ Connected to Kubernetes cluster\n');
        console.log('📊 Cluster Overview:');
        const clusterInfo = await monitor.getClusterInfo();
        console.log(`Version: ${clusterInfo.version}`);
        console.log(`Nodes: ${clusterInfo.healthyNodes}/${clusterInfo.totalNodes} healthy`);
        console.log(`Pods: ${clusterInfo.runningPods}/${clusterInfo.totalPods} running`);
        console.log(`Namespaces: ${clusterInfo.namespaces}`);
        break;

      case 'nodes':
        console.log('🖥️  Node Details:');
        const nodes = await monitor.getNodeDetails();
        nodes.forEach((node: any) => {
          console.log(`\n--- ${node.name} ---`);
          console.log(`Status: ${node.status}`);
          console.log(`OS: ${node.os}`);
          console.log(`CPU: ${node.capacity.cpu} (${node.allocatable.cpu} allocatable)`);
          console.log(`Memory: ${node.capacity.memory} (${node.allocatable.memory} allocatable)`);
          
          const internalIP = node.addresses.find((addr: any) => addr.type === 'InternalIP');
          if (internalIP) console.log(`Internal IP: ${internalIP.address}`);
          
          const criticalConditions = node.conditions.filter((c: any) => 
            ['Ready', 'DiskPressure', 'MemoryPressure', 'PIDPressure'].includes(c.type)
          );
          console.log('Conditions:');
          criticalConditions.forEach((condition: any) => {
            const emoji = condition.status === 'True' && condition.type === 'Ready' ? '✅' : 
                          condition.status === 'False' && condition.type !== 'Ready' ? '✅' : '❌';
            console.log(`  ${emoji} ${condition.type}: ${condition.status}`);
          });
        });
        break;

      case 'metrics':
        console.log('📈 Resource Metrics:');
        try {
          const metrics = await monitor.getResourceMetrics();
          
          if (metrics.nodes.length > 0) {
            console.log('\nNode Metrics:');
            metrics.nodes.forEach(node => {
              console.log(`  ${node.name}:`);
              console.log(`    CPU: ${node.cpu.usage} / ${node.cpu.capacity} (${node.cpu.percentage}%)`);
              console.log(`    Memory: ${node.memory.usage} / ${node.memory.capacity} (${node.memory.percentage}%)`);
            });
          }
          
          if (metrics.pods.length > 0) {
            console.log(`\nTop 10 Resource-Consuming Pods:`);
            metrics.pods
              .sort((a, b) => b.memory.localeCompare(a.memory))
              .slice(0, 10)
              .forEach(pod => {
                console.log(`  ${pod.namespace}/${pod.name}: CPU: ${pod.cpu}, Memory: ${pod.memory}`);
              });
          }
        } catch (error) {
          console.log('  Metrics server not available or accessible');
        }
        break;

      case 'services':
        console.log('🔗 Exposed Services:');
        const exposedServices = await monitor.getExposedServices();
        
        if (exposedServices.length === 0) {
          console.log('  No exposed services found');
          break;
        }

        const servicesByCategory = exposedServices.reduce((acc: any, service) => {
          const category = service.category || 'other';
          if (!acc[category]) acc[category] = [];
          acc[category].push(service);
          return acc;
        }, {});

        Object.entries(servicesByCategory).forEach(([category, services]: [string, any]) => {
          console.log(`\n  📂 ${category.toUpperCase()}`);
          services.forEach((service: ExposedService) => {
            console.log(`    ${service.name} (${service.namespace})`);
            console.log(`      Type: ${service.type}`);
            service.urls.forEach(url => {
              console.log(`      🌐 ${url}`);
            });
            if (service.ports.length > 0) {
              const portInfo = service.ports.map(p => `${p.port}${p.name ? `(${p.name})` : ''}`).join(', ');
              console.log(`      Ports: ${portInfo}`);
            }
          });
        });
        break;

      case 'storage':
        console.log('💾 Storage Information:');
        const storageInfo = await monitor.getStorageInfo();
        
        console.log('\nStorage Classes:');
        storageInfo.storageClasses.forEach(sc => {
          console.log(`  ${sc.name}:`);
          console.log(`    Provisioner: ${sc.provisioner}`);
          console.log(`    Reclaim Policy: ${sc.reclaimPolicy}`);
          console.log(`    Volume Expansion: ${sc.allowVolumeExpansion ? 'Enabled' : 'Disabled'}`);
        });
        
        console.log('\nPersistent Volumes:');
        storageInfo.persistentVolumes.forEach(pv => {
          console.log(`  ${pv.name}: ${pv.capacity} (${pv.status})`);
          if (pv.storageClass) console.log(`    Storage Class: ${pv.storageClass}`);
          console.log(`    Access Modes: ${pv.accessModes.join(', ')}`);
          console.log(`    Reclaim Policy: ${pv.reclaimPolicy}`);
        });
        
        if (storageInfo.persistentVolumeClaims.length > 0) {
          console.log('\nPersistent Volume Claims:');
          const claimsByNamespace = storageInfo.persistentVolumeClaims.reduce((acc: any, pvc) => {
            if (!acc[pvc.namespace]) acc[pvc.namespace] = [];
            acc[pvc.namespace].push(pvc);
            return acc;
          }, {});
          
          Object.entries(claimsByNamespace).forEach(([namespace, claims]: [string, any]) => {
            console.log(`  Namespace: ${namespace}`);
            claims.forEach((pvc: any) => {
              console.log(`    ${pvc.name}: ${pvc.capacity} (${pvc.status})`);
              if (pvc.volumeName) console.log(`      Bound to: ${pvc.volumeName}`);
            });
          });
        }
        break;

      case 'events':
        console.log('📝 Recent Cluster Events:');
        const events = await monitor.getClusterEvents();
        
        if (events.length === 0) {
          console.log('  No recent events found');
          break;
        }

        const warningEvents = events.filter(e => e.type === 'Warning' || e.type === 'Error');
        const normalEvents = events.filter(e => e.type === 'Normal').slice(0, 10);
        
        if (warningEvents.length > 0) {
          console.log('\n⚠️  Warning/Error Events:');
          warningEvents.slice(0, 10).forEach(event => {
            const emoji = event.type === 'Error' ? '❌' : '⚠️';
            console.log(`  ${emoji} ${event.reason} (${event.object})${event.namespace ? ` in ${event.namespace}` : ''}`);
            console.log(`      ${event.message}`);
            console.log(`      Last seen: ${new Date(event.lastTime).toLocaleString()}`);
          });
        }
        
        if (normalEvents.length > 0) {
          console.log('\n✅ Recent Normal Events:');
          normalEvents.forEach(event => {
            console.log(`  ${event.reason} (${event.object})${event.namespace ? ` in ${event.namespace}` : ''}`);
            console.log(`    ${event.message}`);
          });
        }
        break;

      case 'issues':
        console.log('🔍 Cluster Health Issues:');
        const issues = await monitor.detectClusterIssues();
        
        if (issues.length === 0) {
          console.log('  ✅ No issues detected');
          break;
        }

        const criticalIssues = issues.filter(i => i.severity === 'critical');
        const warningIssues = issues.filter(i => i.severity === 'warning');
        
        if (criticalIssues.length > 0) {
          console.log('\n🚨 Critical Issues:');
          criticalIssues.forEach(issue => {
            console.log(`  ❌ ${issue.category}: ${issue.message}`);
            if (issue.object) console.log(`      Object: ${issue.object}${issue.namespace ? ` (${issue.namespace})` : ''}`);
            if (issue.suggestion) console.log(`      💡 ${issue.suggestion}`);
          });
        }
        
        if (warningIssues.length > 0) {
          console.log('\n⚠️  Warnings:');
          warningIssues.forEach(issue => {
            console.log(`  ⚠️  ${issue.category}: ${issue.message}`);
            if (issue.object) console.log(`      Object: ${issue.object}${issue.namespace ? ` (${issue.namespace})` : ''}`);
            if (issue.suggestion) console.log(`      💡 ${issue.suggestion}`);
          });
        }
        break;

      case 'certificates':
      case 'certs':
        console.log('🔒 Certificate Information:');
        const certificates = await monitor.getCertificateInfo();
        
        if (certificates.length === 0) {
          console.log('  No certificates found');
          break;
        }

        certificates.forEach(cert => {
          console.log(`\n  ${cert.name} (${cert.namespace})`);
          console.log(`    Type: ${cert.type}`);
          console.log(`    Status: ${cert.status}`);
          if (cert.issuer) console.log(`    Issuer: ${cert.issuer}`);
          if (cert.dnsNames && cert.dnsNames.length > 0) {
            console.log(`    DNS Names: ${cert.dnsNames.join(', ')}`);
          }
          if (cert.expirationDate) {
            console.log(`    Expires: ${new Date(cert.expirationDate).toLocaleDateString()}`);
            if (cert.daysUntilExpiration !== undefined) {
              const emoji = cert.daysUntilExpiration < 30 ? '🚨' : cert.daysUntilExpiration < 90 ? '⚠️' : '✅';
              console.log(`    Days until expiration: ${emoji} ${cert.daysUntilExpiration}`);
            }
          }
        });
        break;

      case 'custom':
        console.log('🔧 Custom Resources:');
        const customResources = await monitor.getCustomResources();
        
        if (customResources.length === 0) {
          console.log('  No custom resources found or accessible');
          break;
        }

        customResources.forEach(cr => {
          console.log(`\n  ${cr.kind} (${cr.apiVersion})`);
          console.log(`    Count: ${cr.count}`);
          if (cr.items && cr.items.length > 0) {
            console.log(`    Examples:`);
            cr.items.forEach((item: any) => {
              console.log(`      ${item.name}${item.namespace ? ` (${item.namespace})` : ''}`);
            });
          }
        });
        break;

      case 'infrastructure':
      case 'infra':
        console.log('🏗️  Infrastructure Overview:');
        const infrastructure = await monitor.getInfrastructureOverview();
        
        console.log(`\nCluster: ${infrastructure.cluster.version}`);
        console.log(`  Nodes: ${infrastructure.cluster.healthyNodes}/${infrastructure.cluster.totalNodes} healthy`);
        console.log(`  Pods: ${infrastructure.cluster.runningPods}/${infrastructure.cluster.totalPods} running`);
        console.log(`  Namespaces: ${infrastructure.cluster.namespaces}`);
        
        console.log('\nResource Capacity:');
        console.log(`  CPU Cores: ${infrastructure.resources.totalCPUCores}`);
        console.log(`  Memory: ${infrastructure.resources.totalMemoryGB} GB`);
        console.log(`  Storage: ${infrastructure.resources.totalStorageGB} GB`);
        console.log(`  Storage Classes: ${infrastructure.resources.storageClasses}`);
        
        console.log('\nNode Distribution:');
        Object.entries(infrastructure.nodeDistribution).forEach(([os, count]) => {
          console.log(`  ${os}: ${count} nodes`);
        });
        
        if (infrastructure.customResources.length > 0) {
          console.log('\nCustom Resources:');
          infrastructure.customResources.forEach((cr: any) => {
            console.log(`  ${cr.kind}: ${cr.count}`);
          });
        }
        break;

      case 'pods':
        console.log('📦 Pods by Namespace:');
        const podsByNamespace = await monitor.getPodsByNamespace();
        Object.entries(podsByNamespace)
          .sort(([,a], [,b]) => (b as number) - (a as number))
          .forEach(([namespace, count]) => {
            console.log(`  ${namespace}: ${count} pods`);
          });
        break;

      case 'json':
        const data = await monitor.exportClusterData();
        console.log(JSON.stringify(data, null, 2));
        break;

      case 'json-compact':
        const compactData = await monitor.exportClusterData();
        console.log(JSON.stringify(compactData));
        break;

      default:
        console.log('Usage:');
        console.log('  npm run k8s-check [command]');
        console.log('');
        console.log('Commands:');
        console.log('  status, overview     - Show cluster overview (default)');
        console.log('  nodes               - Show detailed node information');
        console.log('  metrics             - Show resource usage metrics');
        console.log('  services            - Show exposed services with URLs');
        console.log('  storage             - Show storage classes, PVs, and PVCs');
        console.log('  events              - Show recent cluster events');
        console.log('  issues              - Detect and show cluster health issues');
        console.log('  certificates, certs - Show certificate information');
        console.log('  custom              - Show custom resources');
        console.log('  infrastructure, infra - Show infrastructure overview');
        console.log('  pods                - Show pods by namespace');
        console.log('  json                - Export all data as formatted JSON');
        console.log('  json-compact        - Export all data as compact JSON');
    }
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

// Export for use in Next.js components
export { KubernetesClusterMonitor };
export type { NodeInfo, ClusterInfo, ExposedService, ResourceMetrics, StorageInfo, ClusterEvent, ClusterIssue, CertificateInfo };

// Run CLI if called directly
if (require.main === module) {
  main();
}