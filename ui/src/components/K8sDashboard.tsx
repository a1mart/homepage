/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */

'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import {
  Server,
  Activity,
  Database,
  Network,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ExternalLink,
  Cpu,
  HardDrive,
  MemoryStick,
  Globe,
  Calendar,
  Zap,
  Settings,
  Monitor,
  RefreshCw,
  TrendingUp,
  Loader2,
} from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

// Types for the data structure
interface ClusterInfo {
  totalNodes: number;
  healthyNodes: number;
  totalPods: number;
  runningPods: number;
  namespaces: number;
  version: string;
}

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
  addresses: Array<{
    type: string;
    address: string;
  }>;
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

interface ClusterIssue {
  severity: 'critical' | 'warning' | 'info';
  category: string;
  message: string;
  object?: string;
  namespace?: string;
  suggestion?: string;
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

interface DashboardData {
  clusterInfo: ClusterInfo;
  nodes: NodeInfo[];
  exposedServices: ExposedService[];
  issues: ClusterIssue[];
  metrics?: ResourceMetrics;
  infrastructure: {
    resources: {
      totalCPUCores: number;
      totalMemoryGB: number;
      totalStorageGB: number;
      nodeCount: number;
      storageClasses: number;
    };
    nodeDistribution: Record<string, number>;
    customResources: Array<{
      kind: string;
      count: number;
    }>;
  };
  podsByNamespace: Record<string, number>;
}

const K8sDashboard: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [selectedNamespace, setSelectedNamespace] = useState<string>('all');

  const fetchClusterData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch data from your API endpoint
      const response = await fetch('/api/k8s-cluster-data');

      if (!response.ok) {
        throw new Error(`Failed to fetch cluster data: ${response.statusText}`);
      }

      const clusterData: DashboardData = await response.json();
      setData(clusterData);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cluster data');
      console.error('Error fetching cluster data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchClusterData();
    // Refresh every 30 seconds
    const interval = setInterval(fetchClusterData, 30000);
    return () => clearInterval(interval);
  }, [fetchClusterData]);

  const getServiceIcon = (category: string) => {
    switch (category) {
      case 'monitoring':
        return <Activity className="h-4 w-4" />;
      case 'ci-cd':
        return <Zap className="h-4 w-4" />;
      case 'storage':
        return <Database className="h-4 w-4" />;
      case 'networking':
        return <Network className="h-4 w-4" />;
      case 'security':
        return <Shield className="h-4 w-4" />;
      default:
        return <Settings className="h-4 w-4" />;
    }
  };

  const getHealthStatus = (healthy: number, total: number) => {
    const percentage = (healthy / total) * 100;
    if (percentage === 100)
      return { status: 'healthy', icon: CheckCircle, color: 'text-green-500' };
    if (percentage >= 80)
      return { status: 'warning', icon: AlertTriangle, color: 'text-yellow-500' };
    return { status: 'critical', icon: XCircle, color: 'text-red-500' };
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p>Loading cluster data...</p>
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="container mx-auto p-6">
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Connection Error</AlertTitle>
          <AlertDescription>
            {error}
            <Button variant="outline" size="sm" className="ml-4" onClick={fetchClusterData}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (!data) return null;

  const nodeHealth = getHealthStatus(data.clusterInfo.healthyNodes, data.clusterInfo.totalNodes);
  const podHealth = getHealthStatus(data.clusterInfo.runningPods, data.clusterInfo.totalPods);
  const criticalIssues = data.issues.filter((issue) => issue.severity === 'critical');
  const warningIssues = data.issues.filter((issue) => issue.severity === 'warning');

  // Filter issues by selected namespace
  const filteredIssues =
    selectedNamespace === 'all'
      ? data.issues
      : data.issues.filter((issue) => issue.namespace === selectedNamespace || !issue.namespace);

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="container mx-auto p-4">
        <div className="flex items-center justify-between space-x-4">
          <div className="flex items-center space-x-3">
            <h1 className="text-2xl font-bold">K8s Homelab</h1>
            <span className="text-sm text-muted-foreground">
              {data.clusterInfo.version} • Last updated {lastRefresh.toLocaleTimeString()}
            </span>
          </div>
          <Button onClick={fetchClusterData} disabled={loading} size="sm">
            <RefreshCw className={`h-4 w-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Cluster Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Nodes:{' '}
                <span className="text-xl font-semibold">
                  {data.clusterInfo.healthyNodes}/{data.clusterInfo.totalNodes}
                </span>
              </span>
              <nodeHealth.icon className={`h-6 w-6 ${nodeHealth.color}`} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Pods:{' '}
                <span className="text-xl font-semibold">
                  {data.clusterInfo.runningPods}/{data.clusterInfo.totalPods}
                </span>
              </span>
              <podHealth.icon className={`h-6 w-6 ${podHealth.color}`} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Namespaces:{' '}
                <span className="text-xl font-semibold">{data.clusterInfo.namespaces}</span>
              </span>
              <Database className="h-6 w-6 text-blue-500" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Issues:{' '}
                <span className="text-xl font-semibold">
                  {criticalIssues.length + warningIssues.length}
                </span>
              </span>
              <AlertTriangle
                className={`h-6 w-6 ${criticalIssues.length > 0 ? 'text-red-500' : 'text-green-500'}`}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="services" className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="services">Services</TabsTrigger>
          <TabsTrigger value="pods">Pods</TabsTrigger>
          <TabsTrigger value="nodes">Nodes</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="issues">Issues</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
        </TabsList>

        <TabsContent value="services" className="space-y-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <Globe className="h-4 w-4" />
                Exposed Services
              </CardTitle>
              <CardDescription className="text-xs">
                Services accessible from outside the cluster
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 p-2">
              {data.exposedServices.length === 0 ? (
                <p className="text-xs text-muted-foreground">No exposed services found</p>
              ) : (
                Object.entries(
                  data.exposedServices.reduce((acc: any, service) => {
                    const category = service.category || 'other';
                    if (!acc[category]) acc[category] = [];
                    acc[category].push(service);
                    return acc;
                  }, {}),
                ).map(([category, services]: [string, any]) => (
                  <div key={category}>
                    <h4 className="font-semibold mb-1 capitalize flex items-center gap-1 text-sm">
                      {getServiceIcon(category)}
                      {category.replace('-', ' ')}
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                      {services.map((service: any) => (
                        <Card
                          key={`${service.namespace}-${service.name}-${service.type}-${service.ingress || 'none'}`}
                          className="relative p-1"
                        >
                          <CardContent className="p-2">
                            <div className="space-y-1 text-xs">
                              <div className="flex items-center justify-between">
                                <h5 className="font-medium">{service.name}</h5>
                                <Badge variant="outline" className="text-xs">
                                  {service.type}
                                </Badge>
                              </div>
                              <p className="text-muted-foreground">{service.namespace}</p>
                              <div className="flex flex-wrap gap-1">
                                {service.urls.map((url: string, idx: number) => (
                                  <a
                                    key={idx}
                                    href={url.replace('<node-ip>', 'localhost')}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-600 hover:underline flex items-center gap-1"
                                  >
                                    {url} <ExternalLink className="h-3 w-3" />
                                  </a>
                                ))}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pods" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                <h2 className="text-lg font-semibold">Pods by Namespace</h2>
              </div>

              {/* Namespace selector using shad/ui Select */}
              <Select
                value={selectedNamespace}
                onValueChange={(value) => setSelectedNamespace(value)}
              >
                <SelectTrigger className="h-8">
                  <SelectValue placeholder="Select namespace" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Namespaces</SelectItem>
                  {Object.keys(data.podsByNamespace).map((ns) => (
                    <SelectItem key={ns} value={ns}>
                      {ns} ({data.podsByNamespace[ns]})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </CardHeader>

            <CardContent className="space-y-4">
              {/* Namespace pod cards */}
              {selectedNamespace === 'all' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {Object.entries(data.podsByNamespace)
                    .sort(([, a], [, b]) => (b as number) - (a as number))
                    .map(([ns, count]) => (
                      <Card
                        key={ns}
                        className="cursor-pointer hover:shadow-md transition-shadow p-3 text-center"
                        onClick={() => setSelectedNamespace(ns)}
                      >
                        <p className="font-medium text-lg">{ns}</p>
                        <p className="text-2xl font-bold text-blue-600">{count}</p>
                        <p className="text-sm text-muted-foreground">pod{count !== 1 ? 's' : ''}</p>
                      </Card>
                    ))}
                </div>
              )}

              {/* Resource usage */}
              {data.metrics && data.metrics.pods.length > 0 && (
                <div className="mt-4">
                  <h4 className="font-semibold mb-2">
                    Resource Usage {selectedNamespace !== 'all' && `in ${selectedNamespace}`}
                  </h4>
                  <div className="space-y-1 max-h-96 overflow-y-auto">
                    {data.metrics.pods
                      .filter(
                        (p) => selectedNamespace === 'all' || p.namespace === selectedNamespace,
                      )
                      .sort((a, b) => parseFloat(b.cpu) - parseFloat(a.cpu)) // Sort descending by CPU
                      .slice(0, 10)
                      .map((pod) => (
                        <div
                          key={`${pod.namespace}-${pod.name}`}
                          className="flex justify-between items-center p-2 rounded border text-sm hover:bg-gray-50 transition-colors"
                        >
                          <div>
                            <span className="font-medium">{pod.name}</span>
                            {selectedNamespace === 'all' && (
                              <span className="text-muted-foreground ml-1">({pod.namespace})</span>
                            )}
                          </div>
                          <div className="flex gap-3">
                            <span>CPU: {pod.cpu}</span>
                            <span>Memory: {pod.memory}</span>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="nodes" className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {data.nodes.map((node) => {
              const nodeMetrics = data.metrics?.nodes?.find((m) => m.name === node.name);
              const internalIP = node.addresses.find((addr) => addr.type === 'InternalIP')?.address;

              return (
                <Card key={node.name} className="p-3">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2 font-semibold">
                        <Server className="h-5 w-5" />
                        {node.name}
                      </span>
                      <Badge
                        variant={node.status === 'Ready' ? 'default' : 'destructive'}
                        className="text-xs px-2 py-0.5"
                      >
                        {node.status}
                      </Badge>
                    </CardTitle>
                    <CardDescription className="text-xs">
                      {node.os} • {node.architecture}
                    </CardDescription>
                  </CardHeader>

                  <CardContent className="p-2 space-y-2 text-sm">
                    <div className="grid grid-cols-3 gap-2">
                      <div>
                        <p className="text-muted-foreground">CPU</p>
                        <p className="font-medium">{node.capacity.cpu}</p>
                        {nodeMetrics && (
                          <Progress value={nodeMetrics.cpu.percentage} className="h-2 mt-1" />
                        )}
                      </div>
                      <div>
                        <p className="text-muted-foreground">Memory</p>
                        <p className="font-medium">{node.capacity.memory}</p>
                        {nodeMetrics && (
                          <Progress value={nodeMetrics.memory.percentage} className="h-2 mt-1" />
                        )}
                      </div>
                      <div>
                        <p className="text-muted-foreground">IP</p>
                        <p className="font-mono truncate">{internalIP || '-'}</p>
                      </div>
                    </div>

                    <div>
                      <p className="text-muted-foreground mb-1">Conditions</p>
                      <div className="flex flex-wrap gap-1 text-xs">
                        {node.conditions
                          .filter((c) =>
                            ['Ready', 'DiskPressure', 'MemoryPressure', 'PIDPressure'].includes(
                              c.type,
                            ),
                          )
                          .map((condition) => {
                            const isGood =
                              (condition.type === 'Ready' && condition.status === 'True') ||
                              (condition.type !== 'Ready' && condition.status === 'False');
                            return (
                              <Badge
                                key={condition.type}
                                variant={isGood ? 'default' : 'destructive'}
                                className="px-2 py-0.5 text-xs"
                              >
                                {condition.type}
                              </Badge>
                            );
                          })}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="metrics" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Resource Metrics
              </CardTitle>
              <CardDescription>Real-time cluster resource usage</CardDescription>
            </CardHeader>
            <CardContent>
              {!data.metrics || data.metrics.nodes.length === 0 ? (
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Metrics Unavailable</AlertTitle>
                  <AlertDescription>
                    Metrics server is not available or accessible. Install metrics-server to view
                    resource usage.
                  </AlertDescription>
                </Alert>
              ) : (
                <div className="space-y-6">
                  <div>
                    <h4 className="font-semibold mb-4">Node Resource Usage</h4>
                    <div className="space-y-4">
                      {data.metrics.nodes.map((node) => (
                        <div key={node.name} className="space-y-2">
                          <div className="flex justify-between items-center">
                            <span className="font-medium">{node.name}</span>
                          </div>
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <div className="flex justify-between text-sm">
                                <span>CPU</span>
                                <span>{node.cpu.percentage}%</span>
                              </div>
                              <Progress value={node.cpu.percentage} className="mt-1" />
                              <p className="text-xs text-muted-foreground mt-1">
                                {node.cpu.usage} / {node.cpu.capacity}
                              </p>
                            </div>
                            <div>
                              <div className="flex justify-between text-sm">
                                <span>Memory</span>
                                <span>{node.memory.percentage}%</span>
                              </div>
                              <Progress value={node.memory.percentage} className="mt-1" />
                              <p className="text-xs text-muted-foreground mt-1">
                                {node.memory.usage} / {node.memory.capacity}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {data.metrics.pods.length > 0 && (
                    <div>
                      <h4 className="font-semibold mb-4">Top Resource Consuming Pods</h4>
                      <div className="space-y-2">
                        {data.metrics.pods.slice(0, 10).map((pod) => (
                          <div
                            key={`${pod.namespace}-${pod.name}`}
                            className="flex justify-between items-center p-2 rounded border"
                          >
                            <div>
                              <span className="font-medium">{pod.name}</span>
                              <span className="text-sm text-muted-foreground ml-2">
                                ({pod.namespace})
                              </span>
                            </div>
                            <div className="flex gap-4 text-sm">
                              <span>CPU: {pod.cpu}</span>
                              <span>Memory: {pod.memory}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="issues" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                Cluster Health Issues
                {selectedNamespace !== 'all' && (
                  <Badge variant="outline" className="ml-2">
                    {selectedNamespace}
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                {selectedNamespace === 'all'
                  ? 'Detected problems and recommendations across all namespaces'
                  : `Issues in ${selectedNamespace} namespace`}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredIssues.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                  <p className="text-lg font-medium">All systems operational</p>
                  <p className="text-muted-foreground">
                    {selectedNamespace === 'all'
                      ? 'No issues detected in your cluster'
                      : `No issues detected in ${selectedNamespace} namespace`}
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredIssues.filter((i) => i.severity === 'critical').length > 0 && (
                    <div>
                      <h4 className="font-semibold text-red-600 mb-2 flex items-center gap-2">
                        <XCircle className="h-4 w-4" />
                        Critical Issues (
                        {filteredIssues.filter((i) => i.severity === 'critical').length})
                      </h4>
                      <div className="space-y-2">
                        {filteredIssues
                          .filter((i) => i.severity === 'critical')
                          .map((issue, idx) => (
                            <Alert key={idx} variant="destructive">
                              <AlertTriangle className="h-4 w-4" />
                              <AlertTitle>{issue.category}</AlertTitle>
                              <AlertDescription>
                                <p>{issue.message}</p>
                                {issue.object && (
                                  <p className="text-sm mt-1">
                                    Object: {issue.object}
                                    {issue.namespace && ` (${issue.namespace})`}
                                  </p>
                                )}
                                {issue.suggestion && (
                                  <p className="text-sm mt-2 font-medium">💡 {issue.suggestion}</p>
                                )}
                              </AlertDescription>
                            </Alert>
                          ))}
                      </div>
                    </div>
                  )}

                  {filteredIssues.filter((i) => i.severity === 'warning').length > 0 && (
                    <div>
                      <h4 className="font-semibold text-yellow-600 mb-2 flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4" />
                        Warnings ({filteredIssues.filter((i) => i.severity === 'warning').length})
                      </h4>
                      <div className="space-y-2">
                        {filteredIssues
                          .filter((i) => i.severity === 'warning')
                          .map((issue, idx) => (
                            <Alert key={idx}>
                              <AlertTriangle className="h-4 w-4" />
                              <AlertTitle>{issue.category}</AlertTitle>
                              <AlertDescription>
                                <p>{issue.message}</p>
                                {issue.object && (
                                  <p className="text-sm mt-1">
                                    Object: {issue.object}
                                    {issue.namespace && ` (${issue.namespace})`}
                                  </p>
                                )}
                                {issue.suggestion && (
                                  <p className="text-sm mt-2 font-medium">💡 {issue.suggestion}</p>
                                )}
                              </AlertDescription>
                            </Alert>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Monitor className="h-5 w-5" />
                  Cluster Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-4 rounded-lg bg-muted">
                    <Cpu className="h-8 w-8 mx-auto mb-2 text-blue-500" />
                    <p className="text-sm text-muted-foreground">Nodes</p>
                    <p className="text-2xl font-bold">{data.clusterInfo.totalNodes}</p>
                  </div>
                  <div className="text-center p-4 rounded-lg bg-muted">
                    <Database className="h-8 w-8 mx-auto mb-2 text-green-500" />
                    <p className="text-sm text-muted-foreground">Namespaces</p>
                    <p className="text-2xl font-bold">{data.clusterInfo.namespaces}</p>
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold mb-2">Node Distribution</h4>
                  <div className="space-y-2">
                    {Object.entries(
                      data.nodes.reduce((acc: any, node) => {
                        const os = node.os.split(' ')[0];
                        acc[os] = (acc[os] || 0) + 1;
                        return acc;
                      }, {}),
                    ).map(([os, count]) => (
                      <div key={os} className="flex justify-between">
                        <span>{os}</span>
                        <Badge variant="outline">{count as string} nodes</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Quick Stats
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span>Kubernetes Version</span>
                    <Badge variant="outline">{data.clusterInfo.version}</Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Total Pods</span>
                    <span className="font-medium">{data.clusterInfo.totalPods}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Running Pods</span>
                    <span className="font-medium text-green-600">
                      {data.clusterInfo.runningPods}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Exposed Services</span>
                    <span className="font-medium">{data.exposedServices.length}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Health Status</span>
                    <Badge
                      variant={
                        criticalIssues.length > 0
                          ? 'destructive'
                          : warningIssues.length > 0
                            ? 'default'
                            : 'outline'
                      }
                    >
                      {criticalIssues.length > 0
                        ? 'Critical Issues'
                        : warningIssues.length > 0
                          ? 'Warnings'
                          : 'Healthy'}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default K8sDashboard;



/*
// Update your existing app/dashboard/page.tsx with these additions
'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { useSession } from 'next-auth/react'; // ADD THIS
import { LoginButton } from '@/components/LoginButton'; // ADD THIS
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
// ... rest of your existing imports

// Add this interface to your existing interfaces
interface DashboardData {
  clusterInfo: ClusterInfo;
  nodes: NodeInfo[];
  exposedServices: ExposedService[];
  issues: ClusterIssue[];
  metrics?: ResourceMetrics;
  infrastructure: {
    resources: {
      totalCPUCores: number;
      totalMemoryGB: number;
      totalStorageGB: number;
      nodeCount: number;
      storageClasses: number;
    };
    nodeDistribution: Record<string, number>;
    customResources: Array<{
      kind: string;
      count: number;
    }>;
  };
  podsByNamespace: Record<string, number>;
  user?: {  // ADD THIS
    name: string;
    email: string;
  };
}

const K8sDashboard: React.FC = () => {
  // ADD THESE LINES after your existing useState declarations
  const { data: session, status } = useSession();
  
  // MODIFY your existing fetchClusterData function
  const fetchClusterData = useCallback(async () => {
    // ADD AUTHENTICATION CHECK
    if (status !== 'authenticated' || !session) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // MODIFY the fetch call to include auth header
      const response = await fetch('/api/k8s-cluster-data', {
        headers: {
          'Authorization': `Bearer ${session.accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch cluster data: ${response.statusText}`);
      }

      const clusterData: DashboardData = await response.json();
      setData(clusterData);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cluster data');
      console.error('Error fetching cluster data:', err);
    } finally {
      setLoading(false);
    }
  }, [session, status]); // ADD session and status as dependencies

  // MODIFY your existing useEffect
  useEffect(() => {
    if (status === 'authenticated') { // ADD THIS CHECK
      fetchClusterData();
      const interval = setInterval(fetchClusterData, 30000);
      return () => clearInterval(interval);
    }
  }, [fetchClusterData, status]); // ADD status as dependency

  // ADD THESE AUTHENTICATION STATES before your existing loading/error checks
  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p>Authenticating...</p>
        </div>
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return (
      <div className="flex items-center justify-center h-screen">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>Authentication Required</CardTitle>
            <CardDescription>
              Please sign in to access the Kubernetes dashboard
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <LoginButton />
          </CardContent>
        </Card>
      </div>
    );
  }

  // Keep all your existing loading and error checks...
  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p>Loading cluster data...</p>
        </div>
      </div>
    );
  }

  // ... rest of your existing component logic

  // MODIFY your header section to include authentication info
  return (
    <div className="container mx-auto p-6 space-y-6">
      { Header - MODIFY this section }
      <div className="container mx-auto p-4">
        <div className="flex items-center justify-between space-x-4">
          <div className="flex items-center space-x-3">
            <h1 className="text-2xl font-bold">K8s Homelab</h1>
            <span className="text-sm text-muted-foreground">
              {data.clusterInfo.version} • Last updated {lastRefresh.toLocaleTimeString()}
            </span>
          </div>
          <div className="flex items-center space-x-2">
            { ADD USER WELCOME }
            {session?.user?.name && (
              <span className="text-sm text-muted-foreground">
                Welcome, {session.user.name}
              </span>
            )}
            <Button onClick={fetchClusterData} disabled={loading} size="sm">
              <RefreshCw className={`h-4 w-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            { ADD LOGIN BUTTON }
            <LoginButton />
          </div>
        </div>
      </div>

      { Keep all your existing dashboard content exactly as it is }
      { ... rest of your component }
    </div>
  );
};
*/