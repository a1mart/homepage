# Local Kubernetes Deployment Guide

## Step 1: Build and Tag Your Image Locally

```bash
# Build the image with a local tag
docker build -t k8sdash:local .

# If using Docker Desktop with Kubernetes, the image is already available
# If using minikube, load the image:
# minikube image load k8sdash:local

# If using kind, load the image:
# kind load docker-image k8sdash:local
```

## Step 2: Create Local Values File

Create `values.local.yaml` for local testing:

```yaml
# values.local.yaml
replicaCount: 1

image:
  repository: k8sdash  # No registry prefix for local image
  tag: local
  pullPolicy: Never    # Important: Never pull from registry

# Use NodePort or LoadBalancer for local access
service:
  type: NodePort
  port: 80
  targetPort: 3000
  nodePort: 32080  # Optional: specify port

# Disable ingress for local testing
ingress:
  enabled: false

# Local environment variables
env:
  NEXTAUTH_URL: "http://localhost:32080"  # Match your NodePort
  KEYCLOAK_ISSUER: "http://10.0.0.10:30786/realms/alm"
  NEXT_PUBLIC_KEYCLOAK_URL: "http://10.0.0.10:30786"
  NEXT_PUBLIC_KEYCLOAK_REALM: "alm"
  NEXT_PUBLIC_KEYCLOAK_CLIENT_ID: "k8s-dashboard"

# Local secrets (for testing only - don't commit these!)
secrets:
  NEXTAUTH_SECRET: "your-local-test-secret-key-32chars"
  KEYCLOAK_CLIENT_ID: "k8s-dashboard"
  KEYCLOAK_CLIENT_SECRET: "your-test-client-secret"

# Reduced resources for local testing
resources:
  limits:
    cpu: "250m"
    memory: "256Mi"
  requests:
    cpu: "50m"
    memory: "64Mi"

# Enable RBAC for Kubernetes API access
rbac:
  create: true
  clusterRole: true

serviceAccount:
  create: true
```

## Step 3: Deploy with Helm

```bash
# Navigate to your chart directory
cd k8s/chart

# Create a test namespace
kubectl create namespace k8s-dash-test

# Install the chart with local values
helm install k8s-dash-local . \
  --namespace k8s-dash-test \
  --values values.local.yaml \
  --debug

# Or use upgrade --install for repeated deployments
helm upgrade --install k8s-dash-local . \
  --namespace k8s-dash-test \
  --values values.local.yaml \
  --debug
```

## Step 4: Access Your Application

```bash
# Check pod status
kubectl get pods -n k8s-dash-test

# Check service
kubectl get svc -n k8s-dash-test

# If using NodePort (recommended for local):
# Access at http://localhost:32080

# If using LoadBalancer and you're on Docker Desktop:
kubectl get svc -n k8s-dash-test
# Look for the EXTERNAL-IP (usually localhost on Docker Desktop)

# Port forward as alternative:
kubectl port-forward -n k8s-dash-test svc/k8s-dash-local-k8s-dash 8080:80
# Then access at http://localhost:8080
```

## Step 5: Debug Issues

```bash
# View pod logs
kubectl logs -n k8s-dash-test -l app.kubernetes.io/name=k8s-dash --follow

# Describe pod for events
kubectl describe pod -n k8s-dash-test -l app.kubernetes.io/name=k8s-dash

# Check configmap and secrets
kubectl get configmap -n k8s-dash-test
kubectl get secrets -n k8s-dash-test

# View configmap contents
kubectl describe configmap k8s-dash-local-k8s-dash-config -n k8s-dash-test
```

## Step 6: Test Different Scenarios

### Test with Different Image Tags
```bash
# Build with different tag
docker build -t k8sdash:test-v2 .

# Update deployment
helm upgrade k8s-dash-local . \
  --namespace k8s-dash-test \
  --values values.local.yaml \
  --set image.tag=test-v2
```

### Test Configuration Changes
```bash
# Test with different environment variables
helm upgrade k8s-dash-local . \
  --namespace k8s-dash-test \
  --values values.local.yaml \
  --set env.NEXTAUTH_URL="http://localhost:32080" \
  --set service.nodePort=32090
```

## Step 7: Cleanup

```bash
# Uninstall the release
helm uninstall k8s-dash-local -n k8s-dash-test

# Delete the namespace
kubectl delete namespace k8s-dash-test

# Clean up local Docker images (optional)
docker rmi k8sdash:local k8sdash:test-v2
```

## Quick Commands Reference

```bash
# One-liner for quick deployment
docker build -t k8sdash:local . && \
helm upgrade --install k8s-dash-local ./k8s/chart \
  --namespace k8s-dash-test \
  --create-namespace \
  --values ./k8s/chart/values.local.yaml

# Quick check status
kubectl get all -n k8s-dash-test

# Quick logs
kubectl logs -n k8s-dash-test -l app.kubernetes.io/name=k8s-dash --tail=50

# Quick restart deployment
kubectl rollout restart deployment k8s-dash-local-k8s-dash -n k8s-dash-test
```

## Tips for Local Development

1. **Use `pullPolicy: Never`** to ensure Kubernetes uses your local image
2. **Use NodePort service** for easy access without ingress complexity
3. **Create a separate namespace** to avoid conflicts
4. **Use `--debug` flag** with helm for verbose output
5. **Keep secrets simple** for local testing (but never commit them!)
6. **Use port-forward** if NodePort doesn't work in your setup

## Before Moving to GitOps

Once everything works locally:

1. **Tag and push your image** to the registry
2. **Update your main values.yaml** with tested configurations
3. **Commit your changes** to git
4. **Deploy via ArgoCD** with confidence!

This approach lets you iterate quickly and catch issues before they hit your CI/CD pipeline.