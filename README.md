# homepage
Homelab Cluster landing page linking to self-hosted services


```bash
cd ui
# build it
docker build -t k8sdash:latest .
# run it
docker run -p 8080:3000 \
  --env-file .env.local \
  -v ~/.kube:/home/nextjs/.kube:ro \
  -e KUBECONFIG=/home/nextjs/.kube/config \
  k8sdash:latest
```