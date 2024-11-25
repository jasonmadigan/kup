#!/bin/bash
# Basically, Helm install and Secure Protect Connect on auto-pilot:
# https://github.com/Kuadrant/kuadrant-operator/blob/main/doc/user-guides/full-walkthrough/secure-protect-connect-openshift.md
#
# Aims to be idempotent.

set -euo pipefail

# User Configurable Environment Variables

# Prepends resources with your $USER - only thing you really need to set
# (assuming you already export KUADRANT_* variables for AWS already)
export PREPEND="-$USER-1"

# These variables are derived from PREPEND.
export KUADRANT_GATEWAY_NS="api-gateway${PREPEND}"
export KUADRANT_GATEWAY_NAME="external${PREPEND}"
export KUADRANT_DEVELOPER_NS="toystore${PREPEND}"
export KUADRANT_CLUSTER_ISSUER_NAME="self-signed${PREPEND}"

# AWS credentials and domain settings must be set in your environment.
export KUADRANT_AWS_ACCESS_KEY_ID="${KUADRANT_AWS_ACCESS_KEY_ID:-}"
export KUADRANT_AWS_SECRET_ACCESS_KEY="${KUADRANT_AWS_SECRET_ACCESS_KEY:-}"
export KUADRANT_AWS_DNS_PUBLIC_ZONE_ID="${KUADRANT_AWS_DNS_PUBLIC_ZONE_ID:-}"
export KUADRANT_ZONE_ROOT_DOMAIN="${KUADRANT_ZONE_ROOT_DOMAIN:-}"

if [[ "${1:-}" == "--delete" ]]; then
  echo "Deleting all deployed resources..."

  echo "Deleting Kuadrant gateway resources..."
  echo "  - Deleting DNSPolicy..."
  kubectl delete dnspolicy.kuadrant.io "${KUADRANT_GATEWAY_NAME}-dnspolicy" -n "${KUADRANT_GATEWAY_NS}" --ignore-not-found
  kubectl wait --for=delete dnspolicy.kuadrant.io/"${KUADRANT_GATEWAY_NAME}-dnspolicy" -n "${KUADRANT_GATEWAY_NS}" --timeout=60s || {
    echo "DNSPolicy deletion timed out. Check for cleanup issues."
    exit 1
  }

  echo "  - Deleting ClusterIssuer..."
  kubectl delete clusterissuer "${KUADRANT_CLUSTER_ISSUER_NAME}" --ignore-not-found

  echo "  - Deleting namespaces ${KUADRANT_GATEWAY_NS} and ${KUADRANT_DEVELOPER_NS}..."
  kubectl delete ns "${KUADRANT_GATEWAY_NS}" --ignore-not-found
  kubectl delete ns "${KUADRANT_DEVELOPER_NS}" --ignore-not-found

  echo "Deleting Istio and sail-operator resources..."
  echo "  - Deleting Istio CR 'default' in istio-system..."
  kubectl delete istio default -n istio-system --ignore-not-found
  echo "  - Uninstalling sail-operator..."
  helm uninstall sail-operator -n istio-system --wait --timeout 300s || true

  echo "Deleting cert-manager..."
  helm uninstall cert-manager -n cert-manager --wait --timeout 300s || true

  echo "Deleting Kuadrant operator and CR..."
  echo "  - Deleting Kuadrant CR 'kuadrant' in kuadrant-system..."
  kubectl delete kuadrant kuadrant -n kuadrant-system --ignore-not-found
  echo "  - Uninstalling kuadrant-operator..."
  helm uninstall kuadrant-operator -n kuadrant-system --wait --timeout 300s || true

  echo "Deleting Gateway API CRDs..."
  kubectl delete crd gatewayclasses.gateway.networking.k8s.io gateways.gateway.networking.k8s.io grpcroutes.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io referencegrants.gateway.networking.k8s.io --ignore-not-found

  echo "Deleting system namespaces (istio-system, cert-manager, kuadrant-system)..."
  kubectl delete ns istio-system --ignore-not-found
  kubectl delete ns cert-manager --ignore-not-found
  kubectl delete ns kuadrant-system --ignore-not-found

  echo "Full cleanup complete."
  exit 0
fi

echo "Applying Gateway API..."
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.1.0/standard-install.yaml

echo "Adding Jetstack helm repo and installing cert-manager..."
helm repo add jetstack https://charts.jetstack.io --force-update
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.15.3 \
  --set crds.enabled=true

echo "Waiting for cert-manager deployments to be available..."
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager

echo "Installing sail-operator..."
helm upgrade --install sail-operator \
  --create-namespace \
  --namespace istio-system \
  --wait \
  --timeout=300s \
  https://github.com/istio-ecosystem/sail-operator/releases/download/0.1.0/sail-operator-0.1.0.tgz

echo "Applying Istio CR for sail-operator..."
kubectl apply -f - <<EOF
apiVersion: sailoperator.io/v1alpha1
kind: Istio
metadata:
  name: default
spec:
  # Supported values: [v1.22.4, v1.23.0]
  version: v1.23.0
  namespace: istio-system
  # Disable autoscaling to reduce dev resources
  values:
    pilot:
      autoscaleEnabled: false
EOF

echo "Waiting for Istio resource to be ready..."
kubectl wait --for=condition=Ready --timeout=300s istio/default -n istio-system

echo "Adding Kuadrant helm repo and installing kuadrant-operator..."
helm repo add kuadrant https://kuadrant.io/helm-charts/ --force-update
# Installing a pre-release chart from a direct URL:
helm upgrade --install kuadrant-operator https://github.com/Kuadrant/kuadrant-operator/releases/download/v1.1.0-alpha1/chart-kuadrant-operator-1.1.0-alpha1.tgz \
  --namespace kuadrant-system \
  --create-namespace

echo "Waiting for kuadrant-operator-controller-manager deployment..."
kubectl wait --for=condition=available --timeout=300s deployment/kuadrant-operator-controller-manager -n kuadrant-system

echo "Applying Kuadrant CR..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1beta1
kind: Kuadrant
metadata:
  name: kuadrant
  namespace: kuadrant-system
EOF

echo "Waiting for Kuadrant CR to be ready..."
kubectl wait --for=condition=Ready --timeout=300s kuadrant/kuadrant -n kuadrant-system

echo "Creating namespace ${KUADRANT_GATEWAY_NS}..."
kubectl create ns "${KUADRANT_GATEWAY_NS}" --dry-run=client -o yaml | kubectl apply -f -

echo "Creating AWS credentials secret in namespace ${KUADRANT_GATEWAY_NS}..."
kubectl -n "${KUADRANT_GATEWAY_NS}" create secret generic aws-credentials${PREPEND} \
  --type=kuadrant.io/aws \
  --from-literal=AWS_ACCESS_KEY_ID="${KUADRANT_AWS_ACCESS_KEY_ID}" \
  --from-literal=AWS_SECRET_ACCESS_KEY="${KUADRANT_AWS_SECRET_ACCESS_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Creating AWS credentials secret in namespace cert-manager..."
kubectl -n cert-manager create secret generic aws-credentials${PREPEND} \
  --type=kuadrant.io/aws \
  --from-literal=AWS_ACCESS_KEY_ID="${KUADRANT_AWS_ACCESS_KEY_ID}" \
  --from-literal=AWS_SECRET_ACCESS_KEY="${KUADRANT_AWS_SECRET_ACCESS_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Creating namespace ${KUADRANT_DEVELOPER_NS}..."
kubectl create ns "${KUADRANT_DEVELOPER_NS}" --dry-run=client -o yaml | kubectl apply -f -

echo "Deploying the toystore example app..."
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/Kuadrant-operator/main/examples/toystore/toystore.yaml -n "${KUADRANT_DEVELOPER_NS}"

echo "Creating ClusterIssuer ${KUADRANT_CLUSTER_ISSUER_NAME}..."
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ${KUADRANT_CLUSTER_ISSUER_NAME}
spec:
  selfSigned: {}
EOF

echo "Waiting for ClusterIssuer ${KUADRANT_CLUSTER_ISSUER_NAME} to be ready..."
kubectl wait clusterissuer/"${KUADRANT_CLUSTER_ISSUER_NAME}" --for=condition=ready=true --timeout=300s

echo "Creating Gateway ${KUADRANT_GATEWAY_NAME} in namespace ${KUADRANT_GATEWAY_NS}..."
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ${KUADRANT_GATEWAY_NAME}
  namespace: ${KUADRANT_GATEWAY_NS}
  labels:
    kuadrant.io/gateway: "true"
spec:
  gatewayClassName: istio
  listeners:
  - allowedRoutes:
      namespaces:
        from: All 
    hostname: "api.${KUADRANT_ZONE_ROOT_DOMAIN}"
    name: api
    port: 443
    protocol: HTTPS
    tls:
      certificateRefs:
      - group: ""
        kind: Secret
        name: api-${KUADRANT_GATEWAY_NAME}-tls
      mode: Terminate
EOF

echo "Waiting for Gateway ${KUADRANT_GATEWAY_NAME} to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s gateway/"${KUADRANT_GATEWAY_NAME}" -n "${KUADRANT_GATEWAY_NS}"

echo "Creating TLSPolicy for the Gateway..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1
kind: TLSPolicy
metadata:
  name: ${KUADRANT_GATEWAY_NAME}-tls
  namespace: ${KUADRANT_GATEWAY_NS}
spec:
  targetRef:
    name: ${KUADRANT_GATEWAY_NAME}
    group: gateway.networking.k8s.io
    kind: Gateway
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: ${KUADRANT_CLUSTER_ISSUER_NAME}
EOF

echo "Waiting for TLSPolicy ${KUADRANT_GATEWAY_NAME}-tls to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s tlspolicy/"${KUADRANT_GATEWAY_NAME}-tls" -n "${KUADRANT_GATEWAY_NS}"

echo "Creating HTTPRoute for the toystore app..."
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: toystore
  namespace: ${KUADRANT_DEVELOPER_NS}
  labels:
    deployment: toystore
    service: toystore
spec:
  parentRefs:
  - name: ${KUADRANT_GATEWAY_NAME}
    namespace: ${KUADRANT_GATEWAY_NS}
  hostnames:
  - "api.${KUADRANT_ZONE_ROOT_DOMAIN}"
  rules:
  - matches:
    - method: GET
      path:
        type: PathPrefix
        value: "/cars"
    - method: GET
      path:
        type: PathPrefix
        value: "/health"    
    backendRefs:
    - name: toystore
      port: 80  
EOF

echo "Creating AuthPolicy (default deny) for the Gateway..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1
kind: AuthPolicy
metadata:
  name: ${KUADRANT_GATEWAY_NAME}-auth
  namespace: ${KUADRANT_GATEWAY_NS}
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: ${KUADRANT_GATEWAY_NAME}
  defaults:
   when:
     - predicate: "request.path != '/health'"
   rules:
    authorization:
      deny-all:
        opa:
          rego: "allow = false"
    response:
      unauthorized:
        headers:
          "content-type":
            value: application/json
        body:
          value: |
            {
              "error": "Forbidden",
              "message": "Access denied by default by the gateway operator. If you are the administrator of the service, create a specific auth policy for the route."
            }
EOF

echo "Waiting for AuthPolicy ${KUADRANT_GATEWAY_NAME}-auth to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s authpolicy/"${KUADRANT_GATEWAY_NAME}-auth" -n "${KUADRANT_GATEWAY_NS}"

echo "Creating RateLimitPolicy for the Gateway..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1
kind: RateLimitPolicy
metadata:
  name: ${KUADRANT_GATEWAY_NAME}-rlp
  namespace: ${KUADRANT_GATEWAY_NS}
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: ${KUADRANT_GATEWAY_NAME}
  defaults:
    limits:
      "low-limit":
        rates:
        - limit: 1
          window: 10s
EOF

echo "Waiting for RateLimitPolicy ${KUADRANT_GATEWAY_NAME}-rlp to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s ratelimitpolicy/"${KUADRANT_GATEWAY_NAME}-rlp" -n "${KUADRANT_GATEWAY_NS}"

echo "Creating DNSPolicy for the Gateway..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1
kind: DNSPolicy
metadata:
  name: ${KUADRANT_GATEWAY_NAME}-dnspolicy
  namespace: ${KUADRANT_GATEWAY_NS}
spec:
  healthCheck:
    failureThreshold: 3
    interval: 1m
    path: /health
  loadBalancing:
    defaultGeo: true
    geo: GEO-NA
    weight: 120
  targetRef:
    name: ${KUADRANT_GATEWAY_NAME}
    group: gateway.networking.k8s.io
    kind: Gateway
  providerRefs:
  - name: aws-credentials${PREPEND}
EOF

echo "Waiting for DNSPolicy ${KUADRANT_GATEWAY_NAME}-dnspolicy to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s dnspolicy/"${KUADRANT_GATEWAY_NAME}-dnspolicy" -n "${KUADRANT_GATEWAY_NS}"

echo "Testing Gateway rate limiting (15 iterations)..."
for i in {1..15}; do 
  curl -k --write-out '%{http_code}\n' --silent --output /dev/null "https://api.${KUADRANT_ZONE_ROOT_DOMAIN}/cars" | grep -E --color "\b(429)\b|$" || true
  sleep 1
done

echo "Creating API key secrets for Bob and Alice in kuadrant-system..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: bob-key
  namespace: kuadrant-system
  labels:
    authorino.kuadrant.io/managed-by: authorino
    app: toystore
  annotations:
    secret.kuadrant.io/user-id: bob
stringData:
  api_key: IAMBOB
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  name: alice-key
  namespace: kuadrant-system
  labels:
    authorino.kuadrant.io/managed-by: authorino
    app: toystore
  annotations:
    secret.kuadrant.io/user-id: alice
stringData:
  api_key: IAMALICE
type: Opaque
EOF

echo "Creating AuthPolicy for the toystore HTTPRoute..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1
kind: AuthPolicy
metadata:
  name: toystore-auth
  namespace: ${KUADRANT_DEVELOPER_NS}
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: toystore
  defaults:
   when:
     - predicate: "request.path != '/health'"  
   rules:
    authentication:
      "api-key-users":
        apiKey:
          selector:
            matchLabels:
              app: toystore
        credentials:
          authorizationHeader:
            prefix: APIKEY
    response:
      success:
        filters:
          "identity":
            json:
              properties:
                "userid":
                  selector: auth.identity.metadata.annotations.secret\.kuadrant\.io/user-id
EOF

echo "Waiting for AuthPolicy toystore-auth to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s authpolicy/toystore-auth -n "${KUADRANT_DEVELOPER_NS}"

echo "Creating RateLimitPolicy for the toystore HTTPRoute..."
kubectl apply -f - <<EOF
apiVersion: kuadrant.io/v1
kind: RateLimitPolicy
metadata:
  name: toystore-rlp
  namespace: ${KUADRANT_DEVELOPER_NS}
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: toystore
  limits:
    "general-user":
      rates:
      - limit: 5
        window: 10s
      counters:
      - expression: auth.identity.userid
      when:
      - predicate: "auth.identity.userid != 'bob'"
    "bob-limit":
      rates:
      - limit: 2
        window: 10s
      when:
      - predicate: "auth.identity.userid == 'bob'"
EOF

echo "Waiting for RateLimitPolicy toystore-rlp to be Accepted..."
kubectl wait --for=condition=Accepted --timeout=300s ratelimitpolicy/toystore-rlp -n "${KUADRANT_DEVELOPER_NS}"

echo "Verifying HTTPRoute rate limit policy (if status is available)..."
kubectl get httproute toystore -n "${KUADRANT_DEVELOPER_NS}" -o=jsonpath='{.status.parents[0].conditions[?(@.type=="kuadrant.io/RateLimitPolicyAffected")].message}'

echo "Testing toystore endpoint rate limiting for API key IAMALICE (10 iterations)..."
for i in {1..10}; do 
  curl -k --write-out '%{http_code}\n' --silent --output /dev/null -H 'Authorization: APIKEY IAMALICE' "https://api.${KUADRANT_ZONE_ROOT_DOMAIN}/cars" | grep -E --color "\b(429)\b|$" || true
  sleep 1
done

echo "Testing toystore endpoint rate limiting for API key IAMBOB (10 iterations)..."
for i in {1..10}; do 
  curl -k --write-out '%{http_code}\n' --silent --output /dev/null -H 'Authorization: APIKEY IAMBOB' "https://api.${KUADRANT_ZONE_ROOT_DOMAIN}/cars" | grep -E --color "\b(429)\b|$" || true
  sleep 1
done

echo "Creating PodMonitor for istio-proxies in namespace ${KUADRANT_GATEWAY_NS}..."
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: istio-proxies-monitor
  namespace: ${KUADRANT_GATEWAY_NS}
spec:
  selector:
    matchExpressions:

      - key: istio-prometheus-ignore
        operator: DoesNotExist
  podMetricsEndpoints:
    - path: /stats/prometheus
      interval: 30s
      relabelings:
        - action: keep
          sourceLabels: ["__meta_kubernetes_pod_container_name"]
          regex: "istio-proxy"
        - action: keep
          sourceLabels:
            ["__meta_kubernetes_pod_annotationpresent_prometheus_io_scrape"]
        - action: replace
          regex: (\d+);(([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})
          replacement: "[\$2]:\$1"
          sourceLabels:
            [
              "__meta_kubernetes_pod_annotation_prometheus_io_port",
              "__meta_kubernetes_pod_ip",
            ]
          targetLabel: "__address__"
        - action: replace
          regex: (\d+);((([0-9]+?)(\.|$)){4})
          replacement: "\$2:\$1"
          sourceLabels:
            [
              "__meta_kubernetes_pod_annotation_prometheus_io_port",
              "__meta_kubernetes_pod_ip",
            ]
          targetLabel: "__address__"
        - action: labeldrop
          regex: "__meta_kubernetes_pod_label_(.+)"
        - sourceLabels: ["__meta_kubernetes_namespace"]
          action: replace
          targetLabel: namespace
        - sourceLabels: ["__meta_kubernetes_pod_name"]
          action: replace
          targetLabel: pod_name
EOF

echo "Installation complete."
