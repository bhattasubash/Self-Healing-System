# Project Heal: Local Lab & Chaos Testing Environment

This lab provides an isolated environment for validating Project Heal's edge-first Kubernetes remediation agent against real bad-change failure modes.

---

## 🏗️ Lab Architecture

- **Cluster Engine:** [kind (Kubernetes in Docker)](https://kind.sigs.k8s.io/)
- **Target Application:** `payments` microservice namespace
  - Deployment: `payment-gateway` (3 replicas, HTTP readiness & liveness probes)
  - ConfigMap: `payment-config`
  - Service: `payment-gateway` (ClusterIP)
- **Failure Injection Scenarios:**
  - `T-01`: Bad container image tag (`ImagePullBackOff` / `ErrImagePull`)
  - `T-02`: Crashing startup command/arguments (`CrashLoopBackOff`)
  - `T-04`: Failing readiness probe (`0/3 ready` replicas)

---

## 🚀 Setup Instructions

### 1. Provision Local kind Cluster
```bash
kind create cluster --config lab/kind-config.yaml
kubectl cluster-info --context kind-heal-lab
```

### 2. Deploy Sample Microservices
```bash
kubectl apply -f lab/manifests/00-namespace.yaml
kubectl apply -f lab/manifests/01-configmap.yaml
kubectl apply -f lab/manifests/02-payment-gateway-deployment.yaml
kubectl apply -f lab/manifests/03-service.yaml

# Wait for healthy baseline
kubectl rollout status deployment/payment-gateway -n payments --timeout=60s
```

### 3. Run Brain Backend
```bash
cd brain
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 💥 Scripted Failure Injections

### T-01: Bad Image Tag Deploy
```bash
python lab/injections/inject_t01_bad_image.py --deployment payment-gateway --namespace payments
# Or via bash:
# ./lab/injections/inject_t01_bad_image.sh payments payment-gateway
```
- **Observed Symptoms:** Pods fail to pull image (`ImagePullBackOff`).
- **Evidence Gate Outcome:** Evaluates rules R1–R8 $\to$ **Tier A**.
- **Proposed Action:** Typed Action `A1_ROLLBACK` (Deployment rollback).
- **Verification:** Waits for pods to transition to Ready; verifies prior template.

### T-02: CrashLoopBackOff After Deploy
```bash
python lab/injections/inject_t02_crashloop.py --deployment payment-gateway --namespace payments
# Or via bash:
# ./lab/injections/inject_t02_crashloop.sh payments payment-gateway
```
- **Observed Symptoms:** Pod container exits with error on startup.
- **Evidence Gate Outcome:** **Tier A** $\to$ Rollback proposed and dry-run diff shown.

### T-04: Failing Readiness Probe
```bash
python lab/injections/inject_t04_failing_readiness.py --deployment payment-gateway --namespace payments
# Or via bash:
# ./lab/injections/inject_t04_failing_readiness.sh payments payment-gateway
```
- **Observed Symptoms:** Pods stay Running but 0/3 Ready.
- **Evidence Gate Outcome:** **Tier A** $\to$ Rollback proposed and dry-run diff shown.

---

## 🧪 Automated Scenario Verification

Run the scenario test suite directly:
```bash
pytest lab/test_lab_scenarios.py -v
```
