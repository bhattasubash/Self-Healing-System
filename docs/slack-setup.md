# Slack Integration & Interactive Approval Setup Guide

This document describes how to configure Slack App integration for Project Heal's interactive remediation approval loop (`/api/v1/approval/interactive`), run it safely via an ingress tunnel (Cloudflare Tunnel), and adhere to strict security invariants.

---

## 1. Architecture & Security Boundaries

```
┌─────────────────┐           ┌────────────────────────────────┐           ┌─────────────────────┐
│                 │  Webhook  │ Cloudflare Tunnel / Ingress    │  HTTP POST │ Project Heal        │
│ Slack Workspace │ ────────> │ (Exposes ONLY approval route)  │ ─────────> │ FastAPI Brain       │
│                 │ <──────── │                                │ <───────── │ :8000               │
└─────────────────┘  Ack <3s  └────────────────────────────────┘  Immediate └─────────────────────┘
         ▲                                                            │
         │                                                            │ Background Rollback
         │                 Asynchronous Update via response_url        ▼
         └───────────────────────────────────────────────────── Kubernetes Cluster
```

### Security Invariants
1. **Perimeter Minimization**: Expose **ONLY** `/api/v1/approval/interactive` through the external tunnel. Alert intake (`/api/v1/alerts/*`), metrics, and temporal store endpoints must remain private inside the cluster.
2. **Zero-Secret Storage**: Never commit tokens, signing secrets, or credentials. All secrets are injected strictly via environment variables or Kubernetes `Secret` resources.
3. **Cryptographic Signature Verification**: Every inbound request is validated against Slack's HMAC-SHA256 signature scheme using `SLACK_SIGNING_SECRET` and timestamp anti-replay validation (5-minute maximum drift).
4. **Sub-3s Acknowledgment**: Slack drops connections and displays errors if an interactive webhook does not return HTTP 200 within 3,000 milliseconds. Brain acknowledges in `<50ms`, runs remediation in the background, and updates Slack via `response_url`.

---

## 2. Slack App Configuration

### Step 1: Create Slack App via Manifest
1. Navigate to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** -> **From an app manifest**.
2. Select your workspace and paste the following manifest:

```json
{
  "display_information": {
    "name": "Project Heal Operator",
    "description": "Autonomous remediation approval and rollback operator",
    "background_color": "#121417"
  },
  "features": {
    "bot_user": {
      "display_name": "HealBot",
      "always_online": true
    }
  },
  "oauth_config": {
    "scopes": {
      "bot": [
        "chat:write",
        "chat:write.public",
        "chat:write.customize"
      ]
    }
  },
  "settings": {
    "interactivity": {
      "is_enabled": true,
      "request_url": "https://<YOUR-TUNNEL-DOMAIN>/api/v1/approval/interactive"
    },
    "org_deploy_enabled": false,
    "socket_mode_enabled": false
  }
}
```

### Step 2: Extract Secrets
From the app dashboard:
- **Basic Information -> App Credentials**: Copy `Signing Secret`.
- **OAuth & Permissions**: Click **Install to Workspace** and copy `Bot User OAuth Token` (`xoxb-...`).

---

## 3. Ingress Tunnel Configuration: Cloudflare Tunnel (`cloudflared`)

To receive interactive webhooks locally or in a lab without a public IP, use an ingress tunnel that strictly adheres to the **Perimeter Minimization** invariant: **only** `/api/v1/approval/interactive` may be exposed externally. Exposing the entire port or running unconstrained tunnels is prohibited by security policy because it exposes private internal endpoints (`/api/v1/alerts/*`, `/ready`, `/health`, analysis engines).

`cloudflared` natively enforces path-level ingress filtering and fails closed on unlisted paths.

Create a configuration file `cloudflared-config.yml`:

```yaml
tunnel: <TUNNEL_UUID>
credentials-file: /path/to/<TUNNEL_UUID>.json

ingress:
  # Rule 1: Expose ONLY the approval endpoint
  - path: /api/v1/approval/interactive
    service: http://127.0.0.1:8000/api/v1/approval/interactive
  # Rule 2: Deny all other routes (fails closed)
  - service: http_status:404
```

Start the tunnel:
```bash
cloudflared tunnel run <TUNNEL_NAME>
```

Update your Slack App Interactivity Request URL to:
`https://<YOUR-TUNNEL-DOMAIN>/api/v1/approval/interactive`

---

## 4. Environment Variables Configuration

Export the required configuration in the Brain process or Kubernetes Secret:

```bash
# Slack App credentials
export SLACK_BOT_TOKEN="xoxb-your-bot-token"
export SLACK_SIGNING_SECRET="your-signing-secret"
export SLACK_APPROVAL_CHANNEL="#sre-incidents"

# Role mappings for Slack user IDs
export SLACK_ALLOWED_APPROVER_ROLES='["sre-lead", "incident-commander"]'
export SLACK_APPROVER_ROLE_MAPPING='{"U0123456789": "sre-lead"}'

# Default deny namespace policy
export KUBERNETES_ALLOWED_NAMESPACES='["payments", "orders"]'
export KUBERNETES_COLLECTOR_ENABLED="true"
export KUBERNETES_WATCH_ENABLED="true"

# Webhook Auth Token for Alertmanager
export ALERT_AUTH_TOKEN="your-alertmanager-secret-token"
```

---

## 5. Verification & End-to-End Walkthrough

1. **Start the Brain Service**:
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
2. **Trigger Failure / Ingest Alert**:
   Send a synthetic or Alertmanager alert matching a deployment failure.
3. **Inspect Slack Channel**:
   A Block Kit card arrives in `#sre-incidents` displaying:
   - Incident ID and Workload (`payments/payment-gateway`).
   - Grounded Evidence Gate classification (`Tier A`, proposed action `A1_ROLLBACK`).
   - Unified dry-run container diff.
   - Interactive buttons: `[Approve & Deploy Fix]` and `[Reject Fix]`.
4. **Approve Action**:
   Click `[Approve & Deploy Fix]`.
   - Brain validates HMAC signature and checks user ID against `SLACK_APPROVER_ROLE_MAPPING`.
   - Immediate HTTP 200 response returns to Slack in `<50ms` (`execution_status: in_progress`).
   - Rollback executes against the live cluster in the background.
   - Upon stabilization verification, Brain updates the original Slack card via `response_url` displaying `Status: RESOLVED` and the cryptographic audit hash.
