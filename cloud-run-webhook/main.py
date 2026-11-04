import hashlib
import hmac
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

# Configuration from environment
ZTRE_WEBHOOK_SECRET = os.getenv("ZTRE_WEBHOOK_SECRET", "dev-secret-change-in-prod").encode()
ZTRE_DRY_RUN = os.getenv("ZTRE_DRY_RUN", "false").lower() in ("true", "1", "yes")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
ZTRE_DEDUP_TTL = int(os.getenv("ZTRE_DEDUP_TTL", "60"))

PROTECTED_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "cilium",
    "tetragon",
    "gmp-system",
    "gke-managed-cim",
    "knative-serving",
}

# ponytail: in-memory dict ceiling single-instance memory; upgrade to Redis/Memorystore when scaling multi-instance Cloud Run
_recent_quarantines: Dict[str, float] = {}

app = FastAPI(title="ZTRE-Serverless", version="1.1.0")


class WorkloadMetadata(BaseModel):
    namespace: str
    pod_name: str
    uid: str
    labels: Dict[str, str] = Field(default_factory=dict)


class ProcessMetadata(BaseModel):
    binary: str
    arguments: str = ""
    parent_binary: str = ""
    pid: Optional[int] = None


class TetragonAlertPayload(BaseModel):
    event_id: str
    timestamp: str
    cluster_id: str = "gke-hybrid-01"
    policy_name: str
    severity: str = "CRITICAL"
    workload: WorkloadMetadata
    process: ProcessMetadata


# Matches Go agent decision.Alert struct (sent by WebhookAlertSink)
class AgentAlert(BaseModel):
    event_id: str
    timestamp: str
    pod_name: str
    namespace: str
    parent_binary: str = ""
    binary: str
    arguments: str = ""
    classification: str = ""
    severity_score: float = 0.0
    context_score: float = 0.0
    asset_score: float = 0.0
    total_risk_score: float = 0.0
    action: str = ""
    recommended_action: str = ""


class RemediationAuditRecord(BaseModel):
    event_id: str
    status: str
    mode: str
    target_pod: str
    target_namespace: str
    applied_label: str = "ztre/quarantine=true"
    network_policy: str = "ztre-zero-trust-quarantine"
    netpol_status: str
    forensic_summary: str
    timestamp: str


def verify_signature(raw_body: bytes, signature_header: Optional[str]) -> None:
    if not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-ZTRE-Signature header",
        )
    signature = signature_header.removeprefix("sha256=").strip()
    expected = hmac.new(ZTRE_WEBHOOK_SECRET, raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-ZTRE-Signature header",
        )


def get_k8s_clients():
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api(), client.NetworkingV1Api()


def enforce_quarantine(namespace: str, pod_name: str) -> str:
    if ZTRE_DRY_RUN:
        return "created"

    core_v1, net_v1 = get_k8s_clients()
    from kubernetes.client.exceptions import ApiException
    from kubernetes.client.models import (
        V1LabelSelector,
        V1NetworkPolicy,
        V1NetworkPolicySpec,
        V1ObjectMeta,
    )

    core_v1.patch_namespaced_pod(
        name=pod_name,
        namespace=namespace,
        body={"metadata": {"labels": {"ztre/quarantine": "true"}}},
    )

    policy = V1NetworkPolicy(
        metadata=V1ObjectMeta(
            name="ztre-zero-trust-quarantine",
            labels={"app.kubernetes.io/managed-by": "ztre-serverless"},
        ),
        spec=V1NetworkPolicySpec(
            pod_selector=V1LabelSelector(match_labels={"ztre/quarantine": "true"}),
            policy_types=["Ingress", "Egress"],
            ingress=[],
            egress=[],
        ),
    )

    try:
        net_v1.create_namespaced_network_policy(namespace=namespace, body=policy)
        return "created"
    except ApiException as e:
        if e.status == 409:
            return "already_present"
        raise


async def generate_ai_triage_summary(
    binary: str, arguments: str, parent_binary: str,
    pod_name: str, namespace: str, policy_name: str = "ztre-agent",
) -> str:
    fallback = (
        f"[Deterministic Triage] Process '{binary}' "
        f"(args: '{arguments}') spawned by '{parent_binary}' "
        f"in pod '{pod_name}' (ns: '{namespace}') "
        f"violated policy '{policy_name}'. Pod isolated via zero-trust NetworkPolicy."
    )

    if not GEMINI_API_KEY:
        return fallback

    prompt = (
        f"Security Alert: Process {binary} ({arguments}) "
        f"spawned by {parent_binary} inside pod {pod_name} "
        f"(namespace: {namespace}) triggered Tetragon policy {policy_name}. "
        f"The pod was quarantined with network policy ztre-zero-trust-quarantine. "
        "Summarize the attack vector and confirmation of socket isolation in exactly two concise sentences."
    )

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    body = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(
                url,
                headers={"x-goog-api-key": GEMINI_API_KEY},
                json=body,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception:
        pass

    return fallback


@app.get("/healthz")
def healthz():
    return {
        "status": "healthy",
        "engine": "ZTRE-Serverless",
        "dry_run": ZTRE_DRY_RUN,
    }


@app.post("/v1/remediate")
async def remediate(
    request: Request,
    x_ztre_signature: Optional[str] = Header(None, alias="X-ZTRE-Signature"),
):
    raw_body = await request.body()
    verify_signature(raw_body, x_ztre_signature)

    payload = TetragonAlertPayload.model_validate_json(raw_body)
    now = time.time()

    # Prune expired dedup entries
    expired = [uid for uid, ts in _recent_quarantines.items() if (now - ts) >= ZTRE_DEDUP_TTL]
    for uid in expired:
        del _recent_quarantines[uid]

    # FR-2: Blast-radius namespace check
    if payload.workload.namespace in PROTECTED_NAMESPACES:
        return {
            "status": "ignored",
            "reason": "protected_namespace",
            "namespace": payload.workload.namespace,
        }

    # FR-2: Workload UID deduplication
    last_quarantine = _recent_quarantines.get(payload.workload.uid)
    if last_quarantine and (now - last_quarantine) < ZTRE_DEDUP_TTL:
        return {
            "status": "deduplicated",
            "workload_uid": payload.workload.uid,
        }

    _recent_quarantines[payload.workload.uid] = now

    # FR-3: Quarantine enforcement
    netpol_status = enforce_quarantine(
        namespace=payload.workload.namespace,
        pod_name=payload.workload.pod_name,
    )

    # FR-4: AI forensic summary
    forensic_summary = await generate_ai_triage_summary(
        binary=payload.process.binary,
        arguments=payload.process.arguments,
        parent_binary=payload.process.parent_binary,
        pod_name=payload.workload.pod_name,
        namespace=payload.workload.namespace,
        policy_name=payload.policy_name,
    )

    audit_record = RemediationAuditRecord(
        event_id=payload.event_id,
        status="quarantined",
        mode="DRY_RUN" if ZTRE_DRY_RUN else "LIVE_ENFORCEMENT",
        target_pod=payload.workload.pod_name,
        target_namespace=payload.workload.namespace,
        netpol_status=netpol_status,
        forensic_summary=forensic_summary,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    return {
        "status": "quarantined",
        "audit_record": audit_record.model_dump(),
    }


@app.post("/v1/agent-alert")
async def agent_alert(request: Request):
    """Receives alerts from ZTRE Go Agent WebhookAlertSink.
    No HMAC required — agent sends plain JSON Alert structs.
    Agent already performed containment; this endpoint adds AI triage + audit logging."""
    raw_body = await request.body()
    alert = AgentAlert.model_validate_json(raw_body)
    now = time.time()

    # Prune expired dedup entries
    expired = [uid for uid, ts in _recent_quarantines.items() if (now - ts) >= ZTRE_DEDUP_TTL]
    for uid in expired:
        del _recent_quarantines[uid]

    # Blast-radius namespace check
    if alert.namespace in PROTECTED_NAMESPACES:
        return {"status": "ignored", "reason": "protected_namespace"}

    # Dedup by event_id (agent uses "podName-PID" as event_id)
    if alert.event_id in _recent_quarantines:
        if (now - _recent_quarantines[alert.event_id]) < ZTRE_DEDUP_TTL:
            return {"status": "deduplicated", "event_id": alert.event_id}
    _recent_quarantines[alert.event_id] = now

    # AI forensic summary (agent already did containment, skip enforce_quarantine)
    forensic_summary = await generate_ai_triage_summary(
        binary=alert.binary,
        arguments=alert.arguments,
        parent_binary=alert.parent_binary,
        pod_name=alert.pod_name,
        namespace=alert.namespace,
    )

    audit_record = RemediationAuditRecord(
        event_id=alert.event_id,
        status="acknowledged",
        mode="AGENT_WEBHOOK",
        target_pod=alert.pod_name,
        target_namespace=alert.namespace,
        netpol_status="agent_handled",
        forensic_summary=forensic_summary,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    return {
        "status": "acknowledged",
        "audit_record": audit_record.model_dump(),
    }
