import requests, json

BASE = "http://127.0.0.1:8000"

# 1. Ingest
r = requests.post(f"{BASE}/api/v1/ingest-text", json={
    "text": (
        "ENTERPRISE CLOUD SECURITY DIRECTIVE 2026. "
        "Section 1: VPN Credential Rotation. "
        "All VPN security credentials, SSH keys, and TLS certificates must be rotated every 30 days. "
        "Section 2: Access Control. "
        "FIDO2 hardware security keys are mandatory for all administrative Kubernetes access."
    ),
    "doc_id": "doc_vpn_test",
    "user_id": "usr_admin_01",
    "org_id": "org_enterprise_01",
    "chunk_size": 500,
    "overlap": 50,
    "filename": "vpn_policy.txt"
})
print("Ingest:", r.status_code, r.json().get("total_chunks"), "chunks")

# 2. Query (normal)
r = requests.post(f"{BASE}/api/v1/query-verify", json={
    "query_text": "How often must VPN credentials be rotated?",
    "user_id": "usr_admin_01",
    "org_id": "org_enterprise_01"
})
d = r.json()
print("Normal query ->", d["status"], "| answer:", (d.get("answer") or "")[:120])

# 3. Tampering
r = requests.post(f"{BASE}/api/v1/query-verify", json={
    "query_text": "How often must VPN credentials be rotated?",
    "user_id": "usr_admin_01",
    "org_id": "org_enterprise_01",
    "simulate_integrity_failure": True
})
print("Tampered ->", r.json()["status"])

# 4. Boundary miss
r = requests.post(f"{BASE}/api/v1/query-verify", json={
    "query_text": "How often must VPN credentials be rotated?",
    "user_id": "usr_admin_01",
    "org_id": "org_enterprise_01",
    "simulate_missing_cluster": True
})
print("Boundary miss ->", r.json()["status"])

# 5. Unauthorized
r = requests.post(f"{BASE}/api/v1/query-verify", json={
    "query_text": "How often must VPN credentials be rotated?",
    "user_id": "usr_guest_external",
    "org_id": "org_enterprise_01"
})
print("Unauthorized ->", r.json()["status"])