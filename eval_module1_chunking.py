import os
import json
import numpy as np
import re
from core.document_ingestion import chunk_text
from core.embedding_service import EmbeddingService

OUTPUT_DIR = "outfolder/module_1_chunking"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SAMPLE_TEXT = """
Enterprise Cloud Security Directive 2026. All engineering staff accessing production Kubernetes clusters, AWS infrastructure, and internal databases must authenticate using hardware FIDO2/WebAuthn security keys. Password-only authentication is strictly prohibited. Multi-factor authentication (MFA) must be enforced with push notifications and biometric verification.

Section 2: VPN Credential Rotation & Session Lifetime. All VPN security credentials, SSH keys, and TLS certificates must be automatically rotated every 30 days. Inactive administrative sessions and remote desktop connections are forcibly terminated after 15 minutes of idle time.

Section 3: Cryptographic Storage & Merkle Verification. All enterprise data stored in cloud vector databases must enforce AES-256-GCM authenticated encryption at rest. Data retrieval pipelines must provide Two-Tier Merkle Mountain Range (MMR) proofs to verify zero tampering before release.
"""

def calc_cohesion(chunks):
    if not chunks: return 0.0
    sims = []
    for c in chunks:
        sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', c) if s.strip()]
        if len(sentences) < 2: continue
        embs = EmbeddingService.embed_batch(sentences)
        for i in range(len(embs)-1):
            sim = np.dot(embs[i], embs[i+1]) / (np.linalg.norm(embs[i]) * np.linalg.norm(embs[i+1]) + 1e-9)
            sims.append(float(sim))
    return round(float(np.mean(sims)), 4) if sims else 1.0

def calc_fragmentation(chunks):
    if not chunks: return 0.0
    frag_count = sum(1 for c in chunks if not c.strip().endswith(('.', '!', '?')))
    return round(frag_count / len(chunks) * 100, 2)

def run():
    fixed_chunks = chunk_text(SAMPLE_TEXT, chunk_size=200, overlap=20, use_semantic=False)
    semantic_chunks = chunk_text(SAMPLE_TEXT, chunk_size=200, overlap=20, use_semantic=True)

    results = {
        "fixed_length": {
            "chunk_count": len(fixed_chunks),
            "size_variance_stdev": round(float(np.std([len(c) for c in fixed_chunks])), 2),
            "boundary_fragmentation_rate_pct": calc_fragmentation(fixed_chunks),
            "semantic_cohesion": calc_cohesion(fixed_chunks)
        },
        "semantic": {
            "chunk_count": len(semantic_chunks),
            "size_variance_stdev": round(float(np.std([len(c) for c in semantic_chunks])), 2),
            "boundary_fragmentation_rate_pct": calc_fragmentation(semantic_chunks),
            "semantic_cohesion": calc_cohesion(semantic_chunks)
        }
    }

    with open(f"{OUTPUT_DIR}/chunking_metrics.json", "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"[Module 1] Chunking metrics saved to {OUTPUT_DIR}/chunking_metrics.json")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run()