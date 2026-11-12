# Unified RAG Verifier

A zero-trust, multi-tenant Retrieval-Augmented Generation system with 5-gate verification: ACL, cryptographic MMR integrity, IVF boundary completeness, AES-256-GCM decryption, and semantic grounding.

## Prerequisites

- Python 3.9+
- Docker Desktop (optional, for persistent Qdrant; otherwise in-memory)

## Setup

```cmd
cd C:\Users\srira\Music\rag
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt