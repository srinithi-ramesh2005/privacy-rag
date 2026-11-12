import os
import json
import time
import uuid
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.hashing import sha256_hex
from crypto.encryption import encrypt_aes_gcm
from database.schemas import ChunkMetadata, EncryptedChunkRecord
from mmr.cloud_mmr import CloudMMR
from mmr.proof import verify_two_tier_proof

OUTPUT_DIR = "outfolder/module_4_mmr"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run():
    chunk_counts = [100, 500, 1000, 2000, 5000]
    results_list = []

    print(f"Running MMR benchmarks for {chunk_counts} chunks...")
    
    for N in chunk_counts:
        chunks = []
        for i in range(N):
            text = f"Document chunk number {i} with some enterprise security text."
            enc = encrypt_aes_gcm(text, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            chunks.append(EncryptedChunkRecord(
                point_id=str(uuid.uuid4()), chunk_id=f"chk_{i}", doc_id="doc_test", org_id="org_test",
                user_id="usr_admin", chunk_index=i, encrypted_content=enc.ciphertext_b64,
                nonce=enc.nonce_b64, chunk_hash=sha256_hex(text), metadata=ChunkMetadata()
            ))

        # 1. Proof Generation Time
        t0 = time.perf_counter()
        cloud_mmr = CloudMMR(org_id="org_test")
        cloud_mmr.build_from_chunks(chunks)
        gen_time_ms = (time.perf_counter() - t0) * 1000

        # 2. Proof Size
        proof = cloud_mmr.get_two_tier_proof(user_id="usr_admin", chunk_id=f"chk_{N//2}")
        proof_json = proof.model_dump_json()
        proof_size_bytes = len(proof_json.encode('utf-8'))

        # 3. Verification Time (Run 100 iterations to get average)
        t0 = time.perf_counter()
        for _ in range(100):
            verify_two_tier_proof(proof, expected_cloud_root=cloud_mmr.cloud_root)
        verify_time_ms = ((time.perf_counter() - t0) / 100) * 1000

        results_list.append({
            "N": N,
            "gen_ms": round(gen_time_ms, 2),
            "verify_ms": round(verify_time_ms, 3),
            "size_bytes": proof_size_bytes
        })
        print(f"  N={N}: Gen={gen_time_ms:.2f}ms, Verify={verify_time_ms:.3f}ms, Size={proof_size_bytes}B")

    with open(f"{OUTPUT_DIR}/mmr_metrics.json", "w") as f:
        json.dump(results_list, f, indent=4)
    
    print(f"[Module 4] MMR metrics saved to {OUTPUT_DIR}/mmr_metrics.json")

if __name__ == "__main__":
    run()