import os
import json
import numpy as np
import requests

OUTPUT_DIR = "outfolder/retrieval_metrics"
os.makedirs(OUTPUT_DIR, exist_ok=True)
API_URL = "http://127.0.0.1:8000/api/v1/query-verify"

def run_retrieval_evaluation():
    test_set = [
        {"query": "How often must VPN credentials be rotated?", "ground_truth_chunk": "doc_cloud_security_policy_chunk_1"},
        {"query": "What is the purpose of the Zero-Trust Verifiable RAG Engine?", "ground_truth_chunk": "doc_john_doe_resume_chunk_2"},
        {"query": "What happens if a temperature deviation exceeds 2C?", "ground_truth_chunk": "doc_global_cold_chain_chunk_3"},
        {"query": "What is the capital of France?", "ground_truth_chunk": "NO_ANSWER"}
    ]

    tp, fp, fn, tn = 0, 0, 0, 0
    mrr_sum = 0
    hit_at_5 = 0
    ndcg_sum = 0
    results_log = []

    for item in test_set:
        payload = {
            "query_text": item["query"],
            "user_id": "usr_admin_01",
            "org_id": "org_enterprise_01"
        }
        try:
            res = requests.post(API_URL, json=payload).json()
        except:
            print("Error connecting to API. Make sure Uvicorn is running.")
            return
        
        chunks = res.get("decrypted_chunks", [])
        retrieved_ids = [c.get("chunk_id", "") for c in chunks]
        gt = item["ground_truth_chunk"]

        if gt == "NO_ANSWER":
            if len(retrieved_ids) == 0:
                tn += 1
                results_log.append({"query": item["query"], "result": "True Negative (Correct Abstention)"})
            else:
                fp += 1
                results_log.append({"query": item["query"], "result": "False Positive (Failed Abstention)"})
        else:
            if gt in retrieved_ids:
                tp += 1
                rank = retrieved_ids.index(gt) + 1
                mrr_sum += 1.0 / rank
                if rank <= 5: hit_at_5 += 1
                ndcg_sum += 1.0 / np.log2(rank + 1)
                results_log.append({"query": item["query"], "result": f"True Positive (Rank {rank})"})
            else:
                fn += 1
                results_log.append({"query": item["query"], "result": "False Negative"})

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    mrr = mrr_sum / len(test_set)
    hit_rate = hit_at_5 / len(test_set)
    ndcg = ndcg_sum / len(test_set)
    abstention_rate = tn / (tn + fp) if (tn + fp) > 0 else 0

    results = {
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "hit_rate_at_5": round(hit_rate, 3),
        "mrr": round(mrr, 3),
        "ndcg": round(ndcg, 3),
        "abstention_rate": round(abstention_rate, 3),
        "details": results_log
    }

    with open(f"{OUTPUT_DIR}/retrieval_metrics.json", "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"[Retrieval] Metrics saved to {OUTPUT_DIR}/retrieval_metrics.json")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_retrieval_evaluation()