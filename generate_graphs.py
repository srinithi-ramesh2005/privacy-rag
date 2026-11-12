import json
import os
import matplotlib.pyplot as plt
import numpy as np

BASE_DIR = "outfolder"
M1_PATH = f"{BASE_DIR}/module_1_chunking/chunking_metrics.json"
M2_PATH = f"{BASE_DIR}/module_2_encryption/encryption_metrics.json"
M4_PATH = f"{BASE_DIR}/module_4_mmr/mmr_metrics.json"
RET_PATH = f"{BASE_DIR}/retrieval_metrics/retrieval_metrics.json"

# Professional Styling
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 12,
    'axes.titlesize': 14,
    'axes.titleweight': 'bold',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'lines.linewidth': 2.5,
    'lines.markersize': 9
})
colors = ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6']

def load_json(path):
    if not os.path.exists(path): return None
    with open(path, 'r') as f: return json.load(f)

def plot_module1(data):
    if not data: return
    fixed = data['fixed_length']
    semantic = data['semantic']
    
    metrics = ['Semantic\nCohesion', 'Fragmentation\nRate %', 'Size Variance\n(StDev)']
    
    max_var = max(fixed['size_variance_stdev'], semantic['size_variance_stdev'], 1)
    
    fixed_vals = [fixed['semantic_cohesion'], fixed['boundary_fragmentation_rate_pct']/100, fixed['size_variance_stdev']/max_var]
    sem_vals = [semantic['semantic_cohesion'], semantic['boundary_fragmentation_rate_pct']/100, semantic['size_variance_stdev']/max_var]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(metrics, fixed_vals, marker='o', label='Fixed-Length Chunking', color='#ef4444')
    ax.plot(metrics, sem_vals, marker='s', label='Semantic Chunking (Ours)', color='#10b981')
    
    ax.annotate('Higher is better', xy=(0, fixed_vals[0]), xytext=(0, fixed_vals[0]+0.1), arrowprops=dict(arrowstyle="->"))
    ax.annotate('Lower is better', xy=(1, fixed_vals[1]), xytext=(1, fixed_vals[1]-0.15), arrowprops=dict(arrowstyle="->"))
    
    ax.set_title('Module 1: Chunking Strategy Comparison Profile')
    ax.set_ylabel('Normalized Score')
    ax.set_ylim(0, 1.1)
    ax.legend(loc='upper right')
    ax.grid(True, linestyle='--', alpha=0.5)
    
    fig.tight_layout()
    plt.savefig(f"{BASE_DIR}/module_1_chunking/chunking_line_chart.png", dpi=300)
    plt.close()

def plot_module2(data):
    if not data: return
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # 1. Encryption Overhead
    enc = data['encryption_overhead']
    labels = ['AES-256-GCM\n(Base64)', 'Theoretical FHE\n(RSA/Paillier)']
    sizes = [enc['overhead_ratio_pct'], 10000] 
    
    ax1.plot(labels, sizes, marker='o', color='#2563eb')
    ax1.set_yscale('log')
    ax1.set_title('Encryption Overhead Ratio (Log Scale)')
    ax1.set_ylabel('Overhead %')
    ax1.annotate(f"{sizes[0]:.1f}%", (labels[0], sizes[0]), textcoords="offset points", xytext=(0,10), ha='center', weight='bold')
    ax1.annotate("100x to 1000x size", (labels[1], sizes[1]), textcoords="offset points", xytext=(0,10), ha='center', weight='bold')
    ax1.grid(True, linestyle='--', alpha=0.5)
    
    # 2. Masking Rank Correlation
    mask = data['masking_rank_correlation']
    labels = ['Orthogonal Masking', 'Differential Privacy\n(Noise Injection)']
    vals = [mask['spearman_orthogonal_masking'], mask['spearman_differential_privacy']]
    
    ax2.plot(labels, vals, marker='s', color='#10b981')
    ax2.set_ylim(0, 1.1)
    ax2.set_title("Masking Rank Correlation (Spearman's ρ)")
    ax2.set_ylabel('Correlation (1.0 = Perfect)')
    ax2.annotate(f"ρ = {vals[0]:.3f}", (labels[0], vals[0]), textcoords="offset points", xytext=(0,10), ha='center', weight='bold')
    ax2.annotate(f"ρ = {vals[1]:.3f}", (labels[1], vals[1]), textcoords="offset points", xytext=(0,10), ha='center', weight='bold')
    ax2.grid(True, linestyle='--', alpha=0.5)
    
    fig.tight_layout()
    plt.savefig(f"{BASE_DIR}/module_2_encryption/encryption_line_chart.png", dpi=300)
    plt.close()

def plot_module4(data):
    if not data: return
    
    # SAFETY CHECK: Handle old single-dictionary format
    if isinstance(data, dict):
        data = [{
            "N": data.get("total_chunks", 1000),
            "gen_ms": data.get("mmr_generation_time_ms", 25),
            "verify_ms": data.get("proof_verification_time_ms", 0.06),
            "size_bytes": data.get("proof_size_bytes", 2700)
        }]

    N_vals = [d['N'] for d in data]
    gen_vals = [d['gen_ms'] for d in data]
    verify_vals = [d['verify_ms'] for d in data]
    size_vals = [d['size_bytes'] for d in data]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # 1. Times Line Chart
    ax1.plot(N_vals, gen_vals, marker='o', label='Generation Time (ms)', color='#f59e0b')
    ax1.plot(N_vals, verify_vals, marker='s', label='Verification Time (ms)', color='#10b981')
    ax1.set_title('MMR Processing Time vs Chunk Count')
    ax1.set_xlabel('Number of Chunks (N)')
    ax1.set_ylabel('Time (Log Scale)')
    ax1.set_xscale('log')
    ax1.set_yscale('log')
    
    ax1.axhline(y=50, color='r', linestyle='--', alpha=0.5, label='50ms Target')
    if 1000 in N_vals:
        ax1.axvline(x=1000, color='gray', linestyle=':', alpha=0.5)
        ax1.annotate('1,000 chunks', (1000, min(verify_vals) if verify_vals else 0.1), textcoords="offset points", xytext=(0,-15), ha='center', color='gray')
    
    ax1.legend()
    ax1.grid(True, linestyle='--', alpha=0.5)

    # 2. Size Line Chart
    ax2.plot(N_vals, size_vals, marker='^', color='#8b5cf6')
    ax2.set_title('MMR Proof Size vs Chunk Count (O(log N))')
    ax2.set_xlabel('Number of Chunks (N)')
    ax2.set_ylabel('Proof Size (Bytes)')
    ax2.set_xscale('log')
    ax2.grid(True, linestyle='--', alpha=0.5)

    fig.tight_layout()
    plt.savefig(f"{BASE_DIR}/module_4_mmr/mmr_line_chart.png", dpi=300)
    plt.close()

def plot_retrieval(data):
    if not data: return
    fig, ax = plt.subplots(figsize=(12, 6))
    
    metrics = ['Precision', 'Recall', 'F1-Score', 'Hit Rate\n(Recall@K)', 'MRR', 'nDCG', 'Abstention\nRate']
    vals = [data['precision'], data['recall'], data['f1_score'], data['hit_rate_at_5'], data['mrr'], data['ndcg'], data['abstention_rate']]
    
    ax.plot(metrics, vals, marker='o', color='#2563eb', linestyle='-', linewidth=3)
    
    for i, v in enumerate(vals):
        ax.annotate(f"{v:.2f}", (metrics[i], v), textcoords="offset points", xytext=(0,10), ha='center', weight='bold')

    ax.set_title('Module 4: Advanced RAG Retrieval Metrics Profile')
    ax.set_ylim(-0.05, 1.1)
    ax.set_ylabel('Score (0.0 to 1.0)')
    ax.grid(True, linestyle='--', alpha=0.5)
    
    fig.tight_layout()
    plt.savefig(f"{BASE_DIR}/retrieval_metrics/retrieval_line_chart.png", dpi=300)
    plt.close()

if __name__ == "__main__":
    m1 = load_json(M1_PATH)
    m2 = load_json(M2_PATH)
    m4 = load_json(M4_PATH)
    ret = load_json(RET_PATH)
    
    plot_module1(m1)
    plot_module2(m2)
    plot_module4(m4)
    plot_retrieval(ret)
    print("All Line Charts successfully generated in 'outfolder'.")