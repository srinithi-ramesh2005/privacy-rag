import subprocess
import sys
import os

def run_script(script_name):
    print(f"\n{'='*50}\nRunning {script_name}...\n{'='*50}")
    result = subprocess.run([sys.executable, script_name], capture_output=False)
    if result.returncode != 0:
        print(f"[ERROR] {script_name} failed.")
        return False
    return True

if __name__ == "__main__":
    scripts = [
        "eval_module1_chunking.py",
        "eval_module2_encryption.py",
        "eval_module4_mmr.py",
        "eval_retrieval_metrics.py"
    ]
    for s in scripts:
        run_script(s)
    print("\nAll evaluations completed. Check the 'outfolder/' directory for results.")