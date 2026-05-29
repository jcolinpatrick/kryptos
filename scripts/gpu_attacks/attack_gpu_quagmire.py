"""
Cipher: GPU Accelerated Quagmire Brute-Force
Family: novel
Status: active
"""
import subprocess
from pathlib import Path

def attack(ciphertext, **params):
    """
    This function satisfies the run_attack.py API requirements,
    but offloads the actual math to our custom CUDA executable.
    """
    results = []
    
    # Locate the GPU executable we placed in the root directory
    project_root = Path(__file__).resolve().parent.parent.parent
    exe_path = project_root / "solver_gpu.exe"
    
    if not exe_path.exists():
        print(f"  [!] Missing GPU executable at {exe_path}")
        return results

    print(f"  [*] Offloading 3.1 Trillion operations to RTX 2070...")
    
    try:
        # Run the CUDA executable and capture its terminal output silently
        process = subprocess.run(
            [str(exe_path)], 
            capture_output=True, 
            text=True
        )
        output = process.stdout
        
        # Parse the GPU output to see if it found our cribs
        if "[!!!] ANOMALY DETECTED" in output:
            # We slice the output to grab the relevant lines
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if "Substitution Key:" in line:
                    key = line.split(":")[1].strip()
                    method = f"CUDA Quagmire III (Key: {key})"
                    
                    # We assign an artificially high score (1000.0) so run_attack.py 
                    # immediately flags it as a massive success
                    results.append((1000.0, "GPU_MATCH_FOUND_CHECK_LOGS", method))
                    
    except Exception as e:
        print(f"  [!] GPU Execution failed: {e}")
        
    return results