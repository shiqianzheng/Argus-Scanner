import os
import subprocess
import time
import json
import argparse
import sys

# Windows path handling
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_PY = os.path.join(BASE_DIR, "main.py")
PERF_EVAL = os.path.join(BASE_DIR, "tests", "performance", "performance_evaluator.py")
GT_PATH = os.path.join(BASE_DIR, "tests", "performance", "ground_truth.json")

def run_command(cmd_args):
    """Executes a command and returns output, execution time, and exit code."""
    start_time = time.time()
    try:
        # Use full path for python to avoid path issues if needed, but 'python' usually works
        result = subprocess.run(cmd_args, capture_output=True, text=True, cwd=BASE_DIR)
        duration = time.time() - start_time
        return result, duration
    except Exception as e:
        print(f"Error executing command {cmd_args}: {e}")
        return None, 0

def get_latest_report(directory, extension=".json"):
    """Finds the most recently created file with the given extension in the directory."""
    if not os.path.exists(directory):
        return None
    files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith(extension)]
    if not files:
        return None
    return max(files, key=os.path.getctime)

def scenario_1_baseline_recall():
    print("\n[Scenario 1] Running Baseline Recall Test...")
    output_dir = os.path.join(BASE_DIR, "tests", "performance", "reports_v1")
    if os.path.exists(output_dir):
        # Optional: Clean up old reports to ensure we get the new one
        for f in os.listdir(output_dir):
            try: os.remove(os.path.join(output_dir, f))
            except: pass
            
    cmd = ["python", MAIN_PY, "./test_cases", "-f", "json", "-o", output_dir]
    
    res, duration = run_command(cmd)
    
    output_file = get_latest_report(output_dir, ".json")
    
    if res and res.returncode == 0 and output_file:
        print(f"Scan completed in {duration:.2f}s. Report: {output_file}")
        print("Running evaluator...")
        eval_cmd = ["python", PERF_EVAL, "--report", output_file, "--gt", GT_PATH]
        eval_res, _ = run_command(eval_cmd)
        print(eval_res.stdout)
        if eval_res.stderr:
            print("Evaluator Errors:", eval_res.stderr)
    else:
        print("Scan failed or report not generated!")
        if res: print(res.stderr)

def scenario_2_benchmark():
    print("\n[Scenario 2] Running Benchmark & Stress Test (Ruoyi-master)...")
    target_dir = os.path.join(BASE_DIR, "Ruoyi-master")
    if not os.path.exists(target_dir):
        print(f"Target directory {target_dir} not found. Skipping.")
        return

    output_dir = os.path.join(BASE_DIR, "tests", "performance", "reports_v2")
    cmd = ["python", MAIN_PY, "./Ruoyi-master", "-f", "html", "-o", output_dir]
    
    print("Starting scan (this may take a while)...")

    res, duration = run_command(cmd)
    
    if res and res.returncode == 0:
        print(f"Scan completed successfully in {duration:.2f}s.")
        # Determine strictness via file existence, simple check for now
        if duration > 300: # Example threshold
             print("WARNING: Scan time exceeded 5 minutes.")
    else:
        print("Scan failed!")
        if res: print(res.stderr)

def scenario_3_fp_check():
    print("\n[Scenario 3] Running False Positive Check (utils/)...")
    target_dir = os.path.join(BASE_DIR, "utils")
    output_dir = os.path.join(BASE_DIR, "tests", "performance", "reports_v3")
    cmd = ["python", MAIN_PY, "./utils", "-f", "json", "-o", output_dir]
    
    if os.path.exists(output_dir):
        for f in os.listdir(output_dir):
            try: os.remove(os.path.join(output_dir, f))
            except: pass

    res, duration = run_command(cmd)
    
    output_file = get_latest_report(output_dir, ".json")
    
    if res and res.returncode == 0 and output_file:
        print(f"Scan completed in {duration:.2f}s.")
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                findings = data.get('findings', [])
                if len(findings) == 0:
                    print("[SUCCESS] 0 False Positives detected.")
                else:
                    print(f"[WARNING] {len(findings)} findings detected in clean set:")
                    for find in findings:
                        print(f" - {find.get('title')} in {find.get('file')}")
        except Exception as e:
            print(f"Error reading report: {e}")
    else:
        print("Scan failed!")
        if res: print(res.stderr)

if __name__ == "__main__":
    print("Starting Performance Test Suite...")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    scenario_1_baseline_recall()
    scenario_2_benchmark()
    scenario_3_fp_check()
    
    print("\nTest Suite Completed.")
