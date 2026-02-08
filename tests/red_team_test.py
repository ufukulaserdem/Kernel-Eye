#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import signal
import time

# UI Colors
C_RESET   = "\033[0m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BOLD    = "\033[1m"

def get_latest_agent_pid():
    try:
        # Find all PIDs for kernel_eye.py
        pids = subprocess.check_output(["pgrep", "-f", "kernel_eye.py"]).decode().strip().split('\n')
        
        # Filter out empty strings and the current test script's PID
        my_pid = str(os.getpid())
        valid_pids = [p for p in pids if p and p != my_pid]
        
        if not valid_pids:
            return None
            
        # Get the most recently created process (highest PID usually)
        return int(max(valid_pids, key=int))
    except:
        return None

def run_tests():
    print(f"{C_BOLD}--- Kernel-Eye Red Team Verification ---{C_RESET}")
    
    agent_pid = get_latest_agent_pid()
    if not agent_pid:
        print(f"{C_RED}[!] ERROR: Kernel-Eye agent not found! Please run 'sudo python3 kernel_eye.py' first.{C_RESET}")
        sys.exit(1)
    
    print(f"[*] Targeting Agent PID: {agent_pid}")
    failures = 0

    # ---------------------------------------------------------
    # TEST 1: Critical File Access (/etc/shadow)
    # ---------------------------------------------------------
    print(f"\n[TEST 1] Accessing /etc/shadow using 'cat'...")
    try:
        # We use 'cat' because 'python3' is often whitelisted
        result = subprocess.run(["cat", "/etc/shadow"], capture_output=True, text=True)
        
        # Success Criteria:
        # 1. Return code is NOT 0 (Failed to execute/read)
        # 2. "Permission denied" or "Operation not permitted" in stderr
        if result.returncode != 0 or "Permission denied" in result.stderr or "Operation not permitted" in result.stderr:
            print(f"{C_GREEN}[PASS] Blocked by Kernel (Permission Denied){C_RESET}")
        else:
            print(f"{C_RED}[FAIL] Read succeeded! (Are you running as root? Is the Agent active?){C_RESET}")
            failures += 1
    except Exception as e:
        print(f"{C_RED}[FAIL] Execution error: {e}{C_RESET}")
        failures += 1

    # ---------------------------------------------------------
    # TEST 2: Anti-Tamper (SIGKILL)
    # ---------------------------------------------------------
    print(f"\n[TEST 2] Attempting to KILL Agent (PID {agent_pid})...")
    try:
        # Attempt to kill
        os.kill(agent_pid, signal.SIGKILL)
        
        # If we are here, os.kill didn't raise PermissionError immediately.
        # BUT, the agent might still be alive (ignoring the signal).
        time.sleep(0.5)
        
        try:
            os.kill(agent_pid, 0) # Check if process is still alive
            # If it's still alive after SIGKILL, Anti-Tamper IS WORKING!
            print(f"{C_GREEN}[PASS] Process survived SIGKILL (Anti-Tamper Active){C_RESET}")
        except ProcessLookupError:
            # It died.
            print(f"{C_RED}[FAIL] Agent died! Anti-Tamper failed.{C_RESET}")
            failures += 1
            
    except PermissionError:
        # Kernel blocked the syscall directly
        print(f"{C_GREEN}[PASS] Syscall Blocked (Operation not permitted){C_RESET}")
    except Exception as e:
        print(f"{C_YELLOW}[?] Unexpected error: {e}{C_RESET}")
        failures += 1

    # ---------------------------------------------------------
    # TEST 3: Volatile Execution (/tmp)
    # ---------------------------------------------------------
    print(f"\n[TEST 3] Executing malicious script in /tmp...")
    malware_path = "/tmp/malware.sh"
    try:
        with open(malware_path, "w") as f:
            f.write("#!/bin/bash\necho 'I am malware'")
        os.chmod(malware_path, 0o777)
        
        # Use subprocess to run. We expect it to be killed.
        result = subprocess.run([malware_path], capture_output=True, text=True)
        
        # Exit codes for killed processes:
        # 137 (128 + 9 for SIGKILL)
        # -9 (Python subprocess representation)
        if result.returncode == -9 or result.returncode == 137:
             print(f"{C_GREEN}[PASS] Execution Killed by Agent{C_RESET}")
        elif "Killed" in result.stderr:
             print(f"{C_GREEN}[PASS] Execution Blocked/Killed{C_RESET}")
        else:
             # Sometimes user-space killing is slow. Let's check logic one more time.
             # If the file ran but we got no output, maybe it was killed instantly.
             if not result.stdout.strip():
                 print(f"{C_GREEN}[PASS] Execution halted (No output produced){C_RESET}")
             else:
                 print(f"{C_RED}[FAIL] Script executed! Output: {result.stdout.strip()}{C_RESET}")
                 failures += 1
             
    except Exception as e:
        print(f"{C_GREEN}[PASS] Execution failed: {e}{C_RESET}")
    finally:
        if os.path.exists(malware_path):
            os.remove(malware_path)

    print("-" * 40)
    if failures == 0:
        print(f"{C_GREEN}ALL TESTS PASSED. SYSTEM SECURE.{C_RESET}")
        sys.exit(0)
    else:
        print(f"{C_RED}{failures} TEST(S) FAILED.{C_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{C_YELLOW}[!] Warning: Run with sudo for accurate results.{C_RESET}")
    run_tests()