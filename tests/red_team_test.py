#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import signal
import subprocess
import sys
import time

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def print_result(name, passed, detail=""):
    status = "[PASS]" if passed else "[FAIL]"
    color = GREEN if passed else RED
    line = f"{color}{status}{RESET} {name}"
    if detail:
        line += f" - {detail}"
    print(line)


def _scan_proc_for_agent():
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", "ignore").replace("\x00", " ").strip()
        except Exception:
            continue
        if "kernel_eye.py" in cmdline or "kernel-eye" in cmdline:
            return pid
    return None


def _find_agent_pid_once():
    env_pid = os.environ.get("KERNEL_EYE_PID")
    if env_pid and env_pid.isdigit():
        return int(env_pid)

    for cmd in (
        ["pgrep", "-f", "kernel_eye.py"],
        ["pgrep", "-f", "python3 .*kernel_eye.py"],
        ["pidof", "kernel-eye"],
    ):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        except Exception:
            continue
        if result.returncode != 0:
            continue
        output = result.stdout.strip()
        if not output:
            continue
        for token in output.split():
            if token.isdigit():
                return int(token)

    return _scan_proc_for_agent()


def find_agent_pid(retries=10, delay_s=1):
    for _ in range(retries):
        pid = _find_agent_pid_once()
        if pid:
            return pid
        time.sleep(delay_s)
    return None


def test_shadow_cat():
    try:
        result = subprocess.run(["cat", "/etc/shadow"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
    except PermissionError:
        return True, "EPERM"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}: {e}"

    if result.returncode != 0:
        err = (result.stderr or "").lower()
        if "permission denied" in err or "operation not permitted" in err:
            return True, "permission denied"
        return True, f"blocked (rc={result.returncode})"

    return False, "read succeeded"


def test_antitamper(pid):
    if pid is None:
        return False, "agent PID not found"
    try:
        os.kill(pid, signal.SIGKILL)
        return False, "SIGKILL succeeded"
    except PermissionError:
        return True, "EPERM"
    except ProcessLookupError:
        return False, "agent PID not running"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}: {e}"


def test_volatile_execution():
    path = "/tmp/malware.sh"
    script = "#!/bin/sh\necho MALWARE\n"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(path, 0o755)

        try:
            proc = subprocess.run([path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            rc = proc.returncode
            if rc == 0:
                return False, "process exited normally"
            if rc < 0:
                return True, f"killed by signal {-rc}"
            if rc in (126, 127, 137):
                return True, f"blocked (rc={rc})"
            return False, f"unexpected return code {rc}"
        except PermissionError:
            return True, "EPERM on exec"
        except subprocess.TimeoutExpired:
            return False, "execution timed out"
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def main():
    failures = 0

    agent_pid = find_agent_pid()

    passed, detail = test_shadow_cat()
    print_result("Test 1: Critical File Access (cat /etc/shadow)", passed, detail)
    if not passed:
        failures += 1

    passed, detail = test_antitamper(agent_pid)
    print_result("Test 2: Anti-Tamper (SIGKILL Agent PID)", passed, detail)
    if not passed:
        failures += 1

    passed, detail = test_volatile_execution()
    print_result("Test 3: Volatile Execution (/tmp)", passed, detail)
    if not passed:
        failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
