#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ctypes
import os
import signal
import subprocess
import sys

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


def set_process_name(name):
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        PR_SET_NAME = 15
        res = prctl(PR_SET_NAME, ctypes.c_char_p(name.encode("utf-8")), 0, 0, 0)
        if res != 0:
            err = ctypes.get_errno()
            return False, os.strerror(err)
        return True, ""
    except Exception as e:
        return False, str(e)


def find_agent_pid():
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", "ignore").replace("\x00", " ").strip()
        except Exception:
            continue
        if "kernel-eye" in cmdline or "kernel_eye.py" in cmdline:
            return pid
    return None


def test_critical_file_access():
    try:
        with open("/etc/shadow", "rb") as f:
            f.read(1)
        return False, "read succeeded"
    except PermissionError:
        return True, "EPERM"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}: {e}"


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
    parser = argparse.ArgumentParser(description="Kernel-Eye red team regression tests")
    parser.add_argument("--pid", type=int, help="Kernel-Eye agent PID (optional)")
    args = parser.parse_args()

    # Avoid whitelist bypass by renaming current task comm
    ok, err = set_process_name("red_team")
    if not ok:
        print(f"{RED}[WARN]{RESET} Could not set process name: {err}")

    agent_pid = args.pid or int(os.environ.get("KERNEL_EYE_PID", "0") or 0) or find_agent_pid()

    passed, detail = test_critical_file_access()
    print_result("Test 1: Critical File Access (/etc/shadow)", passed, detail)

    passed, detail = test_antitamper(agent_pid)
    print_result("Test 2: Anti-Tamper (SIGKILL Agent PID)", passed, detail)

    passed, detail = test_volatile_execution()
    print_result("Test 3: Volatile Execution (/tmp)", passed, detail)


if __name__ == "__main__":
    sys.exit(main())
