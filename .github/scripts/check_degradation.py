#!/usr/bin/env python3
"""CI gate: macOS-only commands must degrade cleanly on Windows/Linux.

Each must exit 0 and say it requires macOS -- never traceback, never act.
On Linux, the commands with a native Linux implementation must instead RUN.
"""
import subprocess
import sys

# Linux has its own security / startup / uninstall / auto (see linux_security,
# linux_system, the sentinel timer): there they must RUN, not degrade.
LINUX_NATIVE = [
    ["security", "--json"],
    ["startup", "--list"],
    ["uninstall", "--list"],
    ["auto", "--status"],
    ["guard", "--status"],
]
MACOS_ONLY = [
    ["security", "--scan"],
    ["privacy", "--scan"],
    ["startup", "--list"],
    ["uninstall", "--list"],
    ["auto", "--status"],
    ["focus"],
    ["restore"],
    ["purge"],
]
if sys.platform.startswith("linux"):
    MACOS_ONLY = [c for c in MACOS_ONLY if c[0] not in {x[0] for x in LINUX_NATIVE}]

failures = []
for cmd in MACOS_ONLY:
    r = subprocess.run([sys.executable, "macmon.py", *cmd], capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    label = " ".join(cmd)
    if r.returncode != 0:
        failures.append(f"{label}: exit {r.returncode} -- {out[:160]}")
    elif "Traceback" in out:
        failures.append(f"{label}: traceback -- {out[:160]}")
    elif "requires macOS" not in out:
        failures.append(f"{label}: no 'requires macOS' notice -- {out[:160]}")
    else:
        print(f"OK  {label:22s} -> {out.splitlines()[0][:70]}")

if sys.platform.startswith("linux"):
    for cmd in LINUX_NATIVE:
        r = subprocess.run([sys.executable, "macmon.py", *cmd], capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        label = " ".join(cmd)
        if r.returncode != 0 or "Traceback" in out or "requires macOS" in out:
            failures.append(f"{label} (Linux-native): exit {r.returncode} -- {out[:160]}")
        else:
            print(f"OK  {label:22s} -> runs natively on Linux")

if failures:
    print("\nFAILURES:")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print("\nAll macOS-only commands degraded cleanly.")
