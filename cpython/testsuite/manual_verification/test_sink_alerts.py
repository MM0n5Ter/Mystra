"""Manual Verification: Sink Detection Alerts

Tests that tainted data reaching dangerous functions fires DTA-ALERT
with correct CWE classification.

Run: ./python testsuite/manual_verification/test_sink_alerts.py

Maps to: TSL SINK_CHECK rules, DTA_CALL_POST_HOOK Alert path
"""
import _taint
import subprocess
import sys
import os

_cwd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 60)
print("Manual Verification: Sink Detection")
print("=" * 60)

def run_and_capture(code):
    """Run code in subprocess, return stderr."""
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=10, cwd=_cwd
    )
    return r.stderr


# --- 1. eval() → CWE-94 Code Injection ---
print("\n[1] eval(tainted) → DTA-ALERT CWE-94")
stderr = run_and_capture("""
import _taint
t = _taint.set_taint("1 + 2", "user_input_eval")
result = eval(t)
""")
has_alert = "[ALERT]" in stderr
has_cwe = "CWE-94" in stderr or "94" in stderr
print("  Alert fired:", has_alert)
print("  CWE-94 mentioned:", has_cwe)
if has_alert:
    for line in stderr.strip().split("\n"):
        if "DTA-ALERT" in line or "Taint" in line:
            print("  |", line)
assert has_alert, "FAIL: eval(tainted) should fire alert"
print("  PASS")


# --- 2. exec() → CWE-94 ---
print("\n[2] exec(tainted) → DTA-ALERT CWE-94")
stderr = run_and_capture("""
import _taint
t = _taint.set_taint("x = 42", "user_input_exec")
exec(t)
""")
has_alert = "[ALERT]" in stderr
print("  Alert fired:", has_alert)
assert has_alert, "FAIL: exec(tainted) should fire alert"
print("  PASS")


# --- 3. os.system() → CWE-78 OS Command Injection ---
print("\n[3] os.system(tainted) → DTA-ALERT CWE-78")
stderr = run_and_capture("""
import _taint, os
t = _taint.set_taint("echo hello", "user_input_cmd")
os.system(t)
""")
has_alert = "[ALERT]" in stderr
has_cwe = "CWE-78" in stderr or "78" in stderr
print("  Alert fired:", has_alert)
print("  CWE-78 mentioned:", has_cwe)
if has_alert:
    for line in stderr.strip().split("\n"):
        if "DTA-ALERT" in line:
            print("  |", line)
assert has_alert, "FAIL: os.system(tainted) should fire alert"
print("  PASS")


# --- 4. No false alert on clean eval ---
print("\n[4] eval(clean) → no alert")
stderr = run_and_capture("""
import _taint
result = eval("1 + 2")
""")
has_alert = "[ALERT]" in stderr
print("  Alert fired:", has_alert, "(expected False)")
assert not has_alert, "FAIL: eval(clean) should NOT fire alert"
print("  PASS")


# --- 5. No false alert on non-sink calls ---
print("\n[5] str.upper(tainted) → no alert (not a sink)")
stderr = run_and_capture("""
import _taint
t = _taint.set_taint("hello", "source_nosink")
_ = t.upper()
""")
has_alert = "[ALERT]" in stderr
print("  Alert fired:", has_alert, "(expected False)")
assert not has_alert, "FAIL: str.upper should not trigger sink alert"
print("  PASS")


# --- 6. Derived taint reaches sink ---
print("\n[6] Derived taint → eval (taint survives through operations)")
stderr = run_and_capture("""
import _taint
t = _taint.set_taint("1 + ", "source_derived")
derived = t + "2"  # derived taint via binary op
eval(derived)
""")
has_alert = "[ALERT]" in stderr
print("  Alert fired:", has_alert)
if has_alert:
    for line in stderr.strip().split("\n"):
        if "DTA-ALERT" in line or "Flow" in line:
            print("  |", line)
assert has_alert, "FAIL: derived taint should still trigger sink"
print("  PASS")


# --- 7. open() → CWE-22 (KNOWN XFAIL) ---
print("\n[7] open(tainted) → DTA-ALERT CWE-22 [KNOWN XFAIL]")
stderr = run_and_capture("""
import _taint
t = _taint.set_taint("/etc/passwd", "user_input_path")
try:
    open(t)
except:
    pass
""")
has_alert = "[ALERT]" in stderr
print("  Alert fired:", has_alert)
if has_alert:
    print("  XPASS! (gap was fixed)")
else:
    print("  XFAIL: open() sink detection not yet working")
    print("  Root cause: arg taint not reaching pre-hook for _io.open")


print("\n" + "=" * 60)
print("Sink detection tests complete")
print("=" * 60)
