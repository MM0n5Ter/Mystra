"""Synthetic Taint Test D: Sink Detection"""
import _taint
import subprocess
import sys
import os

results = []
_cwd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check(name, condition):
    results.append((name, condition))
    print("  %s: %s" % ("PASS" if condition else "FAIL", name))

def capture(code):
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=10, cwd=_cwd
    )
    return r.stderr

print("--- D. Sink Detection ---")

# Tainted → sink should alert
stderr = capture("""
import _taint
t = _taint.set_taint("1+1", "user_query")
eval(t)
""")
check("eval(tainted) → CWE-94 alert", "[ALERT]" in stderr and "94" in stderr)

stderr = capture("""
import _taint
t = _taint.set_taint("x=1", "user_code")
exec(t)
""")
check("exec(tainted) → alert", "[ALERT]" in stderr)

stderr = capture("""
import _taint, os
t = _taint.set_taint("echo pwned", "user_cmd")
os.system(t)
""")
check("os.system(tainted) → CWE-78 alert", "[ALERT]" in stderr and "78" in stderr)

stderr = capture("""
import _taint
t = _taint.set_taint("/etc/shadow", "user_path")
try:
    open(t)
except:
    pass
""")
# Known XFAIL: open() detection may not work
has_alert = "[ALERT]" in stderr
check("open(tainted) → CWE-22 alert " + ("" if has_alert else "[XFAIL]"), has_alert)

# Clean → sink should NOT alert
stderr = capture("""
import _taint
eval("1+1")
""")
check("eval(clean) → no alert", "[ALERT]" not in stderr)

stderr = capture("""
import _taint, os
os.system("echo safe")
""")
check("os.system(clean) → no alert", "[ALERT]" not in stderr)

stderr = capture("""
import _taint
try:
    open("/dev/null")
except:
    pass
""")
check("open(clean) → no alert", "[ALERT]" not in stderr)

passed = sum(1 for _, c in results if c)
failed = sum(1 for _, c in results if not c)
print("  [D] %d passed, %d failed" % (passed, failed))
