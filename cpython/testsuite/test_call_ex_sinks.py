"""CALL_FUNCTION_EX: f(*args) sink detection via the TSL dispatcher.

Star-arg calls compile to CALL_FUNCTION_EX, which previously reached sink
detection only through a hardcoded adapter table. It now routes through the
same TSL SINK_CHECK path as a regular CALL, so tainted *args reach sinks and
clean *args do not over-taint.
"""
import sys
import subprocess
import os

passed = 0
failed = 0


def test(name, condition):
    global passed, failed
    if condition:
        print("  PASS: " + name)
        passed += 1
    else:
        print("  FAIL: " + name)
        failed += 1


_cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def capture(code):
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=10, cwd=_cwd)
    return r.stderr


print("=" * 60)
print("CALL_FUNCTION_EX sink detection via TSL")
print("=" * 60)

# [1] os.system(*args) — CWE-78 (command runs `true`, harmless)
s = capture("""
import os, _taint
a = (_taint.set_taint("true", "CMD"),)
try: os.system(*a)
except Exception: pass
""")
test("os.system(*tainted) -> [ALERT] CWE-78", "[ALERT]" in s and "78" in s)

# [2] exec(*args) — CWE-94
s = capture("""
import _taint
a = (_taint.set_taint("1 + 1", "CODE"),)
exec(*a)
""")
test("exec(*tainted) -> [ALERT] CWE-94", "[ALERT]" in s and "94" in s)

# [3] open(*args) — CWE-22 (path traversal), file created under a temp dir
s = capture("""
import tempfile, _taint
d = tempfile.mkdtemp()
a = (d + "/" + _taint.set_taint("../evil", "PATH"), "wb+")
try: open(*a).close()
except OSError: pass
""")
test("open(*tainted) -> [ALERT] CWE-22", "[ALERT]" in s and "22" in s)

# [N1] clean *args must NOT alert (no over-tainting through the EX path)
s = capture("""
import os
a = ("true",)
os.system(*a)
""")
test("os.system(*clean) -> no alert", "[ALERT]" not in s)

# [N2] a tainted value that is NOT the sink arg still resolves cleanly:
#      exec of a clean literal, taint present elsewhere in the tuple-free call
s = capture("""
import _taint
t = _taint.set_taint("x", "T")   # tainted, but not passed to a sink
exec(*("2 + 2",))
""")
test("exec(*clean) with unrelated taint -> no alert", "[ALERT]" not in s)

print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
