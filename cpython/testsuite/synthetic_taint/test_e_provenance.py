"""Synthetic Taint Test E: End-to-End Provenance"""
import _taint
import subprocess
import sys
import os

results = []
_cwd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check(name, condition):
    results.append((name, condition))
    print("  %s: %s" % ("PASS" if condition else "FAIL", name))

print("--- E. End-to-End Provenance ---")
print()
print("  Scenario: HTTP parameter → function → transform → container → sink")
print()

def t_e2e():
    # 1. Source: simulate HTTP input
    user_input = _taint.set_taint("'; DROP TABLE users; --", "HTTP_GET_q")
    assert _taint.get_taint(user_input) > 0, "source failed"

    # 2. Function: pass through sanitization attempt (no-op)
    def sanitize(s):
        return s.strip()
    sanitized = sanitize(user_input)
    assert _taint.get_taint(sanitized) > 0, "function propagation failed"

    # 3. Transform: build query
    query = "SELECT * FROM users WHERE name = '" + sanitized + "'"
    assert _taint.get_taint(query) > 0, "concat propagation failed"

    # 4. Container: store in request context
    class Request:
        pass
    req = Request()
    req.query = query
    assert _taint.get_taint(req.query) > 0, "attribute propagation failed"

    # 5. Provenance: print flow tree for the final value
    print("  Flow tree for req.query:")
    _taint.print_flow_tree(req.query)

    # Verify source label appears in provenance
    # (We can't capture stderr from print_flow_tree in-process,
    #  but we verify the taint chain is intact)
    tid_source = _taint.get_taint(user_input)
    tid_final = _taint.get_taint(req.query)
    print("  Source taint_id: %d" % tid_source)
    print("  Final taint_id:  %d" % tid_final)
    print("  (Final > Source confirms derivation chain)")
    assert tid_final > tid_source, "derivation chain broken"

    return True

check("e2e: source → function → transform → container", t_e2e())

# 6. Verify sink detection with the derived value
print()
print("  Now passing derived taint to eval() sink:")
stderr_capture = subprocess.run(
    [sys.executable, "-c", """
import _taint

user_input = _taint.set_taint("1+1", "HTTP_GET_calc")

def sanitize(s):
    return s.strip()

sanitized = sanitize(user_input)
query = sanitized + " + 0"

class Ctx:
    pass
ctx = Ctx()
ctx.expr = query

eval(ctx.expr)
"""],
    capture_output=True, text=True, timeout=10, cwd=_cwd
).stderr

has_alert = "[ALERT]" in stderr_capture
check("e2e sink: derived taint reaches eval()", has_alert)
if has_alert:
    for line in stderr_capture.strip().split("\n"):
        if "DTA-ALERT" in line or "Flow" in line or "ID:" in line:
            print("    |", line)

passed = sum(1 for _, c in results if c)
failed = sum(1 for _, c in results if not c)
print()
print("  [E] %d passed, %d failed" % (passed, failed))
