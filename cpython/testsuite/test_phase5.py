"""Phase 5: TSL Rules + Sink Detection (PAPER MILESTONE)"""
import sys
import subprocess

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


import os
_cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def capture(code):
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=10, cwd=_cwd)
    return r.stderr


print("=" * 60)
print("Phase 5: TSL Rules + Sink Detection (Paper Milestone)")
print("=" * 60)

import _taint

# === TSL PROPAGATE rules ===
print("\n[1] TSL Propagate rules")
def t_upper():
    return _taint.get_taint(_taint.set_taint("x").upper()) > 0
test("str.upper → Propagate", t_upper())

def t_lower():
    return _taint.get_taint(_taint.set_taint("X").lower()) > 0
test("str.lower → Propagate", t_lower())

def t_replace():
    return _taint.get_taint(_taint.set_taint("x").replace("x", "y")) > 0
test("str.replace → Propagate", t_replace())

def t_strip():
    return _taint.get_taint(_taint.set_taint("  x  ").strip()) > 0
test("str.strip → Propagate", t_strip())

def t_encode():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t.encode()) > 0
test("str.encode → Propagate", t_encode())

def t_split():
    return _taint.get_taint(_taint.set_taint("a,b").split(",")) > 0
test("str.split → Propagate", t_split())

def t_join():
    sep = _taint.set_taint(",")
    return _taint.get_taint(sep.join(["a", "b"])) > 0
test("sep.join → Propagate", t_join())

# === TSL CLEAR rules ===
print("\n[2] TSL Clear rules")
def t_len():
    return _taint.get_taint(len(_taint.set_taint("hello"))) == 0
test("len → Clear", t_len())

def t_type():
    return _taint.get_taint(type(_taint.set_taint("hello"))) == 0
test("type → Clear", t_type())

def t_isinstance():
    return _taint.get_taint(isinstance(_taint.set_taint("x"), str)) == 0
test("isinstance → Clear", t_isinstance())

def t_find():
    return _taint.get_taint(_taint.set_taint("hello").find("l")) == 0
test("str.find → Clear", t_find())

def t_startswith():
    return _taint.get_taint(_taint.set_taint("hello").startswith("h")) == 0
test("str.startswith → Clear", t_startswith())

# === TSL SINK_CHECK rules ===
print("\n[3] Sink detection (CWE alerts)")

stderr_eval = capture("""
import _taint
t = _taint.set_taint("1 + 2")
try:
    eval(t)
except:
    pass
""")
test("eval(tainted) → DTA-ALERT", "[ALERT]" in stderr_eval)
test("eval alert → CWE-94", "CWE-94" in stderr_eval or "94" in stderr_eval)

stderr_exec = capture("""
import _taint
t = _taint.set_taint("x = 1")
try:
    exec(t)
except:
    pass
""")
test("exec(tainted) → DTA-ALERT", "[ALERT]" in stderr_exec)

stderr_system = capture("""
import _taint, os
t = _taint.set_taint("echo hi")
try:
    os.system(t)
except:
    pass
""")
test("os.system(tainted) → DTA-ALERT", "[ALERT]" in stderr_system)
test("os.system alert → CWE-78", "CWE-78" in stderr_system or "78" in stderr_system)

stderr_compile = capture("""
import _taint
t = _taint.set_taint("x = 1")
try:
    compile(t, "<string>", "exec")
except:
    pass
""")
test("compile(tainted) → DTA-ALERT", "[ALERT]" in stderr_compile)

# === No false alerts ===
print("\n[4] No false alerts")
stderr_clean_eval = capture("import _taint; eval('1 + 2')")
test("eval(clean) → no alert", "[ALERT]" not in stderr_clean_eval)

stderr_clean_upper = capture("""
import _taint
t = _taint.set_taint("hello")
_ = t.upper()
""")
test("str.upper → no alert", "[ALERT]" not in stderr_clean_upper)

# === Derived taint reaches sink ===
print("\n[5] Derived taint reaches sink")
stderr_derived = capture("""
import _taint
t = _taint.set_taint("1 + ")
derived = t + "2"
try:
    eval(derived)
except:
    pass
""")
test("eval(derived_taint) → DTA-ALERT", "[ALERT]" in stderr_derived)

# === Singleton integrity ===
print("\n[6] Singleton integrity")
def t_singletons():
    _taint.set_taint("trigger")
    return (_taint.get_taint(True) == 0 and
            _taint.get_taint(False) == 0 and
            _taint.get_taint(None) == 0 and
            _taint.get_taint(0) == 0 and
            _taint.get_taint(1) == 0)
test("singletons clean", t_singletons())

# === Regression ===
print("\n[7] Regression")
def t_p1():
    x = _taint.set_taint("p1"); return _taint.get_taint(x) > 0
test("Phase 1: locals", t_p1())

def t_p2():
    return _taint.get_taint(_taint.set_taint("a") + "b") > 0
test("Phase 2: binop", t_p2())

def t_p3():
    return _taint.get_taint(_taint.set_taint("x").upper()) > 0
test("Phase 3: call", t_p3())

def t_p4():
    class O: pass
    o = O(); o.x = _taint.set_taint("a"); return _taint.get_taint(o.x) > 0
test("Phase 4: attr", t_p4())

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
