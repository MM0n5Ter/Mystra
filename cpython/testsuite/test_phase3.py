"""Phase 3: Call Dispatch — Taint Propagation Through Function Calls"""
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


print("=" * 60)
print("Phase 3: Call Dispatch")
print("=" * 60)

import _taint

# --- str method propagation ---
print("\n[1] String method propagation")
def test_upper():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t.upper())
test("str.upper() propagates", test_upper() > 0)

def test_lower():
    t = _taint.set_taint("HELLO")
    return _taint.get_taint(t.lower())
test("str.lower() propagates", test_lower() > 0)

def test_replace():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t.replace("h", "j"))
test("str.replace() propagates", test_replace() > 0)

def test_strip():
    t = _taint.set_taint("  hello  ")
    return _taint.get_taint(t.strip())
test("str.strip() propagates", test_strip() > 0)

def test_encode():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t.encode("utf-8"))
test("str.encode() propagates", test_encode() > 0)

# --- Clear rules (meta-operations) ---
print("\n[2] Clear rules (meta-ops must NOT propagate)")
def test_len_clear():
    t = _taint.set_taint("hello")
    return _taint.get_taint(len(t))
test("len(tainted) is clean", test_len_clear() == 0)

def test_type_clear():
    t = _taint.set_taint("hello")
    return _taint.get_taint(type(t))
test("type(tainted) is clean", test_type_clear() == 0)

def test_isinstance_clear():
    t = _taint.set_taint("hello")
    return _taint.get_taint(isinstance(t, str))
test("isinstance(tainted, str) is clean", test_isinstance_clear() == 0)

def test_bool_clear():
    t = _taint.set_taint("hello")
    return _taint.get_taint(bool(t))
test("bool(tainted) is clean", test_bool_clear() == 0)

# --- Python function propagation (transparent via shadow frame) ---
print("\n[3] Python function propagation")
def test_py_func():
    def identity(x): return x
    t = _taint.set_taint("through_func")
    return _taint.get_taint(identity(t))
test("Python identity(tainted) propagates", test_py_func() > 0)

def test_py_transform():
    def transform(x): return x + "!"
    t = _taint.set_taint("base")
    return _taint.get_taint(transform(t))
test("Python transform(tainted) + '!' propagates", test_py_transform() > 0)

# --- str() / tuple() type conversion ---
print("\n[4] Type conversion")
def test_str_conversion():
    t = _taint.set_taint(12345)
    return _taint.get_taint(str(t))
test("str(tainted_int) propagates", test_str_conversion() > 0)

# --- Clean isolation ---
print("\n[5] Clean isolation")
def test_clean_call():
    clean = "completely_clean_string_xyz"
    r = clean.upper()
    return _taint.get_taint(r)
test("clean.upper() stays clean", test_clean_call() == 0)

def test_clean_after_tainted():
    t = _taint.set_taint("tainted")
    _ = t.upper()
    clean = "clean_after_tainted_unique"
    return _taint.get_taint(clean.lower())
test("clean call after tainted call stays clean", test_clean_after_tainted() == 0)

# --- Singleton integrity ---
print("\n[6] Singleton integrity")
def test_singletons():
    _taint.set_taint("trigger")
    return (_taint.get_taint(True) == 0 and
            _taint.get_taint(False) == 0 and
            _taint.get_taint(None) == 0 and
            _taint.get_taint(0) == 0 and
            _taint.get_taint(1) == 0 and
            _taint.get_taint("") == 0)
test("singletons all clean", test_singletons())

# --- Sink detection (subprocess capture) ---
print("\n[7] Sink detection")
def capture_alert(code):
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=10
    )
    return result.stderr

stderr_eval = capture_alert("""
import _taint
t = _taint.set_taint("1 + 2")
try:
    eval(t)
except:
    pass
""")
test("eval(tainted) fires DTA-ALERT", "[ALERT]" in stderr_eval)
test("eval alert contains CWE-94", "CWE-94" in stderr_eval)

stderr_clean = capture_alert("""
import _taint
eval("1 + 2")
""")
test("eval(clean) does NOT fire alert", "[ALERT]" not in stderr_clean)

stderr_system = capture_alert("""
import _taint, os
t = _taint.set_taint("echo hi")
try:
    os.system(t)
except:
    pass
""")
test("os.system(tainted) fires DTA-ALERT", "[ALERT]" in stderr_system)
test("os.system alert contains CWE-78", "CWE-78" in stderr_system)

# --- Regression ---
print("\n[8] Regression")
test("Phase 0: set/get works", _taint.get_taint(_taint.set_taint("reg")) > 0)
test("Phase 0: clean stays clean", _taint.get_taint("untainted") == 0)

def test_phase1_reg():
    x = _taint.set_taint("p1")
    y = x
    return _taint.get_taint(y) > 0
test("Phase 1: local propagation", test_phase1_reg())

def test_phase2_reg():
    t = _taint.set_taint("a")
    r = t + "b"
    return _taint.get_taint(r) > 0
test("Phase 2: binary op merge", test_phase2_reg())

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
