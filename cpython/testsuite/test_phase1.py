"""Phase 1: Shadow Frame — Local Variable Propagation Tests"""
import sys

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
print("Phase 1: Shadow Frame (Local Variables)")
print("=" * 60)

import _taint

# --- Basic local propagation ---
print("\n[1] Basic local propagation")
x = _taint.set_taint("secret")
y = x
test("y = x propagates taint", _taint.get_taint(y) > 0)

# --- Cross-function propagation ---
print("\n[2] Cross-function propagation")
def identity(arg):
    local = arg
    return local

result = identity(_taint.set_taint("cross_func"))
test("identity(tainted) propagates", _taint.get_taint(result) > 0)

# --- Clean isolation ---
print("\n[3] Clean isolation")
def test_isolation():
    tainted = _taint.set_taint("tainted_value")
    clean = "clean_value_unique_12345"
    _ = tainted
    result = clean
    return _taint.get_taint(result)

test("clean local not contaminated by tainted sibling", test_isolation() == 0)

# --- Multiple tainted locals ---
print("\n[4] Multiple tainted locals")
def test_multi_locals():
    a = _taint.set_taint("aaa")
    b = _taint.set_taint("bbb")
    tid_a = _taint.get_taint(a)
    tid_b = _taint.get_taint(b)
    return tid_a > 0 and tid_b > 0 and tid_a != tid_b

test("two tainted locals have distinct IDs", test_multi_locals())

# --- Nested function chain ---
print("\n[5] Nested function chain")
def id1(x): return x
def id2(x): return id1(x)
def id3(x): return id2(x)

nested_result = id3(_taint.set_taint("nested"))
test("3-deep identity chain preserves taint", _taint.get_taint(nested_result) > 0)

# --- RETURN_CONST ---
print("\n[6] RETURN_CONST (return literal)")
def return_literal():
    return "literal_string"

lit = return_literal()
test("return literal is clean", _taint.get_taint(lit) == 0)

# --- DELETE_FAST ---
print("\n[7] DELETE_FAST clears shadow slot")
def test_delete_fast():
    x = _taint.set_taint("to_delete")
    tid_before = _taint.get_taint(x)
    del x
    y = "replacement_unique_98765"
    return tid_before > 0 and _taint.get_taint(y) == 0

test("del x clears slot; new var is clean", test_delete_fast())

# --- Function with multiple args ---
print("\n[8] Multiple arguments")
def multi_args(a, b, c):
    return b

t = _taint.set_taint("mid_arg")
r = multi_args("clean1", t, "clean2")
test("tainted middle arg propagates via return", _taint.get_taint(r) > 0)

# --- Clean function return after tainted one ---
print("\n[9] Clean return after tainted return")
def tainted_func():
    return _taint.set_taint("from_func")

def clean_func():
    return "completely_clean_unique_45678"

_ = tainted_func()
c = clean_func()
test("clean function after tainted returns clean", _taint.get_taint(c) == 0)

# --- Phase 0 regression ---
print("\n[10] Phase 0 regression")
test("set_taint/get_taint still works", _taint.get_taint(_taint.set_taint("reg")) > 0)
test("clean still clean", _taint.get_taint("untainted") == 0)
test("singleton integrity", _taint.get_taint(True) == 0 and _taint.get_taint(None) == 0)

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
