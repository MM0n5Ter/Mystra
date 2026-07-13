"""Phase 2: Binary Operation Taint Merge Tests"""
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
print("Phase 2: Binary Operation Taint Merge")
print("=" * 60)

import _taint

# --- String concat (tainted left) ---
print("\n[1] String concat (tainted left)")
def test_str_concat_left():
    t = _taint.set_taint("secret")
    r = t + " leaked"
    return _taint.get_taint(r)
test("tainted + clean → tainted", test_str_concat_left() > 0)

# --- String concat (tainted right) ---
print("\n[2] String concat (tainted right)")
def test_str_concat_right():
    t = _taint.set_taint("secret")
    r = "prefix-" + t
    return _taint.get_taint(r)
test("clean + tainted → tainted", test_str_concat_right() > 0)

# --- Both clean ---
print("\n[3] Both clean")
def test_clean():
    a = "hello"
    b = " world"
    c = a + b
    return _taint.get_taint(c)
test("clean + clean → clean", test_clean() == 0)

# --- Int arithmetic (values > 256 for singleton safety) ---
print("\n[4] Int arithmetic")
def test_int_add():
    ti = _taint.set_taint(1000)
    ri = ti + 1
    return _taint.get_taint(ri)
test("tainted_int + 1 → tainted", test_int_add() > 0)

def test_int_mul():
    ti = _taint.set_taint(500)
    ri = ti * 3
    return _taint.get_taint(ri)
test("tainted_int * 3 → tainted", test_int_mul() > 0)

def test_int_sub():
    ti = _taint.set_taint(1000)
    ri = ti - 1
    return _taint.get_taint(ri)
test("tainted_int - 1 → tainted", test_int_sub() > 0)

# --- Float arithmetic ---
print("\n[5] Float arithmetic")
def test_float_add():
    tf = _taint.set_taint(3.14)
    rf = tf + 1.0
    return _taint.get_taint(rf)
test("tainted_float + 1.0 → tainted", test_float_add() > 0)

def test_float_mul():
    tf = _taint.set_taint(2.718)
    rf = tf * 2.0
    return _taint.get_taint(rf)
test("tainted_float * 2.0 → tainted", test_float_mul() > 0)

# --- Both tainted merge ---
print("\n[6] Both tainted merge")
def test_both_tainted():
    a = _taint.set_taint("left")
    b = _taint.set_taint("right")
    merged = a + b
    tid = _taint.get_taint(merged)
    tid_a = _taint.get_taint(a)
    tid_b = _taint.get_taint(b)
    return tid > 0 and tid != tid_a and tid != tid_b
test("tainted + tainted → new merged taint", test_both_tainted())

# --- Inplace += ---
print("\n[7] Inplace +=")
def test_inplace():
    s = _taint.set_taint("start")
    s += "_end"
    return _taint.get_taint(s)
test("s += clean → tainted", test_inplace() > 0)

# --- Derived has different ID than source ---
print("\n[8] Derived taint ID differs from source")
def test_derived_id():
    src = _taint.set_taint("source")
    derived = src + "-derived"
    tid_src = _taint.get_taint(src)
    tid_der = _taint.get_taint(derived)
    return tid_der > 0 and tid_der != tid_src
test("derived has different ID than source", test_derived_id())

# --- Sequential: clean after tainted stays clean ---
print("\n[9] Sequential isolation")
def test_sequential():
    t = _taint.set_taint("tainted")
    _ = t + " something"
    clean = "aaa" + "bbb"
    return _taint.get_taint(clean)
test("clean op after tainted op → clean", test_sequential() == 0)

# --- Phase 0 + 1 regression ---
print("\n[10] Regression")
test("Phase 0: set/get works", _taint.get_taint(_taint.set_taint("reg")) > 0)
test("Phase 0: clean stays clean", _taint.get_taint("untainted") == 0)
test("Phase 0: singletons clean", _taint.get_taint(True) == 0 and _taint.get_taint(None) == 0)

def test_phase1_regression():
    x = _taint.set_taint("p1")
    y = x
    return _taint.get_taint(y) > 0
test("Phase 1: local propagation", test_phase1_regression())

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
