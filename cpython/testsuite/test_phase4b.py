"""Phase 4b: Shadow Heap — Globals, Closures, Unpack, Container Build Tests"""
import sys
import gc

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
print("Phase 4b: Shadow Heap (Globals, Closures, Unpack, Build)")
print("=" * 60)

import _taint

# --- Global variable ---
print("\n[1] Global variable propagation")
g_tainted = None

def test_global_write():
    global g_tainted
    g_tainted = _taint.set_taint("global_secret")

def test_global_read():
    return _taint.get_taint(g_tainted)

test_global_write()
test("global var tainted after write", test_global_read() > 0)

g_clean = "global_clean"
test("clean global stays clean", _taint.get_taint(g_clean) == 0)

# --- Closure ---
print("\n[2] Closure propagation")
def test_closure():
    x = _taint.set_taint("closure_val")
    def inner():
        return x
    return _taint.get_taint(inner())
test("closure captures tainted var", test_closure() > 0)

def test_closure_clean():
    x = "clean_closure"
    def inner():
        return x
    return _taint.get_taint(inner())
test("clean closure stays clean", test_closure_clean() == 0)

# --- Unpack ---
print("\n[3] Unpack propagation")
def test_unpack_list():
    a, b = [_taint.set_taint("unpacked"), "clean"]
    return _taint.get_taint(a)
test("a, b = [tainted, clean] → a tainted", test_unpack_list() > 0)

def test_unpack_tuple():
    a, b, c = (_taint.set_taint("t1"), "c1", "c2")
    return _taint.get_taint(a)
test("a, b, c = (tainted, clean, clean) → a tainted", test_unpack_tuple() > 0)

def test_unpack_clean():
    a, b = ["clean1", "clean2"]
    return _taint.get_taint(a) == 0 and _taint.get_taint(b) == 0
test("unpack all clean stays clean", test_unpack_clean())

# --- Build list/tuple ---
print("\n[4] Container build")
def test_build_list():
    t = _taint.set_taint("in_list")
    lst = [t, "clean"]
    return _taint.get_taint(lst[0])
test("[tainted, clean] → lst[0] tainted", test_build_list() > 0)

def test_build_tuple():
    t = _taint.set_taint("in_tuple")
    tup = (t, "clean")
    return _taint.get_taint(tup[0])
test("(tainted, clean) → tup[0] tainted", test_build_tuple() > 0)

def test_build_clean():
    lst = ["a", "b", "c"]
    return _taint.get_taint(lst[0])
test("[clean, clean, clean] → clean", test_build_clean() == 0)

# --- List extend (splat) ---
print("\n[5] List extend / splat")
def test_list_extend():
    base = [_taint.set_taint("base_item")]
    extended = [*base, "clean"]
    return _taint.get_taint(extended[0])
test("[*tainted_list, clean] → first tainted", test_list_extend() > 0)

# --- Singleton integrity ---
print("\n[6] Singleton integrity")
def test_singletons():
    _taint.set_taint("trigger")
    return (_taint.get_taint(True) == 0 and
            _taint.get_taint(False) == 0 and
            _taint.get_taint(None) == 0 and
            _taint.get_taint(0) == 0)
test("singletons all clean", test_singletons())

# --- Regression ---
print("\n[7] Regression")
test("Phase 0", _taint.get_taint(_taint.set_taint("r")) > 0)

def test_p1():
    x = _taint.set_taint("p1")
    return _taint.get_taint(x)
test("Phase 1", test_p1() > 0)

def test_p2():
    t = _taint.set_taint("a")
    return _taint.get_taint(t + "b")
test("Phase 2", test_p2() > 0)

def test_p3():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t.upper())
test("Phase 3", test_p3() > 0)

def test_p4a():
    class O: pass
    o = O()
    o.x = _taint.set_taint("attr")
    return _taint.get_taint(o.x)
test("Phase 4a", test_p4a() > 0)

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
