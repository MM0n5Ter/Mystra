"""Phase 4a: Shadow Heap — Attributes + Subscripts Tests"""
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
print("Phase 4a: Shadow Heap (Attributes + Subscripts)")
print("=" * 60)

import _taint

# --- Attribute round-trip ---
print("\n[1] Attribute propagation")
def test_attr_roundtrip():
    class Obj: pass
    o = Obj()
    o.data = _taint.set_taint("secret_attr")
    return _taint.get_taint(o.data)
test("obj.data = tainted; obj.data is tainted", test_attr_roundtrip() > 0)

def test_attr_clean():
    class Obj: pass
    o = Obj()
    o.data = "clean_value"
    return _taint.get_taint(o.data)
test("obj.data = clean; obj.data is clean", test_attr_clean() == 0)

def test_attr_mixed():
    class Obj: pass
    o = Obj()
    o.tainted = _taint.set_taint("secret")
    o.clean = "public"
    return _taint.get_taint(o.tainted) > 0 and _taint.get_taint(o.clean) == 0
test("mixed attrs: tainted stays tainted, clean stays clean", test_attr_mixed())

# --- Delete attr ---
print("\n[2] Delete attribute")
def test_delete_attr():
    class Obj: pass
    o = Obj()
    o.data = _taint.set_taint("to_delete")
    tid_before = _taint.get_taint(o.data)
    del o.data
    o.data = "replacement"
    return tid_before > 0 and _taint.get_taint(o.data) == 0
test("del attr then reassign is clean", test_delete_attr())

# --- List subscript ---
print("\n[3] List subscript")
def test_list_subscr():
    lst = [None]
    lst[0] = _taint.set_taint("list_item")
    return _taint.get_taint(lst[0])
test("lst[0] = tainted; lst[0] is tainted", test_list_subscr() > 0)

def test_list_clean():
    lst = ["clean_item"]
    return _taint.get_taint(lst[0])
test("lst[0] = clean; lst[0] is clean", test_list_clean() == 0)

# --- Dict subscript ---
print("\n[4] Dict subscript")
def test_dict_subscr():
    d = {}
    d["key"] = _taint.set_taint("dict_value")
    return _taint.get_taint(d["key"])
test("d['key'] = tainted; d['key'] is tainted", test_dict_subscr() > 0)

def test_dict_clean():
    d = {"key": "clean_value"}
    return _taint.get_taint(d["key"])
test("d['key'] = clean; d['key'] is clean", test_dict_clean() == 0)

# --- Slice ---
print("\n[5] Slice propagation")
def test_slice():
    t = _taint.set_taint("hello world")
    return _taint.get_taint(t[:5])
test("tainted[:5] propagates", test_slice() > 0)

# --- Nested attribute ---
print("\n[6] Nested attribute")
def test_nested_attr():
    class Inner: pass
    class Outer: pass
    o = Outer()
    o.inner = Inner()
    o.inner.val = _taint.set_taint("nested")
    return _taint.get_taint(o.inner.val)
test("outer.inner.val taint propagates", test_nested_attr() > 0)

# --- Dealloc cleanup ---
print("\n[7] Dealloc cleanup")
def test_dealloc():
    class Obj: pass
    o = Obj()
    o.data = _taint.set_taint("temp_" + str(id(o)))
    del o
    gc.collect()
    o2 = Obj()
    o2.data = "clean_replacement"
    return _taint.get_taint(o2.data) == 0
test("del tainted obj + gc → new obj is clean", test_dealloc())

# --- Negative: meta-ops ---
print("\n[8] Negative: meta-ops")
def test_neg_len():
    lst = [_taint.set_taint("x")]
    return _taint.get_taint(len(lst))
test("len(tainted_list) is clean", test_neg_len() == 0)

# --- Singleton integrity ---
print("\n[9] Singleton integrity")
def test_singletons():
    _taint.set_taint("trigger")
    return (_taint.get_taint(True) == 0 and
            _taint.get_taint(False) == 0 and
            _taint.get_taint(None) == 0 and
            _taint.get_taint(0) == 0 and
            _taint.get_taint("") == 0)
test("singletons all clean", test_singletons())

# --- Regression ---
print("\n[10] Regression")
test("Phase 0", _taint.get_taint(_taint.set_taint("r")) > 0)

def test_p1():
    x = _taint.set_taint("p1")
    return _taint.get_taint(x)
test("Phase 1: local propagation", test_p1() > 0)

def test_p2():
    t = _taint.set_taint("a")
    return _taint.get_taint(t + "b")
test("Phase 2: binary op", test_p2() > 0)

def test_p3():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t.upper())
test("Phase 3: call propagation", test_p3() > 0)

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
