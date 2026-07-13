"""Manual Verification: Shadow Heap

Tests taint propagation through attributes, subscripts, globals, closures.

Run: ./python testsuite/manual_verification/test_shadow_heap.py

Maps to: Shadow Heap (Phase 4a + 4b)
"""
import _taint
import gc

print("=" * 60)
print("Manual Verification: Shadow Heap")
print("=" * 60)

# --- 1. Attribute store/load ---
print("\n[1] Attribute store/load")
def test_attr():
    class Container:
        pass
    obj = Container()
    obj.secret = _taint.set_taint("attr_secret", "source_attr")
    obj.public = "clean_data"

    tid_secret = _taint.get_taint(obj.secret)
    tid_public = _taint.get_taint(obj.public)

    print("  obj.secret taint_id:", tid_secret, "(expected >0)")
    print("  obj.public taint_id:", tid_public, "(expected 0)")
    assert tid_secret > 0, "FAIL: tainted attr should propagate"
    assert tid_public == 0, "FAIL: clean attr should stay clean"
    print("  PASS")
test_attr()

# --- 2. List subscript ---
print("\n[2] List subscript")
def test_list():
    lst = ["clean_item", None, "another_clean"]
    lst[1] = _taint.set_taint("list_secret", "source_list")

    tid_0 = _taint.get_taint(lst[0])
    tid_1 = _taint.get_taint(lst[1])
    tid_2 = _taint.get_taint(lst[2])

    print("  lst[0] taint_id:", tid_0, "(expected 0)")
    print("  lst[1] taint_id:", tid_1, "(expected >0)")
    print("  lst[2] taint_id:", tid_2, "(expected 0)")
    assert tid_0 == 0, "FAIL: lst[0] should be clean"
    assert tid_1 > 0, "FAIL: lst[1] should be tainted"
    assert tid_2 == 0, "FAIL: lst[2] should be clean"
    print("  PASS")
test_list()

# --- 3. Dict subscript ---
print("\n[3] Dict subscript")
def test_dict():
    d = {}
    d["bad"] = _taint.set_taint("dict_secret", "source_dict")
    d["good"] = "safe_value"

    tid_bad = _taint.get_taint(d["bad"])
    tid_good = _taint.get_taint(d["good"])

    print("  d['bad'] taint_id:", tid_bad, "(expected >0)")
    print("  d['good'] taint_id:", tid_good, "(expected 0)")
    assert tid_bad > 0, "FAIL: d['bad'] should be tainted"
    assert tid_good == 0, "FAIL: d['good'] should be clean"
    print("  PASS")
test_dict()

# --- 4. Global variable ---
print("\n[4] Global variable")
_global_tainted = None

def test_global_write():
    global _global_tainted
    _global_tainted = _taint.set_taint("global_secret", "source_global")

def test_global_read():
    return _taint.get_taint(_global_tainted)

test_global_write()
tid_global = test_global_read()
print("  global taint_id:", tid_global, "(expected >0)")
assert tid_global > 0, "FAIL: global should be tainted"
print("  PASS")

# --- 5. Closure ---
print("\n[5] Closure variable")
def test_closure():
    captured = _taint.set_taint("closure_secret", "source_closure")
    def inner():
        return captured
    r = inner()
    tid = _taint.get_taint(r)
    print("  closure result taint_id:", tid, "(expected >0)")
    assert tid > 0, "FAIL: closure should propagate taint"
    print("  PASS")
test_closure()

# --- 6. Dealloc cleanup ---
print("\n[6] Dealloc cleanup (address reuse)")
def test_dealloc():
    class Obj:
        pass
    o = Obj()
    o.data = _taint.set_taint("temporary_" + str(id(o)), "source_dealloc")
    tid_before = _taint.get_taint(o.data)
    del o
    gc.collect()
    # New object at potentially same address should be clean
    o2 = Obj()
    o2.data = "replacement_clean"
    tid_after = _taint.get_taint(o2.data)
    print("  before del taint_id:", tid_before, "(expected >0)")
    print("  after del+gc taint_id:", tid_after, "(expected 0)")
    assert tid_before > 0, "FAIL: original should be tainted"
    assert tid_after == 0, "FAIL: new object should be clean"
    print("  PASS")
test_dealloc()

print("\n" + "=" * 60)
print("All shadow heap tests PASSED")
print("=" * 60)
