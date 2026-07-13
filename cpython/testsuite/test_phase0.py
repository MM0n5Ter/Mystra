"""Phase 0: Core Engine Integration — Acceptance Tests"""
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
print("Phase 0: Core Engine Integration")
print("=" * 60)

# --- Module Import ---
print("\n[1] Module Import")
import _taint
test("import _taint succeeds", True)

# --- set_taint / get_taint ---
print("\n[2] set_taint / get_taint")
x = _taint.set_taint("hello")
test("set_taint returns the same string", x == "hello")

tid = _taint.get_taint(x)
test("taint_id > 0 for tainted object", tid > 0)

# --- Clean objects ---
print("\n[3] Clean objects")
clean = "world"
test("clean string has taint 0", _taint.get_taint(clean) == 0)
test("clean int has taint 0", _taint.get_taint(42) == 0)
test("None has taint 0", _taint.get_taint(None) == 0)

# --- Distinct IDs ---
print("\n[4] Distinct taint IDs")
a = _taint.set_taint("aaa", "SourceA")
b = _taint.set_taint("bbb", "SourceB")
c = _taint.set_taint("ccc", "SourceC")
tid_a = _taint.get_taint(a)
tid_b = _taint.get_taint(b)
tid_c = _taint.get_taint(c)
test("all taint IDs are positive", tid_a > 0 and tid_b > 0 and tid_c > 0)
test("all taint IDs are distinct", len({tid_a, tid_b, tid_c}) == 3)

# --- Custom label ---
print("\n[5] Custom label")
labeled = _taint.set_taint("data", "UserInput")
test("labeled taint has positive ID", _taint.get_taint(labeled) > 0)

# --- print_flow_tree ---
print("\n[6] print_flow_tree (must not crash)")
_taint.print_flow_tree(labeled)
test("print_flow_tree runs without crash", True)

_taint.print_flow_tree("clean_string")
test("print_flow_tree on clean object runs without crash", True)

# --- Dealloc cleanup ---
print("\n[7] Dealloc cleanup")
def test_dealloc():
    obj = _taint.set_taint("temporary_" + str(id(test_dealloc)))
    addr = id(obj)
    tid_before = _taint.get_taint(obj)
    assert tid_before > 0, "object should be tainted"
    del obj
    gc.collect()
    new_obj = "replacement_" + str(addr)
    tid_after = _taint.get_taint(new_obj)
    return tid_after == 0

test("dealloc cleans up heap taint", test_dealloc())

# --- Singleton integrity ---
print("\n[8] Singleton integrity")
_taint.set_taint("trigger_something")
test("True not tainted", _taint.get_taint(True) == 0)
test("False not tainted", _taint.get_taint(False) == 0)
test("None not tainted", _taint.get_taint(None) == 0)
test("0 not tainted", _taint.get_taint(0) == 0)
test("1 not tainted", _taint.get_taint(1) == 0)
test("empty string not tainted", _taint.get_taint("") == 0)

# --- PYTHONDTA disable ---
print("\n[9] Engine existence")
test("engine is active (PYTHONDTA not set to 0)", _taint.get_taint(_taint.set_taint("x")) > 0)

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
