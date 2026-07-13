"""Manual Verification: Basic Taint Propagation

Tests shadow stack propagation through local variables, binary ops,
method calls, and f-strings.

Run: ./python testsuite/manual_verification/test_propagation.py

Maps to: Shadow Stack (Phase 1-2), TSL PROPAGATE (Phase 3), f-string (Phase 6)
"""
import _taint

print("=" * 60)
print("Manual Verification: Propagation")
print("=" * 60)

# --- 1. Assignment propagation (Shadow Stack) ---
print("\n[1] Assignment propagation (Shadow Stack)")
def test_assignment():
    x = _taint.set_taint("secret_data", "source_assign")
    y = x  # STORE_FAST + LOAD_FAST
    tid_x = _taint.get_taint(x)
    tid_y = _taint.get_taint(y)
    print("  x taint_id:", tid_x, "(expected >0)")
    print("  y taint_id:", tid_y, "(expected >0, same as x)")
    print("  y is x:", y is x, "(expected True — same object)")
    assert tid_x > 0, "FAIL: x should be tainted"
    assert tid_y > 0, "FAIL: y should be tainted"
    assert tid_y == tid_x, "FAIL: y should have same taint as x"
    print("  PASS")
test_assignment()

# --- 2. String concatenation (Shadow Stack + Binary Op Merge) ---
print("\n[2] String concatenation (Binary Op Merge)")
def test_concat():
    t = _taint.set_taint("user_input", "source_concat")
    r = t + " appended"
    tid_t = _taint.get_taint(t)
    tid_r = _taint.get_taint(r)
    print("  source taint_id:", tid_t)
    print("  concat taint_id:", tid_r, "(expected >0, differs from source)")
    assert tid_r > 0, "FAIL: concat result should be tainted"
    assert tid_r != tid_t, "FAIL: derived node should have new ID"
    print("  PASS")
test_concat()

# --- 3. Method chain (TSL PROPAGATE) ---
print("\n[3] Method chain: upper().strip() (TSL PROPAGATE)")
def test_method_chain():
    t = _taint.set_taint("  Hello World  ", "source_chain")
    r1 = t.upper()
    r2 = r1.strip()
    tid_src = _taint.get_taint(t)
    tid_r1 = _taint.get_taint(r1)
    tid_r2 = _taint.get_taint(r2)
    print("  source taint_id:", tid_src)
    print("  .upper() taint_id:", tid_r1, "(expected >0)")
    print("  .strip() taint_id:", tid_r2, "(expected >0)")
    assert tid_r1 > 0, "FAIL: upper() should propagate"
    assert tid_r2 > 0, "FAIL: strip() should propagate"
    print("  PASS")
test_method_chain()

# --- 4. f-string (FORMAT_SIMPLE + BUILD_STRING) ---
print("\n[4] f-string interpolation (FORMAT_SIMPLE + BUILD_STRING)")
def test_fstring():
    t = _taint.set_taint("injected_value", "source_fstr")
    r = f"prefix {t} suffix"
    tid_src = _taint.get_taint(t)
    tid_r = _taint.get_taint(r)
    print("  source taint_id:", tid_src)
    print("  f-string taint_id:", tid_r, "(expected >0)")
    assert tid_r > 0, "FAIL: f-string should propagate taint"
    print("  PASS")
test_fstring()

# --- 5. Cross-function propagation (Shadow Frame push/pop) ---
print("\n[5] Cross-function propagation (Shadow Frame)")
def test_cross_func():
    def transform(s):
        return s.replace("a", "b")
    t = _taint.set_taint("banana", "source_func")
    r = transform(t)
    tid_r = _taint.get_taint(r)
    print("  transform(tainted) taint_id:", tid_r, "(expected >0)")
    assert tid_r > 0, "FAIL: cross-function should propagate"
    print("  PASS")
test_cross_func()

# --- 6. Multi-step derivation ---
print("\n[6] Multi-step: set_taint → upper → concat → replace")
def test_multi_step():
    t = _taint.set_taint("raw_input", "source_multi")
    step1 = t.upper()
    step2 = step1 + "_SUFFIX"
    step3 = step2.replace("RAW", "COOKED")
    tid = _taint.get_taint(step3)
    print("  final taint_id:", tid, "(expected >0)")
    assert tid > 0, "FAIL: multi-step should propagate"
    print("  PASS")
    print("\n  Provenance graph:")
    _taint.print_flow_tree(step3)
test_multi_step()

print("\n" + "=" * 60)
print("All propagation tests PASSED")
print("=" * 60)
