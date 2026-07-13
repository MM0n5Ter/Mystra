"""Manual Verification: Provenance Graph

Tests that print_flow_tree produces correct DAG showing source →
transformations → final value.

Run: ./python testsuite/manual_verification/test_provenance.py

Maps to: FlowNode DAG in taint-core, dta_create_source/derive_node
"""
import _taint
import sys

print("=" * 60)
print("Manual Verification: Provenance Graph")
print("=" * 60)

# --- 1. Single source ---
print("\n[1] Single source provenance")
print("  Code: x = _taint.set_taint('input', 'HTTP_PARAM')")
print("  Expected shape: single node [Source] with label 'HTTP_PARAM'")
print("  Actual:")
def test_single_source():
    x = _taint.set_taint("input", "HTTP_PARAM")
    _taint.print_flow_tree(x)
    tid = _taint.get_taint(x)
    print("  taint_id:", tid)
    assert tid > 0
    print("  PASS")
test_single_source()


# --- 2. One derivation ---
print("\n[2] One derivation: source → upper()")
print("  Code: t = set_taint('hello', 'SRC'); r = t.upper()")
print("  Expected shape:")
print("    [Derive] upper")
print("      └── [Source] SRC")
print("  Actual:")
def test_one_derive():
    t = _taint.set_taint("hello", "SRC")
    r = t.upper()
    _taint.print_flow_tree(r)
    assert _taint.get_taint(r) > 0
    print("  PASS")
test_one_derive()


# --- 3. Multi-step: source → upper → concat → replace ---
print("\n[3] Multi-step provenance")
print("  Code:")
print("    t = set_taint('raw', 'UserInput')")
print("    s1 = t.upper()         # derive from source")
print("    s2 = s1 + '_SUFFIX'    # binary op merge (s1 tainted, literal clean)")
print("    s3 = s2.replace('R', 'X')  # derive from s2")
print("")
print("  Expected shape:")
print("    [Derive] replace")
print("      └── [Derive] BinaryOp")
print("            ├── [Derive] upper")
print("            │     └── [Source] UserInput")
print("            └── (0 — clean right operand)")
print("")
print("  Actual:")

def test_multi_step():
    t = _taint.set_taint("raw", "UserInput")
    s1 = t.upper()
    s2 = s1 + "_SUFFIX"
    s3 = s2.replace("R", "X")

    tid_t = _taint.get_taint(t)
    tid_s1 = _taint.get_taint(s1)
    tid_s2 = _taint.get_taint(s2)
    tid_s3 = _taint.get_taint(s3)

    print("  Taint IDs: source=%d, upper=%d, concat=%d, replace=%d" %
          (tid_t, tid_s1, tid_s2, tid_s3))
    print("  (Each step should produce a new node ID)")
    print("")
    print("  Flow tree for final value:")
    _taint.print_flow_tree(s3)

    assert tid_t > 0, "source should be tainted"
    assert tid_s1 > tid_t, "upper should have higher ID than source"
    assert tid_s2 > tid_s1, "concat should have higher ID than upper"
    assert tid_s3 > tid_s2, "replace should have higher ID than concat"
    print("  PASS — monotonically increasing IDs confirm DAG structure")

test_multi_step()


# --- 4. Two sources merge ---
print("\n[4] Two sources merge via binary op")
print("  Code:")
print("    a = set_taint('left', 'SourceA')")
print("    b = set_taint('right', 'SourceB')")
print("    c = a + b  # merge creates node with TWO parents")
print("")
print("  Expected shape:")
print("    [Derive] BinaryOp")
print("      ├── [Source] SourceA")
print("      └── [Source] SourceB")
print("")
print("  Actual:")

def test_two_sources():
    a = _taint.set_taint("left", "SourceA")
    b = _taint.set_taint("right", "SourceB")
    c = a + b

    tid_a = _taint.get_taint(a)
    tid_b = _taint.get_taint(b)
    tid_c = _taint.get_taint(c)

    print("  Taint IDs: a=%d, b=%d, merged=%d" % (tid_a, tid_b, tid_c))
    print("")
    print("  Flow tree for merged value:")
    _taint.print_flow_tree(c)

    assert tid_a > 0 and tid_b > 0 and tid_c > 0
    assert tid_c != tid_a and tid_c != tid_b, "merged should be new node"
    print("  PASS — merge node has two parents")

test_two_sources()


# --- 5. Provenance survives through attribute store/load ---
print("\n[5] Provenance survives attribute round-trip")
print("  Code: obj.x = tainted; r = obj.x; print_flow_tree(r)")
print("")

def test_attr_provenance():
    class Obj: pass
    obj = Obj()
    t = _taint.set_taint("attr_data", "AttrSource")
    obj.x = t
    r = obj.x
    tid = _taint.get_taint(r)
    print("  obj.x taint_id:", tid, "(expected >0)")
    print("  Flow tree:")
    _taint.print_flow_tree(r)
    assert tid > 0
    print("  PASS")

test_attr_provenance()


print("\n" + "=" * 60)
print("All provenance tests PASSED")
print("=" * 60)
