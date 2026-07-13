"""Thorough test of all DTA taint propagation paths"""
import sys
import subprocess
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
print("Thorough DTA Test")
print("=" * 60)

import _taint

# === LOCAL VARIABLES ===
print("\n--- Local Variables ---")
def t_local_assign():
    x = _taint.set_taint("a")
    y = x
    return _taint.get_taint(y) > 0
test("local assign propagates", t_local_assign())

def t_cross_func():
    def f(x): return x
    return _taint.get_taint(f(_taint.set_taint("b"))) > 0
test("cross-function propagates", t_cross_func())

# === BINARY OPS ===
print("\n--- Binary Operations ---")
def t_str_concat():
    t = _taint.set_taint("hello")
    return _taint.get_taint(t + " world") > 0
test("str concat", t_str_concat())

def t_int_add():
    t = _taint.set_taint(1000)
    return _taint.get_taint(t + 1) > 0
test("int add", t_int_add())

def t_float_mul():
    t = _taint.set_taint(3.14)
    return _taint.get_taint(t * 2.0) > 0
test("float mul", t_float_mul())

def t_inplace():
    s = _taint.set_taint("start")
    s += "_end"
    return _taint.get_taint(s) > 0
test("inplace +=", t_inplace())

def t_chained():
    t = _taint.set_taint("a")
    r = t + "b" + "c"
    return _taint.get_taint(r) > 0
test("chained concat", t_chained())

# === CALL DISPATCH ===
print("\n--- Call Dispatch ---")
def t_str_upper():
    return _taint.get_taint(_taint.set_taint("hello").upper()) > 0
test("str.upper()", t_str_upper())

def t_str_replace():
    return _taint.get_taint(_taint.set_taint("hello").replace("h", "j")) > 0
test("str.replace()", t_str_replace())

def t_str_split():
    t = _taint.set_taint("a,b,c")
    parts = t.split(",")
    return _taint.get_taint(parts) > 0
test("str.split() result tainted", t_str_split())

def t_str_join():
    sep = _taint.set_taint(",")
    return _taint.get_taint(sep.join(["a", "b"])) > 0
test("tainted_sep.join()", t_str_join())

def t_str_conv():
    return _taint.get_taint(str(_taint.set_taint(12345))) > 0
test("str(tainted_int)", t_str_conv())

def t_len_clear():
    return _taint.get_taint(len(_taint.set_taint("hello"))) == 0
test("len() is clean (Clear)", t_len_clear())

def t_type_clear():
    return _taint.get_taint(type(_taint.set_taint("hello"))) == 0
test("type() is clean (Clear)", t_type_clear())

def t_isinstance_clear():
    return _taint.get_taint(isinstance(_taint.set_taint("x"), str)) == 0
test("isinstance() is clean", t_isinstance_clear())

# === ATTRIBUTES ===
print("\n--- Attributes ---")
def t_attr():
    class O: pass
    o = O()
    o.x = _taint.set_taint("attr_val")
    return _taint.get_taint(o.x) > 0
test("obj.x = tainted; obj.x tainted", t_attr())

def t_attr_clean():
    class O: pass
    o = O()
    o.x = "clean"
    return _taint.get_taint(o.x) == 0
test("clean attr stays clean", t_attr_clean())

def t_nested_attr():
    class A: pass
    a = A()
    a.b = A()
    a.b.c = _taint.set_taint("nested")
    return _taint.get_taint(a.b.c) > 0
test("nested attr a.b.c", t_nested_attr())

# === SUBSCRIPTS ===
print("\n--- Subscripts ---")
def t_list_sub():
    lst = [None]
    lst[0] = _taint.set_taint("lst_item")
    return _taint.get_taint(lst[0]) > 0
test("lst[0] = tainted; lst[0] tainted", t_list_sub())

def t_dict_sub():
    d = {}
    d["k"] = _taint.set_taint("dict_val")
    return _taint.get_taint(d["k"]) > 0
test("d['k'] = tainted; d['k'] tainted", t_dict_sub())

def t_slice():
    t = _taint.set_taint("hello world")
    return _taint.get_taint(t[:5]) > 0
test("tainted[:5]", t_slice())

# === GLOBALS ===
print("\n--- Globals ---")
_g = None
def t_global_write():
    global _g
    _g = _taint.set_taint("global_val")
def t_global_read():
    return _taint.get_taint(_g) > 0
t_global_write()
test("global write/read", t_global_read())

# === CLOSURES ===
print("\n--- Closures ---")
def t_closure():
    x = _taint.set_taint("closed")
    def inner(): return x
    return _taint.get_taint(inner()) > 0
test("closure var", t_closure())

# === UNPACK ===
print("\n--- Unpack ---")
def t_unpack():
    a, b = [_taint.set_taint("u1"), "u2"]
    return _taint.get_taint(a) > 0
test("a, b = [tainted, clean]", t_unpack())

# === BUILD ===
print("\n--- Container Build ---")
def t_build_list():
    t = _taint.set_taint("in_list")
    lst = [t, "clean"]
    return _taint.get_taint(lst[0]) > 0
test("[tainted, clean] → lst[0] tainted", t_build_list())

def t_build_tuple():
    t = _taint.set_taint("in_tuple")
    tup = (t, "clean")
    return _taint.get_taint(tup[0]) > 0
test("(tainted, clean) → tup[0] tainted", t_build_tuple())

def t_build_dict():
    t = _taint.set_taint("dict_v")
    d = {"k": t}
    return _taint.get_taint(d["k"]) > 0
test("{'k': tainted} → d['k'] tainted", t_build_dict())

def t_build_set():
    t = _taint.set_taint("set_v")
    s = {t, "clean"}
    return any(_taint.get_taint(x) > 0 for x in s)
test("{tainted, clean} → some element tainted", t_build_set())

def t_list_extend():
    base = [_taint.set_taint("base")]
    ext = [*base, "clean"]
    return _taint.get_taint(ext[0]) > 0
test("[*tainted_list] → extended tainted", t_list_extend())

# === SINK DETECTION ===
print("\n--- Sink Detection ---")
def capture(code):
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=10)
    return r.stderr

test("eval(tainted) → ALERT",
     "[ALERT]" in capture("import _taint; eval(_taint.set_taint('1+2'))"))

test("os.system(tainted) → ALERT",
     "[ALERT]" in capture("import _taint,os; os.system(_taint.set_taint('echo'))"))

test("eval(clean) → no alert",
     "[ALERT]" not in capture("import _taint; eval('1+2')"))

# === NEGATIVE / CLEAN ===
print("\n--- Negative Tests ---")
def t_clean_after_tainted():
    _ = _taint.set_taint("t").upper()
    c = "clean_unique_xyz"
    return _taint.get_taint(c.lower()) == 0
test("clean call after tainted stays clean", t_clean_after_tainted())

def t_clean_binop():
    _ = _taint.set_taint("t") + "x"
    a = "aa"
    b = "bb"
    return _taint.get_taint(a + b) == 0
test("clean binop after tainted stays clean", t_clean_binop())

# === SINGLETON INTEGRITY ===
print("\n--- Singleton Integrity ---")
def t_singletons():
    # Trigger various taint operations
    t = _taint.set_taint("trigger")
    _ = t.upper()
    _ = t + " x"
    _ = len(t)
    return (_taint.get_taint(True) == 0 and
            _taint.get_taint(False) == 0 and
            _taint.get_taint(None) == 0 and
            _taint.get_taint(0) == 0 and
            _taint.get_taint(1) == 0 and
            _taint.get_taint(42) == 0 and
            _taint.get_taint("") == 0)
test("all singletons clean after operations", t_singletons())

# === DEALLOC CLEANUP ===
print("\n--- Dealloc Cleanup ---")
def t_dealloc():
    class Obj: pass
    o = Obj()
    o.data = _taint.set_taint("temp")
    del o
    gc.collect()
    o2 = Obj()
    o2.data = "clean_replacement"
    return _taint.get_taint(o2.data) == 0
test("dealloc cleanup", t_dealloc())

# === EDGE CASES ===
print("\n--- Edge Cases ---")
def t_deep_chain():
    def f1(x): return x.upper()
    def f2(x): return f1(x)
    def f3(x): return f2(x)
    return _taint.get_taint(f3(_taint.set_taint("deep"))) > 0
test("3-deep function chain", t_deep_chain())

def t_multi_return():
    def f():
        t = _taint.set_taint("multi")
        return t, t + "x"
    a, b = f()
    return _taint.get_taint(a) > 0 and _taint.get_taint(b) > 0
test("multiple return values", t_multi_return())

def t_comprehension():
    t = _taint.set_taint("comp")
    lst = [t + str(i) for i in range(3)]
    return _taint.get_taint(lst[0]) > 0
test("list comprehension propagates", t_comprehension())

def t_kwarg_call():
    def f(x="", sep=","): return x + sep
    t = _taint.set_taint("kw")
    return _taint.get_taint(f(x=t)) > 0
test("keyword argument propagates", t_kwarg_call())

# --- Summary ---
print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
