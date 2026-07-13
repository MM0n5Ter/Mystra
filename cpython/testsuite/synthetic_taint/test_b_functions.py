"""Synthetic Taint Test B: Function Propagation"""
import _taint

results = []

def check(name, condition):
    results.append((name, condition))
    print("  %s: %s" % ("PASS" if condition else "FAIL", name))

print("--- B. Function Propagation ---")

def t_arg_in():
    def process(s):
        return _taint.get_taint(s) > 0
    x = _taint.set_taint("param", "src_argin")
    return process(x)
check("tainted arg visible inside function", t_arg_in())

def t_return():
    def produce():
        return _taint.set_taint("returned", "src_return")
    r = produce()
    return _taint.get_taint(r) > 0
check("tainted return value propagates", t_return())

def t_transform():
    def transform(s):
        return s.upper() + "!"
    x = _taint.set_taint("input", "src_transform")
    r = transform(x)
    return _taint.get_taint(r) > 0
check("taint survives function transform", t_transform())

def t_nested():
    def f1(s): return s.lower()
    def f2(s): return f1(s)
    def f3(s): return f2(s)
    x = _taint.set_taint("NESTED", "src_nested")
    r = f3(x)
    return _taint.get_taint(r) > 0
check("3-deep nested function propagates", t_nested())

def t_clean_arg():
    def identity(s):
        return s
    c = "clean_param"
    r = identity(c)
    return _taint.get_taint(r) == 0
check("clean arg stays clean through function", t_clean_arg())

def t_multi_args():
    def select_second(a, b, c):
        return b
    x = _taint.set_taint("middle", "src_multi")
    r = select_second("clean1", x, "clean2")
    return _taint.get_taint(r) > 0
check("tainted middle arg propagates via return", t_multi_args())

def t_clean_after_tainted():
    def tainted_func():
        return _taint.set_taint("from_func", "src_tainted_func")
    def clean_func():
        return "pure_clean_value"
    _ = tainted_func()
    r = clean_func()
    return _taint.get_taint(r) == 0
check("clean function after tainted returns clean", t_clean_after_tainted())

passed = sum(1 for _, c in results if c)
failed = sum(1 for _, c in results if not c)
print("  [B] %d passed, %d failed" % (passed, failed))
