"""Synthetic Taint Test A: Basic Propagation"""
import _taint

results = []

def check(name, condition):
    results.append((name, condition))
    print("  %s: %s" % ("PASS" if condition else "FAIL", name))

print("--- A. Basic Propagation ---")

def t_source():
    x = _taint.set_taint("abc", "source_basic")
    return _taint.get_taint(x) > 0
check("set_taint creates source", t_source())

def t_assign():
    x = _taint.set_taint("data", "src_assign")
    y = x
    return _taint.get_taint(y) > 0
check("assignment propagates", t_assign())

def t_concat():
    x = _taint.set_taint("prefix", "src_concat")
    r = x + "_suffix"
    return _taint.get_taint(r) > 0
check("string concat propagates", t_concat())

def t_fstring():
    x = _taint.set_taint("injected", "src_fstr")
    r = f"before {x} after"
    return _taint.get_taint(r) > 0
check("f-string propagates", t_fstring())

def t_upper():
    x = _taint.set_taint("hello", "src_upper")
    return _taint.get_taint(x.upper()) > 0
check("str.upper() propagates", t_upper())

def t_lower():
    x = _taint.set_taint("HELLO", "src_lower")
    return _taint.get_taint(x.lower()) > 0
check("str.lower() propagates", t_lower())

def t_strip():
    x = _taint.set_taint("  data  ", "src_strip")
    return _taint.get_taint(x.strip()) > 0
check("str.strip() propagates", t_strip())

def t_join():
    sep = _taint.set_taint(",", "src_join")
    r = sep.join(["a", "b", "c"])
    return _taint.get_taint(r) > 0
check("sep.join() propagates", t_join())

def t_replace():
    x = _taint.set_taint("hello world", "src_replace")
    r = x.replace("hello", "goodbye")
    return _taint.get_taint(r) > 0
check("str.replace() propagates", t_replace())

passed = sum(1 for _, c in results if c)
failed = sum(1 for _, c in results if not c)
print("  [A] %d passed, %d failed" % (passed, failed))
