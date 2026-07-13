"""Synthetic Taint Test C: Container/Object Propagation"""
import _taint

results = []

def check(name, condition):
    results.append((name, condition))
    print("  %s: %s" % ("PASS" if condition else "FAIL", name))

print("--- C. Container/Object Propagation ---")

def t_list_store_load():
    lst = [None]
    lst[0] = _taint.set_taint("list_val", "src_list")
    return _taint.get_taint(lst[0]) > 0
check("list[0] store/load", t_list_store_load())

def t_dict_store_load():
    d = {}
    d["key"] = _taint.set_taint("dict_val", "src_dict")
    return _taint.get_taint(d["key"]) > 0
check("dict['key'] store/load", t_dict_store_load())

def t_attr_store_load():
    class Obj: pass
    o = Obj()
    o.secret = _taint.set_taint("attr_val", "src_attr")
    return _taint.get_taint(o.secret) > 0
check("obj.attr store/load", t_attr_store_load())

def t_global():
    global _g_tainted
    _g_tainted = _taint.set_taint("global_val", "src_global")
    return _taint.get_taint(_g_tainted) > 0
check("global variable", t_global())

def t_closure():
    captured = _taint.set_taint("closure_val", "src_closure")
    def inner():
        return captured
    return _taint.get_taint(inner()) > 0
check("closure variable", t_closure())

def t_class_method():
    class Service:
        def __init__(self):
            self.data = _taint.set_taint("field", "src_method")
        def process(self):
            return self.data.upper()
    svc = Service()
    r = svc.process()
    return _taint.get_taint(r) > 0
check("class method using tainted field", t_class_method())

def t_nested_container():
    outer = {"inner": [None]}
    outer["inner"][0] = _taint.set_taint("deep", "src_deep")
    return _taint.get_taint(outer["inner"][0]) > 0
check("nested dict→list store/load", t_nested_container())

def t_list_clean_isolation():
    lst = [_taint.set_taint("bad", "src_iso"), "good"]
    return _taint.get_taint(lst[1]) == 0
check("list[1] stays clean when list[0] tainted", t_list_clean_isolation())

passed = sum(1 for _, c in results if c)
failed = sum(1 for _, c in results if not c)
print("  [C] %d passed, %d failed" % (passed, failed))
