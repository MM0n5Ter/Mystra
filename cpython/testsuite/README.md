# CPython DTA — test suite

Curated, self-contained tests for the CPython Dynamic Taint Analysis port.
Every test here is green on the patched interpreter and depends only on the
built `./python` and the `_taint` module — no third-party packages, no
application code.

## Running

The tests locate the ruleset relative to the interpreter's working directory,
so run them from the **root of the patched-and-built CPython tree** (the one
that has `./python` and `./tsl/cpython-rules.tbin`). Copy this directory in:

```bash
cp -r /path/to/testsuite .          # into the cpython repo root
for f in testsuite/test_phase*.py testsuite/test_thorough.py \
         testsuite/test_var_store.py testsuite/test_call_ex_sinks.py \
         testsuite/test_open_sink.py; do ./python "$f" || exit 1; done
./python testsuite/synthetic_taint/run_synthetic_taint_tests.py
for f in testsuite/manual_verification/test_*.py; do ./python "$f"; done
```

## Contents

| File / dir | Assertions | Validates |
|------------|-----------:|-----------|
| `test_phase0.py` | 19 | Module import, set/get taint, distinct IDs, dealloc cleanup, singleton integrity |
| `test_phase1.py` | 12 | Local-variable propagation (LOAD_FAST/STORE_FAST), cross-function, isolation |
| `test_phase2.py` | 16 | BINARY_OP taint merge: concat, arithmetic, in-place, both-tainted, clean+clean |
| `test_phase3.py` | 24 | str methods, CLEAR meta-ops, Python-function propagation, eval/os.system sinks |
| `test_phase4a.py` | 17 | Attribute + subscript shadow heap round-trip, slice, dealloc, negative meta-ops |
| `test_phase4b.py` | 17 | Globals, closures, tuple/list unpack, BUILD_LIST/TUPLE, splat |
| `test_phase5.py` | 26 | TSL propagate/clear rules + sink alerts (eval/exec/system/compile), no false alerts |
| `test_phase6.py` | 11 | f-strings (FORMAT_VALUE / BUILD_STRING), singleton integrity |
| `test_thorough.py` | 40 | Cross-cutting: every propagation + negative path, all sinks, edge cases |
| `test_var_store.py` | 7 | I/O boundary `fs_taint` write-park / read-restore across the filesystem |
| `test_call_ex_sinks.py` | 5 | `f(*args)` (CALL_FUNCTION_EX) sink detection via TSL (CWE-78/94/22) |
| `test_open_sink.py` | 7 | `_io.open` CWE-22 sink + single-route logger (`[ALERT]` / one JSONL record) |
| `synthetic_taint/` | 33 | Propagation, functions, containers, sinks, provenance DAG (with a runner) |
| `manual_verification/` | ~30 | Human-readable propagation / negative / provenance / shadow-heap / sink demos |

Roughly 264 assertions total.

## Not included

Real-world CVE/advisory reproducers (path-traversal, RCE, SQLi validations) are
omitted here: they embed third-party application snippets and are validation
material rather than engine unit tests.
