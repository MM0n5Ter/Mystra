# CPython DTA port — code patch + rule snapshot

Snapshot of the CPython 3.13.13 Dynamic Taint Analysis port for the Mystra engine.

## Contents

| File | What |
|------|------|
| `dta_code.patch` | Code-only diff vs vanilla CPython 3.13.13 (commit `01104ce1beb3135c2e0c01ec835b994c1f55a1c0`). Shared core (`Python/dta/taint-*`), CPython adapter (`Python/dta/cpython_*`), bytecode instrumentation (`Python/bytecodes.c`, `Python/ceval_macros.h`, regenerated `generated_cases.c.h`/`executor_cases.c.h`), dealloc hook (`Objects/object.c`), engine lifecycle (`Python/pystate.c`), and the `_taint` module. **No** `tsl/`, tests, or docs. |
| `cpython-rules.tsl` | The TSL rule set (Mystra v3 grammar) — 127 rules: propagate/forward/clear meta-ops + CWE-22/78/89/94/95/502 sinks + the `fs_taint` I/O write-park store. |
| `cpython-rules.tbin` | Compiled ruleset loaded by the engine at startup (`./tsl/cpython-rules.tbin`). Byte-reproducible from the `.tsl` via `language/mystra-compiler.py`. |

## Apply + build

```bash
git clone https://github.com/python/cpython && cd cpython
git checkout 01104ce1beb3135c2e0c01ec835b994c1f55a1c0
git apply /path/to/dta_code.patch
./configure --disable-experimental-jit          # DTA instruments Tier-1 only
make regen-cases && rm -f Python/ceval.o && make -j16
mkdir -p tsl && cp /path/to/cpython-rules.tbin tsl/   # engine loads ./tsl/cpython-rules.tbin
```

Run: `./python script.py` tracks taint; `PYTHONDTA=0 ./python …` disables it;
`DTA_JSON=/path/out.jsonl ./python …` streams `{ts,cwe,sink,args,dag}` alert records
(otherwise alerts print `[ALERT] CWE-N | Sink: …` to stderr).

## Recompile the rules

```bash
# needs: pip install tree_sitter
python3 language/mystra-compiler.py cpython-rules.tsl -o cpython-rules.tbin
```
