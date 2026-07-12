# Mystra / Shar — Dynamic Taint Analysis via a Shadow Virtual Machine

This repository is the **V8 / Node.js instantiation of Shar**, a runtime-independent
dynamic taint analysis (DTA) framework driven by **Mystra**, a declarative taint
specification language. Taint semantics are specified as Mystra rules and executed
by a Shadow Virtual Machine embedded natively in V8 — tracking register-level and
heap-level taint, provenance, and cross-invocation context across both the Ignition
interpreter and the Maglev JIT, without deoptimizing back to the interpreter.

It is built on **Node.js v24.13.1**. Adding support for a new vulnerability class
requires only declarative Mystra rules (`language/v8-rules.tsl`) — no engine changes.

> Reference: *Mystra: Declarative Dynamic Taint Analysis via Shadow Virtual Machine.*

## Build

A full build takes ~30 minutes and produces `./out/Release/node` (symlinked as `./node`).

```bash
./configure                    # first time only
make BUILDTYPE=Release -j16
```

Taint rules are compiled ahead of time into a binary (`language/v8-rules.tbin`) that
the engine loads at startup. The prebuilt binary is checked in; rebuild it only if
you edit the rules:

```bash
cd language
pip install -r requirements.txt
python3 mystra-compiler.py v8-rules.tsl    # -> v8-rules.tbin
```

See `language/README.md` for the Mystra language and rule-compiler details.

## Running

Enable taint tracking with `--dta-maglev`. Mark taint sources and query taint from
JavaScript with the `%SetTaint` / `%GetTaint` intrinsics (which require
`--allow-natives-syntax`):

```bash
./node --dta-maglev --allow-natives-syntax testsuite/test-string-dta.js
```

```js
const secret = %SetTaint("payload");    // mark a taint source
const derived = "cmd " + secret;        // taint propagates through operations
%GetTaint(derived);                     // -> non-zero taint id
```

By default the engine loads `./language/v8-rules.tbin`; override with the
`DTA_RULES_PATH` environment variable.

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--dta-maglev` | off | Enable DTA taint tracking through the Maglev JIT (the main mode). Also blocks Turbofan/OSR/Sparkplug tiering, which lack DTA hooks. |
| `--dta-suppress-jit` | on | Keep taint-carrying functions in the Ignition interpreter for full tracking (implied off by `--dta-maglev`). |
| `--dta-disable-skipbit` | off | Debug: disable fast-path skip optimizations, forcing every call through the C++ slow path with verbose logging. |
| `--dta-json-log <path>` | — | Write structured DTA output (alerts, provenance, coverage gaps) as JSONL. |
| `--allow-natives-syntax` | — | Required to use the `%SetTaint` / `%GetTaint` intrinsics. |
| `--expose-gc` | — | Used by GC-safety tests. |

The test suite lives in `testsuite/`, e.g.:

```bash
./node --dta-maglev --allow-natives-syntax testsuite/test-stress-dta.js   # GC / cross-tier stress
./node --dta-maglev --allow-natives-syntax testsuite/test-ipc-dta.js      # IPC taint serialization
./node --dta-maglev --allow-natives-syntax testsuite/test-var-dta.js      # Mystra global stores
```

## Repository layout

```
deps/v8/src/taint/     DTA engine core: Shadow VM, host adapter, rule interpreter,
                       binary rule loader (the engine-agnostic taint library)
language/              Mystra language — rules (v8-rules.tsl), the rule compiler,
                       tree-sitter grammar, and the VS Code extension
testsuite/             DTA test suite (string/buffer/promise/ipc/var/… taint)
src/                   Node.js integration points touched by the engine
deps/v8/               V8 with DTA instrumentation (Ignition, Maglev, runtime)
NODEREADME.md          Upstream Node.js README
LICENSE                License texts (see below)
```

## License

The Mystra/Shar additions in this repository are released under the **MIT License**
(see the top of `LICENSE`). This project is a fork of Node.js; Node.js, V8, and all
bundled dependencies remain under their own licenses, which are retained in full in
`LICENSE`.
