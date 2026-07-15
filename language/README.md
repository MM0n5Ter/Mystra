# Mystra — Taint Specification Language (TSL)

Mystra is the declarative rule language that drives the Shadow VM's dynamic
taint analysis. A `.tsl` file maps host/runtime API functions to **taint-flow
actions** (propagate, sink, inject, …). Rules are compiled **ahead of time**
into a compact binary (`.tbin`) that the engine loads at startup and dispatches
in constant time — no runtime parsing.

## Files in this directory

| File | Purpose |
|------|---------|
| `grammar.js` | Tree-sitter grammar (source of truth for the syntax) |
| `Grammar.ebnf` | Human-readable EBNF (same language, for reading/paper) |
| `mystra-compiler.py` | Compiler: `.tsl` CST → `.tbin` binary |
| `v8-rules.tsl` | The V8/Node.js ruleset (source) |
| `v8-rules.tbin` | Compiled binary ruleset (loaded by the engine) |
| `tsl_parser.so` | Generated tree-sitter parser (used by the compiler) |
| `queries/highlights.scm` | Tree-sitter highlight queries (Neovim/Helix/GitHub) |
| `vscode-tsl/` | VS Code extension (TextMate grammar) |

## Language at a glance

```tsl
# A rule binds a namespaced signature to one or more sub-rules.
# Named params are sugar; the compiler lowers them to positional @args[N].
# No terminator — the body ends at the next `rule` / `let` / EOF.

rule V8_hostapi::CreateHTTPServer.request:
    source -> @ret                       # introduce fresh taint on the return

rule V8_native::StringPrototypeConcat(...parts):
    propagate @self, parts -> @ret       # derive taint into the result

rule V8_native::StringPrototypeStartsWith:
    clear                                # result is a boolean, taint removed

rule V8_native::openFileHandle(_, path):
    sink path @cwe(22)                   # alert if `path` is tainted

rule V8_native::ObjectDefineProperty(tar, key, desc):
    propagate desc.value -> tar[key]
    sink desc @cwe(1321) where tar.is_proto   # guarded action
```

**Actions** (all lowercase): `propagate` `inject` `extract` `sink`
`source` `clear` `preserve` `set`.

**Locators** address operands: `@self`, `@ret`, `@args[i]` / `@args[i:j]`, or a
param name; with an optional path — `[*]`/`[**]` (element wildcards), `.*`/`.**`
(property wildcards), `.name` (specific prop), or `[key]` (dynamic key).

**Higher-order functions** bridge taint across native callbacks:

```tsl
rule V8_native::ArrayPrototypeMap(callback, arg):
    inject @self[*] -> callback.param[0]   # container element -> callback arg
    extract callback.ret -> @ret[*]        # callback result   -> result element
```

**Global stores** persist taint across invocation boundaries. Declare with
`let`, then read/write with a **bare name** (no `$` sigil) — the compiler resolves
whether a name is a store or an object locator by whether it was declared:

```tsl
let filelist[string] -> taint ;

rule V8_hostapi::fs.writeFile(path, data):
    set filelist[path.value] = data.taint

rule V8_hostapi::fs.readFile(path):
    propagate filelist[path.value] -> @ret
```

See `Grammar.ebnf` for the complete grammar.

## Building rules

Requires Python with the `tree-sitter` binding (`pip install -r requirements.txt`).

```bash
# Compile the ruleset to binary
python3 mystra-compiler.py v8-rules.tsl            # -> v8-rules.tbin

# Inspect the compiled binary (rules, sub-rules, var table)
python3 mystra-compiler.py --dump v8-rules.tbin | head -40
```

The engine loads `./language/v8-rules.tbin` by default, or the path in the
`DTA_RULES_PATH` environment variable.

### Regenerating the parser (only if you edit `grammar.js`)

```bash
npx tree-sitter generate            # grammar.js -> src/parser.c
npx tree-sitter build -o tsl_parser.so
npx tree-sitter parse v8-rules.tsl  # sanity-check: no ERROR nodes
```

## Editor support

### VS Code

The extension in `vscode-tsl/` provides syntax highlighting for `.tsl` files.

```bash
# Install the prebuilt package:
code --install-extension vscode-tsl/tsl-language-0.1.0.vsix

# Or, after editing the TextMate grammar, rebuild the .vsix:
cd vscode-tsl && npx @vscode/vsce package
```

After installing, `.tsl` files are highlighted automatically (the extension
registers the `.tsl` file extension). Reload the window if it doesn't apply.

### Tree-sitter editors (Neovim, Helix, …)

Use `queries/highlights.scm` with the generated parser. For Neovim + nvim-treesitter,
register the grammar (pointing at this directory) and drop `highlights.scm` into
`queries/tsl/`. The queries reference the same node names as `grammar.js`.
