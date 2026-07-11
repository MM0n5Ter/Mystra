// taint-compiler.h — Taint Rule Compiler
// Loads .tbin binary rules into in-memory IR (BuiltinRuleDescriptor) collections.
//
// =========================================================================
// TBIN v2 Binary Protocol (Mystra v3 aligned)
// =========================================================================
//
// Compiler: language/mystra-compiler.py (Lark-based, emits v2)
// Grammar:  DTAdoc/tsl/Grammar_v3.lark
// Loader:   this file (CompileBinary)
//
// Header (14 bytes):
//   [0:4]   Magic "TBIN"
//   [4:6]   Version = 2 (u16 LE)
//   [6:8]   Flags (u16 LE, reserved = 0)
//   [8:10]  RuleCount (u16 LE)
//   [10:14] StringTableOffset (u32 LE)
//
// Per Rule:
//   [0:2]   SignatureIndex (u16 LE) — index into string table
//   [2]     DispatchCategory (u8):
//             0 = V8_native   (builtin ID array, O(1))
//             1 = V8_runtime  (runtime action table, O(1))
//             2 = V8_bytecode (bytecode rule table)
//             3 = Node        (host API hash map)
//   [3]     SubRuleCount (u8)
//
// Per SubRule:
//   [0]     ActionType (u8):
//             0 = Propagate (PROPAGATE)
//             1 = Forward   (FORWARD)
//             2 = Clear     (CLEAR)
//             3 = Sink     (SINK)
//             4 = Preserve  (PRESERVE)
//             5 = Collapse  (COLLAPSE)
//             6 = TaintSource (TAINT_SOURCE)
//             7 = Inject    (INJECT)
//             8 = Extract   (EXTRACT)
//   [1:3]   AlertCWE (u16 LE) — CWE ID for Sink, 0 otherwise
//   [3]     GuardCount (u8)
//   ...guards (variable)
//   [N]     SourceCount (u8)
//   ...sources (variable)
//   [M]     SinkCount (u8)
//   ...sinks (variable)
//
// String Table (at StringTableOffset):
//   [0:2]   EntryCount (u16 LE)
//   Per Entry: Length (u16 LE) + UTF-8 bytes
//
// =========================================================================
#pragma once

#include <string>
#include <unordered_map>
#include "src/taint/taint-interpreter.h"

namespace dynalysis {

// Compilation output: all rules with their dispatch categories
struct ParsedRuleSet {
    // Flat collection: dispatch routing determined by BuiltinRuleDescriptor.category
    std::unordered_map<std::string, BuiltinRuleDescriptor> rules;
    // Legacy split (populated by v1 binary for backward compat)
    std::unordered_map<std::string, BuiltinRuleDescriptor> v8_builtins;
    std::unordered_map<std::string, BuiltinRuleDescriptor> host_apis;
    // Var declarations (tbin v4+)
    std::vector<VarDeclaration> var_declarations;
};

// Rule compiler (stateless, pure static)
class TaintCompiler {
public:
    // Binary .tbin -> in-memory IR
    static ParsedRuleSet CompileBinary(const uint8_t* data, size_t size);
};

} // namespace dynalysis
