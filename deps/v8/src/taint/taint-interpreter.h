// taint-interpreter.h — Mystra Interpreter (Shadow VM Rule Engine)
// Defines the Mystra IR, the VM abstraction
// interface, and the unified interpreter dispatch engine.
#pragma once

#include "src/taint/taint-core.h"
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_set>

namespace dynalysis {

// =========================================================================
// Action types — aligned with Mystra v3 keyword names
// =========================================================================
enum class ActionType {
    kPropagate = 0,    // PROPAGATE: create new derived FlowNode (multi-parent merge)
    kForward = 1,      // FORWARD: copy taint ID unchanged (single parent, cheaper)
    kClear = 2,        // CLEAR: block taint flow (set accumulator = 0)
    kSink = 3,    // SINK: pre-hook security alert with CWE classification
    kPreserve = 4,     // PRESERVE: NOP (keep accumulator taint through trampoline)
    kCollapse = 5,     // COLLAPSE: merge container wildcard [*] into scalar
    kTaintSource = 6,  // TAINT_SOURCE: mark API output as taint origin
    kInject = 7,       // INJECT: bridge taint INTO HOF callback parameters
    kExtract = 8,      // EXTRACT: bridge taint FROM HOF callback return
    kSet = 9,          // SET: write to a Mystra var store
};

// =========================================================================
// Dispatch category — determines C++ lookup table for rule resolution
// Encoded as 1 byte in .tbin v2 binary format per rule.
// =========================================================================
enum class DispatchCategory : uint8_t {
    kV8Native = 0,     // V8 builtin: O(1) array lookup by builtin_id
    kV8Runtime = 1,    // V8 Runtime function: action table by runtime_id
    kV8Bytecode = 2,   // V8 bytecode: bytecode rule table (Phase 4)
    kHostApi = 3,      // Embedder host API (Node.js, Blink DOM, Electron): hash map by signature
    kNode = kHostApi,  // Alias for backward compat
    kLegacy = 0xFF,    // Legacy v1: infer from name matching
};

// =========================================================================
// Mystra Intermediate Representation
// =========================================================================

// Base entity — addressing origin on either side of the arrow
enum class BaseEntity {
    kSelf,           // self (Receiver / this, arg mapping index 0)
    kArg,            // arg[i] (single argument)
    kArgRange,       // arg[start:end] (argument range)
    kReturn,         // ret (return value / accumulator)
    kGlobal,         // global (global proxy object)
    kCallbackParam,  // callback.param[i] (HOF callback parameter)
    kCallbackReturn, // callback.ret (HOF callback return value)
    kVarLookup       // var store lookup as propagation source
};

// Offset type — further addressing on top of the base
// Values must match Python mystra-compiler.py OffsetType enum for binary format compatibility.
enum class OffsetType {
    kNone = 0,              // No heap offset (register/pointer value only)
    kElemShallow = 1,       // [*]  Element shallow wildcard (ELEM_SHALLOW_KEY, no contagion)
    kPropShallow = 2,       // .*   Property shallow wildcard (PROP_SHALLOW_KEY, no contagion)
    kSpecificProperty = 3,  // .xxx Named property (hash / internalized string)
    kDeepScan = 4,          // Unused legacy (was "deep object graph traversal")
    kDynamicKey = 5,        // [key] Dynamic key from another parameter's runtime value
    kElemDeep = 6,          // [**] Element deep wildcard (ELEM_DEEP_KEY, WITH contagion)
    kPropDeep = 7,          // .** Property deep wildcard (PROP_DEEP_KEY, WITH contagion)
    // Backward compat aliases
    kElementWildcard = kElemShallow,
    kPropertyWildcard = kPropShallow
};

// Source locator (LHS) — where to collect taint from
struct SourceLocator {
    BaseEntity base;
    int index{0};           // Target index for kArg; var_index for kVarLookup
    int end_index{-1};      // End index for kArgRange (-1 = through the end)
    OffsetType offset{OffsetType::kNone};
    const char* prop_name{nullptr};
    int dynamic_key_arg_index{-1};  // For kDynamicKey: which arg provides the key
    int callback_owner_arg_index{-1}; // For kCallbackReturn: -1=any, 0+=specific HOF arg, -2=spread
    int spread_start_index{0};        // For spread (-2): first arg index of spread
    std::vector<struct ValueSource> var_key_sources; // For kVarLookup: key resolution
};

// Sink locator (RHS) — where to scatter taint to
struct SinkLocator {
    BaseEntity base;
    int index{0};
    OffsetType offset{OffsetType::kNone};
    const char* prop_name{nullptr};
    int dynamic_key_arg_index{-1};  // For kDynamicKey: which arg provides the key
    int callback_owner_arg_index{-1}; // For kCallbackParam: -1=any, 0+=specific HOF arg, -2=spread
    int spread_start_index{0};        // For spread (-2): first arg index of spread
};

// Guard predicate — Datalog-style filter on when a sub-rule fires
struct GuardPredicate {
    enum class ExprType : uint8_t {
        kMagicGlobal = 0,        // @argc, @is_new
        kLocatorMagicProp = 1,   // x.tainted, x.isnull, x.type
        kLocatorValue = 2,       // x.value (Category 2 — always true in v1)
        kVarLookup = 3           // var store lookup (var[keys].tainted / .value)
    };
    enum class MagicPropType : uint8_t {
        kValue = 0, kTainted = 1, kIsNull = 2, kType = 3,
        kIsCallback = 4, kIsPrototype = 5, kNA = 255
    };
    enum class CompareOp : uint8_t {
        kEq = 0, kNeq = 1, kGt = 2, kGte = 3, kLt = 4, kLte = 5,
        kIn = 6, kMatches = 7
    };
    enum class LitType : uint8_t {
        kString = 0, kInt = 1, kBool = 2, kNull = 3, kStringSet = 4
    };

    ExprType expr_type{ExprType::kMagicGlobal};
    uint8_t magic_global_id{0};       // 0=@argc, 1=@is_new
    int param_index{0};               // For kLocatorMagicProp/kLocatorValue
    const char* prop_name{nullptr};   // For property chain (x.prop.tainted)
    MagicPropType magic_prop{MagicPropType::kNA};
    CompareOp compare_op{CompareOp::kEq};
    bool negate{false};

    LitType literal_type{LitType::kBool};
    const char* literal_string{nullptr};
    int literal_int{0};
    bool literal_bool{false};
    std::vector<const char*> literal_string_set;

    // kVarLookup fields
    uint16_t var_index{0};
    std::vector<struct ValueSource> var_key_sources;
};

// Value source — resolves to a runtime value for SET actions and var guard lookups
enum class ValueSourceType : uint8_t {
    kLocatorTaint = 0,   // Taint ID from locator (base.index)
    kLocatorRef = 1,     // Identity hash / ref from locator
    kLocatorValue = 2,   // Raw value (physical address) from locator
    kLiteral = 3,        // Compile-time literal
};

struct ValueSource {
    ValueSourceType type{ValueSourceType::kLiteral};
    BaseEntity base{BaseEntity::kSelf};
    int index{0};
    GuardPredicate::LitType literal_type{GuardPredicate::LitType::kNull};
    int literal_int{0};
    const char* literal_string{nullptr};
    bool literal_bool{false};
};

// Sub-rule — a single derivation sequent
struct SubRule {
    const char* label_suffix;           // Flow graph node label suffix (e.g. "-> ret[*]")
    ActionType action;
    std::vector<SourceLocator> sources; // LHS: all taint sources
    std::vector<SinkLocator> sinks;     // RHS: all taint sinks
    std::vector<GuardPredicate> guards; // All must pass (AND semantics)
    uint16_t alert_cwe{0};             // CWE ID for Alert actions (0 = unclassified)

    // SET action fields (kSet only)
    uint16_t set_var_index{0};
    std::vector<ValueSource> set_key_sources;
    ValueSource set_value_source;
};

// HOF (Higher-Order Function) descriptor — precomputed INJECT/EXTRACT sub-rules
struct HofDescriptor {
    bool is_hof{false};
    std::vector<const SubRule*> inject_rules;
    std::vector<const SubRule*> extract_rules;
};

// Built-in function rule descriptor
struct BuiltinRuleDescriptor {
    const char* operation_name;         // Operation name (e.g. "StringPrototypeSlice")
    std::vector<SubRule> sub_rules;     // All sub-rules for this function
    bool is_valid{false};               // Whether this is a valid rule (empty slots are false)
    DispatchCategory category{DispatchCategory::kLegacy};  // Mystra v3 dispatch routing
    HofDescriptor hof;                  // Precomputed HOF INJECT/EXTRACT rules
};

// =========================================================================
// VM Abstraction Interface — isolates the core engine from V8 types
// =========================================================================
class IVmAdapter {
public:
    virtual ~IVmAdapter() = default;

    // Arg mapping: physical (untagged) address and taint by arg index
    virtual uintptr_t GetPhysicalAddrFromMapping(int arg_index) = 0;
    virtual uint32_t  GetTaintFromMapping(int arg_index) = 0;

    // Untagged address of the current context's global proxy object
    virtual uintptr_t GetGlobalProxyAddress() = 0;

    // Intern a UTF-8 property name and return its stable untagged address
    virtual uintptr_t GetPropertyKey(const char* prop_name) = 0;

    // Builtin enumeration for rule-table initialization
    virtual int         GetBuiltinCount() = 0;
    virtual const char* GetBuiltinName(int builtin_id) = 0;
    virtual int         GetBuiltinId(const char* name) = 0;

    // Per-isolate builtin skip bitmap lifecycle
    virtual uint8_t* GetBuiltinBitmap() = 0;
    virtual void     SetBuiltinBitmap(uint8_t* bitmap) = 0;

    // Per-isolate runtime action table lifecycle
    virtual int         GetRuntimeCount() = 0;
    virtual const char* GetRuntimeName(int runtime_id) = 0;
    virtual uint8_t*    GetRuntimeActionTable() = 0;
    virtual void        SetRuntimeActionTable(uint8_t* table) = 0;

    // Deep scan: recursively traverse object property graph, collecting taint IDs
    virtual void DeepScanObjectForTaint(uintptr_t obj_addr, int current_depth,
        int max_depth, std::unordered_set<uint32_t>& found_taints) = 0;

    // DynamicKey: resolve a JS value (typically a String) to an interned property key
    virtual uintptr_t GetDynamicPropertyKey(uintptr_t value_addr) = 0;

    // HOF callback frame access: read a callback's physical argument from its frame
    virtual uintptr_t ReadCallbackFrameArg(uintptr_t frame_ptr, int arg_index) = 0;

    // Guard evaluation (Category 1):
    virtual bool IsConstructCall() = 0;               // @is_new
    virtual bool IsNullOrUndefined(int arg_index) = 0; // x.isnull
    virtual bool IsCallable(int arg_index) = 0;        // x.isCallback
    virtual bool IsPrototypeObject(int arg_index) = 0; // x.isPrototype
    virtual const char* GetTypeTag(int arg_index) = 0;  // x.type ("string"/"number"/...)

    // Identity hash and raw value access for SET/var guard resolution
    virtual uintptr_t GetIdentityHash(int arg_index) = 0;
    virtual uintptr_t GetIdentityHashForAddr(uintptr_t addr) = 0;
    virtual uintptr_t GetParamRawValue(int arg_index) = 0;

    // Content-based hash for cross-process var keys (FNV-1a of UTF-8 bytes)
    virtual uint64_t GetStringContentHash(int arg_index) = 0;

    // Debug utilities
    virtual void PrintStackTrace() = 0;
    virtual void PrintObject(uintptr_t obj_addr) = 0;

    // --- Host configuration (engine-specific, resolved by the adapter) ---
    // Path to the compiled .tbin rule file. The core stays filesystem-agnostic;
    // the adapter owns flag/env/default resolution.
    virtual std::string GetRulesPath() = 0;
};

// =========================================================================
// Execution phase — which pipeline stage is invoking the interpreter
// =========================================================================
enum class ExecutionPhase : uint8_t {
    kPreHook    = 0,
    kPostHook   = 1,
    kHofInject  = 2,
    kHofExtract = 3,
};

// =========================================================================
// Execution context — runtime parameters for interpreter dispatch
// =========================================================================
struct ExecutionContext {
    uintptr_t result_addr{0};
    uintptr_t callback_frame_ptr{0};
    uint32_t* callback_shadow_base{nullptr};
    int param_operand_base{0};
    int matched_callback_arg_index{-1};
};

// =========================================================================
// TslInterpreter — Unified Shadow VM interpreter
//
// Replaces the four legacy dispatch methods with a single Interpret() entry
// point that routes sub-rules based on ExecutionPhase. Legacy dispatch
// methods are retained as forwarders for backward compatibility.
// =========================================================================
class TslInterpreter {
public:
    // =====================================================================
    // New unified entry points
    // =====================================================================

    // Interpret rules for the current call frame target in the given phase.
    // Returns the final taint ID (post-hook) or 0 (pre-hook / HOF).
    static uint32_t Interpret(IVmAdapter& vm, TaintEngine* engine,
                              ExecutionPhase phase,
                              const ExecutionContext& ctx = {});

    // Interpret a specific descriptor (for HOF and external callers that
    // already resolved the descriptor).
    static uint32_t InterpretDescriptor(IVmAdapter& vm, TaintEngine* engine,
                                        const BuiltinRuleDescriptor& desc,
                                        ExecutionPhase phase,
                                        const ExecutionContext& ctx = {});

    // =====================================================================
    // Lookup and query
    // Old names are the canonical definitions (implemented in .cc).
    // New names are inline forwarders for the Shadow VM vocabulary.
    // =====================================================================

    // Builtin descriptor lookup by builtin_id (O(1) array access).
    static const BuiltinRuleDescriptor* GetBuiltinDescriptor(int builtin_id);

    // Rule existence queries (for SFI learning mechanism).
    static bool HasRulesForBuiltin(int builtin_id);
    static bool HasRulesForHostApi(const std::string& signature);

    // Bytecode-level rule descriptor (rule-driven switch, no dispatcher).
    // Returns the compiled rule or nullptr if no bytecode rule loaded.
    static const BuiltinRuleDescriptor* GetBytecodePropertyStoreRule();

    // New-name forwarders (Shadow VM vocabulary)
    static inline const BuiltinRuleDescriptor* LookupBuiltin(int builtin_id) {
        return GetBuiltinDescriptor(builtin_id);
    }
    static inline bool HasBuiltinRules(int builtin_id) {
        return HasRulesForBuiltin(builtin_id);
    }
    static inline bool HasHostApiRules(const std::string& signature) {
        return HasRulesForHostApi(signature);
    }
    static inline const BuiltinRuleDescriptor* GetBytecodeRule() {
        return GetBytecodePropertyStoreRule();
    }

    // =====================================================================
    // Legacy dispatch methods (retained for Step 1 compat, removed in Step 4)
    // =====================================================================

    // Pre-hook pipeline: fire Alert rules (args freshly mapped, frame clean,
    // immune to exception unwinding)
    static void DispatchPreExecution(IVmAdapter& vm, TaintEngine* engine);

    // Post-hook pipeline: fire propagation rules (return value available)
    static uint32_t DispatchAndApply(IVmAdapter& vm, TaintEngine* engine, uintptr_t result_addr);

    // HOF INJECT/EXTRACT dispatch — rule-driven callback taint bridging
    // matched_callback_arg_index: -1=unknown/any, 0+=specific HOF arg position
    static void DispatchHofInject(IVmAdapter& vm, TaintEngine* engine,
                                   const BuiltinRuleDescriptor& hof_desc,
                                   uintptr_t callback_frame_ptr,
                                   uint32_t* callback_shadow_base,
                                   int param_operand_base,
                                   int matched_callback_arg_index = -1);
    static void DispatchHofExtract(IVmAdapter& vm, TaintEngine* engine,
                                    const BuiltinRuleDescriptor& hof_desc,
                                    uintptr_t result_addr,
                                    int matched_callback_arg_index = -1);

    // =====================================================================
    // Initialization and infrastructure
    // =====================================================================

    // Var declarations from tbin v4+ (for engine var store initialization)
    static const std::vector<VarDeclaration>* GetVarDeclarations();

    // Populate builtin skip bitmap (builtins without rules marked as skip)
    static void PopulateBuiltinSkipBitmap(uint8_t* bitmap, int builtin_count,
                                          int call_builtin_id, int apply_builtin_id,
                                          int api_call_builtin_id,
                                          int reflect_apply_builtin_id = -1);

    // Eager initialization (called once during Isolate::Init)
    static void EagerInitialize(IVmAdapter& vm);

    // Guard evaluation: returns true if all guards pass (AND semantics)
    static bool EvaluateGuards(IVmAdapter& vm, TaintEngine* engine,
                               const std::vector<GuardPredicate>& guards);

private:
    // =====================================================================
    // Descriptor resolution
    // =====================================================================

    // Resolve the descriptor for the current call frame target.
    static const BuiltinRuleDescriptor* ResolveDescriptor(TaintEngine* engine);

    // Check whether a sub-rule should fire in the given execution phase.
    static bool ShouldFireInPhase(ActionType action, ExecutionPhase phase, const SubRule& sr);

    // =====================================================================
    // Opcode handlers — one per ActionType
    // =====================================================================

    static void ExecPropagate(IVmAdapter& vm, TaintEngine* engine,
                              const BuiltinRuleDescriptor& desc,
                              const SubRule& sr, const ExecutionContext& ctx);
    static void ExecForward(IVmAdapter& vm, TaintEngine* engine,
                            const BuiltinRuleDescriptor& desc,
                            const SubRule& sr, const ExecutionContext& ctx);
    static void ExecCollapse(IVmAdapter& vm, TaintEngine* engine,
                             const BuiltinRuleDescriptor& desc,
                             const SubRule& sr, const ExecutionContext& ctx);
    static void ExecTaintSource(IVmAdapter& vm, TaintEngine* engine,
                                const BuiltinRuleDescriptor& desc,
                                const SubRule& sr, const ExecutionContext& ctx);
    static void ExecSink(IVmAdapter& vm, TaintEngine* engine,
                         const SubRule& sr);
    static void ExecSet(IVmAdapter& vm, TaintEngine* engine,
                        const SubRule& sr, const ExecutionContext& ctx);
    static void ExecInject(IVmAdapter& vm, TaintEngine* engine,
                           const BuiltinRuleDescriptor& desc,
                           const SubRule& sr, const ExecutionContext& ctx);
    static void ExecExtract(IVmAdapter& vm, TaintEngine* engine,
                            const BuiltinRuleDescriptor& desc,
                            const SubRule& sr, const ExecutionContext& ctx);
    static void ExecClear(TaintEngine* engine);

    // =====================================================================
    // Propagation pipeline core components
    // =====================================================================

    static std::vector<uint32_t> CollectSources(
        IVmAdapter& vm, TaintEngine* engine, const std::vector<SourceLocator>& locators);
    static uint32_t Propagate(
        TaintEngine* engine, const std::string& op_label,
        const std::vector<uint32_t>& sources, ActionType action);
    static void ScatterToSink(
        IVmAdapter& vm, TaintEngine* engine, uint32_t final_id,
        const SinkLocator& sink, uintptr_t result_addr);

    // New-name forwarder (Shadow VM vocabulary)
    static inline uint32_t CreateFlowNode(
        TaintEngine* engine, const std::string& op_label,
        const std::vector<uint32_t>& sources, ActionType action) {
        return Propagate(engine, op_label, sources, action);
    }
};

// Backward-compatible alias — allows existing code (taint-adapter.cc, etc.)
// to compile without changes during the transition.
using TaintSummaryEngine = TslInterpreter;

} // namespace dynalysis
