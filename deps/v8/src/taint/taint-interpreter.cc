// src/taint/taint-interpreter.cc
#include <cstdio>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "src/taint/taint-interpreter.h"
#include "src/taint/taint-compiler.h"
#include "src/taint/taint-logger.h"
#include "src/flags/flags.h"

namespace dynalysis {

#define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))

// =========================================================================
// Data-Driven Configuration
// =========================================================================
// 1. V8 builtins: O(1) contiguous array indexed by builtin ID
static std::vector<BuiltinRuleDescriptor>* g_builtin_rules = nullptr;

// 2. Node.js native API / third-party extensions: O(1) hash map by signature
static std::unordered_map<std::string, BuiltinRuleDescriptor>* g_host_api_rules = nullptr;

// 3. Bytecode-level rule descriptor — compiled guards evaluated at property store time.
// Populated by InitializeTaintRules from V8_bytecode rules.
// nullptr = no bytecode rules loaded (detection disabled).
static BuiltinRuleDescriptor* g_bytecode_property_store_rule = nullptr;

// 4. Var declarations (tbin v4+) — stored statically for engine initialization
static std::vector<VarDeclaration>* g_var_declarations = nullptr;

// =========================================================================
// Rule loader — .tbin binary only
// =========================================================================
static ParsedRuleSet LoadRules() {
    const char* env_path = std::getenv("DTA_RULES_PATH");
    std::string file_path;

    if (env_path && strlen(env_path) > 0) {
        file_path = std::string(env_path);
    } else {
        file_path = "./language/v8-rules.tbin";
    }

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[DTA-ERROR] Cannot open rules file: " << file_path
                  << " — returning empty ruleset" << std::endl;
        return ParsedRuleSet{};
    }
    size_t sz = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> buf(sz);
    file.read(reinterpret_cast<char*>(buf.data()), sz);
    std::cerr << "[DTA-INFO] Loaded binary rules: " << file_path
              << " (" << sz << " bytes)" << std::endl;
    return TaintCompiler::CompileBinary(buf.data(), buf.size());
}

static void InitializeTaintRules(IVmAdapter& vm) {
    if (g_builtin_rules) return;
    int builtin_count = vm.GetBuiltinCount();
    g_builtin_rules = new std::vector<BuiltinRuleDescriptor>(builtin_count);
    g_host_api_rules = new std::unordered_map<std::string, BuiltinRuleDescriptor>();

    // Load rules (.tbin binary)
    ParsedRuleSet ruleset = LoadRules();

    // Store var declarations for engine initialization
    if (!ruleset.var_declarations.empty()) {
        g_var_declarations = new std::vector<VarDeclaration>(std::move(ruleset.var_declarations));
    }

    // --- v2 path: explicit dispatch category routing ---
    int v8_count = 0, runtime_count = 0, node_count = 0;
    for (auto& [name, desc] : ruleset.rules) {
        switch (desc.category) {
            case DispatchCategory::kV8Native: {
                int id = vm.GetBuiltinId(name.c_str());
                if (name.find("Slice") != std::string::npos) {
                    std::fprintf(stderr, "[DTA-DEBUG] Rule '%s' -> builtin_id=%d\n", name.c_str(), id);
                }
                if (id >= 0 && id < builtin_count) {
                    (*g_builtin_rules)[id] = std::move(desc);
                    (*g_builtin_rules)[id].is_valid = true;
                    v8_count++;
                }
                break;
            }
            case DispatchCategory::kV8Runtime:
                // Runtime rules go into host_apis with "Runtime_" prefix
                // (the runtime action table lookup uses this prefix)
                (*g_host_api_rules)[name] = std::move(desc);
                runtime_count++;
                break;
            case DispatchCategory::kNode:
                (*g_host_api_rules)[name] = std::move(desc);
                node_count++;
                break;
            case DispatchCategory::kV8Bytecode:
                // Merge bytecode rules into a single descriptor.
                // Multiple bytecode rules (StaKeyedProperty + StaNamedProperty)
                // share the same property store hook — merge their sub-rules.
                if (!g_bytecode_property_store_rule) {
                    g_bytecode_property_store_rule = new BuiltinRuleDescriptor(std::move(desc));
                } else {
                    // Append sub-rules from this rule to the existing descriptor
                    for (auto& sr : desc.sub_rules) {
                        g_bytecode_property_store_rule->sub_rules.push_back(std::move(sr));
                    }
                }
                break;
            default:
                // kLegacy: should not appear in v2 rules
                (*g_host_api_rules)[name] = std::move(desc);
                break;
        }
    }

    // --- v1 legacy path: infer category from name matching ---
    // (v1 binary still populates v8_builtins / host_apis)
    for (auto& [name, desc] : ruleset.v8_builtins) {
        int id = vm.GetBuiltinId(name.c_str());
        if (id >= 0 && id < builtin_count) {
            (*g_builtin_rules)[id] = std::move(desc);
            (*g_builtin_rules)[id].is_valid = true;
            v8_count++;
        }
    }
    for (int i = 0; i < builtin_count; i++) {
        if ((*g_builtin_rules)[i].is_valid) continue;
        const char* builtin_name = vm.GetBuiltinName(i);
        if (!builtin_name) continue;
        auto it = ruleset.host_apis.find(builtin_name);
        if (it != ruleset.host_apis.end()) {
            (*g_builtin_rules)[i] = std::move(it->second);
            (*g_builtin_rules)[i].is_valid = true;
            ruleset.host_apis.erase(it);
            v8_count++;
        }
    }
    for (auto& [name, desc] : ruleset.host_apis) {
        (*g_host_api_rules)[name] = std::move(desc);
        node_count++;
    }

    // Precompute HOF descriptors for all builtin rules.
    // INJECT/EXTRACT sub-rules are identified once at init-time so
    // DtaPushFrameAndLeave can dispatch them without scanning sub_rules.
    int hof_count = 0;
    for (auto& desc : *g_builtin_rules) {
        if (!desc.is_valid) continue;
        for (const auto& sr : desc.sub_rules) {
            if (sr.action == ActionType::kInject) {
                desc.hof.is_hof = true;
                desc.hof.inject_rules.push_back(&sr);
            } else if (sr.action == ActionType::kExtract) {
                desc.hof.is_hof = true;
                desc.hof.extract_rules.push_back(&sr);
            }
        }
        if (desc.hof.is_hof) hof_count++;
    }

    std::cerr << "[DTA-INIT] Rules: V8_native=" << v8_count
              << " V8_runtime=" << runtime_count
              << " Node=" << node_count
              << " HOF=" << hof_count;
    if (g_bytecode_property_store_rule) {
        std::cerr << " Bytecode=" << g_bytecode_property_store_rule->sub_rules.size() << "rules";
    }
    if (g_var_declarations) {
        std::cerr << " Vars=" << g_var_declarations->size();
    }
    std::cerr << std::endl;
}

// Phase 3: Eager initialization — called via TaintAdapter::EagerInitializeForIsolate
void TslInterpreter::EagerInitialize(IVmAdapter& vm) {
    InitializeTaintRules(vm);
    // Populate the per-Isolate builtin skip bitmap
    if (!vm.GetBuiltinBitmap()) {
        int count = vm.GetBuiltinCount();
        uint8_t* bm = new uint8_t[count]();
        PopulateBuiltinSkipBitmap(bm, count,
            vm.GetBuiltinId("FunctionPrototypeCall"),
            vm.GetBuiltinId("FunctionPrototypeApply"),
            vm.GetBuiltinId("HandleApiCallOrConstruct"),
            vm.GetBuiltinId("ReflectApply"));
        vm.SetBuiltinBitmap(bm);
    }
    // Populate the per-Isolate runtime action table (O(1) skip byte lookup)
    if (!vm.GetRuntimeActionTable()) {
        int count = vm.GetRuntimeCount();
        uint8_t* table = new uint8_t[count];
        // Default: all runtime functions are Untracked (0x03 = fast skip, clear acc)
        std::memset(table, 0x03, count);
        // Override from rules with V8_runtime category or "Runtime_" prefix
        if (g_host_api_rules) {
            for (int i = 0; i < count; i++) {
                const char* name = vm.GetRuntimeName(i);
                if (!name) continue;
                // Try v2 format: category=kV8Runtime, key=bare name (e.g. "SetTaint")
                std::string bare_key(name);
                // Try v1 format: key="Runtime_" + name (e.g. "Runtime_SetTaint")
                std::string legacy_key = std::string("Runtime_") + name;
                auto it = g_host_api_rules->find(bare_key);
                if (it == g_host_api_rules->end() ||
                    it->second.category != DispatchCategory::kV8Runtime) {
                    it = g_host_api_rules->find(legacy_key);
                }
                if (it != g_host_api_rules->end()) {
                    bool is_preserve = false;
                    for (const auto& sub : it->second.sub_rules) {
                        if (sub.action == ActionType::kPreserve) {
                            is_preserve = true;
                            break;
                        }
                    }
                    table[i] = is_preserve ? 0x02 : 0x00;
                }
            }
        }
        vm.SetRuntimeActionTable(table);
    }
}

// Forward declaration — CollectSources (VarLookup) calls ResolveValueSource
static uint64_t ResolveValueSource(
    IVmAdapter& vm, TaintEngine* engine, const ValueSource& vs,
    int arg_count, uintptr_t result_addr, bool for_var_key = false);

// =========================================================================
// LAYER 1: COLLECT (Source Locators)
// =========================================================================
std::vector<uint32_t> TslInterpreter::CollectSources(
    IVmAdapter& vm,
    TaintEngine* engine,
    const std::vector<SourceLocator>& locators)
{
    std::vector<uint32_t> sources;
    int arg_count = static_cast<int>(engine->GetArgMappingCount());

    auto add_taint = [&](int rt_idx, OffsetType offset, const char* prop, int dyn_key_arg = -1) {
        if (rt_idx < 0 || rt_idx >= arg_count) {
            return;
        }
        uint32_t t = 0;

        if (offset == OffsetType::kNone) {
            t = vm.GetTaintFromMapping(rt_idx);
        } else {
            // Rule requires deep offset (ELEM/PROP) — resolve physical address
            uintptr_t obj_addr = vm.GetPhysicalAddrFromMapping(rt_idx);
            if (obj_addr != 0) {
                if (offset == OffsetType::kElemShallow || offset == OffsetType::kElemDeep ||
                    offset == OffsetType::kPropShallow || offset == OffsetType::kPropDeep) {
                    // First check the wildcard key itself
                    uintptr_t wkey;
                    if (offset == OffsetType::kElemShallow) wkey = ELEM_SHALLOW_KEY;
                    else if (offset == OffsetType::kElemDeep) wkey = ELEM_DEEP_KEY;
                    else if (offset == OffsetType::kPropDeep) wkey = PROP_DEEP_KEY;
                    else wkey = PROP_SHALLOW_KEY;
                    t = engine->GetHeapTaint(obj_addr, wkey);
                    // If no wildcard entry, scan ALL edge taints on this object.
                    // This catches specific-key entries (e.g., Smi(1) from StaInArrayLiteral)
                    // that indicate "this object has tainted content".
                    if (t == 0) {
                        std::vector<uint32_t> all_taints;
                        engine->CollectAllHeapTaints(obj_addr, all_taints);
                        for (uint32_t at : all_taints) {
                            sources.push_back(at);
                        }
                    }
                } else if (offset == OffsetType::kSpecificProperty && prop) {
                    uintptr_t key = vm.GetPropertyKey(prop);
                    if (key != 0) t = engine->GetHeapTaint(obj_addr, key);
                } else if (offset == OffsetType::kDynamicKey && dyn_key_arg >= 0) {
                    // Dynamic key: resolve arg value as property key
                    int key_rt_idx = dyn_key_arg + 1;  // +1 for receiver offset
                    if (key_rt_idx >= 0 && key_rt_idx < arg_count) {
                        uintptr_t key_obj = vm.GetPhysicalAddrFromMapping(key_rt_idx);
                        if (key_obj != 0) {
                            uintptr_t key = vm.GetDynamicPropertyKey(key_obj);
                            if (key != 0) t = engine->GetHeapTaint(obj_addr, key);
                        }
                    }
                }
            }
        }
        if (t != 0 || offset != OffsetType::kNone) {
            engine->logger()->Collect(rt_idx, (int)offset, vm.GetPhysicalAddrFromMapping(rt_idx), t);
        }
        if (t != 0) {
            sources.push_back(t);
        }
    };

    for (const auto& loc : locators) {
        if (loc.base == BaseEntity::kSelf) {
            add_taint(0, loc.offset, loc.prop_name, loc.dynamic_key_arg_index);
        }
        else if (loc.base == BaseEntity::kArg) {
            int rt_idx = (loc.index >= 0) ? (loc.index + 1) : (arg_count + loc.index);
            add_taint(rt_idx, loc.offset, loc.prop_name, loc.dynamic_key_arg_index);
        }
        else if (loc.base == BaseEntity::kArgRange) {
            int start = (loc.index >= 0) ? (loc.index + 1) : (arg_count + loc.index);
            int end = (loc.end_index == -1) ? arg_count : ((loc.end_index >= 0) ? (loc.end_index + 1) : (arg_count + loc.end_index));
            for (int i = start; i < end; ++i) {
                add_taint(i, loc.offset, loc.prop_name, loc.dynamic_key_arg_index);
            }
        }
        else if (loc.base == BaseEntity::kGlobal) {
            uintptr_t global_obj_addr = vm.GetGlobalProxyAddress();

            uintptr_t key = 0;
            if (loc.offset == OffsetType::kElemShallow || loc.offset == OffsetType::kElemDeep) {
                key = (loc.offset == OffsetType::kElemDeep) ? ELEM_DEEP_KEY : ELEM_SHALLOW_KEY;
            } else if (loc.offset == OffsetType::kPropShallow || loc.offset == OffsetType::kPropDeep) {
                key = (loc.offset == OffsetType::kPropDeep) ? PROP_DEEP_KEY : PROP_SHALLOW_KEY;
            } else if (loc.offset == OffsetType::kSpecificProperty && loc.prop_name) {
                key = vm.GetPropertyKey(loc.prop_name);
            }

            if (key != 0) {
                uint32_t t = engine->GetHeapTaint(global_obj_addr, key);
                if (t != 0) sources.push_back(t);
            }
        }
        else if (loc.base == BaseEntity::kVarLookup) {
            uint16_t var_idx = static_cast<uint16_t>(loc.index);
            uint64_t var_val = 0;
            if (loc.var_key_sources.empty()) {
                var_val = engine->VarGetScalar(var_idx);
            } else if (loc.var_key_sources.size() == 1) {
                uintptr_t k1 = static_cast<uintptr_t>(
                    ResolveValueSource(vm, engine, loc.var_key_sources[0], arg_count, 0, true));
                var_val = engine->VarGetMap1(var_idx, k1);
            } else {
                uintptr_t k1 = static_cast<uintptr_t>(
                    ResolveValueSource(vm, engine, loc.var_key_sources[0], arg_count, 0, true));
                uintptr_t k2 = static_cast<uintptr_t>(
                    ResolveValueSource(vm, engine, loc.var_key_sources[1], arg_count, 0, true));
                var_val = engine->VarGetMap2(var_idx, k1, k2);
            }
            uint32_t t = static_cast<uint32_t>(var_val);
            if (t != 0) {
                // Cross-process bridge: if taint ID doesn't exist locally,
                // create a synthetic source node
                if (engine->GetNode(t) == nullptr) {
                    t = engine->CreateNode("cross-process-bridge");
                }
                sources.push_back(t);
            }
        }
    }
    return sources;
}

// =========================================================================
// LAYER 2: PROPAGATE (Action dispatch and FlowNode graph generation)
// =========================================================================
uint32_t TslInterpreter::Propagate(
    TaintEngine* engine, 
    const std::string& op_label, 
    const std::vector<uint32_t>& sources, 
    ActionType action) 
{
    if (sources.empty() && action != ActionType::kTaintSource) return 0;
    if (action == ActionType::kPropagate || action == ActionType::kCollapse) {
        return engine->CreateNode(op_label, sources);
    } else if (action == ActionType::kForward) {
        return engine->CreateTransformNode(op_label, sources.front());
    } else if (action == ActionType::kTaintSource) {
        return engine->CreateNode(op_label);  // Source node, no parents
    }
    return 0;
}

// =========================================================================
// GUARD EVALUATION (Datalog-style predicate filter)
// Category 1: @argc, @is_new, .tainted, .isnull, .type — evaluated now
// Category 2: .value — always returns true (sound overapproximation)
// =========================================================================
static bool EvaluateOneGuard(IVmAdapter& vm, TaintEngine* engine,
                             const GuardPredicate& g,
                             int override_arg_count = -1) {
    using ET = GuardPredicate::ExprType;
    using MP = GuardPredicate::MagicPropType;
    using CO = GuardPredicate::CompareOp;

    // Category 2: .value — always true (deferred)
    if (g.expr_type == ET::kLocatorValue) return true;

    // Category 3: var store lookup
    if (g.expr_type == ET::kVarLookup) {
        int ac = (override_arg_count >= 0)
                     ? override_arg_count
                     : static_cast<int>(engine->GetArgMappingCount());
        uint64_t var_val = 0;
        if (g.var_key_sources.empty()) {
            var_val = engine->VarGetScalar(g.var_index);
        } else if (g.var_key_sources.size() == 1) {
            uintptr_t k1 = static_cast<uintptr_t>(
                ResolveValueSource(vm, engine, g.var_key_sources[0], ac, 0, true));
            var_val = engine->VarGetMap1(g.var_index, k1);
        } else {
            uintptr_t k1 = static_cast<uintptr_t>(
                ResolveValueSource(vm, engine, g.var_key_sources[0], ac, 0, true));
            uintptr_t k2 = static_cast<uintptr_t>(
                ResolveValueSource(vm, engine, g.var_key_sources[1], ac, 0, true));
            var_val = engine->VarGetMap2(g.var_index, k1, k2);
        }

        bool result = true;
        if (g.magic_prop == MP::kTainted) {
            bool val = (var_val != 0);
            if (g.compare_op == CO::kEq) result = (val == g.literal_bool);
            else if (g.compare_op == CO::kNeq) result = (val != g.literal_bool);
        } else {
            // kValue or kNA: compare var_val as integer
            int int_cmp = static_cast<int>(var_val);
            int lit = g.literal_int;
            switch (g.compare_op) {
                case CO::kEq:  result = (int_cmp == lit); break;
                case CO::kNeq: result = (int_cmp != lit); break;
                case CO::kGt:  result = (int_cmp > lit);  break;
                case CO::kGte: result = (int_cmp >= lit); break;
                case CO::kLt:  result = (int_cmp < lit);  break;
                case CO::kLte: result = (int_cmp <= lit); break;
                default: break;
            }
        }
        return g.negate ? !result : result;
    }

    int int_val = 0;
    bool bool_val = false;
    const char* str_val = nullptr;
    bool is_int_expr = false;
    bool is_bool_expr = false;
    bool is_str_expr = false;

    if (g.expr_type == ET::kMagicGlobal) {
        if (g.magic_global_id == 0) {
            // @argc — subtract receiver to get user-visible arg count
            int_val = static_cast<int>(engine->GetArgMappingCount()) - 1;
            is_int_expr = true;
        } else if (g.magic_global_id == 1) {
            // @is_new
            bool_val = vm.IsConstructCall();
            is_bool_expr = true;
        }
    } else if (g.expr_type == ET::kLocatorMagicProp) {
        int rt_idx = g.param_index + 1;  // +1 for receiver offset
        if (g.param_index == -1) rt_idx = 0;  // @self

        if (g.magic_prop == MP::kTainted) {
            bool_val = (vm.GetTaintFromMapping(rt_idx) != 0);
            is_bool_expr = true;
        } else if (g.magic_prop == MP::kIsNull) {
            bool_val = vm.IsNullOrUndefined(rt_idx);
            is_bool_expr = true;
        } else if (g.magic_prop == MP::kType) {
            str_val = vm.GetTypeTag(rt_idx);
            is_str_expr = true;
        } else if (g.magic_prop == MP::kIsCallback) {
            bool_val = vm.IsCallable(rt_idx);
            is_bool_expr = true;
        } else if (g.magic_prop == MP::kIsPrototype) {
            bool_val = vm.IsPrototypeObject(rt_idx);
            is_bool_expr = true;
        }
    }

    bool result = true;  // default: pass (sound)

    if (is_int_expr) {
        int lit = g.literal_int;
        switch (g.compare_op) {
            case CO::kEq:  result = (int_val == lit); break;
            case CO::kNeq: result = (int_val != lit); break;
            case CO::kGt:  result = (int_val > lit);  break;
            case CO::kGte: result = (int_val >= lit); break;
            case CO::kLt:  result = (int_val < lit);  break;
            case CO::kLte: result = (int_val <= lit); break;
            default: break;
        }
    } else if (is_bool_expr) {
        bool lit = g.literal_bool;
        if (g.compare_op == CO::kEq) result = (bool_val == lit);
        else if (g.compare_op == CO::kNeq) result = (bool_val != lit);
    } else if (is_str_expr && str_val) {
        if (g.compare_op == CO::kEq) {
            result = g.literal_string && strcmp(str_val, g.literal_string) == 0;
        } else if (g.compare_op == CO::kNeq) {
            result = !g.literal_string || strcmp(str_val, g.literal_string) != 0;
        } else if (g.compare_op == CO::kIn) {
            result = false;
            for (const char* s : g.literal_string_set) {
                if (s && strcmp(str_val, s) == 0) { result = true; break; }
            }
        }
    }

    return g.negate ? !result : result;
}

// =========================================================================
// SET action helpers: resolve ValueSource, execute SET, check @ret references
// =========================================================================
static uint64_t ResolveValueSource(
    IVmAdapter& vm, TaintEngine* engine, const ValueSource& vs,
    int arg_count, uintptr_t result_addr, bool for_var_key) {
    switch (vs.type) {
        case ValueSourceType::kLocatorTaint: {
            int rt_idx = -1;
            if (vs.base == BaseEntity::kSelf) rt_idx = 0;
            else if (vs.base == BaseEntity::kArg) rt_idx = vs.index + 1;
            else if (vs.base == BaseEntity::kReturn) return engine->GetAccumulatorTaint();
            if (rt_idx < 0 || rt_idx >= arg_count) return 0;
            uint32_t t = vm.GetTaintFromMapping(rt_idx);
            if (t != 0) return t;
            // GC-safe deep scan fallback for nested taint
            uintptr_t addr = vm.GetPhysicalAddrFromMapping(rt_idx);
            if (addr != 0) {
                t = engine->GetAnyWildcardTaint(addr);
                if (t != 0) return t;
                std::unordered_set<uint32_t> deep;
                vm.DeepScanObjectForTaint(addr, 0, 3, deep);
                if (!deep.empty()) return *deep.begin();
            }
            return 0;
        }
        case ValueSourceType::kLocatorRef: {
            // For var keys, use content-based hash (cross-process stable)
            if (for_var_key) {
                if (vs.base == BaseEntity::kSelf) return vm.GetStringContentHash(0);
                if (vs.base == BaseEntity::kArg) return vm.GetStringContentHash(vs.index + 1);
                // Return falls through to identity hash
                if (vs.base == BaseEntity::kReturn) return vm.GetIdentityHashForAddr(result_addr);
                return 0;
            }
            if (vs.base == BaseEntity::kSelf) return vm.GetIdentityHash(0);
            if (vs.base == BaseEntity::kReturn) return vm.GetIdentityHashForAddr(result_addr);
            if (vs.base == BaseEntity::kArg) return vm.GetIdentityHash(vs.index + 1);
            return 0;
        }
        case ValueSourceType::kLocatorValue: {
            if (vs.base == BaseEntity::kSelf) return vm.GetParamRawValue(0);
            if (vs.base == BaseEntity::kReturn) return result_addr;
            if (vs.base == BaseEntity::kArg) return vm.GetParamRawValue(vs.index + 1);
            return 0;
        }
        case ValueSourceType::kLiteral: {
            if (vs.literal_type == GuardPredicate::LitType::kInt)
                return static_cast<uint64_t>(vs.literal_int);
            if (vs.literal_type == GuardPredicate::LitType::kBool)
                return vs.literal_bool ? 1 : 0;
            if (vs.literal_type == GuardPredicate::LitType::kString && vs.literal_string)
                return static_cast<uint64_t>(vm.GetPropertyKey(vs.literal_string));
            return 0;
        }
    }
    return 0;
}

static bool SetReferencesReturn(const SubRule& sr) {
    auto refs_ret = [](const ValueSource& vs) {
        return vs.base == BaseEntity::kReturn &&
               vs.type != ValueSourceType::kLiteral;
    };
    if (refs_ret(sr.set_value_source)) return true;
    for (const auto& ks : sr.set_key_sources) {
        if (refs_ret(ks)) return true;
    }
    return false;
}

static void ExecuteSet(IVmAdapter& vm, TaintEngine* engine,
                       const SubRule& sr, int arg_count, uintptr_t result_addr) {
    uint64_t value = ResolveValueSource(vm, engine, sr.set_value_source, arg_count, result_addr);
    if (sr.set_key_sources.empty()) {
        engine->VarSetScalar(sr.set_var_index, value);
    } else if (sr.set_key_sources.size() == 1) {
        uintptr_t k1 = static_cast<uintptr_t>(
            ResolveValueSource(vm, engine, sr.set_key_sources[0], arg_count, result_addr, true));
        engine->VarSetMap1(sr.set_var_index, k1, value);
    } else {
        uintptr_t k1 = static_cast<uintptr_t>(
            ResolveValueSource(vm, engine, sr.set_key_sources[0], arg_count, result_addr, true));
        uintptr_t k2 = static_cast<uintptr_t>(
            ResolveValueSource(vm, engine, sr.set_key_sources[1], arg_count, result_addr, true));
        engine->VarSetMap2(sr.set_var_index, k1, k2, value);
    }
}

bool TslInterpreter::EvaluateGuards(
    IVmAdapter& vm, TaintEngine* engine,
    const std::vector<GuardPredicate>& guards) {
    for (const auto& g : guards) {
        if (!EvaluateOneGuard(vm, engine, g)) return false;
    }
    return true;
}

// =========================================================================
// LAYER 3: SCATTER (Sink Locators)
// =========================================================================
void TslInterpreter::ScatterToSink(
    IVmAdapter& vm,
    TaintEngine* engine,
    uint32_t final_id,
    const SinkLocator& sink,
    uintptr_t result_addr)
{
    if (final_id == 0) return;

    uintptr_t target_addr = 0;
    if (sink.base == BaseEntity::kReturn) {
        target_addr = result_addr;
        engine->SetAccumulatorTaint(final_id);
    } else if (sink.base == BaseEntity::kSelf) {
        target_addr = vm.GetPhysicalAddrFromMapping(0);
    } else if (sink.base == BaseEntity::kGlobal) {
        target_addr = vm.GetGlobalProxyAddress();
    } else if (sink.base == BaseEntity::kArg) {
        int arg_count = static_cast<int>(engine->GetArgMappingCount());
        int rt_idx = (sink.index >= 0) ? (sink.index + 1) : (arg_count + sink.index);
        if (rt_idx >= 0 && rt_idx < arg_count) {
            target_addr = vm.GetPhysicalAddrFromMapping(rt_idx);
        }
    }

    if (target_addr != 0) {
        uintptr_t key = 0;
        if (sink.offset == OffsetType::kElemShallow || sink.offset == OffsetType::kNone) {
            key = ELEM_SHALLOW_KEY;
        } else if (sink.offset == OffsetType::kElemDeep) {
            key = ELEM_DEEP_KEY;
        } else if (sink.offset == OffsetType::kPropShallow) {
            key = PROP_SHALLOW_KEY;
        } else if (sink.offset == OffsetType::kPropDeep) {
            key = PROP_DEEP_KEY;
        } else if (sink.offset == OffsetType::kSpecificProperty && sink.prop_name) {
            key = vm.GetPropertyKey(sink.prop_name);
        } else if (sink.offset == OffsetType::kDynamicKey && sink.dynamic_key_arg_index >= 0) {
            // Dynamic key: resolve arg value as property key at runtime
            int key_rt_idx = sink.dynamic_key_arg_index + 1;  // +1 for receiver offset
            int arg_count = static_cast<int>(engine->GetArgMappingCount());
            if (key_rt_idx >= 0 && key_rt_idx < arg_count) {
                uintptr_t key_obj = vm.GetPhysicalAddrFromMapping(key_rt_idx);
                if (key_obj != 0) {
                    key = vm.GetDynamicPropertyKey(key_obj);
                }
            }
        }

        if (key != 0) {
            engine->logger()->Scatter(target_addr, key, final_id, (int)sink.base);
            engine->SetHeapTaint(target_addr, key, final_id);
        }
    } else {
        engine->logger()->ScatterFail((int)sink.base, sink.index);
    }
}


// =========================================================================
// DESCRIPTOR RESOLUTION — unified rule lookup for all phases
// =========================================================================
const BuiltinRuleDescriptor* TslInterpreter::ResolveDescriptor(TaintEngine* engine) {
    TargetCategory category = engine->GetTargetCategory();
    if (category == TargetCategory::kNativeBuiltin) {
        int target_id = engine->GetTargetId();
        if (target_id >= 0 && target_id < static_cast<int>(g_builtin_rules->size())) {
            const auto& d = (*g_builtin_rules)[target_id];
            return d.is_valid ? &d : nullptr;
        }
    } else if (category == TargetCategory::kHostApi) {
        std::string sig = engine->GetTargetSignature();
        if (g_host_api_rules) {
            auto it = g_host_api_rules->find(sig);
            if (it != g_host_api_rules->end()) return &it->second;
        }
    }
    return nullptr;
}

// =========================================================================
// PHASE ROUTING TABLE — determines which actions fire in which phase
// =========================================================================
bool TslInterpreter::ShouldFireInPhase(ActionType action, ExecutionPhase phase, const SubRule& sr) {
    switch (action) {
        case ActionType::kSink:
            return phase == ExecutionPhase::kPreHook;
        case ActionType::kInject:
            return phase == ExecutionPhase::kHofInject;
        case ActionType::kExtract:
            return phase == ExecutionPhase::kHofExtract;
        case ActionType::kSet:
            if (phase == ExecutionPhase::kPreHook) return !SetReferencesReturn(sr);
            if (phase == ExecutionPhase::kPostHook) return SetReferencesReturn(sr);
            return false;
        default: // kPropagate, kForward, kClear, kPreserve, kCollapse, kTaintSource
            return phase == ExecutionPhase::kPostHook;
    }
}

// =========================================================================
// OPCODE HANDLERS — one per ActionType
// =========================================================================

void TslInterpreter::ExecSink(IVmAdapter& vm, TaintEngine* engine,
                              const SubRule& sr) {
    // Check ALL args for taint (over-approximation for recall).
    // Includes deep scan for nested tainted properties (e.g., opts.cmd).
    int arg_count = static_cast<int>(engine->GetArgMappingCount());
    std::vector<std::pair<int, uint32_t>> tainted_args;  // (arg_index, taint_id)

    for (int i = 0; i < arg_count; i++) {
        uint32_t t = vm.GetTaintFromMapping(i);
        if (t != 0) { tainted_args.push_back({i, t}); continue; }
        uintptr_t obj_addr = vm.GetPhysicalAddrFromMapping(i);
        if (obj_addr == 0) continue;
        t = engine->GetAnyWildcardTaint(obj_addr);
        if (t != 0) { tainted_args.push_back({i, t}); continue; }
        // GC-safe deep scan: walks V8 elements/properties directly without
        // allocating (reads existing FixedArray, no GetOwnKeys).
        std::unordered_set<uint32_t> deep;
        vm.DeepScanObjectForTaint(obj_addr, 0, 3, deep);
        for (uint32_t dt : deep) tainted_args.push_back({i, dt});
    }

    if (!tainted_args.empty()) {
        TargetCategory category = engine->GetTargetCategory();
        std::string sig;
        if (category == TargetCategory::kHostApi) {
            sig = engine->GetTargetSignature();
        } else if (category == TargetCategory::kNativeBuiltin) {
            const char* name = vm.GetBuiltinName(engine->GetTargetId());
            sig = name ? name : "Unknown";
        }
        engine->logger()->Alert(sr.alert_cwe, sig.c_str(),
                                tainted_args, engine);
    }
}

void TslInterpreter::ExecSet(IVmAdapter& vm, TaintEngine* engine,
                             const SubRule& sr, const ExecutionContext& ctx) {
    int ac = static_cast<int>(engine->GetArgMappingCount());
    ExecuteSet(vm, engine, sr, ac, ctx.result_addr);
}

void TslInterpreter::ExecPropagate(IVmAdapter& vm, TaintEngine* engine,
                                   const BuiltinRuleDescriptor& desc,
                                   const SubRule& sr, const ExecutionContext& ctx) {
    auto sources = CollectSources(vm, engine, sr.sources);
    if (sources.empty()) return;
    std::string label = std::string(desc.operation_name) + " [" + sr.label_suffix + "]";
    uint32_t new_id = Propagate(engine, label, sources, sr.action);
    for (const SinkLocator& sink : sr.sinks) {
        ScatterToSink(vm, engine, new_id, sink, ctx.result_addr);
    }
}

void TslInterpreter::ExecForward(IVmAdapter& vm, TaintEngine* engine,
                                 const BuiltinRuleDescriptor& desc,
                                 const SubRule& sr, const ExecutionContext& ctx) {
    auto sources = CollectSources(vm, engine, sr.sources);
    if (sources.empty()) return;
    std::string label = std::string(desc.operation_name) + " [" + sr.label_suffix + "]";
    uint32_t new_id = Propagate(engine, label, sources, ActionType::kForward);
    for (const SinkLocator& sink : sr.sinks) {
        ScatterToSink(vm, engine, new_id, sink, ctx.result_addr);
    }
}

void TslInterpreter::ExecCollapse(IVmAdapter& vm, TaintEngine* engine,
                                  const BuiltinRuleDescriptor& desc,
                                  const SubRule& sr, const ExecutionContext& ctx) {
    auto sources = CollectSources(vm, engine, sr.sources);
    if (sources.empty()) return;
    std::string label = std::string(desc.operation_name) + " [" + sr.label_suffix + "]";
    uint32_t new_id = Propagate(engine, label, sources, ActionType::kCollapse);
    for (const SinkLocator& sink : sr.sinks) {
        ScatterToSink(vm, engine, new_id, sink, ctx.result_addr);
    }
}

void TslInterpreter::ExecTaintSource(IVmAdapter& vm, TaintEngine* engine,
                                     const BuiltinRuleDescriptor& desc,
                                     const SubRule& sr, const ExecutionContext& ctx) {
    std::string label = std::string(desc.operation_name) + " [" + sr.label_suffix + "]";
    uint32_t new_id = Propagate(engine, label, {}, ActionType::kTaintSource);
    for (const SinkLocator& sink : sr.sinks) {
        ScatterToSink(vm, engine, new_id, sink, ctx.result_addr);
    }
}

void TslInterpreter::ExecClear(TaintEngine* engine) {
    engine->SetAccumulatorTaint(0);
}

void TslInterpreter::ExecInject(IVmAdapter& vm, TaintEngine* engine,
                                const BuiltinRuleDescriptor& desc,
                                const SubRule& sr, const ExecutionContext& ctx) {
    for (const SinkLocator& sink : sr.sinks) {
        if (sink.base != BaseEntity::kCallbackParam) continue;

        // Multi-callback filtering: skip rules targeting a different callback
        if (sink.callback_owner_arg_index >= 0 &&
            ctx.matched_callback_arg_index >= 0 &&
            sink.callback_owner_arg_index != ctx.matched_callback_arg_index)
            continue;

        // Spread filtering: skip if callback is before spread start
        if (sink.callback_owner_arg_index == -2 &&
            ctx.matched_callback_arg_index >= 0 &&
            ctx.matched_callback_arg_index < sink.spread_start_index)
            continue;

        int param_idx = sink.index;
        uint32_t taint = 0;

        // PRECISION PATH: read callback's physical arg[param_idx] from frame
        uintptr_t physical_arg = vm.ReadCallbackFrameArg(
            ctx.callback_frame_ptr, param_idx);
        if (physical_arg != 0 && (physical_arg & 1) != 0) {
            // HeapObject (tagged pointer with bit 0 = 1): check heap taint
            uintptr_t addr = physical_arg & ~static_cast<uintptr_t>(1);
            taint = engine->GetAnyWildcardTaint(addr);
        }

        // FALLBACK: container wildcard from rule source locator
        if (!taint && !sr.sources.empty()) {
            auto sources = CollectSources(vm, engine, sr.sources);
            if (!sources.empty()) {
                std::string label = std::string(desc.operation_name) + " [INJECT]";
                taint = Propagate(engine, label, sources, ActionType::kPropagate);
            }
        }

        if (taint && ctx.callback_shadow_base) {
            ctx.callback_shadow_base[ctx.param_operand_base + param_idx] = taint;
            if (param_idx == 0) {
                engine->SetAccumulatorTaint(taint);
            }
            engine->logger()->HofInject(desc.operation_name, param_idx, taint);
        }
    }
}

void TslInterpreter::ExecExtract(IVmAdapter& vm, TaintEngine* engine,
                                 const BuiltinRuleDescriptor& desc,
                                 const SubRule& sr, const ExecutionContext& ctx) {
    uint32_t cb_ret_taint = engine->GetAccumulatorTaint();
    if (cb_ret_taint == 0) return;

    // Multi-callback source filtering
    for (const auto& src : sr.sources) {
        if (src.base == BaseEntity::kCallbackReturn &&
            src.callback_owner_arg_index >= 0 &&
            ctx.matched_callback_arg_index >= 0 &&
            src.callback_owner_arg_index != ctx.matched_callback_arg_index)
            return;  // Skip this rule entirely
    }

    engine->logger()->HofExtract(desc.operation_name, cb_ret_taint);
    for (const SinkLocator& sink : sr.sinks) {
        ScatterToSink(vm, engine, cb_ret_taint, sink, ctx.result_addr);
    }
}

// =========================================================================
// INTERPRETER LOOP — iterate sub-rules, dispatch to opcode handlers
// =========================================================================
uint32_t TslInterpreter::InterpretDescriptor(
    IVmAdapter& vm, TaintEngine* engine,
    const BuiltinRuleDescriptor& desc,
    ExecutionPhase phase,
    const ExecutionContext& ctx)
{
    for (const SubRule& sr : desc.sub_rules) {
        if (!ShouldFireInPhase(sr.action, phase, sr)) continue;
        if (!sr.guards.empty() && !EvaluateGuards(vm, engine, sr.guards)) continue;

        switch (sr.action) {
            case ActionType::kPropagate:
                ExecPropagate(vm, engine, desc, sr, ctx); break;
            case ActionType::kForward:
                ExecForward(vm, engine, desc, sr, ctx); break;
            case ActionType::kCollapse:
                ExecCollapse(vm, engine, desc, sr, ctx); break;
            case ActionType::kTaintSource:
                ExecTaintSource(vm, engine, desc, sr, ctx); break;
            case ActionType::kSink:
                ExecSink(vm, engine, sr); break;
            case ActionType::kSet:
                ExecSet(vm, engine, sr, ctx); break;
            case ActionType::kInject:
                ExecInject(vm, engine, desc, sr, ctx); break;
            case ActionType::kExtract:
                ExecExtract(vm, engine, desc, sr, ctx); break;
            case ActionType::kClear:
                ExecClear(engine); break;
            case ActionType::kPreserve:
                break;  // NOP
        }
    }
    return engine->GetAccumulatorTaint();
}

// =========================================================================
// INTERPRET — unified public entry point
// =========================================================================
uint32_t TslInterpreter::Interpret(
    IVmAdapter& vm, TaintEngine* engine,
    ExecutionPhase phase,
    const ExecutionContext& ctx)
{
    if (!g_builtin_rules || !engine->IsTrackingActive()) return 0;

    const BuiltinRuleDescriptor* desc = ResolveDescriptor(engine);

    // Post-hook: emit [RULE] log + gap reporting
    if (phase == ExecutionPhase::kPostHook) {
        TargetCategory category = engine->GetTargetCategory();
        std::string sig;
        if (category == TargetCategory::kHostApi) {
            sig = engine->GetTargetSignature();
        } else if (category == TargetCategory::kNativeBuiltin) {
            const char* name = vm.GetBuiltinName(engine->GetTargetId());
            sig = name ? name : "";
        }

        if (!sig.empty()) {
            int ac = static_cast<int>(engine->GetArgMappingCount());
            int capped = ac < 8 ? ac : 8;
            uintptr_t addrs[8] = {};
            uint32_t taints[8] = {};
            for (int i = 0; i < capped; i++) {
                addrs[i] = vm.GetPhysicalAddrFromMapping(i);
                taints[i] = vm.GetTaintFromMapping(i);
            }
            engine->logger()->Rule(sig.c_str(), (desc && desc->is_valid), ac, addrs, taints);
        }

        if (!desc || !desc->is_valid) {
            // Gap reporting
            std::string gap_sig;
            const char* gap_ns = nullptr;
            if (category == TargetCategory::kHostApi) {
                gap_sig = engine->GetTargetSignature();
                gap_ns = "host_api";
            } else if (category == TargetCategory::kNativeBuiltin) {
                const char* name = vm.GetBuiltinName(engine->GetTargetId());
                gap_sig = name ? std::string("V8_Builtin_") + name : "";
                gap_ns = "v8_builtin";
            }
            if (!gap_sig.empty() && gap_ns) {
                if (engine->missing_apis_.find(gap_sig) == engine->missing_apis_.end()) {
                    engine->missing_apis_.insert(gap_sig);
                    engine->logger()->Gap(gap_sig.c_str(), gap_ns);
                }
            }
            return 0;
        }

        // Clear accumulator before post-hook propagation (same as old DispatchAndApply)
        engine->SetAccumulatorTaint(0);
    } else {
        if (!desc || !desc->is_valid) return 0;
    }

    return InterpretDescriptor(vm, engine, *desc, phase, ctx);
}

// =========================================================================
// LEGACY DISPATCH METHODS — forwarders to Interpret/InterpretDescriptor
// =========================================================================

// PRE-EXECUTION PIPELINE: Fire Alert rules in the pre-hook
// Called from CallPrepareRuntimeArgs BEFORE function execution.
// At this point: args mapped, frame clean, no exception risk.
void TslInterpreter::DispatchPreExecution(IVmAdapter& vm, TaintEngine* engine) {
    Interpret(vm, engine, ExecutionPhase::kPreHook);
}

// =========================================================================
// POST-EXECUTION PIPELINE: Fire Propagation rules after function execution
// =========================================================================
uint32_t TslInterpreter::DispatchAndApply(
    IVmAdapter& vm,
    TaintEngine* engine,
    uintptr_t result_addr)
{
    ExecutionContext ctx;
    ctx.result_addr = result_addr;
    return Interpret(vm, engine, ExecutionPhase::kPostHook, ctx);
}

// =========================================================================
// Phase 3: Rule existence checks for SFI learning
// =========================================================================
bool TslInterpreter::HasRulesForBuiltin(int builtin_id) {
    if (!g_builtin_rules) return true;  // Not initialized yet — assume rules exist (don't learn)
    if (builtin_id < 0 || builtin_id >= static_cast<int>(g_builtin_rules->size())) return false;
    return (*g_builtin_rules)[builtin_id].is_valid;
}

bool TslInterpreter::HasRulesForHostApi(const std::string& signature) {
    if (!g_host_api_rules) return true;  // Not initialized yet — assume rules exist
    return g_host_api_rules->find(signature) != g_host_api_rules->end();
}

const BuiltinRuleDescriptor* TslInterpreter::GetBytecodePropertyStoreRule() {
    return g_bytecode_property_store_rule;
}

const std::vector<VarDeclaration>* TslInterpreter::GetVarDeclarations() {
    return g_var_declarations;
}

const BuiltinRuleDescriptor* TslInterpreter::GetBuiltinDescriptor(int builtin_id) {
    if (!g_builtin_rules || builtin_id < 0 ||
        builtin_id >= static_cast<int>(g_builtin_rules->size()))
        return nullptr;
    auto& desc = (*g_builtin_rules)[builtin_id];
    return desc.is_valid ? &desc : nullptr;
}

void TslInterpreter::DispatchHofInject(
    IVmAdapter& vm, TaintEngine* engine,
    const BuiltinRuleDescriptor& hof_desc,
    uintptr_t callback_frame_ptr,
    uint32_t* callback_shadow_base,
    int param_operand_base,
    int matched_callback_arg_index)
{
    ExecutionContext ctx;
    ctx.callback_frame_ptr = callback_frame_ptr;
    ctx.callback_shadow_base = callback_shadow_base;
    ctx.param_operand_base = param_operand_base;
    ctx.matched_callback_arg_index = matched_callback_arg_index;
    InterpretDescriptor(vm, engine, hof_desc, ExecutionPhase::kHofInject, ctx);
}

void TslInterpreter::DispatchHofExtract(
    IVmAdapter& vm, TaintEngine* engine,
    const BuiltinRuleDescriptor& hof_desc,
    uintptr_t result_addr,
    int matched_callback_arg_index)
{
    ExecutionContext ctx;
    ctx.result_addr = result_addr;
    ctx.matched_callback_arg_index = matched_callback_arg_index;
    InterpretDescriptor(vm, engine, hof_desc, ExecutionPhase::kHofExtract, ctx);
}

void TslInterpreter::PopulateBuiltinSkipBitmap(uint8_t* bitmap, int builtin_count,
                                                    int call_builtin_id, int apply_builtin_id,
                                                    int api_call_builtin_id,
                                                    int reflect_apply_builtin_id) {
    if (!g_builtin_rules || !bitmap) return;
    // Debug mode: zero the entire bitmap so no builtin is ever inline-skipped.
    if (v8::internal::v8_flags.dta_disable_skipbit) {
        memset(bitmap, 0, builtin_count);
        // Logger not available here (static context); use stderr directly.
        std::cerr << "[DTA-DEBUG] Builtin skip bitmap DISABLED (all zeros)" << std::endl;
        return;
    }
    for (int i = 0; i < builtin_count; i++) {
        bool has_rules = (i < static_cast<int>(g_builtin_rules->size()) &&
                          (*g_builtin_rules)[i].is_valid);
        // These builtins must NEVER be bitmap-skipped:
        // - .call()/.apply(): calling convention unwrap in slow path
        // - HandleApiCallOrConstruct: ALL embedder Host API functions share this
        //   builtin ID; must reach slow path for name-based rule lookup.
        //   Engine-agnostic — works for Node.js, Chromium, Electron, any V8 embedder.
        bool must_not_skip = (i == call_builtin_id || i == apply_builtin_id ||
                              i == api_call_builtin_id || i == reflect_apply_builtin_id);
        bitmap[i] = (has_rules || must_not_skip) ? 0 : 1;
    }
}

} // namespace dynalysis
