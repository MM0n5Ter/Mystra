// taint-core.h — Dynamic Taint Analysis Core Engine
// Pure C++ implementation with no V8 type dependencies.
// Shares state with the Isolate's hot fields via external pointers.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <memory>
#include <cstring>
#include <unordered_set>

namespace dynalysis {

class DtaLogger;  // forward decl (defined in taint-logger.h)

// =========================================================================
// Global constants: shadow heap wildcard keys
// =========================================================================
// 4-Wildcard System (Mystra-driven recursion semantics)
// SHALLOW: propagates taint to shadow_acc on read, but does NOT contagion result
// DEEP:    propagates taint to shadow_acc AND sets wildcard on result object (recursive)
constexpr uintptr_t ELEM_SHALLOW_KEY = 0xFFFFFFFFFFFFFFFF; // [*]  — element, no recursion
constexpr uintptr_t PROP_SHALLOW_KEY = 0xFFFFFFFFFFFFFFFE; // .*   — property, no recursion
constexpr uintptr_t PROP_DEEP_KEY    = 0xFFFFFFFFFFFFFFFD; // .**  — property, WITH recursion
constexpr uintptr_t ELEM_DEEP_KEY    = 0xFFFFFFFFFFFFFFFC; // [**] — element, WITH recursion

// Backward compatibility aliases
constexpr uintptr_t ELEM_WILDCARD_KEY = ELEM_SHALLOW_KEY;
constexpr uintptr_t PROP_WILDCARD_KEY = PROP_SHALLOW_KEY;

// =========================================================================
// Reserved DTA internal metadata keys (magic keys)
// These occupy the high address range and cannot collide with normal
// Smi indices or String hashes in the dual-layer shadow_heap.
// =========================================================================
constexpr uintptr_t DTA_GENERATOR_ACC_KEY         = 0xDEAD0000; // Generator shadow_acc save/restore
constexpr uintptr_t DTA_PROMISE_RESOLVED_KEY      = 0xDEAD0001; // Promise resolved value taint
constexpr uintptr_t DTA_PROMISE_REJECT_REASON_KEY = 0xDEAD0002; // Promise reject reason taint
constexpr uintptr_t DTA_SERIALIZED_TAINT_KEY      = 0xDEAD0010; // Future: IPC serialization marker

// =========================================================================
// Var store types (used by Mystra var declarations and taint-compiler loader)
// =========================================================================
enum class VarValueType : uint8_t {
    kNumber = 0, kString = 1, kBool = 2, kTaint = 3, kRef = 4
};

enum class VarStructure : uint8_t {
    kScalar = 0, kMap1 = 1, kMap2 = 2
};

struct VarDeclaration {
    const char* name;
    VarValueType value_type;
    VarStructure structure;
    VarValueType key1_type{VarValueType::kNumber};
    VarValueType key2_type{VarValueType::kNumber};
};

// =========================================================================
// Flow graph node types
// =========================================================================
enum class FlowNodeType {
    kSource,     // Taint source (injected by %SetTaint)
    kDerive,     // Derived node (e.g. concat/replace, may have multiple parents)
    kTransform   // Transform node (e.g. toLowerCase/trim, exactly 1 parent)
};

struct FlowNode {
    uint32_t id;
    std::string operation;
    std::string location;  // "filename:line" captured at creation time
    std::vector<uint32_t> parents;
    FlowNodeType type;

    FlowNode() = default;
    FlowNode(uint32_t i, std::string op, std::vector<uint32_t> p, FlowNodeType t = FlowNodeType::kDerive)
        : id(i), operation(std::move(op)), parents(std::move(p)), type(t) {}
    FlowNode(uint32_t i, std::string op, std::string loc, std::vector<uint32_t> p, FlowNodeType t = FlowNodeType::kDerive)
        : id(i), operation(std::move(op)), location(std::move(loc)), parents(std::move(p)), type(t) {}
};

// =========================================================================
// Call target classification
// =========================================================================
enum class TargetCategory {
    kUserFunction,    // User JS function (bytecode-transparent, has DtaRestoreArgs)
    kNativeBuiltin,   // V8 built-in function (opaque, needs summary rules)
    kHostApi,         // Host API (e.g. Node.js native addon)
    kUnknown
};

// =========================================================================
// Call frame context: records arg mapping and classification for a single call
// =========================================================================
struct CallFrameContext {
    TargetCategory category{TargetCategory::kUnknown};
    int target_id{-1};                  // Builtin ID or Runtime function ID
    char target_signature[64];          // Host API signature (e.g. "spawn_sync.spawn")
    int arg_reg_mapping[32];            // Arg index -> register operand mapping
    uintptr_t arg_physical_addrs[32];   // Physical addresses captured in pre-hook
    int mapping_count{0};
    uintptr_t caller_frame_ptr{0};      // Caller's interpreted frame pointer
    uintptr_t target_func_addr{0};      // Raw target address (Smi=Runtime, HeapObj=JSFunction)
    bool is_construct{false};           // true if called via `new` (Construct bytecode)
    size_t shadow_depth_at_entry{0};    // Shadow frame depth when pre-hook fired

    // HOF multi-callback dispatch: callable arguments detected at pre-hook time
    struct CallableArgRecord {
        int owner_arg_index{-1};        // HOF arg position of this callable (0-based)
        uintptr_t func_addr{0};          // Untagged function address for identity matching
    };
    CallableArgRecord callable_args[8]; // Max 8 callable args per HOF call
    int callable_count{0};

    // HOF EXTRACT accumulator: collects callback return taint IDs per-iteration.
    // Flushed as one flat CreateNode on HOF return. No per-iteration graph nodes.
    static constexpr int kMaxHofAcc = 256;
    uint32_t hof_acc[kMaxHofAcc];
    int hof_acc_count{0};
};

// =========================================================================
// TaintEngine — per-Isolate core taint analysis engine
// =========================================================================
class TaintEngine {
public:
    // Shadow frame arena constants
    static constexpr size_t kFrameSlotCount = 512;    // Register range [-256, +255]
    static constexpr size_t kFrameSlotOffset = 256;   // Operand 0 -> array index 256
    static constexpr size_t kMaxFrameDepth = 4096;

    // Constructor takes external pointers to Isolate hot fields,
    // enabling CSA and C++ to share the same accumulator/frame-base memory.
    // Skip stack is allocated internally — accessed via direct ExternalReference.
    TaintEngine(uint32_t* external_acc_ptr, uint32_t** external_frame_base_ptr);
    ~TaintEngine();

    // ---------------------------------------------------------
    // 0. Location provider — set by runtime adapter at init time.
    // ---------------------------------------------------------
    using LocationProviderFn = std::string(*)(void* context);
    void SetLocationProvider(LocationProviderFn fn, void* ctx) {
        location_provider_ = fn;
        location_context_ = ctx;
    }

    // Taint-live callback — set by runtime adapter at init time. Invoked the
    // first time any taint node is minted (CreateNode/CreateTransformNode), so
    // the engine-agnostic core can notify the host runtime that taint has
    // entered without referencing any host (V8) types. Used by V8 to flip an
    // Isolate latch that gates the inline DtaShadowHeapLoad fast path.
    using TaintLiveCallbackFn = void(*)(void* context);
    void SetTaintLiveCallback(TaintLiveCallbackFn fn, void* ctx) {
        taint_live_callback_ = fn;
        taint_live_context_ = ctx;
    }

    // ---------------------------------------------------------
    // 1. Flow graph construction (append-only, no reference counting)
    // ---------------------------------------------------------
    uint32_t CreateNode(const std::string& operation);
    uint32_t CreateNode(const std::string& operation, uint32_t parent);
    uint32_t CreateNode(const std::string& operation, uint32_t p1, uint32_t p2);
    uint32_t CreateNode(const std::string& operation, const std::vector<uint32_t>& parents);
    uint32_t CreateTransformNode(const std::string& operation, uint32_t parent);
    void AddParent(uint32_t child_id, uint32_t parent_id);
    const FlowNode* GetNode(uint32_t id);
    std::vector<const FlowNode*> CollectAncestorDAG(uint32_t tip_id) const;
    void PrintFlowTree(uint32_t node_id);

    // ---------------------------------------------------------
    // 2. Epoch management (bulk clear replaces fine-grained RC)
    // ---------------------------------------------------------
    void ResetEpoch();

    // ---------------------------------------------------------
    // 3. Shadow heap mapping: (object addr, field key) -> taint ID
    // ---------------------------------------------------------
    void SetHeapTaint(uintptr_t obj_addr, uintptr_t field_addr, uint32_t id);
    uint32_t GetHeapTaint(uintptr_t obj_addr, uintptr_t field_addr);
    // Exact key lookup only — no wildcard fallback.
    uint32_t GetHeapTaintExact(uintptr_t obj_addr, uintptr_t field_addr);
    // Wildcard lookup with depth info. Returns taint and sets is_deep flag.
    // Used by property load contagion (needs to know DEEP vs SHALLOW for stamping).
    uint32_t GetHeapTaintWildcard(uintptr_t obj_addr, bool is_smi_key, bool* out_is_deep);
    // Get any wildcard taint from object. Priority: DEEP → SHALLOW.
    // Used by all DETECTION reads (HOF inject, sink checks, heap fallback, etc.).
    uint32_t GetAnyWildcardTaint(uintptr_t obj_addr);
    // Collect all non-zero taint IDs from any field of the object.
    // Used by CollectSources when a rule queries ElementWildcard/PropertyWildcard.
    void CollectAllHeapTaints(uintptr_t obj_addr, std::vector<uint32_t>& out);
    // Copy all shadow heap entries from one object to another (for object spread)
    void CopyAllHeapTaints(uintptr_t from_addr, uintptr_t to_addr);
    bool HasHeapTaint(uintptr_t obj_addr, uintptr_t field_addr);
    void RemoveHeapTaint(uintptr_t obj_addr);
    void MoveHeapTaint(uintptr_t from_addr, uintptr_t to_addr);
    bool IsObjectTracked(uintptr_t obj_addr);

    // ---------------------------------------------------------
    // 4. Shadow frame arena (flat contiguous memory)
    //    CSA accesses the current frame via *frame_base_ptr_ directly
    //    (zero C calls). These C++ methods manage arena lifetime
    //    and slow-path access to non-top frames.
    // ---------------------------------------------------------
    uint32_t* PushShadowFrame(uintptr_t frame_ptr);
    uint32_t* PopShadowFrame();
    void UnwindShadowFramesTo(uintptr_t target_fp);
    size_t* frame_stack_top_address() { return &frame_stack_top_; }
    uint32_t** sentinel_frame_base_address() { return &sentinel_frame_base_; }

    // Skip stack accessors (for ExternalReference)
    uint8_t** skip_stack_ptr_address() { return &skip_stack_; }
    uint8_t* skip_stack_ptr() { return skip_stack_; }
    uint32_t* skip_top_address() { return &skip_top_; }
    uint32_t skip_top() const { return skip_top_; }
    void SetRegisterTaint(uintptr_t frame_ptr, int reg_idx, uint32_t id);
    uint32_t GetRegisterTaint(uintptr_t frame_ptr, int reg_idx);

    // Dual-Track Taint Resolution: returns shadow-frame taint if non-zero,
    // otherwise falls back to shadow-heap taint for the actual object.
    // This is the canonical way to read argument taint for tracked calls.
    uint32_t GetEffectiveTaint(uintptr_t frame_ptr, int reg_operand,
                                uintptr_t obj_addr);

    // ---------------------------------------------------------
    // 5. Shadow accumulator (CSA and C++ share the same uint32_t)
    // ---------------------------------------------------------
    void SetAccumulatorTaint(uint32_t id) { *acc_taint_ptr_ = id; }
    uint32_t GetAccumulatorTaint() { return *acc_taint_ptr_; }

    // ---------------------------------------------------------
    // 6. Call frame context stack
    // ---------------------------------------------------------
    void EnterCallFrame(uintptr_t frame_ptr = 0);
    void LeaveCallFrame();
    void SetCurrentTarget(TargetCategory category, int id = -1);
    TargetCategory GetTargetCategory();
    int GetTargetId();
    bool IsCurrentCallConstruct();
    void SetCurrentCallConstruct(bool is_construct);
    size_t GetCallStackTop() const { return call_stack_top_; }
    // Peek at parent call frame (one level below current top)
    const CallFrameContext* GetParentCallFrame() const {
        if (call_stack_top_ < 2) return nullptr;
        return &call_stack_[call_stack_top_ - 2];
    }
    // Access call stack entry at absolute index
    const CallFrameContext& GetCallStackEntry(size_t idx) const {
        return call_stack_[idx];
    }
    CallFrameContext& GetMutableCallStackEntry(size_t idx) {
        return call_stack_[idx];
    }

    void PushArgMapping(int reg_idx);
    void SetArgMapping(size_t index, int reg_idx);
    void SetArgMappingCount(size_t count);
    void SetArgPhysicalAddr(size_t index, uintptr_t addr);
    uintptr_t GetArgPhysicalAddr(size_t index);
    int GetArgMapping(size_t index);
    uintptr_t GetCallerFramePtr();
    size_t GetArgMappingCount();

    void SetCurrentTargetSignature(TargetCategory category, const std::string& signature);
    std::string GetTargetSignature();
    void SetTargetFuncAddr(uintptr_t addr);
    uintptr_t GetTargetFuncAddr();

    // ---------------------------------------------------------
    // 7. Activation state and missing-model cache
    // ---------------------------------------------------------
    bool IsTrackingActive() const { return is_tracking_active_; }
    void EnableTracking() { is_tracking_active_ = true; }
    bool is_child_process() const { return var_store_is_child_; }
    std::unordered_set<std::string> missing_apis_;

    // ---------------------------------------------------------
    // 8. Logger (set by Isolate after construction)
    // ---------------------------------------------------------
    void set_logger(DtaLogger* l) { logger_ = l; }
    DtaLogger* logger() const { return logger_; }

    // ---------------------------------------------------------
    // 9. Var store (Mystra var declarations)
    // ---------------------------------------------------------
    void InitVarStore(const std::vector<VarDeclaration>& decls);
    void VarSetScalar(uint16_t var_idx, uint64_t value);
    uint64_t VarGetScalar(uint16_t var_idx);
    void VarSetMap1(uint16_t var_idx, uintptr_t key1, uint64_t value);
    uint64_t VarGetMap1(uint16_t var_idx, uintptr_t key1);
    bool VarHasMap1(uint16_t var_idx, uintptr_t key1) const;
    void VarSetMap2(uint16_t var_idx, uintptr_t key1, uintptr_t key2, uint64_t value);
    uint64_t VarGetMap2(uint16_t var_idx, uintptr_t key1, uintptr_t key2) const;
    bool VarHasMap2(uint16_t var_idx, uintptr_t key1, uintptr_t key2) const;
    uint16_t GetVarCount() const { return static_cast<uint16_t>(var_store_.size()); }

private:
    // Location provider (engine-agnostic callback)
    LocationProviderFn location_provider_ = nullptr;
    void* location_context_ = nullptr;
    std::string GetLocation() {
        if (!location_provider_) return "";
        return location_provider_(location_context_);
    }

    // Taint-live notification (see SetTaintLiveCallback). Fired from the node
    // mint; the callback itself is cheap and idempotent (sets a byte), so it is
    // safe to call on every mint without a separate "first time" guard.
    TaintLiveCallbackFn taint_live_callback_ = nullptr;
    void* taint_live_context_ = nullptr;
    // Monotonic core-side mirror of "any taint ever minted". While false the
    // shadow arena is provably all-zero (calloc'd, never written), so frame
    // pushes can skip the per-entry zeroing memset.
    bool taint_ever_minted_ = false;
    void NotifyTaintLive() {
        taint_ever_minted_ = true;
        if (taint_live_callback_) taint_live_callback_(taint_live_context_);
    }

    // External hot-field pointers (owned by Isolate, shared with CSA)
    uint32_t* acc_taint_ptr_;
    uint32_t** frame_base_ptr_;

    // Flow graph (append-only within an epoch)
    std::vector<std::unique_ptr<FlowNode>> nodes_;
    void PrintFlowTreeRecursive(uint32_t node_id, const std::string& prefix, bool is_last);

    // Shadow heap (guarded by shadow_heap_mutex_ — parallel GC workers call MoveHeapTaint)
    std::mutex shadow_heap_mutex_;
    std::unordered_map<uintptr_t, std::unordered_map<uintptr_t, uint32_t>> shadow_heap_;

    // Shadow frame arena
    uint32_t* shadow_arena_;
    uint32_t* sentinel_frame_base_;
    struct ShadowFrameInfo {
        uintptr_t frame_ptr;
        uint32_t* base;
    };
    ShadowFrameInfo frame_info_stack_[kMaxFrameDepth];
    size_t frame_stack_top_{0};

public:
    // Skip stack (heap-allocated, 4096 entries)
    // Accessed by CSA/Maglev via ExternalReference → direct address into TaintEngine
    uint8_t* skip_stack_{nullptr};
    uint32_t skip_top_{0};
    static constexpr size_t kSkipStackSize = 65536;
private:

    // Call frame context stack
    CallFrameContext call_stack_[8192];
    size_t call_stack_top_{0};

    bool is_tracking_active_{false};
    DtaLogger* logger_{nullptr};

    // Var store (Mystra var declarations)
    struct VarSlot {
        VarValueType value_type;
        VarStructure structure;
        uint64_t scalar{0};
        std::unordered_map<uintptr_t, uint64_t> map1;
        std::unordered_map<uintptr_t, std::unordered_map<uintptr_t, uint64_t>> map2;
    };
    std::vector<VarSlot> var_store_;

    // File-backed var store for cross-process taint bridging
    void InitFileVarStore();
    void SyncVarStoreFromFile();
    void AppendVarFileEntry(uint16_t var_idx, uint64_t key, uint64_t value);
    std::string var_store_path_;
    bool var_store_is_child_{false};
    bool var_store_synced_{false};
    int var_store_fd_{-1};

    // Binary file entry format (24 bytes)
    struct VarFileEntry {
        uint16_t var_idx;
        uint16_t pad;
        uint32_t pad2;
        uint64_t key;
        uint64_t value;
    };
};

} // namespace dynalysis
