#include "taint-core.h"
#include "taint-logger.h"
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <queue>
#include <unordered_set>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace dynalysis {

// =================================================================
// Construction / Destruction
// =================================================================
TaintEngine::TaintEngine(uint32_t* external_acc_ptr,
                         uint32_t** external_frame_base_ptr)
    : acc_taint_ptr_(external_acc_ptr),
      frame_base_ptr_(external_frame_base_ptr) {

    // Root node at index 0 (taint_id == 0 means "clean")
    nodes_.push_back(std::make_unique<FlowNode>(0, "Root", std::vector<uint32_t>{}));

    // Allocate the flat shadow frame arena:
    //   kMaxFrameDepth frames × kFrameSlotCount slots × 4 bytes
    //   = 1024 × 512 × 4 = 2 MB
    size_t arena_bytes = kMaxFrameDepth * kFrameSlotCount * sizeof(uint32_t);
    shadow_arena_ = static_cast<uint32_t*>(std::calloc(arena_bytes, 1));

    // Frame 0 is the sentinel (never popped, catches stray accesses)
    sentinel_frame_base_ = shadow_arena_ + kFrameSlotOffset;
    frame_info_stack_[0] = {0, sentinel_frame_base_};
    frame_stack_top_ = 1;

    // Initialize external pointers so CSA reads valid data from the start
    *frame_base_ptr_ = sentinel_frame_base_;

    // Allocate skip stack on heap (1024 entries, accessed via direct ExternalReference)
    skip_stack_ = static_cast<uint8_t*>(std::calloc(kSkipStackSize, sizeof(uint8_t)));
}

TaintEngine::~TaintEngine() {
    fprintf(stderr, "[DTA-DBG] ~TaintEngine: skip_top=%u frame_depth=%zu nodes=%zu\n",
            skip_top_, frame_stack_top_, nodes_.size());
    if (var_store_fd_ >= 0) {
        close(var_store_fd_);
        // Owner process cleans up the file
        if (!var_store_is_child_ && !var_store_path_.empty()) {
            unlink(var_store_path_.c_str());
        }
    }
    std::free(skip_stack_);
    std::free(shadow_arena_);
}

// =================================================================
// Node Creation (append-only, NO reference counting)
// =================================================================
uint32_t TaintEngine::CreateNode(const std::string& operation) {
    return CreateNode(operation, std::vector<uint32_t>{});
}

uint32_t TaintEngine::CreateNode(const std::string& operation, uint32_t parent) {
    return CreateNode(operation, std::vector<uint32_t>{parent});
}

uint32_t TaintEngine::CreateNode(const std::string& operation, uint32_t p1, uint32_t p2) {
    return CreateNode(operation, std::vector<uint32_t>{p1, p2});
}

uint32_t TaintEngine::CreateNode(const std::string& operation, const std::vector<uint32_t>& parents) {
    is_tracking_active_ = true;
    NotifyTaintLive();
    uint32_t new_id = static_cast<uint32_t>(nodes_.size());

    std::vector<uint32_t> unique_parents;
    for (uint32_t p : parents) {
        if (p != 0 && std::find(unique_parents.begin(), unique_parents.end(), p) == unique_parents.end()) {
            unique_parents.push_back(p);
        }
    }

    std::string loc = GetLocation();
    nodes_.push_back(std::make_unique<FlowNode>(new_id, operation, loc, unique_parents));
    return new_id;
}

uint32_t TaintEngine::CreateTransformNode(const std::string& operation, uint32_t parent_id) {
    if (parent_id == 0 || parent_id >= nodes_.size() || !nodes_[parent_id]) {
        return 0;
    }

    // Fold consecutive identical transforms
    if (nodes_[parent_id]->type == FlowNodeType::kTransform &&
        nodes_[parent_id]->operation == operation) {
        return parent_id;
    }

    NotifyTaintLive();
    uint32_t new_id = static_cast<uint32_t>(nodes_.size());
    std::vector<uint32_t> parents = {parent_id};
    std::string loc = GetLocation();
    nodes_.push_back(std::make_unique<FlowNode>(new_id, operation, loc, parents, FlowNodeType::kTransform));
    return new_id;
}

// =================================================================
// Graph Operations
// =================================================================
void TaintEngine::AddParent(uint32_t child_id, uint32_t parent_id) {
    if (parent_id == 0 || child_id == 0 || child_id >= nodes_.size() || !nodes_[child_id]) return;
    auto& node = nodes_[child_id];
    if (std::find(node->parents.begin(), node->parents.end(), parent_id) != node->parents.end()) {
        return;
    }
    node->parents.push_back(parent_id);
}

const FlowNode* TaintEngine::GetNode(uint32_t id) {
    if (id == 0 || id >= nodes_.size() || !nodes_[id]) return nullptr;
    return nodes_[id].get();
}

std::vector<const FlowNode*> TaintEngine::CollectAncestorDAG(uint32_t tip_id) const {
    std::vector<const FlowNode*> result;
    if (tip_id == 0 || tip_id >= nodes_.size()) return result;

    // BFS to collect all ancestors (including the tip itself)
    std::unordered_set<uint32_t> visited;
    std::queue<uint32_t> work;
    work.push(tip_id);
    visited.insert(tip_id);

    while (!work.empty()) {
        uint32_t id = work.front(); work.pop();
        if (id >= nodes_.size()) continue;
        const FlowNode* node = nodes_[id].get();
        if (!node) continue;
        result.push_back(node);
        for (uint32_t parent_id : node->parents) {
            if (parent_id != 0 && visited.find(parent_id) == visited.end()) {
                visited.insert(parent_id);
                work.push(parent_id);
            }
        }
    }

    // Sort by ascending ID = topological order (parents always have lower IDs)
    std::sort(result.begin(), result.end(),
              [](const FlowNode* a, const FlowNode* b) { return a->id < b->id; });
    return result;
}

// =================================================================
// Epoch Management
// =================================================================
void TaintEngine::ResetEpoch() {
    // Bulk-clear the flow graph (keep the root node)
    nodes_.clear();
    nodes_.push_back(std::make_unique<FlowNode>(0, "Root", std::vector<uint32_t>{}));

    // Clear all shadow heap entries
    shadow_heap_.clear();

    // Reset shadow frame arena to sentinel only
    size_t arena_bytes = kMaxFrameDepth * kFrameSlotCount * sizeof(uint32_t);
    std::memset(shadow_arena_, 0, arena_bytes);
    frame_stack_top_ = 1; // Keep sentinel at [0]
    *frame_base_ptr_ = sentinel_frame_base_;

    // Reset accumulator
    *acc_taint_ptr_ = 0;

    // Reset call frame context
    call_stack_top_ = 0;

    is_tracking_active_ = false; 
    missing_apis_.clear();
}

// =================================================================
// Shadow Heap (unchanged logic, but without RC calls)
// =================================================================
void TaintEngine::SetHeapTaint(uintptr_t obj_addr, uintptr_t field_addr, uint32_t id) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    shadow_heap_[obj_addr][field_addr] = id;
    static const bool dta_dbg_ght = (getenv("DTA_DBG_GHT") != nullptr);
    if (dta_dbg_ght) {
        const char* kind;
        long smi = -1;
        if (field_addr == 0xFFFFFFFFFFFFFFFFULL) kind = "ELEM_SHALLOW";
        else if (field_addr == 0xFFFFFFFFFFFFFFFEULL) kind = "PROP_SHALLOW";
        else if (field_addr == 0xFFFFFFFFFFFFFFFDULL) kind = "PROP_DEEP";
        else if (field_addr == 0xFFFFFFFFFFFFFFFCULL) kind = "ELEM_DEEP";
        else { kind = "SMI/key"; smi = (long)(field_addr >> 32); }
        fprintf(stderr, "[SETHEAP] obj=0x%lx key=0x%lx(%s smi=%ld) id=%u\n",
                (unsigned long)obj_addr, (unsigned long)field_addr, kind, smi, id);
    }
}

uint32_t TaintEngine::GetHeapTaint(uintptr_t obj_addr, uintptr_t field_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto obj_it = shadow_heap_.find(obj_addr);
    if (obj_it != shadow_heap_.end()) {
        // 1. Specific key (exact match)
        auto field_it = obj_it->second.find(field_addr);
        if (field_it != obj_it->second.end()) {
            return field_it->second;
        }
        // 2. DEEP wildcards (stronger — implies SHALLOW)
        auto it = obj_it->second.find(ELEM_DEEP_KEY);
        if (it != obj_it->second.end()) return it->second;
        it = obj_it->second.find(PROP_DEEP_KEY);
        if (it != obj_it->second.end()) return it->second;
        // 3. SHALLOW wildcards (weakest)
        it = obj_it->second.find(ELEM_SHALLOW_KEY);
        if (it != obj_it->second.end()) return it->second;
        it = obj_it->second.find(PROP_SHALLOW_KEY);
        if (it != obj_it->second.end()) return it->second;
    }
    return 0;
}

void TaintEngine::CollectAllHeapTaints(uintptr_t obj_addr, std::vector<uint32_t>& out) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto obj_it = shadow_heap_.find(obj_addr);
    if (obj_it != shadow_heap_.end()) {
        for (const auto& entry : obj_it->second) {
            if (entry.second != 0) {
                out.push_back(entry.second);
            }
        }
    }
}

void TaintEngine::CopyAllHeapTaints(uintptr_t from_addr, uintptr_t to_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto it = shadow_heap_.find(from_addr);
    if (it == shadow_heap_.end()) return;
    auto& target_map = shadow_heap_[to_addr];
    for (const auto& entry : it->second) {
        if (entry.second != 0) {
            target_map[entry.first] = entry.second;
        }
    }
}

bool TaintEngine::HasHeapTaint(uintptr_t obj_addr, uintptr_t field_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto obj_it = shadow_heap_.find(obj_addr);
    if (obj_it != shadow_heap_.end()) {
        return obj_it->second.find(field_addr) != obj_it->second.end();
    }
    return false;
}

void TaintEngine::RemoveHeapTaint(uintptr_t obj_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    shadow_heap_.erase(obj_addr);
}

bool TaintEngine::IsObjectTracked(uintptr_t obj_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    return shadow_heap_.find(obj_addr) != shadow_heap_.end();
}

uint32_t TaintEngine::GetHeapTaintExact(uintptr_t obj_addr, uintptr_t field_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto obj_it = shadow_heap_.find(obj_addr);
    if (obj_it == shadow_heap_.end()) return 0;
    auto field_it = obj_it->second.find(field_addr);
    return (field_it != obj_it->second.end()) ? field_it->second : 0;
}

uint32_t TaintEngine::GetHeapTaintWildcard(uintptr_t obj_addr, bool is_smi_key, bool* out_is_deep) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    *out_is_deep = false;
    auto obj_it = shadow_heap_.find(obj_addr);
    if (obj_it == shadow_heap_.end()) return 0;
    const auto& fields = obj_it->second;
    // Check ALL 4 wildcards with priority order based on key type.
    // DEEP before SHALLOW (DEEP triggers contagion), preferred category first.
    if (is_smi_key) {
        // Smi key: prefer ELEM, then PROP as fallback
        auto it = fields.find(ELEM_DEEP_KEY);
        if (it != fields.end()) { *out_is_deep = true; return it->second; }
        it = fields.find(ELEM_SHALLOW_KEY);
        if (it != fields.end()) { return it->second; }
        it = fields.find(PROP_DEEP_KEY);
        if (it != fields.end()) { *out_is_deep = true; return it->second; }
        it = fields.find(PROP_SHALLOW_KEY);
        if (it != fields.end()) { return it->second; }
    } else {
        // String key: prefer PROP, then ELEM as fallback
        auto it = fields.find(PROP_DEEP_KEY);
        if (it != fields.end()) { *out_is_deep = true; return it->second; }
        it = fields.find(PROP_SHALLOW_KEY);
        if (it != fields.end()) { return it->second; }
        it = fields.find(ELEM_DEEP_KEY);
        if (it != fields.end()) { *out_is_deep = true; return it->second; }
        it = fields.find(ELEM_SHALLOW_KEY);
        if (it != fields.end()) { return it->second; }
    }
    return 0;
}

uint32_t TaintEngine::GetAnyWildcardTaint(uintptr_t obj_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto obj_it = shadow_heap_.find(obj_addr);
    if (obj_it == shadow_heap_.end()) return 0;
    const auto& fields = obj_it->second;
    // Priority: DEEP → SHALLOW (DEEP is stronger, implies SHALLOW).
    // Check all 4 — any hit means the object has taint.
    auto it = fields.find(ELEM_DEEP_KEY);
    if (it != fields.end()) return it->second;
    it = fields.find(PROP_DEEP_KEY);
    if (it != fields.end()) return it->second;
    it = fields.find(ELEM_SHALLOW_KEY);
    if (it != fields.end()) return it->second;
    it = fields.find(PROP_SHALLOW_KEY);
    if (it != fields.end()) return it->second;
    return 0;
}

void TaintEngine::MoveHeapTaint(uintptr_t from_addr, uintptr_t to_addr) {
    std::lock_guard<std::mutex> lock(shadow_heap_mutex_);
    auto node = shadow_heap_.extract(from_addr);
    if (!node.empty()) {
        static const bool dta_dbg_ght = (getenv("DTA_DBG_GHT") != nullptr);
        if (dta_dbg_ght) {
            fprintf(stderr, "[MOVEHEAP] from=0x%lx -> to=0x%lx (%zu fields)\n",
                    (unsigned long)from_addr, (unsigned long)to_addr, node.mapped().size());
        }
        node.key() = to_addr;
        shadow_heap_.insert(std::move(node));
    }
}

// =================================================================
// Shadow Frame Arena (flat contiguous memory)
// =================================================================
uint32_t* TaintEngine::PushShadowFrame(uintptr_t frame_ptr) {
    if (frame_stack_top_ >= kMaxFrameDepth) {
        // Overflow safety: clamp at max, reuse top frame in-place.
        // Do NOT increment frame_stack_top_ — prevents unbounded growth
        // and keeps Push/Pop balanced.
        if (logger_) {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "Shadow frame stack overflow (%zu/%zu). Clamping.",
                     frame_stack_top_, kMaxFrameDepth);
            logger_->Warn(msg);
        }
        return frame_info_stack_[frame_stack_top_ - 1].base;
    }

    // Calculate new frame's position in the arena
    size_t arena_offset = frame_stack_top_ * kFrameSlotCount;
    uint32_t* frame_start = shadow_arena_ + arena_offset;
    uint32_t* new_base = frame_start + kFrameSlotOffset;

    // Zero the frame (fast memset — 512 * 4 = 2 KB) to clear stale taint from
    // a prior occupant of this arena slot. Skipped while no taint has ever been
    // minted: the arena is calloc'd and no SetRegisterTaint can have written a
    // non-zero id yet, so every slot is already zero.
    if (taint_ever_minted_) {
        std::memset(frame_start, 0, kFrameSlotCount * sizeof(uint32_t));
    }

    // Record frame info
    frame_info_stack_[frame_stack_top_] = {frame_ptr, new_base};
    frame_stack_top_++;

    // Update the external pointer for CSA inline access
    *frame_base_ptr_ = new_base;

    return new_base;
}

void TaintEngine::UnwindShadowFramesTo(uintptr_t target_fp) {
    // Pop shadow frames until the top frame belongs to the handler or below.
    // Use >= (not ==) to prevent infinite unwinding if target_fp has no
    // corresponding shadow frame (e.g., C++ entry frame, builtin frame).
    // x64 stack grows downward: handler_fp >= unwound frames' fps.
    while (frame_stack_top_ > 1) {
        uintptr_t top_fp = frame_info_stack_[frame_stack_top_ - 1].frame_ptr;
        if (top_fp >= target_fp) break;
        PopShadowFrame();
    }
    // NOTE: shadow_acc is NOT cleared here. The caller
    // (TaintAdapter::UnwindAndRecoverExceptionTaint) sets it to the
    // thrown object's taint so catch blocks receive the correct taint.
}

uint32_t* TaintEngine::PopShadowFrame() {
    // Never pop below the sentinel
    if (frame_stack_top_ <= 1) {
        *frame_base_ptr_ = sentinel_frame_base_;
        return sentinel_frame_base_;
    }

    frame_stack_top_--;

    // Restore previous frame's base pointer
    uint32_t* prev_base = frame_info_stack_[frame_stack_top_ - 1].base;
    *frame_base_ptr_ = prev_base;

    return prev_base;
}

// Slow-path: find frame by V8 physical frame pointer
void TaintEngine::SetRegisterTaint(uintptr_t frame_ptr, int reg_idx, uint32_t id) {
    // Search from top of stack (most common: accessing current or immediate caller)
    for (size_t i = frame_stack_top_; i > 0; i--) {
        if (frame_info_stack_[i - 1].frame_ptr == frame_ptr) {
            frame_info_stack_[i - 1].base[reg_idx] = id;
            return;
        }
    }
    // Frame not found — write to current frame as fallback
    if (frame_stack_top_ > 0) {
        frame_info_stack_[frame_stack_top_ - 1].base[reg_idx] = id;
    }
}

uint32_t TaintEngine::GetRegisterTaint(uintptr_t frame_ptr, int reg_idx) {
    for (size_t i = frame_stack_top_; i > 0; i--) {
        if (frame_info_stack_[i - 1].frame_ptr == frame_ptr) {
            return frame_info_stack_[i - 1].base[reg_idx];
        }
    }
    return 0;
}

uint32_t TaintEngine::GetEffectiveTaint(uintptr_t frame_ptr, int reg_operand,
                                         uintptr_t obj_addr) {
    // Track 1: Shadow Frame (Reference Flow) — fast path
    uint32_t frame_taint = GetRegisterTaint(frame_ptr, reg_operand);
    if (frame_taint != 0) return frame_taint;

    // Track 2: Shadow Heap (Payload Flow) — fallback for derived strings
    // Skip Smis (bit 0 = 0 in tagged representation means Smi)
    if ((obj_addr & 1) == 0) return 0;

    uintptr_t addr = obj_addr & ~static_cast<uintptr_t>(1);  // untag
    uint32_t heap_taint = GetHeapTaint(addr, ELEM_WILDCARD_KEY);
    if (!heap_taint)
        heap_taint = GetHeapTaint(addr, PROP_WILDCARD_KEY);

    return heap_taint;
}

// =================================================================
// Call Frame Context
// =================================================================
void TaintEngine::EnterCallFrame(uintptr_t frame_ptr) {
    if (call_stack_top_ < 8192) {
        CallFrameContext& ctx = call_stack_[call_stack_top_];
        ctx.caller_frame_ptr = frame_ptr;
        ctx.mapping_count = 0;
        ctx.category = TargetCategory::kUnknown;
        ctx.target_id = -1;
        ctx.target_func_addr = 0;
        ctx.target_signature[0] = '\0';
        ctx.shadow_depth_at_entry = frame_stack_top_;
        std::memset(ctx.arg_physical_addrs, 0, sizeof(ctx.arg_physical_addrs));
        call_stack_top_++;
    } else {
        if (logger_) logger_->Warn("Call frame stack full");
    }
}

void TaintEngine::LeaveCallFrame() {
    if (call_stack_top_ > 0) {
        call_stack_top_--;
    }
}

void TaintEngine::SetCurrentTarget(TargetCategory category, int id) {
    if (call_stack_top_ > 0) {
        call_stack_[call_stack_top_ - 1].category = category;
        call_stack_[call_stack_top_ - 1].target_id = id;
    }
}

TargetCategory TaintEngine::GetTargetCategory() {
    if (call_stack_top_ > 0) {
        return call_stack_[call_stack_top_ - 1].category;
    }
    return TargetCategory::kUnknown;
}

int TaintEngine::GetTargetId() {
    if (call_stack_top_ > 0) {
        return call_stack_[call_stack_top_ - 1].target_id;
    }
    return -1;
}

bool TaintEngine::IsCurrentCallConstruct() {
    if (call_stack_top_ > 0) {
        return call_stack_[call_stack_top_ - 1].is_construct;
    }
    return false;
}

void TaintEngine::SetCurrentCallConstruct(bool is_construct) {
    if (call_stack_top_ > 0) {
        call_stack_[call_stack_top_ - 1].is_construct = is_construct;
    }
}

void TaintEngine::PushArgMapping(int reg_idx) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        if (ctx.mapping_count < 32) {
            ctx.arg_reg_mapping[ctx.mapping_count++] = reg_idx;
        }
    }
}

void TaintEngine::SetArgMapping(size_t index, int reg_idx) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        if (index < 32) {
            ctx.arg_reg_mapping[index] = reg_idx;
        }
    }
}

void TaintEngine::SetArgMappingCount(size_t count) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        ctx.mapping_count = static_cast<int>(count < 32 ? count : 32);
    }
}

void TaintEngine::SetArgPhysicalAddr(size_t index, uintptr_t addr) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        if (index < 32) {
            ctx.arg_physical_addrs[index] = addr;
        }
    }
}

uintptr_t TaintEngine::GetArgPhysicalAddr(size_t index) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        if (index < static_cast<size_t>(ctx.mapping_count)) {
            return ctx.arg_physical_addrs[index];
        }
    }
    return 0;
}

int TaintEngine::GetArgMapping(size_t index) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        if (index < static_cast<size_t>(ctx.mapping_count)) {
            return ctx.arg_reg_mapping[index];
        }
    }
    return -999;
}

uintptr_t TaintEngine::GetCallerFramePtr() {
    if (call_stack_top_ > 0) {
        return call_stack_[call_stack_top_ - 1].caller_frame_ptr;
    }
    return 0;
}

size_t TaintEngine::GetArgMappingCount() {
    if (call_stack_top_ > 0) {
        return call_stack_[call_stack_top_ - 1].mapping_count;
    }
    return 0;
}

void TaintEngine::SetCurrentTargetSignature(TargetCategory category, const std::string& signature) {
    if (call_stack_top_ > 0) {
        CallFrameContext& ctx = call_stack_[call_stack_top_ - 1];
        ctx.category = category;
        snprintf(ctx.target_signature, sizeof(ctx.target_signature), "%s", signature.c_str());
    }
}

std::string TaintEngine::GetTargetSignature() {
    if (call_stack_top_ > 0) {
        const char* sig = call_stack_[call_stack_top_ - 1].target_signature;
        if (sig && sig[0] != '\0') return std::string(sig);
    }
    return "";
}

void TaintEngine::SetTargetFuncAddr(uintptr_t addr) {
    if (call_stack_top_ > 0) {
        call_stack_[call_stack_top_ - 1].target_func_addr = addr;
    }
}

uintptr_t TaintEngine::GetTargetFuncAddr() {
    if (call_stack_top_ > 0) {
        return call_stack_[call_stack_top_ - 1].target_func_addr;
    }
    return 0;
}

// =================================================================
// Flow Tree Printer
// =================================================================
void TaintEngine::PrintFlowTree(uint32_t node_id) {
    fprintf(stderr, "\n=== Taint Flow Tree (ID: %u) ===\n", node_id);
    PrintFlowTreeRecursive(node_id, "", true);
    fprintf(stderr, "================================\n\n");
}

void TaintEngine::PrintFlowTreeRecursive(uint32_t node_id, const std::string& prefix, bool is_last) {
    if (node_id == 0 || node_id >= nodes_.size() || !nodes_[node_id]) {
        return;
    }

    const auto& node = nodes_[node_id];
    std::string type_str;
    switch (node->type) {
        case FlowNodeType::kSource: type_str = "Source"; break;
        case FlowNodeType::kDerive: type_str = "Propagate"; break;
        case FlowNodeType::kTransform: type_str = "Forward"; break;
        default: type_str = "Unknown"; break;
    }

    fprintf(stderr, "%s%s[ID: %u] %s [%s]\n",
        prefix.c_str(),
        is_last ? "\\-- " : "|-- ",
        node->id,
        node->operation.c_str(),
        type_str.c_str());

    std::string new_prefix = prefix + (is_last ? "    " : "|   ");
    for (size_t i = 0; i < node->parents.size(); ++i) {
        bool is_last_child = (i == node->parents.size() - 1);
        PrintFlowTreeRecursive(node->parents[i], new_prefix, is_last_child);
    }
}

// =================================================================
// Var Store (Mystra var declarations)
// =================================================================
void TaintEngine::InitVarStore(const std::vector<VarDeclaration>& decls) {
    var_store_.resize(decls.size());
    for (size_t i = 0; i < decls.size(); i++) {
        var_store_[i].value_type = decls[i].value_type;
        var_store_[i].structure = decls[i].structure;
        var_store_[i].scalar = 0;
        var_store_[i].map1.clear();
        var_store_[i].map2.clear();
    }
    InitFileVarStore();
}

void TaintEngine::VarSetScalar(uint16_t var_idx, uint64_t value) {
    if (var_idx >= var_store_.size()) return;
    if (var_store_[var_idx].structure != VarStructure::kScalar) return;
    var_store_[var_idx].scalar = value;
    AppendVarFileEntry(var_idx, 0, value);
}

uint64_t TaintEngine::VarGetScalar(uint16_t var_idx) {
    if (var_idx >= var_store_.size()) return 0;
    if (var_store_[var_idx].structure != VarStructure::kScalar) return 0;
    uint64_t val = var_store_[var_idx].scalar;
    if (val == 0 && var_store_is_child_ && !var_store_synced_) {
        SyncVarStoreFromFile();
        val = var_store_[var_idx].scalar;
    }
    return val;
}

void TaintEngine::VarSetMap1(uint16_t var_idx, uintptr_t key1, uint64_t value) {
    if (var_idx >= var_store_.size()) return;
    if (var_store_[var_idx].structure != VarStructure::kMap1) return;
    var_store_[var_idx].map1[key1] = value;
    AppendVarFileEntry(var_idx, static_cast<uint64_t>(key1), value);
}

uint64_t TaintEngine::VarGetMap1(uint16_t var_idx, uintptr_t key1) {
    if (var_idx >= var_store_.size()) return 0;
    if (var_store_[var_idx].structure != VarStructure::kMap1) return 0;
    auto it = var_store_[var_idx].map1.find(key1);
    if (it != var_store_[var_idx].map1.end()) return it->second;
    if (var_store_is_child_ && !var_store_synced_) {
        SyncVarStoreFromFile();
        it = var_store_[var_idx].map1.find(key1);
        if (it != var_store_[var_idx].map1.end()) return it->second;
    }
    return 0;
}

bool TaintEngine::VarHasMap1(uint16_t var_idx, uintptr_t key1) const {
    if (var_idx >= var_store_.size()) return false;
    if (var_store_[var_idx].structure != VarStructure::kMap1) return false;
    return var_store_[var_idx].map1.find(key1) != var_store_[var_idx].map1.end();
}

void TaintEngine::VarSetMap2(uint16_t var_idx, uintptr_t key1, uintptr_t key2, uint64_t value) {
    if (var_idx >= var_store_.size()) return;
    if (var_store_[var_idx].structure != VarStructure::kMap2) return;
    var_store_[var_idx].map2[key1][key2] = value;
}

uint64_t TaintEngine::VarGetMap2(uint16_t var_idx, uintptr_t key1, uintptr_t key2) const {
    if (var_idx >= var_store_.size()) return 0;
    if (var_store_[var_idx].structure != VarStructure::kMap2) return 0;
    auto it1 = var_store_[var_idx].map2.find(key1);
    if (it1 == var_store_[var_idx].map2.end()) return 0;
    auto it2 = it1->second.find(key2);
    return (it2 != it1->second.end()) ? it2->second : 0;
}

bool TaintEngine::VarHasMap2(uint16_t var_idx, uintptr_t key1, uintptr_t key2) const {
    if (var_idx >= var_store_.size()) return false;
    if (var_store_[var_idx].structure != VarStructure::kMap2) return false;
    auto it1 = var_store_[var_idx].map2.find(key1);
    if (it1 == var_store_[var_idx].map2.end()) return false;
    return it1->second.find(key2) != it1->second.end();
}

// =================================================================
// File-Backed Var Store (Cross-Process Taint Bridging)
// =================================================================

void TaintEngine::InitFileVarStore() {
    const char* env_path = std::getenv("DTA_VARSTORE_PATH");
    if (env_path && env_path[0] != '\0') {
        // Child process: use parent's file
        var_store_path_ = env_path;
        var_store_is_child_ = true;
        var_store_synced_ = false;
        // Open for reading (child) and appending (child may also SET)
        var_store_fd_ = open(var_store_path_.c_str(),
                             O_RDWR | O_CREAT | O_APPEND, 0644);
    } else {
        // Parent process: create new file
        char path_buf[128];
        snprintf(path_buf, sizeof(path_buf), "/tmp/.dta_vars_%d",
                 static_cast<int>(getpid()));
        var_store_path_ = path_buf;
        var_store_is_child_ = false;
        var_store_synced_ = true;  // Parent doesn't need to sync from file
        // Create and open for appending
        var_store_fd_ = open(var_store_path_.c_str(),
                             O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0644);
        // Set env var so children inherit the path
        setenv("DTA_VARSTORE_PATH", var_store_path_.c_str(), 0);
    }
}

void TaintEngine::AppendVarFileEntry(uint16_t var_idx, uint64_t key,
                                     uint64_t value) {
    if (var_store_fd_ < 0) return;
    VarFileEntry entry;
    entry.var_idx = var_idx;
    entry.pad = 0;
    entry.pad2 = 0;
    entry.key = key;
    entry.value = value;
    // Atomic-ish append (O_APPEND guarantees atomic writes < PIPE_BUF on Linux)
    (void)write(var_store_fd_, &entry, sizeof(entry));
}

void TaintEngine::SyncVarStoreFromFile() {
    if (var_store_synced_ || var_store_fd_ < 0) return;
    var_store_synced_ = true;

    // Read entire file from beginning
    int fd = open(var_store_path_.c_str(), O_RDONLY);
    if (fd < 0) return;

    VarFileEntry entry;
    while (read(fd, &entry, sizeof(entry)) == sizeof(entry)) {
        uint16_t idx = entry.var_idx;
        if (idx >= var_store_.size()) continue;

        if (entry.key == 0 &&
            var_store_[idx].structure == VarStructure::kScalar) {
            // Scalar entry
            var_store_[idx].scalar = entry.value;
        } else if (var_store_[idx].structure == VarStructure::kMap1) {
            // Map1 entry: last-writer-wins
            var_store_[idx].map1[static_cast<uintptr_t>(entry.key)] = entry.value;
        }
        // Note: Map2 entries use key as (key1 ^ key2) — simplified for now.
        // Full Map2 support would need a different file format entry.
    }
    close(fd);
}

} // namespace dynalysis
