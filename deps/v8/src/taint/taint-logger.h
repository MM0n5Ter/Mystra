// taint-logger.h — DTA Unified Logging System
// Pure C++ implementation with no V8 dependencies.
// Same isolation layer as taint-core.h.
#pragma once

#include <cstdint>
#include <cstdio>
#include <utility>
#include <vector>

namespace dynalysis {

// Forward declarations (avoid pulling in taint-core.h)
class TaintEngine;
struct FlowNode;

// =========================================================================
// DtaLogger — per-Isolate structured logging for DTA events
// =========================================================================
// Dual-mode output: JSONL (machine-readable) or text (human-readable).
// Debug/trace methods use inline level check + outlined Impl pattern so
// filtered-out calls compile to a single branch-not-taken on the hot path.
// Alert/Info methods are NOT inlined (rare events).
// =========================================================================

class DtaLogger {
 public:
  enum class Level : uint8_t {
    kOff = 0,     // No logging
    kAlert = 1,   // Alerts only (sink reachability)
    kInfo = 2,    // Alerts + init/warn/error/gap
    kDebug = 3,   // + classify/rule/collect/scatter/binop/hof
    kTrace = 4    // + frame push/pop, object dumps, API calls
  };

  DtaLogger() = default;
  ~DtaLogger();

  // Non-copyable, non-movable
  DtaLogger(const DtaLogger&) = delete;
  DtaLogger& operator=(const DtaLogger&) = delete;

  // --- Lifecycle --------------------------------------------------------
  void Init(const char* json_path, Level level);
  void Shutdown();

  // --- Level query (inline, zero-cost) ----------------------------------
  Level level() const { return level_; }
  bool IsJsonMode() const { return json_file_ != nullptr; }

  // === ALERT LAYER (Level >= kAlert) ====================================
  // These are NOT inlined — rare events, full implementation in .cc.

  // Alert with multiple tainted args: vector of (arg_index, taint_id)
  void Alert(int cwe, const char* sink,
             const std::vector<std::pair<int, uint32_t>>& tainted_args,
             TaintEngine* engine);

  // Alert from bytecode-level detection: single taint_id
  void AlertBytecode(int cwe, const char* sink, uint32_t taint_id,
                     TaintEngine* engine);

  // === INFO LAYER (Level >= kInfo) ======================================

  void Gap(const char* api, const char* ns);
  void InitReport(int v8_native, int v8_runtime, int node, int hof,
                  int bytecode);
  void Warn(const char* msg);
  void Error(const char* msg);

  // === DEBUG LAYER (Level >= kDebug) ====================================
  // Inline level check + outlined Impl.

  inline void Classify(const char* name, const char* category,
                       bool has_rules) {
    if (level_ < Level::kDebug) return;
    ClassifyImpl(name, category, has_rules);
  }

  inline void Rule(const char* sig, bool found, int argc,
                   const uintptr_t* addrs, const uint32_t* taints) {
    if (level_ < Level::kDebug) return;
    RuleImpl(sig, found, argc, addrs, taints);
  }

  inline void Collect(int rt_idx, int offset, uintptr_t addr,
                      uint32_t taint) {
    if (level_ < Level::kDebug) return;
    CollectImpl(rt_idx, offset, addr, taint);
  }

  inline void Scatter(uintptr_t addr, uintptr_t key, uint32_t taint,
                      int base) {
    if (level_ < Level::kDebug) return;
    ScatterImpl(addr, key, taint, base);
  }

  inline void ScatterFail(int base, int index) {
    if (level_ < Level::kDebug) return;
    ScatterFailImpl(base, index);
  }

  inline void BinOp(uint32_t left, uint32_t right, const char* op,
                    uint32_t result, uintptr_t result_addr) {
    if (level_ < Level::kDebug) return;
    BinOpImpl(left, right, op, result, result_addr);
  }

  inline void HofInject(const char* op, int param, uint32_t taint) {
    if (level_ < Level::kDebug) return;
    HofInjectImpl(op, param, taint);
  }

  inline void HofExtract(const char* op, uint32_t taint) {
    if (level_ < Level::kDebug) return;
    HofExtractImpl(op, taint);
  }

  inline void HofExtractAddr(const char* op, uint32_t taint, uintptr_t addr) {
    if (level_ < Level::kDebug) return;
    HofExtractAddrImpl(op, taint, addr);
  }

  inline void HofInjectSkip(int depth, int expected) {
    if (level_ < Level::kDebug) return;
    HofInjectSkipImpl(depth, expected);
  }

  inline void SkipBitmapDisabled() {
    if (level_ < Level::kDebug) return;
    SkipBitmapDisabledImpl();
  }

  // === TRACE LAYER (Level >= kTrace) ====================================

  inline void Frame(uintptr_t fp, int skip_idx, uint8_t old_val,
                    uint8_t new_val, int argc, uint32_t acc,
                    const uint32_t* buf, int buf_len) {
    if (level_ < Level::kTrace) return;
    FrameImpl(fp, skip_idx, old_val, new_val, argc, acc, buf, buf_len);
  }

  inline void FrameHof(uintptr_t fp, int call_top, uint32_t acc, bool hof) {
    if (level_ < Level::kTrace) return;
    FrameHofImpl(fp, call_top, acc, hof);
  }

  inline void ObjectDump(const char* type_name) {
    if (level_ < Level::kTrace) return;
    ObjectDumpImpl(type_name);
  }

  inline void ApiGetTaint(uintptr_t addr, uint32_t elem, uint32_t prop) {
    if (level_ < Level::kTrace) return;
    ApiGetTaintImpl(addr, elem, prop);
  }

 private:
  // --- Internal helpers -------------------------------------------------
  static uint64_t NowMs();
  static void FormatTimestamp(char* buf, size_t size);
  static void EscapeJsonString(const char* src, char* dst, size_t dst_size);
  void SerializeDag(const TaintEngine* engine, uint32_t taint_id, char* buf,
                    size_t buf_size);
  void WriteJsonLine(const char* json_str);
  void WriteText(const char* text);
  void PrintDagText(TaintEngine* engine, uint32_t taint_id);
  void PrintDagTextRecursive(TaintEngine* engine, uint32_t node_id,
                             const char* prefix, bool is_last);

  // --- Outlined Impl methods (Debug layer) ------------------------------
  void ClassifyImpl(const char* name, const char* category, bool has_rules);
  void RuleImpl(const char* sig, bool found, int argc, const uintptr_t* addrs,
                const uint32_t* taints);
  void CollectImpl(int rt_idx, int offset, uintptr_t addr, uint32_t taint);
  void ScatterImpl(uintptr_t addr, uintptr_t key, uint32_t taint, int base);
  void ScatterFailImpl(int base, int index);
  void BinOpImpl(uint32_t left, uint32_t right, const char* op,
                 uint32_t result, uintptr_t result_addr);
  void HofInjectImpl(const char* op, int param, uint32_t taint);
  void HofExtractImpl(const char* op, uint32_t taint);
  void HofExtractAddrImpl(const char* op, uint32_t taint, uintptr_t addr);
  void HofInjectSkipImpl(int depth, int expected);
  void SkipBitmapDisabledImpl();

  // --- Outlined Impl methods (Trace layer) ------------------------------
  void FrameImpl(uintptr_t fp, int skip_idx, uint8_t old_val, uint8_t new_val,
                 int argc, uint32_t acc, const uint32_t* buf, int buf_len);
  void FrameHofImpl(uintptr_t fp, int call_top, uint32_t acc, bool hof);
  void ObjectDumpImpl(const char* type_name);
  void ApiGetTaintImpl(uintptr_t addr, uint32_t elem, uint32_t prop);

  // --- State ------------------------------------------------------------
  Level level_{Level::kOff};
  FILE* json_file_{nullptr};
};

}  // namespace dynalysis
