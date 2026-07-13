// taint-adapter.h — V8 Adapter Layer
// All DTA operations exposed as plain C ABI static methods, registered as
// ExternalReferences for CSA to call. This layer is the sole bridge between
// V8 types and the pure C++ core engine.
#ifndef V8_TAINT_TAINT_ADAPTER_H_
#define V8_TAINT_TAINT_ADAPTER_H_

#include "src/common/globals.h"
#include "src/taint/taint-interpreter.h"
#include <unordered_set>

namespace v8 {
namespace internal {

class Isolate;

namespace taint {

// =========================================================================
// V8VmAdapter — Concrete IVmAdapter implementation
// Wires VM abstraction interface calls to V8 internal APIs, so
// taint-interpreter.cc never needs to include V8 headers.
// =========================================================================
class V8VmAdapter : public dynalysis::IVmAdapter {
 public:
  explicit V8VmAdapter(Isolate* isolate) : isolate_(isolate) {}

  uintptr_t GetPhysicalAddrFromMapping(int arg_index) override;
  uint32_t  GetTaintFromMapping(int arg_index) override;
  uintptr_t GetGlobalProxyAddress() override;
  uintptr_t GetPropertyKey(const char* prop_name) override;
  int         GetBuiltinCount() override;
  const char* GetBuiltinName(int builtin_id) override;
  int         GetBuiltinId(const char* name) override;
  uint8_t*  GetBuiltinBitmap() override;
  void      SetBuiltinBitmap(uint8_t* bitmap) override;
  int         GetRuntimeCount() override;
  const char* GetRuntimeName(int runtime_id) override;
  uint8_t*    GetRuntimeActionTable() override;
  void        SetRuntimeActionTable(uint8_t* table) override;
  void DeepScanObjectForTaint(uintptr_t obj_addr, int current_depth,
      int max_depth, std::unordered_set<uint32_t>& found_taints) override;
  uintptr_t GetDynamicPropertyKey(uintptr_t value_addr) override;
  bool IsConstructCall() override;
  bool IsNullOrUndefined(int arg_index) override;
  bool IsCallable(int arg_index) override;
  bool IsPrototypeObject(int arg_index) override;
  const char* GetTypeTag(int arg_index) override;
  uintptr_t ReadCallbackFrameArg(uintptr_t frame_ptr, int arg_index) override;
  uintptr_t GetIdentityHash(int arg_index) override;
  uintptr_t GetIdentityHashForAddr(uintptr_t addr) override;
  uintptr_t GetParamRawValue(int arg_index) override;
  uint64_t GetStringContentHash(int arg_index) override;
  void PrintStackTrace() override;
  void PrintObject(uintptr_t obj_addr) override;
  std::string GetRulesPath() override;

 private:
  Isolate* isolate_;
};

// =========================================================================
// TaintAdapter — Stateless static gateway
// All state is maintained by the TaintEngine instance inside the Isolate.
// Methods marked [ER] are registered as ExternalReferences — do not rename.
// =========================================================================
class TaintAdapter {
 public:
  // --- Shadow register read/write [ER] ---
  static uint32_t GetRegisterTaint(Address frame_ptr, int reg_operand);
  static void SetRegisterTaint(Address frame_ptr, int reg_operand, uint32_t id);

  // --- Shadow accumulator read/write [ER] ---
  static uint32_t GetAccumulatorTaint();
  static void SetAccumulatorTaint(uint32_t id);

  // --- Shadow heap property read/write [ER] ---
  static uint32_t CallGetNamedPropertyTaint(Address object_addr, Address name_addr, Address result_addr);
  static uint32_t CallSetNamedPropertyTaint(Address object_addr, Address name_addr, uint32_t taint_id, uint32_t key_taint = 0);

  // --- Exception unwind: sync shadow frames + recover thrown object taint ---
  static void UnwindAndRecoverExceptionTaint(
      Isolate* isolate, uintptr_t handler_fp, Tagged<Object> exception);

  // --- GC synchronization [ER] ---
  static void MoveHeapTaint(Isolate* isolate, Address from, Address to);
  static void RemoveHeapTaint(Isolate* isolate, Address obj_addr);
  static void RegisterWeakHandleIfNecessary(Isolate* isolate, Address obj_addr);

  // --- String representation change taint migration ---
  static void MigrateStringFlattenTaint(Isolate* isolate, Address cons_addr,
                                        Address flat_addr);

  // --- Builtin-to-JS callback heap taint bridge [ER] ---
  static Address HofExtractOnReturn(Address return_value);
  static void BridgeCallbackHeapTaint(Address frame_ptr);

  // --- Consumer-side heap taint fallback [ER] ---
  // Called from TaintBinaryOp when shadow frame taint is 0.
  // Looks up ELEM_WILDCARD/PROP_WILDCARD in shadow_heap for the object.
  // Also handles ThinString → resolves to actual string's taint.
  static uint32_t GetHeapTaintForObject(Address obj_addr);

  // Copy all shadow heap taint from source to target (for CloneObject/spread)
  static void CopyObjectTaint(Address source, Address target);

  // --- Dual-Track Taint Resolution [ER] ---
  // C-ABI wrapper for GetEffectiveTaint — callable from CSA via ExternalReference.
  // Returns shadow-frame taint if non-zero, otherwise falls back to heap taint.
  static uint32_t GetEffectiveTaintForArg(Address frame_ptr, int reg_operand, Address obj_addr);

  // --- Binary operation propagation [ER] ---
  static uint32_t PropagateBinaryOp(uint32_t left_id, uint32_t right_id, int op_token, Address result_addr);

  // --- Shadow frame lifecycle [ER] ---
  static void AllocateShadowFrame(Address frame_ptr, int register_count);
  static void DestroyFrame(Address frame_ptr);
  static void LeaveCallFrame(Isolate* isolate);
  static void LeaveCallFrameStatic();   // No-arg version for CSA ExternalReference

  // [DTA Maglev] Combined pre-hook for Maglev JIT with GC-safe arg values.
  // Receives actual tagged arg pointers from Runtime Arguments (not frame reads).
  // Fixes Maglev frame layout mismatch: Maglev has no interpreter register file.
  static void DtaMaglevCallPreHook(Address target_func, int first_reg_operand,
                                   int arg_count, int prepend_receiver,
                                   Address* arg_tagged_ptrs);

  // --- Pre-hook: call entry [ER] ---
  //     Maps arg registers, captures physical addresses, classifies target,
  //     fires Alert pre-execution pipeline.
  static uint32_t CallPrepareRuntimeArgs(Address frame_ptr, Address target_func, Address receiver_obj, int first_reg_operand, int arg_count);
  static uint32_t CallPrepareRuntimeArgs_UndefinedReceiver(Address frame_ptr, Address target_func, Address receiver_obj, int first_reg_operand, int arg_count);
  static uint32_t CallPrepareRuntimeArgs_N0(Address frame_ptr, Address target_func, Address receiver_obj, int prepend_receiver);
  static uint32_t CallPrepareRuntimeArgs_N1(Address frame_ptr, Address target_func, Address receiver_obj, int reg0, int prepend_receiver);
  static uint32_t CallPrepareRuntimeArgs_N2(Address frame_ptr, Address target_func, Address receiver_obj, int reg0, int reg1, int prepend_receiver);
  static uint32_t CallPrepareRuntimeArgs_N3(Address frame_ptr, Address target_func, Address receiver_obj, int reg0, int reg1, int reg2, int prepend_receiver);

  // --- Pre-hook: spread call entry [ER] ---
  //     Like CallPrepareRuntimeArgs but expands spread array into arg taint buffer.
  //     Resolves JSArray length and ElementWildcard taint from shadow heap.
  static uint32_t CallPrepareSpreadArgs(Address frame_ptr, Address target_func,
                                        int first_reg_operand, int normal_arg_count,
                                        int spread_reg_operand, Address spread_obj_addr);

  // --- Function entry: shadow frame push + arg taint restore [ER] ---
  static void CallRestoreRuntimeArgs(Address frame_ptr);   // Legacy path (CallRuntime)
  static void DtaPushFrameAndLeave(Address frame_ptr);     // Lightweight path (DtaRestoreArgs)

  // --- Post-hook: call exit [ER] ---
  //     Fires propagation post-execution pipeline, returns result taint ID.
  static uint32_t CallApplyCallRuleTaint(Address result_addr);

  // --- Internal helpers (not ExternalReferences) ---
  static uint32_t GetRuntimeArgTaint(Isolate* isolate, int index);
  static Address GetPhysicalAddrFromMapping(Isolate* isolate, int arg_index);
  static uint32_t GetTaintFromMapping(Isolate* isolate, int arg_index);

  // --- Initialization [ER] ---
  static void EagerInitializeForIsolate(Isolate* isolate);

  // --- Node.js module context naming ---
  static void EnterAddonContext(const char* module_name);
  static void LeaveAddonContext();
  static std::string GetCurrentAddonContext();
};

}  // namespace taint
}  // namespace internal
}  // namespace v8

#endif  // V8_TAINT_TAINT_ADAPTER_H_
