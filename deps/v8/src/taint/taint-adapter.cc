// src/taint/taint-adapter.cc
#include "src/execution/isolate.h"
#include "src/execution/frames.h"
#include "src/parsing/token.h"
#include "src/handles/global-handles.h"
#include "src/objects/objects-inl.h"
#include "src/api/api-inl.h"
#include "src/execution/frame-constants.h"
#include "src/taint/taint-core.h"
#include "src/taint/taint-adapter.h"
#include "src/taint/taint-interpreter.h"
#include "src/taint/taint-logger.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/templates.h"
#include "src/objects/templates-inl.h"
#include "src/objects/js-function.h"
#include "src/objects/js-function-inl.h"
#include "src/builtins/builtins.h"
#include "src/runtime/runtime.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/read-only-spaces.h"
#include "src/heap/heap.h"
#include "src/heap/heap-inl.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/factory.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/string-inl.h"
#include "src/objects/contexts-inl.h"
#include "src/interpreter/bytecodes.h"
#include "include/v8.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace v8 {
namespace internal {
namespace taint {

static std::string& GetAddonContext() {
  static std::string* context = new std::string("");
  return *context;
}

void TaintAdapter::EnterAddonContext(const char* module_name) {
  if (module_name) {
    GetAddonContext() = module_name;
  }
}

void TaintAdapter::LeaveAddonContext() {
  GetAddonContext() = "";
}

std::string TaintAdapter::GetCurrentAddonContext() {
  return GetAddonContext();
}

static Isolate* GetCurrentInternalIsolate() {
    return reinterpret_cast<Isolate*>(v8::Isolate::GetCurrent());
}

// Conservatively validate that a tagged value is a real, dereferenceable heap
// object before reading its map. DTA deep-scans arbitrary object graphs and
// some slots (unboxed/embedder/foreign fields) hold raw non-pointer data whose
// low bit is incidentally set, so the naive tag-bit IsHeapObject() check is not
// enough — dereferencing them as a map SIGSEGVs.
//
// Crash-safety invariant: NEVER read page metadata for a candidate address
// until a pure-arithmetic range check has proven the address falls inside a
// reservation whose chunk headers are mapped. Each metadata-reading Contains
// below is gated by such a range check (or, for read-only space, by the
// ContainsSlow page-list comparison which never touches the candidate at all).
//
// Recall-safety invariant: accept objects in ALL heap reservations a live
// object can occupy — this isolate's own heap, the shared heap (internalized
// strings live here when the string table is shared), and read-only space.
// An earlier version only consulted Heap::Contains(), which returns false for
// read-only objects and for shared-heap objects (their pages are outside this
// isolate's allocator range). Whether a derived string gets internalized into
// RO/shared space is decided by V8's per-process random string-hash seed, so
// that narrow check silently dropped taint on ~50% of process runs.
static bool DtaIsDereferenceableHeapObject(Isolate* isolate, Address tagged) {
    if ((tagged & kHeapObjectTagMask) != kHeapObjectTag) return false;
    if (isolate == nullptr) return false;
    Heap* heap = isolate->heap();
    if (heap == nullptr) return false;
    Address addr = tagged & ~static_cast<Address>(kHeapObjectTagMask);
    Tagged<HeapObject> obj = Cast<HeapObject>(Tagged<Object>(tagged));

    // (1) Read-only space. ContainsSlow iterates the registered RO page list and
    // compares chunk pointers — it never dereferences the candidate, so it is
    // safe on a wholly bogus address. RO-internalized strings are valid,
    // dereferenceable objects that can carry taint, so accept them.
    ReadOnlyHeap* ro_heap = isolate->read_only_heap();
    if (ro_heap != nullptr && ro_heap->read_only_space() != nullptr &&
        ro_heap->read_only_space()->ContainsSlow(addr)) {
        return true;
    }

    // (2) This isolate's own heap. Range-guard before any page-metadata read.
    if (!heap->memory_allocator()->IsOutsideAllocatedSpace(addr) &&
        heap->Contains(obj)) {
        return true;
    }

    // (3) Shared heap. Shared pages are reserved by the shared-space isolate's
    // allocator, so range-guard against THAT allocator before the
    // metadata-reading SharedHeapContains. Skip when this isolate has no shared
    // space, or is itself the shared-space isolate (covered by (2)).
    if (isolate->has_shared_space() && !isolate->is_shared_space_isolate()) {
        Isolate* shared = isolate->shared_space_isolate();
        Heap* shared_heap = (shared != nullptr) ? shared->heap() : nullptr;
        if (shared_heap != nullptr &&
            !shared_heap->memory_allocator()->IsOutsideAllocatedSpace(addr) &&
            heap->SharedHeapContains(obj)) {
            return true;
        }
    }

    return false;
}

#define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))

static uintptr_t GetPhysicalAddrFromFrame(Address frame_ptr, int reg_operand) {
    // V8's register operand (from BytecodeOperandReg / Register::ToOperand())
    // already encodes the full signed offset from fp in pointer-size units.
    // The CSA LoadRegister loads from: fp + operand * kSystemPointerSize.
    // Negative operands → local registers (below fp).
    // Positive operands → parameter registers (above fp).
    Address obj_ptr_addr = frame_ptr + reg_operand * kSystemPointerSize;

    Address obj_addr = *reinterpret_cast<Address*>(obj_ptr_addr);

    if (!HAS_SMI_TAG(obj_addr) && obj_addr != kNullAddress) {
        return UNTAG(obj_addr);
    }
    return 0;
}

// =======================================================================
// Shadow Register (legacy C-call path — kept for non-inline callers)
// Note: Hot-path bytecodes (Ldar/Star/Mov) now use CSA inline access
// and never call these functions.
// =======================================================================
uint32_t TaintAdapter::GetRegisterTaint(Address frame_ptr, int reg_operand) {
  Isolate* isolate = GetCurrentInternalIsolate();
  return isolate->taint_engine()->GetRegisterTaint(frame_ptr, reg_operand);
}

void TaintAdapter::SetRegisterTaint(Address frame_ptr, int reg_operand, uint32_t id) {
  Isolate* isolate = GetCurrentInternalIsolate();
  isolate->taint_engine()->SetRegisterTaint(frame_ptr, reg_operand, id);
}

// =======================================================================
// Shadow Accumulator (legacy C-call path)
// Hot-path bytecodes now use CSA inline access to Isolate::shadow_acc_taint_.
// These functions access the same memory through the TaintEngine pointer.
// =======================================================================
uint32_t TaintAdapter::GetAccumulatorTaint() {
  Isolate* isolate = GetCurrentInternalIsolate();
  return isolate->taint_engine()->GetAccumulatorTaint();
}

void TaintAdapter::SetAccumulatorTaint(uint32_t id) {
  Isolate* isolate = GetCurrentInternalIsolate();
  isolate->taint_engine()->SetAccumulatorTaint(id);
}

// =======================================================================
// Shadow Heap — Property Load with Deep Wildcard Contagion
// =======================================================================
uint32_t TaintAdapter::CallGetNamedPropertyTaint(Address object_addr, Address name_addr, Address result_addr) {
  // Level 0: Smi source cannot have shadow heap entry
  if (HAS_SMI_TAG(object_addr)) return 0;

  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return 0;

  uintptr_t obj_untag = UNTAG(static_cast<uintptr_t>(object_addr));
  uintptr_t name_untag = UNTAG(static_cast<uintptr_t>(name_addr));

  // Level 1: fast exit if source not tracked (99.9% of reads exit here)
  if (!engine->IsObjectTracked(obj_untag)) {
    // Result-side fallback: the parent object may be untracked (e.g., Blink-created
    // event object) but the result value itself may carry heap taint (e.g., IPC
    // deserialized string, DOM getter return value). Check result's own taint.
    if (!HAS_SMI_TAG(result_addr)) {
      uintptr_t result_untag = UNTAG(static_cast<uintptr_t>(result_addr));
      if (engine->IsObjectTracked(result_untag)) {
        return engine->GetAnyWildcardTaint(result_untag);
      }
    }
    return 0;
  }

  // === Mode A: Exact Match ===
  // Specific field has taint entry (from StaNamedProperty store) — no contagion
  uint32_t taint = engine->GetHeapTaintExact(obj_untag, name_untag);
  if (taint != 0) return taint;

  // === Mode B: Wildcard Fallback ===
  // Check wildcards with depth awareness (DEEP vs SHALLOW)
  bool is_smi_key = HAS_SMI_TAG(name_addr);
  bool is_deep = false;
  taint = engine->GetHeapTaintWildcard(obj_untag, is_smi_key, &is_deep);
  if (taint == 0) return 0;

  // Level 3: Recursive Wildcard Contagion (only for DEEP wildcards)
  if (is_deep && !HAS_SMI_TAG(result_addr)) {
    // Result is a HeapObject — apply Type-Based Membrane
    Tagged<Object> result_obj(result_addr);
    if (IsHeapObject(result_obj)) {
      Tagged<HeapObject> heap_result = Cast<HeapObject>(result_obj);
      Tagged<Map> result_map = heap_result->map();

      // Read-Write Asymmetry: READ membrane blocks contagion to
      // Functions and Prototype objects (system infrastructure).
      // WRITE to prototype triggers CWE-1321 alert (StaKeyedProperty sink).
      if (!IsCallable(heap_result) && !result_map->is_prototype_map()) {
        uintptr_t result_untag = UNTAG(static_cast<uintptr_t>(result_addr));
        if (IsString(heap_result)) {
          // Primitive termination: strings get ELEM_SHALLOW only.
          // Taint propagates through shadow_acc, not heap contagion.
          engine->SetHeapTaint(result_untag, dynalysis::ELEM_SHALLOW_KEY, taint);
        } else {
          // Tree isomorphism: JSObject/JSArray child gets BOTH ELEM_DEEP + PROP_DEEP.
          // Attacker controls the full subtree — we don't know if next access is
          // arr[i] (index) or obj.key (property), so stamp both.
          engine->SetHeapTaint(result_untag, dynalysis::ELEM_DEEP_KEY, taint);
          engine->SetHeapTaint(result_untag, dynalysis::PROP_DEEP_KEY, taint);
        }
      }
    }
  }

  return taint;
}

// -----------------------------------------------------------------------
// Specialized bytecode guard evaluator — no IVmAdapter, no virtual dispatch.
// Evaluates compiled guards from the Mystra bytecode rule directly on the
// raw property store operands: target=param[0], key=param[1], value=param[2].
// -----------------------------------------------------------------------
static bool EvaluateBytecodeGuard(
    const dynalysis::GuardPredicate& g,
    Address target, Address key, uint32_t value_taint, uint32_t key_taint) {
  using MP = dynalysis::GuardPredicate::MagicPropType;
  using CO = dynalysis::GuardPredicate::CompareOp;
  using ET = dynalysis::GuardPredicate::ExprType;
  using LT = dynalysis::GuardPredicate::LitType;

  bool result = true;  // Default: pass (sound)

  // Category 2: .value string comparison for property name
  if (g.expr_type == ET::kLocatorValue && g.param_index == 1) {
    // Compare the property name (key) against a string literal
    if (g.literal_type == LT::kString && g.literal_string != nullptr) {
      bool match = false;
      if (!HAS_SMI_TAG(key) && key != kNullAddress) {
        Tagged<Object> obj(key);
        if (IsString(obj)) {
          std::unique_ptr<char[]> key_str = Cast<String>(obj)->ToCString();
          match = (strcmp(key_str.get(), g.literal_string) == 0);
        }
      }
      result = (g.compare_op == CO::kEq) ? match : !match;
      return g.negate ? !result : result;
    }
  }

  if (g.expr_type == ET::kLocatorMagicProp) {
    if (g.magic_prop == MP::kIsPrototype && g.param_index == 0) {
      // target.isPrototype — one pointer chase through map
      bool val = false;
      if (!HAS_SMI_TAG(target)) {
        Tagged<Object> obj(target);
        val = IsJSObject(obj) && Cast<JSObject>(obj)->map()->is_prototype_map();
      }
      result = (g.compare_op == CO::kEq) ? (val == g.literal_bool) : (val != g.literal_bool);
    } else if (g.magic_prop == MP::kTainted) {
      uint32_t t = 0;
      if (g.param_index == 0) t = 0;  // target taint (not tracked)
      else if (g.param_index == 1) t = key_taint;
      else if (g.param_index == 2) t = value_taint;
      bool val = (t != 0);
      result = (g.compare_op == CO::kEq) ? (val == g.literal_bool) : (val != g.literal_bool);
    }
  } else if (g.expr_type == ET::kLocatorValue && g.param_index == 1) {
    // key.value == literal — Category 2 implemented for bytecode rules
    Tagged<Object> obj(key);
    if (g.literal_type == LT::kString && g.literal_string) {
      if (!HAS_SMI_TAG(key) && IsString(obj)) {
        bool eq = Cast<String>(obj)->IsEqualTo(
            base::CStrVector(g.literal_string));
        result = (g.compare_op == CO::kEq) ? eq : !eq;
      } else {
        result = (g.compare_op == CO::kEq) ? false : true;
      }
    }
  }

  return g.negate ? !result : result;
}

uint32_t TaintAdapter::CallSetNamedPropertyTaint(Address object_addr, Address name_addr, uint32_t taint_id, uint32_t key_taint_param) {
  Isolate* isolate = GetCurrentInternalIsolate();
  if (taint_id != 0) {
      RegisterWeakHandleIfNecessary(isolate, object_addr);
  }

  // Rule-driven bytecode-level detection (CWE-1321 prototype pollution).
  // The compiled rule descriptor drives the detection — delete the Mystra rule
  // and detection turns off. Modify guards and the oracle changes.
  const auto* bc_rule = dynalysis::TslInterpreter::GetBytecodeRule();
  dynalysis::TaintEngine* bc_engine = isolate->taint_engine();
  if (bc_rule && bc_engine && bc_engine->IsTrackingActive()) {
      // Fast path: check if ANY taint exists (value or key)
      // Key taint: use register taint passed from interpreter (primary),
      // fall back to heap taint on the key object (for heap-only taint).
      uint32_t key_taint = key_taint_param;
      if (key_taint == 0 && taint_id == 0 && !HAS_SMI_TAG(name_addr)) {
          // Heap fallback — only when both register taints are 0
          dynalysis::TaintEngine* engine = isolate->taint_engine();
          if (engine && engine->IsTrackingActive()) {
              key_taint = GetHeapTaintForObject(name_addr);
          }
      }
      if (taint_id != 0 || key_taint != 0) {
          // Evaluate compiled guards from the bytecode rule
          for (size_t sri = 0; sri < bc_rule->sub_rules.size(); sri++) {
              const auto& sr = bc_rule->sub_rules[sri];
              if (sr.action != dynalysis::ActionType::kSink) continue;
              // Check which source the sub-rule inspects
              bool source_tainted = false;
              for (const auto& src : sr.sources) {
                  if (src.index == 2 && taint_id != 0) source_tainted = true;  // value
                  if (src.index == 1 && key_taint != 0) source_tainted = true;  // key
              }
              if (!source_tainted) continue;
              // Evaluate all guards (AND semantics)
              bool guards_pass = true;
              for (const auto& g : sr.guards) {
                  if (!EvaluateBytecodeGuard(g, object_addr, name_addr, taint_id, key_taint)) {
                      guards_pass = false;
                      break;
                  }
              }
              if (guards_pass) {
                  uint32_t alert_taint = taint_id ? taint_id : key_taint;
                  std::string sink_name = "StaNamedProperty";
                  if (!HAS_SMI_TAG(name_addr) && name_addr != kNullAddress) {
                      Tagged<Object> nobj(name_addr);
                      if (IsString(nobj)) {
                          std::unique_ptr<char[]> ns = Cast<String>(nobj)->ToCString();
                          sink_name = std::string("StaNamedProperty:") + ns.get();
                      }
                  }
                  isolate->dta_logger()->AlertBytecode(
                      sr.alert_cwe, sink_name.c_str(),
                      alert_taint, isolate->taint_engine());
              }
          }
      }
  }

  isolate->taint_engine()->SetHeapTaint(UNTAG(object_addr), UNTAG(name_addr), taint_id);
  return 0;
}

// =======================================================================
// GC Weak Handle Mechanism
// =======================================================================
struct TaintInternalGCHandle {
  uintptr_t last_known_addr;
  v8::Global<v8::Value> global_handle;
  Isolate* i_isolate;
};

static void OnInternalTaintedObjectFreed(const v8::WeakCallbackInfo<TaintInternalGCHandle>& data) {
  TaintInternalGCHandle* handle = data.GetParameter();
  static const bool dta_dbg_ght = (getenv("DTA_DBG_GHT") != nullptr);
  if (dta_dbg_ght) {
    fprintf(stderr, "[FREED] RemoveHeapTaint addr=0x%lx\n",
            (unsigned long)handle->last_known_addr);
  }
  handle->i_isolate->taint_engine()->RemoveHeapTaint(handle->last_known_addr);
  handle->global_handle.Reset();
  delete handle;
}

void TaintAdapter::RegisterWeakHandleIfNecessary(Isolate* isolate, Address obj_addr) {
  if (HAS_SMI_TAG(obj_addr)) return;
  HandleScope scope(isolate);

  if (isolate->serializer_enabled()) return;

  uintptr_t normalized_addr = UNTAG(static_cast<uintptr_t>(obj_addr));
  if (!isolate->taint_engine()->IsObjectTracked(normalized_addr)) {

    Handle<Object> obj(Tagged<Object>(obj_addr), isolate);
    v8::Isolate* api_isolate = reinterpret_cast<v8::Isolate*>(isolate);
    v8::Local<v8::Value> api_value = v8::Utils::ToLocal(obj);

    TaintInternalGCHandle* gc_handle = new TaintInternalGCHandle();
    gc_handle->last_known_addr = normalized_addr;
    gc_handle->i_isolate = isolate;
    gc_handle->global_handle.Reset(api_isolate, api_value);
    gc_handle->global_handle.SetWeak(gc_handle, OnInternalTaintedObjectFreed, v8::WeakCallbackType::kParameter);
  }
}

// =======================================================================
// Exception Unwind: sync shadow frames + recover thrown object taint
// =======================================================================
void TaintAdapter::UnwindAndRecoverExceptionTaint(
    Isolate* isolate, uintptr_t handler_fp, Tagged<Object> exception) {
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine) return;

  // 1. Unwind shadow frames to the handler
  engine->UnwindShadowFramesTo(handler_fp);

  // 2. Recover the thrown object's taint into shadow_acc.
  //    V8 places the exception into the accumulator at catch block entry.
  if (!IsSmi(exception)) {
    uintptr_t exc_addr = exception.ptr() - kHeapObjectTag;
    constexpr uintptr_t WILDCARD = 0xFFFFFFFFFFFFFFFF;
    uint32_t exc_taint = engine->GetHeapTaint(exc_addr, WILDCARD);
    engine->SetAccumulatorTaint(exc_taint);
  } else {
    engine->SetAccumulatorTaint(0);
  }
}

// =======================================================================
// GC Move
// =======================================================================
void TaintAdapter::MoveHeapTaint(Isolate* isolate, Address from, Address to) {
  uintptr_t from_addr = UNTAG(static_cast<uintptr_t>(from));
  uintptr_t to_addr = UNTAG(static_cast<uintptr_t>(to));
  if (from_addr == to_addr) return;
  isolate->taint_engine()->MoveHeapTaint(from_addr, to_addr);
  // Re-arm weak handle for the new address so GC tracks the moved object.
  // Without this, the next GC cycle frees the taint entry (no weak handle → freed).
  RegisterWeakHandleIfNecessary(isolate, to);
}

void TaintAdapter::RemoveHeapTaint(Isolate* isolate, Address obj_addr) {
  isolate->taint_engine()->RemoveHeapTaint(UNTAG(static_cast<uintptr_t>(obj_addr)));
}

// =======================================================================
// Binary Op Propagation
// =======================================================================
uint32_t TaintAdapter::PropagateBinaryOp(uint32_t left_id, uint32_t right_id, int op_token, Address result_addr) {
  Isolate* isolate = GetCurrentInternalIsolate();
  if (left_id == 0 && right_id == 0) {
    return 0;
  }

  dynalysis::TaintEngine* engine = isolate->taint_engine();
  Token::Value token = static_cast<Token::Value>(op_token);
  const char* op_name = Token::Name(token);
  std::string operation = op_name ? op_name : "UnknownBinaryOp";

  uint32_t taint_id = engine->CreateNode(operation, left_id, right_id);

  isolate->dta_logger()->BinOp(left_id, right_id, operation.c_str(),
                               taint_id, static_cast<uintptr_t>(result_addr));

  return taint_id;
}

// =======================================================================
// Shadow Frame Lifecycle
// Push: called from DtaRestoreArgs (once per function entry)
// Pop:  called from Return handler (once per function exit)
// =======================================================================
void TaintAdapter::AllocateShadowFrame(Address frame_ptr, int register_count) {
  Isolate* isolate = GetCurrentInternalIsolate();
  // PushShadowFrame allocates a zeroed frame in the arena and
  // updates isolate->shadow_frame_base_ for CSA inline access
  isolate->taint_engine()->PushShadowFrame(frame_ptr);
}

void TaintAdapter::LeaveCallFrameStatic() {
  Isolate* isolate = GetCurrentInternalIsolate();
  isolate->taint_engine()->LeaveCallFrame();
}

void TaintAdapter::DestroyFrame(Address frame_ptr) {
  Isolate* isolate = GetCurrentInternalIsolate();
  isolate->taint_engine()->PopShadowFrame();
}

void TaintAdapter::LeaveCallFrame(Isolate* isolate) {
  isolate->taint_engine()->LeaveCallFrame();
}

// =======================================================================
// Target Classification (unchanged)
// =======================================================================
// Phase 3: Set the SFI TaintSkipBit if the function has no summary rules.
// This is safe here because the JSFunction pointer is freshly loaded from
// a register — no GC can have relocated it yet.
static void MaybeSetTaintSkipBit(Isolate* isolate, Tagged<SharedFunctionInfo> sfi, bool has_rules) {
  if (has_rules) return;
  // Debug mode: never set the SFI skip bit — all calls reach the slow path.
  if (v8_flags.dta_disable_skipbit) return;
  if (isolate->serializer_enabled()) return;
  // Built-in SFIs live in V8's read-only heap (immutable after snapshot).
  // Writing to read-only memory causes SEGV_ACCERR. Skip these.
  if (ReadOnlyHeap::Contains(sfi)) return;
  int32_t current_flags = sfi->flags(kRelaxedLoad);
  if (!SharedFunctionInfo::TaintSkipBit::decode(current_flags)) {
    sfi->set_flags(
        SharedFunctionInfo::TaintSkipBit::update(current_flags, true),
        kRelaxedStore);
  }
}

// Forward declarations
static void ClassifyAndSetTarget(Isolate* isolate, Address target_func_addr,
                                 Address bound_this_override = kNullAddress);

// Resolve the actual target function for .call()/.apply() unwrapping.
static Builtin MaybeUnwrapCallApply(Tagged<Object> obj) {
  if (!IsJSFunction(obj)) return Builtin::kNoBuiltinId;
  Tagged<JSFunction> js_func = Cast<JSFunction>(obj);
  Tagged<SharedFunctionInfo> sfi = js_func->shared();
  if (!sfi->HasBuiltinId()) return Builtin::kNoBuiltinId;
  Builtin id = sfi->builtin_id();
  if (id == Builtin::kFunctionPrototypeCall ||
      id == Builtin::kFunctionPrototypeApply ||
      id == Builtin::kReflectApply) {
    return id;
  }
  return Builtin::kNoBuiltinId;
}

// Unwrap .call()/.apply(): reclassify using the actual callee and remap args.
static void UnwrapCallApply(Isolate* isolate, Builtin wrapper_id,
                            Address receiver_obj) {
  dynalysis::TaintEngine* engine = isolate->taint_engine();

  // Remap: shift arg mappings so arg[0] (thisArg) becomes the new receiver.
  size_t count = engine->GetArgMappingCount();
  if (count >= 2) {
    for (size_t i = 0; i + 1 < count; i++) {
      int reg = engine->GetArgMapping(i + 1);
      engine->SetArgMapping(i, reg);
      engine->SetArgPhysicalAddr(i, engine->GetArgPhysicalAddr(i + 1));
    }
    engine->SetArgMappingCount(count - 1);
  }

  uint32_t* arg_buf = isolate->dta_arg_taint_buf_address();
  uint8_t buf_count = *(isolate->dta_arg_count_address());

  if (wrapper_id == Builtin::kFunctionPrototypeCall) {
    // .call(thisArg, arg0, arg1, ...) — flat args, static shift by 1.
    // Buffer BEFORE: [recv, thisArg, arg0, arg1, ...]
    // Buffer AFTER:  [thisArg, arg0, arg1, ...]
    if (buf_count >= 1) {
      for (int i = 0; i + 1 < buf_count; i++) {
        arg_buf[i] = arg_buf[i + 1];
      }
      *(isolate->dta_arg_count_address()) = buf_count - 1;
    }
  } else if (wrapper_id == Builtin::kFunctionPrototypeApply) {
    // .apply(thisArg, argsArray) — V8 dynamically unpacks the array via
    // CallWithArrayLike (CSA), then tail-calls the inner function.
    // We must scan the argsArray NOW (before unpack) and populate the buffer
    // with individual element taints for DtaTransferArgTaintsFromBuf.
    //
    // After engine remap, the arg mapping is:
    //   mapping[0] = thisArg register, mapping[1] = argsArray register
    // The argsArray register contains the JSArray. Read it from the caller's frame.
    uintptr_t caller_fp = engine->GetCallerFramePtr();
    if (caller_fp != 0 && engine->GetArgMappingCount() >= 2) {
      int arr_reg = engine->GetArgMapping(engine->GetArgMappingCount() - 1);
      Address arr_slot = caller_fp + arr_reg * kSystemPointerSize;
      Address arr_tagged = *reinterpret_cast<Address*>(arr_slot);

      // thisArg taint from buffer position 1 (original layout)
      uint32_t this_taint = (buf_count >= 2) ? arg_buf[1] : 0;
      arg_buf[0] = this_taint;
      int new_count = 1;

      if (!HAS_SMI_TAG(arr_tagged)) {
        Tagged<Object> arr_obj(arr_tagged);
        if (IsJSArray(arr_obj)) {
          Tagged<JSArray> arr = Cast<JSArray>(arr_obj);
          int length = IsSmi(arr->length()) ? Smi::ToInt(arr->length()) : 0;
          Tagged<FixedArrayBase> elements = arr->elements();

          uintptr_t arr_key = (arr_tagged & ~static_cast<Address>(1));
          for (int j = 0; j < length && new_count < 31; j++) {
            uint32_t elem_taint = 0;
            // Check array's shadow heap with Smi key for this index
            uintptr_t smi_key = static_cast<uintptr_t>(Smi::FromInt(j).ptr())
                                & ~static_cast<uintptr_t>(1);
            elem_taint = engine->GetHeapTaint(arr_key, smi_key);
            // Fallback: array wildcard
            if (elem_taint == 0)
              elem_taint = engine->GetAnyWildcardTaint(arr_key);
            // Fallback: element object's own heap taint
            if (elem_taint == 0 && IsFixedArray(elements) && j < elements->length()) {
              Tagged<Object> elem = Cast<FixedArray>(elements)->get(j);
              if (!IsSmi(elem))
                elem_taint = TaintAdapter::GetHeapTaintForObject(elem.ptr());
            }
            arg_buf[new_count++] = elem_taint;
          }
        }
      }
      *(isolate->dta_arg_count_address()) = new_count;
    }
  } else if (wrapper_id == Builtin::kReflectApply) {
    // Reflect.apply(target, thisArg, argumentsList)
    // After engine remap: mapping[0]=target, mapping[1]=thisArg, mapping[2]=argumentsList
    // Same array unpacking as .apply(), but target is at mapping[0], array at mapping[2].
    uintptr_t caller_fp = engine->GetCallerFramePtr();
    size_t remapped = engine->GetArgMappingCount();
    if (caller_fp != 0 && remapped >= 3) {
      // Read argsArray from caller frame at the last mapped register
      int arr_reg = engine->GetArgMapping(remapped - 1);
      Address arr_slot = caller_fp + arr_reg * kSystemPointerSize;
      Address arr_tagged = *reinterpret_cast<Address*>(arr_slot);

      // thisArg taint from buffer (position 2 in original: [Reflect, target, thisArg, arr])
      uint32_t this_taint = (buf_count >= 3) ? arg_buf[2] : 0;
      arg_buf[0] = this_taint;
      int new_count = 1;

      if (!HAS_SMI_TAG(arr_tagged)) {
        Tagged<Object> arr_obj(arr_tagged);
        if (IsJSArray(arr_obj)) {
          Tagged<JSArray> arr = Cast<JSArray>(arr_obj);
          int length = IsSmi(arr->length()) ? Smi::ToInt(arr->length()) : 0;
          Tagged<FixedArrayBase> elements = arr->elements();
          uintptr_t arr_key = (arr_tagged & ~static_cast<Address>(1));

          for (int j = 0; j < length && new_count < 31; j++) {
            uint32_t elem_taint = 0;
            uintptr_t smi_key = static_cast<uintptr_t>(Smi::FromInt(j).ptr())
                                & ~static_cast<uintptr_t>(1);
            elem_taint = engine->GetHeapTaint(arr_key, smi_key);
            if (elem_taint == 0)
              elem_taint = engine->GetAnyWildcardTaint(arr_key);
            if (elem_taint == 0 && IsFixedArray(elements) && j < elements->length()) {
              Tagged<Object> elem = Cast<FixedArray>(elements)->get(j);
              if (!IsSmi(elem))
                elem_taint = TaintAdapter::GetHeapTaintForObject(elem.ptr());
            }
            arg_buf[new_count++] = elem_taint;
          }
        }
      }
      *(isolate->dta_arg_count_address()) = new_count;

      // For Reflect.apply: the actual callee is at mapping[0] (target).
      // Read it from the caller's frame and reclassify.
      int target_reg = engine->GetArgMapping(0);
      Address target_slot = caller_fp + target_reg * kSystemPointerSize;
      Address target_tagged = *reinterpret_cast<Address*>(target_slot);
      ClassifyAndSetTarget(isolate, target_tagged);
      return;  // Skip the ClassifyAndSetTarget below
    }
  }

  // Reclassify using the actual callee (receiver_obj of the .call()/.apply()).
  ClassifyAndSetTarget(isolate, receiver_obj);
}

static void ClassifyAndSetTarget(Isolate* isolate, Address target_func_addr,
                                 Address bound_this_override) {
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  Tagged<Object> obj(target_func_addr);

  if (IsSmi(obj)) {
    int runtime_id = Smi::ToInt(obj);
    engine->SetCurrentTarget(dynalysis::TargetCategory::kNativeBuiltin, runtime_id);
    engine->SetTargetFuncAddr(static_cast<uintptr_t>(target_func_addr));
    if (runtime_id == static_cast<int>(Runtime::kResolvePossiblyDirectEval)) {
      engine->SetCurrentTargetSignature(dynalysis::TargetCategory::kHostApi,
                                        "Runtime_ResolvePossiblyDirectEval");
    }
    return;
  }

  // JSBoundFunction: unwrap to the actual target function (recursive).
  // Primordials like ArrayPrototypeJoin use bind(call) → JSBoundFunction
  // whose bound_target_function is FunctionPrototypeCall.
  // Pass bound_this as override so .call() unwrap knows the actual callee.
  if (IsJSBoundFunction(obj)) {
    Tagged<JSBoundFunction> bound = Cast<JSBoundFunction>(obj);
    Tagged<HeapObject> target = bound->bound_target_function();
    Tagged<Object> bound_this = bound->bound_this();
    ClassifyAndSetTarget(isolate, target.ptr(), bound_this.ptr());
    return;
  }

  if (!IsJSFunction(obj)) {
    engine->SetCurrentTarget(dynalysis::TargetCategory::kUnknown);
    return;
  }

  Tagged<JSFunction> js_func = Cast<JSFunction>(obj);
  Tagged<SharedFunctionInfo> sfi = js_func->shared();

  if (sfi->HasBuiltinId()) {
    Builtin builtin_id = sfi->builtin_id();

    // API functions (Node.js native bindings) have builtin_id = HandleApiCallOrConstruct.
    // Redirect them to the host API path for name-based rule lookup.
    // This is engine-agnostic: any embedder's native functions get the same treatment.
    if (builtin_id == Builtin::kHandleApiCallOrConstruct) {
      goto host_api_path;
    }

    bool is_call_apply = (builtin_id == Builtin::kFunctionPrototypeCall ||
                          builtin_id == Builtin::kFunctionPrototypeApply ||
                          builtin_id == Builtin::kReflectApply);

    // .call()/.apply() with bound_this_override: unwrap to the actual callee.
    if (is_call_apply && bound_this_override != kNullAddress) {
      UnwrapCallApply(isolate, builtin_id, bound_this_override);
      return;
    }

    engine->SetCurrentTarget(dynalysis::TargetCategory::kNativeBuiltin, static_cast<int>(builtin_id));
    bool builtin_has_rules = is_call_apply ||
        dynalysis::TslInterpreter::HasBuiltinRules(static_cast<int>(builtin_id));
    if (isolate->dta_logger()->level() >= dynalysis::DtaLogger::Level::kDebug) {
      std::unique_ptr<char[]> bname = sfi->DebugNameCStr();
      isolate->dta_logger()->Classify(
          bname.get() ? bname.get() : "<null>", "builtin", builtin_has_rules);
    }
    // NEVER skip-bit .call()/.apply() — they need the slow path for unwrapping.
    MaybeSetTaintSkipBit(isolate, sfi, builtin_has_rules);
  } else if (sfi->IsApiFunction()) {
  host_api_path:
    std::unique_ptr<char[]> debug_name = sfi->DebugNameCStr();
    std::string func_name = "UnknownApi";
    if (char* raw = debug_name.get()) {
        func_name = (*raw != '\0') ? raw : "AnonymousHostApi";
    }
    // Replace spaces with underscores (Blink uses "get innerHTML", "set innerHTML")
    for (char& c : func_name) { if (c == ' ') c = '_'; }

    // Compose InterfaceName.func_name for Blink DOM API callbacks.
    // FunctionTemplateInfo::interface_name() is set by Blink via SetInterfaceName().
    // This gives us "Element.set_innerHTML" instead of just "set_innerHTML".
    std::string signature = func_name;
    Tagged<FunctionTemplateInfo> fti = sfi->api_func_data();
    if (!IsUndefined(fti->interface_name())) {
        Tagged<String> iface = Cast<String>(fti->interface_name());
        std::unique_ptr<char[]> iface_cstr = iface->ToCString();
        if (iface_cstr.get() && iface_cstr.get()[0] != '\0') {
            signature = std::string(iface_cstr.get()) + "." + func_name;
        }
    }

    bool host_has_rules = dynalysis::TslInterpreter::HasHostApiRules(signature);
    // Fallback: if no rules with InterfaceName prefix, try without prefix
    // (backward compatible with existing Node.js rules that use bare names)
    if (!host_has_rules && signature != func_name) {
        host_has_rules = dynalysis::TslInterpreter::HasHostApiRules(func_name);
        if (host_has_rules) signature = func_name;
    }
    engine->SetCurrentTargetSignature(dynalysis::TargetCategory::kHostApi, signature);
    isolate->dta_logger()->Classify(signature.c_str(), "host_api", host_has_rules);
    MaybeSetTaintSkipBit(isolate, sfi, host_has_rules);
  } else {
    // User functions: NEVER set TaintSkipBit (they need DtaRestoreArgs)
    engine->SetCurrentTarget(dynalysis::TargetCategory::kUserFunction);
    if (isolate->dta_logger()->level() >= dynalysis::DtaLogger::Level::kDebug) {
      std::unique_ptr<char[]> uname = sfi->DebugNameCStr();
      isolate->dta_logger()->Classify(
          uname.get() ? uname.get() : "<anon>", "user_func", true);
    }
  }
}

// =======================================================================
// Arg Mapping + Physical Address Pre-capture
// =======================================================================
// Capture physical addresses from the interpreter frame BEFORE the call.
// After a native call, V8 may overwrite the parameter area, making
// post-hook frame reads unreliable.
static void CaptureArgPhysicalAddrs(dynalysis::TaintEngine* engine, Address frame_ptr) {
  size_t count = engine->GetArgMappingCount();
  for (size_t i = 0; i < count; i++) {
    int reg_idx = engine->GetArgMapping(i);
    if (reg_idx == -999) {
      engine->SetArgPhysicalAddr(i, 0);
    } else {
      uintptr_t addr = GetPhysicalAddrFromFrame(frame_ptr, reg_idx);
      engine->SetArgPhysicalAddr(i, addr);
    }
  }
}

// Detect callable arguments for HOF multi-callback dispatch.
// For rules with named callback refs (callback_owner_arg_index >= 0),
// we record which HOF arguments are callable functions so the callback
// identity matching in DtaPushFrameAndLeave can determine which INJECT
// rules to fire.
static void MaybeDetectCallableArgs(Isolate* isolate) {
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine->IsTrackingActive()) return;
  if (engine->GetCallStackTop() == 0) return;

  // Only for builtin targets that have HOF rules
  if (engine->GetTargetCategory() != dynalysis::TargetCategory::kNativeBuiltin)
    return;
  int tid = engine->GetTargetId();
  if (tid < 0) return;
  const auto* desc = dynalysis::TslInterpreter::LookupBuiltin(tid);
  if (!desc || !desc->hof.is_hof) return;

  // Check if any INJECT/EXTRACT rule uses named callbacks (owner >= 0)
  bool need_detection = false;
  for (const auto* sr : desc->hof.inject_rules) {
    for (const auto& sink : sr->sinks) {
      if (sink.base == dynalysis::BaseEntity::kCallbackParam &&
          sink.callback_owner_arg_index >= 0) {
        need_detection = true; break;
      }
    }
    if (need_detection) break;
  }
  if (!need_detection) {
    for (const auto* sr : desc->hof.extract_rules) {
      for (const auto& src : sr->sources) {
        if (src.base == dynalysis::BaseEntity::kCallbackReturn &&
            src.callback_owner_arg_index >= 0) {
          need_detection = true; break;
        }
      }
      if (need_detection) break;
    }
  }
  if (!need_detection) return;

  // Scan arguments for callable objects and record them
  size_t stack_top = engine->GetCallStackTop();
  if (stack_top == 0) return;
  auto& ctx = engine->GetMutableCallStackEntry(stack_top - 1);
  ctx.callable_count = 0;
  int mapping_count = static_cast<int>(engine->GetArgMappingCount());
  for (int i = 0; i < mapping_count && i < 8; i++) {
    uintptr_t addr = engine->GetArgPhysicalAddr(i);
    if (addr == 0) continue;
    // Re-tag and check if callable
    Tagged<Object> obj(static_cast<Address>(addr) | kHeapObjectTag);
    if (IsHeapObject(obj) && IsCallable(obj)) {
      // Record Mystra parameter index (exclude receiver at runtime arg[0]).
      // Mystra owner=0 means first named param, which is runtime arg[1].
      ctx.callable_args[ctx.callable_count].owner_arg_index = i - 1;
      ctx.callable_args[ctx.callable_count].func_addr = addr;
      ctx.callable_count++;
    }
  }
}

// Fire pre-execution Alert rules after classification
static void MaybeFirePreExecutionAlerts(Isolate* isolate) {
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine->IsTrackingActive()) return;
  MaybeDetectCallableArgs(isolate);
  V8VmAdapter vm_adapter(isolate);
  dynalysis::TslInterpreter::DispatchPreExecution(vm_adapter, engine);
}

static void MapArgsToEngine(Isolate* isolate, Address frame_ptr, int first_reg_operand, int arg_count, bool prepend_receiver) {
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  engine->EnterCallFrame(frame_ptr);

  if (prepend_receiver) {
    engine->PushArgMapping(-999);
  }

  int direction = (first_reg_operand < 0) ? -1 : 1;
  for (int i = 0; i < arg_count; i++) {
      int op = first_reg_operand + (i * direction);
      engine->PushArgMapping(op);
  }

  CaptureArgPhysicalAddrs(engine, frame_ptr);
}

// Helper: classify target, then unwrap .call()/.apply() if needed.
static void ClassifyAndMaybeUnwrap(Isolate* isolate, Address target_func, Address receiver_obj) {
  Builtin wrapper = MaybeUnwrapCallApply(Tagged<Object>(target_func));
  if (wrapper != Builtin::kNoBuiltinId) {
    // .call()/.apply() is transparent: V8 tail-calls the inner function.
    // Only ONE TaintPostCall exists. DtaPushFrameAndLeave ORs 0x02 into
    // the skip byte (0x00 → 0x02). PostCall preserves shadow_acc.
    // This is CORRECT — the inner function's Return sets shadow_acc with
    // the return value's register taint. The preserve path keeps it.
    UnwrapCallApply(isolate, wrapper, receiver_obj);
  } else {
    ClassifyAndSetTarget(isolate, target_func);
  }
}

uint32_t TaintAdapter::CallPrepareRuntimeArgs_N0(Address frame_ptr, Address target_func, Address receiver_obj, int prepend_receiver) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  engine->EnterCallFrame(frame_ptr);
  if (prepend_receiver == 1) engine->PushArgMapping(-999);
  CaptureArgPhysicalAddrs(engine, frame_ptr);
  ClassifyAndMaybeUnwrap(isolate, target_func, receiver_obj);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

uint32_t TaintAdapter::CallPrepareRuntimeArgs_N1(Address frame_ptr, Address target_func, Address receiver_obj, int reg0, int prepend_receiver) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  engine->EnterCallFrame(frame_ptr);
  if (prepend_receiver == 1) engine->PushArgMapping(-999);
  engine->PushArgMapping(reg0);
  CaptureArgPhysicalAddrs(engine, frame_ptr);
  ClassifyAndMaybeUnwrap(isolate, target_func, receiver_obj);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

uint32_t TaintAdapter::CallPrepareRuntimeArgs_N2(Address frame_ptr, Address target_func, Address receiver_obj, int reg0, int reg1, int prepend_receiver) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  engine->EnterCallFrame(frame_ptr);
  if (prepend_receiver == 1) engine->PushArgMapping(-999);
  engine->PushArgMapping(reg0);
  engine->PushArgMapping(reg1);
  CaptureArgPhysicalAddrs(engine, frame_ptr);
  ClassifyAndMaybeUnwrap(isolate, target_func, receiver_obj);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

uint32_t TaintAdapter::CallPrepareRuntimeArgs_N3(Address frame_ptr, Address target_func, Address receiver_obj, int reg0, int reg1, int reg2, int prepend_receiver) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  engine->EnterCallFrame(frame_ptr);
  if (prepend_receiver == 1) engine->PushArgMapping(-999);
  engine->PushArgMapping(reg0);
  engine->PushArgMapping(reg1);
  engine->PushArgMapping(reg2);
  CaptureArgPhysicalAddrs(engine, frame_ptr);
  ClassifyAndMaybeUnwrap(isolate, target_func, receiver_obj);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

uint32_t TaintAdapter::CallPrepareRuntimeArgs(Address frame_ptr, Address target_func, Address receiver_obj, int first_reg_operand, int arg_count) {
  Isolate* isolate = GetCurrentInternalIsolate();
  MapArgsToEngine(isolate, frame_ptr, first_reg_operand, arg_count, false);
  ClassifyAndMaybeUnwrap(isolate, target_func, receiver_obj);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

uint32_t TaintAdapter::CallPrepareRuntimeArgs_UndefinedReceiver(Address frame_ptr, Address target_func, Address receiver_obj, int first_reg_operand, int arg_count) {
  Isolate* isolate = GetCurrentInternalIsolate();
  MapArgsToEngine(isolate, frame_ptr, first_reg_operand, arg_count, true);
  ClassifyAndMaybeUnwrap(isolate, target_func, receiver_obj);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

// =======================================================================
// CallWithSpread: expand spread array into arg taint buffer
// =======================================================================
uint32_t TaintAdapter::CallPrepareSpreadArgs(Address frame_ptr, Address target_func,
                                              int first_reg_operand, int normal_arg_count,
                                              int spread_reg_operand, Address spread_obj_addr) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();

  // 1. Map normal args (receiver + non-spread args) — already in taint buffer from CSA
  MapArgsToEngine(isolate, frame_ptr, first_reg_operand, normal_arg_count, false);

  // 2. Use the spread array passed directly from CSA (avoids frame read issues)
  uintptr_t spread_addr = static_cast<uintptr_t>(spread_obj_addr);
  Tagged<Object> spread_obj(spread_obj_addr);

  // 3. Expand spread array's taint into the buffer
  uint32_t* buf = isolate->dta_arg_taint_buf_address();
  uint8_t buf_count = *(isolate->dta_arg_count_address());



  if (!IsSmi(spread_obj) && IsJSArray(spread_obj)) {
    Tagged<JSArray> arr = Cast<JSArray>(spread_obj);
    int length = 0;
    Tagged<Object> len_obj = arr->length();
    if (IsSmi(len_obj)) {
      length = Smi::ToInt(len_obj);
    }

    uintptr_t obj_key = spread_addr & ~static_cast<uintptr_t>(1);

    // For each spread element, look up its specific index taint first,
    // then fall back to ElementWildcard. This handles both:
    // - StaInArrayLiteral (stores with Smi index key via UNTAG)
    // - Rules that set ElementWildcard (e.g. ArrayFrom)
    for (int i = 0; i < length && buf_count < 32; i++) {
      // Element keys in shadow heap are stored as UNTAG(Smi(index).ptr())
      uintptr_t smi_key = UNTAG(static_cast<uintptr_t>(Smi::FromInt(i).ptr()));
      uint32_t elem_taint = engine->GetHeapTaint(obj_key, smi_key);
      buf[buf_count] = elem_taint;
      engine->PushArgMapping(spread_reg_operand);
      buf_count++;
    }
  } else {
    // Non-JSArray spread (Set, Map, generator, etc.): conservative single entry
    uint32_t elem_taint = 0;
    if (!IsSmi(spread_obj)) {
      elem_taint = engine->GetAnyWildcardTaint(
          spread_addr & ~static_cast<uintptr_t>(1));
    }
    if (buf_count < 32) {
      buf[buf_count] = elem_taint;
      engine->PushArgMapping(spread_reg_operand);
      buf_count++;
    }
  }

  *(isolate->dta_arg_count_address()) = buf_count;

  // 4. Classify target + fire alerts
  ClassifyAndSetTarget(isolate, target_func);
  CaptureArgPhysicalAddrs(engine, frame_ptr);
  MaybeFirePreExecutionAlerts(isolate);
  return 0;
}

// =======================================================================
// DtaRestoreArgs: Push shadow frame + restore arg taints from caller
// =======================================================================
void TaintAdapter::CallRestoreRuntimeArgs(Address frame_ptr) {
  // Legacy path: kept for CallRuntime which doesn't fill the inline buffer.
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();

  uint32_t* new_base = engine->PushShadowFrame(frame_ptr);

  size_t stored_count = engine->GetArgMappingCount();
  for (size_t i = 0; i < stored_count; ++i) {
      uint32_t taint = GetRuntimeArgTaint(isolate, static_cast<int>(i));
      if (taint != 0) {
          int param_index = static_cast<int>(i);
          int reg_operand = interpreter::Register::FromParameterIndex(param_index).ToOperand();
          new_base[reg_operand] = taint;
      }
  }

  // Only set user_func bit if the call context was for a user function
  bool is_user = (engine->GetCallStackTop() > 0 &&
                  engine->GetTargetCategory() == dynalysis::TargetCategory::kUserFunction);
  engine->LeaveCallFrame();

  if (is_user) {
    uint32_t skip_top = isolate->dta_skip_top();
    if (skip_top > 0) {
      isolate->dta_skip_stack_ptr()[skip_top - 1] |= 0x02;
    }
  }
}

// Phase 4: Lightweight version — just pushes frame and cleans up call context.
// CSA handles the taint transfer inline via DtaTransferArgTaintsFromBuf().
void TaintAdapter::DtaPushFrameAndLeave(Address frame_ptr) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  engine->PushShadowFrame(frame_ptr);

  // [DTA] Lazy PromiseHook registration — deferred from EagerInitialize
  // because SetPromiseHook during bootstrap causes segfault (Isolate not ready).
  // By the time DtaPushFrameAndLeave runs, bootstrap is complete.
  // Skip for child processes — they only need sink detection, not async
  // taint tracking. PromiseHook prevents event loop drain in simple scripts.
  static bool promise_hook_registered = false;
  if (!promise_hook_registered && engine->IsTrackingActive()) {
    promise_hook_registered = true;
    if (!engine->is_child_process()) {
      isolate->SetHasContextPromiseHooks(true);
    }
  }

  // Rule-driven call frame preservation for higher-order function callbacks.
  //
  // When a native builtin with taint rules (Array.map, .filter, .reduce) calls
  // a JS callback internally, the builtin's call frame must survive through all
  // callback iterations so the post-hook (CallApplyCallRuleTaint) can fire the
  // builtin's macro rule (e.g., ArrayMap: self[*] → ret[*]).
  //
  // We preserve the frame ONLY when BOTH conditions are met:
  //  1. The top of the call stack is a kNativeBuiltin
  //  2. That builtin has a macro rule in taint-rules.json (HasRulesForBuiltin)
  //
  // Builtins WITHOUT rules (ReflectApply, ArrayIteratorPrototypeNext, etc.)
  // are consumed normally — their post-hook returns 0 anyway, so preserving
  // them would only leak call frames.
  // This is data-driven: adding a rule in JSON auto-protects the frame.
  bool is_protected_hof = false;
  const dynalysis::BuiltinRuleDescriptor* hof_desc = nullptr;
  if (engine->GetCallStackTop() > 0 &&
      engine->GetTargetCategory() == dynalysis::TargetCategory::kNativeBuiltin) {
    int tid = engine->GetTargetId();
    hof_desc = dynalysis::TslInterpreter::LookupBuiltin(tid);
    if (hof_desc && hof_desc->hof.is_hof) {
      is_protected_hof = true;
    } else if (hof_desc) {
      // Non-HOF builtin with rules: still preserve frame for post-hook
      is_protected_hof = true;
      hof_desc = nullptr;  // No HOF dispatch needed
    }
  }

  if (!is_protected_hof) {
    // Normal path: consume the call frame (original behavior).
    bool is_user = (engine->GetCallStackTop() > 0 &&
                    engine->GetTargetCategory() == dynalysis::TargetCategory::kUserFunction);
    engine->LeaveCallFrame();

    if (is_user) {
      uint32_t skip_top = isolate->dta_skip_top();
      if (skip_top > 0 && skip_top <= dynalysis::TaintEngine::kSkipStackSize) {
        uint8_t old_val = isolate->dta_skip_stack_ptr()[skip_top - 1];
        isolate->dta_skip_stack_ptr()[skip_top - 1] |= 0x02;
        {
          uint8_t ac = *(isolate->dta_arg_count_address());
          isolate->dta_logger()->Frame(
              static_cast<uintptr_t>(frame_ptr), skip_top - 1, old_val,
              isolate->dta_skip_stack_ptr()[skip_top - 1],
              ac, *(isolate->shadow_acc_taint_address()),
              isolate->dta_arg_taint_buf_address(),
              ac < 8 ? ac : 8);
        }
      }
    }
  } else {
    // HOF callback: preserve call frame for post-hook rule application.
    isolate->dta_logger()->FrameHof(
        static_cast<uintptr_t>(frame_ptr),
        static_cast<int>(engine->GetCallStackTop()),
        *(isolate->shadow_acc_taint_address()),
        hof_desc ? true : false);

    // HOF INJECT: dispatch rules to bridge taint into callback parameters.
    //
    // DEPTH GUARD: Only fire INJECT at shadow_depth == hof_depth + 1.
    // The callback enters at exactly one level deeper than the HOF pre-hook.
    // Functions called WITHIN the callback (console.error, internal helpers)
    // are at depth >= hof_depth + 2 and must NOT trigger INJECT.
    // Without this guard, a single-element forEach with console.error in the
    // callback fires INJECT 50+ times (once per internal JS function entry).
    if (hof_desc && hof_desc->hof.is_hof) {
      const auto& hof_frame = engine->GetCallStackEntry(engine->GetCallStackTop() - 1);
      size_t current_depth = *(engine->frame_stack_top_address());
      if (current_depth == hof_frame.shadow_depth_at_entry + 1) {
        uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
        if (shadow_base) {
          V8VmAdapter vm_adapter(isolate);
          constexpr int kFirstUserParamOperand =
              interpreter::Register::FromParameterIndex(1).ToOperand();

          // Multi-callback identity matching: determine which HOF arg
          // this callback corresponds to by comparing function addresses.
          int matched_callback_arg_index = -1;
          if (hof_frame.callable_count > 0) {
            // Get entering callback's function from StandardFrame::kFunctionOffset
            Address func_slot = frame_ptr + StandardFrameConstants::kFunctionOffset;
            Address tagged_func = *reinterpret_cast<Address*>(func_slot);
            uintptr_t func_addr = tagged_func & ~static_cast<uintptr_t>(kHeapObjectTagMask);
            for (int ci = 0; ci < hof_frame.callable_count; ci++) {
              if (hof_frame.callable_args[ci].func_addr == func_addr) {
                matched_callback_arg_index = hof_frame.callable_args[ci].owner_arg_index;
                break;
              }
            }
          }

          dynalysis::TslInterpreter::DispatchHofInject(
              vm_adapter, engine, *hof_desc,
              static_cast<uintptr_t>(frame_ptr), shadow_base,
              kFirstUserParamOperand, matched_callback_arg_index);
        }
      } else {
        isolate->dta_logger()->HofInjectSkip(
            static_cast<int>(current_depth),
            static_cast<int>(hof_frame.shadow_depth_at_entry + 1));
      }
    }
  }
}

// =======================================================================
// Maglev JIT combined pre-hook with GC-safe tagged arg values.
// Called from Runtime with actual tagged pointers passed via Arguments object.
// This fixes the Maglev frame layout mismatch: Maglev frames have NO
// interpreter-style register file, so frame_ptr + operand reads were garbage.
// Now we receive the actual tagged arg values from the SSA graph.
// =======================================================================
void TaintAdapter::DtaMaglevCallPreHook(Address target_func, int first_reg_operand,
                                        int arg_count, int prepend_receiver,
                                        Address* arg_tagged_ptrs) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();

  // 1. Check SFI taint_skip / builtin bitmap (UNCHANGED)
  bool should_skip = false;
  Tagged<Object> obj(target_func);
  if (!v8_flags.dta_disable_skipbit && !IsSmi(obj) && IsJSFunction(obj)) {
    Tagged<JSFunction> js_func = Cast<JSFunction>(obj);
    Tagged<SharedFunctionInfo> sfi = js_func->shared();
    int32_t flags = sfi->flags(kRelaxedLoad);
    if (SharedFunctionInfo::TaintSkipBit::decode(flags)) {
      should_skip = true;
    }
    if (!should_skip && sfi->HasBuiltinId()) {
      Builtin builtin_id = sfi->builtin_id();
      if (builtin_id == Builtin::kHandleApiCallOrConstruct) {
        should_skip = false;
      } else {
        uint8_t* bitmap = isolate->dta_builtin_bitmap();
        if (bitmap && bitmap[static_cast<int>(builtin_id)] != 0) {
          should_skip = true;
        }
      }
    }
  }

  // 2. Push skip stack + early exit for skipped targets
  uint32_t skip_top = isolate->dta_skip_top();
  if (skip_top >= dynalysis::TaintEngine::kSkipStackSize) return;
  if (should_skip) {
    isolate->dta_skip_stack_ptr()[skip_top] = 0x03;
    *(isolate->dta_skip_top_address()) = skip_top + 1;
    ClassifyAndSetTarget(isolate, target_func);
    return;
  }
  isolate->dta_skip_stack_ptr()[skip_top] = 0x00;
  *(isolate->dta_skip_top_address()) = skip_top + 1;

  // 3. Fill arg taint buffer: MERGE shadow frame taint + heap taint.
  // Shadow frame is operand-indexed (correct for both tiers).
  // Heap taint from actual tagged pointers (NOW SAFE — no frame read needed).
  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  uint32_t* arg_buf = isolate->dta_arg_taint_buf_address();
  uint8_t buf_idx = 0;
  if (prepend_receiver) {
    arg_buf[buf_idx++] = 0;  // receiver has no taint
  }
  int direction = (first_reg_operand < 0) ? -1 : 1;
  for (int i = 0; i < arg_count && buf_idx < 32; i++) {
    int reg_idx = first_reg_operand + i * direction;
    // Primary: shadow frame taint (register-propagated via DtaTaintBinaryOp etc.)
    uint32_t taint = shadow_base ? shadow_base[reg_idx] : 0;
    // Secondary: heap taint from actual tagged pointer (was impossible before!)
    if (taint == 0 && arg_tagged_ptrs) {
      Address tagged = arg_tagged_ptrs[i];
      if (!HAS_SMI_TAG(tagged) && tagged != kNullAddress) {
        taint = GetHeapTaintForObject(tagged);
      }
    }
    arg_buf[buf_idx++] = taint;
  }
  *(isolate->dta_arg_count_address()) = buf_idx;

  // 4. EnterCallFrame + capture CORRECT physical addresses from tagged ptrs.
  // Previously CaptureArgPhysicalAddrs read from frame (garbage in Maglev).
  // Now we derive physical addresses directly from the actual tagged pointers.
  engine->EnterCallFrame(0);
  if (prepend_receiver) engine->PushArgMapping(-999);
  for (int i = 0; i < arg_count; i++) {
    int op = first_reg_operand + i * direction;
    engine->PushArgMapping(op);
  }
  // Store correct physical addresses from actual tagged pointers
  for (int i = 0; i < arg_count; i++) {
    int map_idx = i + (prepend_receiver ? 1 : 0);
    if (arg_tagged_ptrs) {
      Address tagged = arg_tagged_ptrs[i];
      uintptr_t phys = (!HAS_SMI_TAG(tagged) && tagged != kNullAddress)
                           ? UNTAG(tagged) : 0;
      engine->SetArgPhysicalAddr(map_idx, phys);
    } else {
      engine->SetArgPhysicalAddr(map_idx, 0);
    }
  }

  // 5. Classify target + unwrap .call()/.apply() using CORRECT receiver.
  // Previously read receiver from frame_ptr (garbage). Now from arg_tagged_ptrs[0].
  Builtin wrapper = MaybeUnwrapCallApply(Tagged<Object>(target_func));
  if (wrapper != Builtin::kNoBuiltinId && arg_count > 0 && arg_tagged_ptrs) {
    Address receiver_obj = arg_tagged_ptrs[0];
    if (receiver_obj != kNullAddress && !HAS_SMI_TAG(receiver_obj)) {
      UnwrapCallApply(isolate, wrapper, receiver_obj);
    } else {
      ClassifyAndSetTarget(isolate, target_func);
    }
  } else {
    ClassifyAndSetTarget(isolate, target_func);
  }

  // 6. Fire pre-execution alerts
  MaybeFirePreExecutionAlerts(isolate);
}

uint32_t TaintAdapter::GetRuntimeArgTaint(Isolate* isolate, int index) {
  return GetTaintFromMapping(isolate, index);
}

// =======================================================================
// Lazy Arg Resolver (unchanged logic)
// =======================================================================
Address TaintAdapter::GetPhysicalAddrFromMapping(Isolate* isolate, int arg_index) {
    dynalysis::TaintEngine* engine = isolate->taint_engine();
    int reg_idx = engine->GetArgMapping(arg_index);
    if (reg_idx == -999) return kNullAddress;

    // Use pre-captured physical address (captured in pre-hook before the call).
    // V8 may overwrite the parameter area during native function execution,
    // making post-hook frame reads unreliable.
    uintptr_t addr = engine->GetArgPhysicalAddr(static_cast<size_t>(arg_index));
    return addr != 0 ? static_cast<Address>(addr) : kNullAddress;
}

uint32_t TaintAdapter::GetTaintFromMapping(Isolate* isolate, int arg_index) {
    dynalysis::TaintEngine* engine = isolate->taint_engine();
    int reg_idx = engine->GetArgMapping(arg_index);
    if (reg_idx == -999) return 0;

    uintptr_t frame_ptr = engine->GetCallerFramePtr();
    if (frame_ptr == 0) return 0;

    uint32_t taint = engine->GetRegisterTaint(frame_ptr, reg_idx);


    // Fallback: check heap taint on the physical object
    if (taint == 0) {
        Address obj_addr = GetPhysicalAddrFromMapping(isolate, arg_index);
        if (obj_addr != kNullAddress) {
            taint = engine->GetAnyWildcardTaint(UNTAG(obj_addr));
            if (taint == 0) taint = GetHeapTaintForObject(obj_addr);
        }
    }

    return taint;
}

// =======================================================================
// Post-Call Rule Application
// =======================================================================
// =======================================================================
// SFI Learning: Mark a function as taint-irrelevant if it has no rules.
// On subsequent calls, the CSA pre-hook will read this bit and skip
// both the pre-hook and post-hook C++ boundary crossings entirely.
// =======================================================================
// Phase 3: Mark a function's SFI as taint-irrelevant after learning.
uint32_t TaintAdapter::CallApplyCallRuleTaint(Address result_addr) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();


  if (!engine->IsTrackingActive()) {
      engine->LeaveCallFrame();
      return 0;
  }

  dynalysis::TargetCategory category = engine->GetTargetCategory();

  // [TEMP] Debug: print ALL post-hook calls after tracking activates

  uint32_t result_taint = 0;

  if (category == dynalysis::TargetCategory::kUserFunction) {
      // User function: return shadow_acc directly.
      // HOF EXTRACT is handled in the Return bytecode handler
      // (HofExtractOnReturn) which fires BEFORE CallDestroyFrame.
      result_taint = engine->GetAccumulatorTaint();
  } else {
      // Save acc taint BEFORE DispatchAndApply (which clears it internally).
      // Runtime functions like %SetTaint set acc taint during execution.
      uint32_t saved_acc_taint = engine->GetAccumulatorTaint();

      uintptr_t physical_ret_addr = UNTAG(static_cast<uintptr_t>(result_addr));

      // Only dispatch to summary engine for JSFunction builtins.
      // Runtime functions (Smi-classified) use a different ID space and must
      // NOT be looked up in the builtin rules array.
      uintptr_t func_addr = engine->GetTargetFuncAddr();
      bool is_runtime_func = (func_addr != 0 && HAS_SMI_TAG(static_cast<Address>(func_addr)));

      if (!is_runtime_func) {
          V8VmAdapter vm_adapter(isolate);
          result_taint = dynalysis::TslInterpreter::DispatchAndApply(vm_adapter, engine, physical_ret_addr);
      } else {
          // Runtime functions (% prefix): inherit acc taint.
          // Alert rules for runtime sinks (like eval) are handled by
          // DispatchPreExecution in the pre-hook — no special case needed here.
          result_taint = saved_acc_taint;
      }

      if (result_taint == 0 && !HAS_SMI_TAG(result_addr)) {
          constexpr uintptr_t WILDCARD_KEY = 0xFFFFFFFFFFFFFFFF;
          result_taint = engine->GetHeapTaint(physical_ret_addr, WILDCARD_KEY);
      }

      if (result_taint != 0 && !HAS_SMI_TAG(result_addr)) {
          RegisterWeakHandleIfNecessary(isolate, result_addr);
      }
  }

  // HOF EXTRACT flush: if this frame accumulated callback return taints,
  // dedup and create ONE flat FlowNode, then write to result array wildcard.
  {
    size_t top = engine->GetCallStackTop();
    if (top > 0) {
      auto& frame = engine->GetMutableCallStackEntry(top - 1);
      if (frame.hof_acc_count > 0 && !HAS_SMI_TAG(result_addr)) {
        uintptr_t ret_untag = UNTAG(static_cast<uintptr_t>(result_addr));
        // Dedup
        std::vector<uint32_t> parents(frame.hof_acc,
            frame.hof_acc + frame.hof_acc_count);
        std::sort(parents.begin(), parents.end());
        parents.erase(std::unique(parents.begin(), parents.end()), parents.end());
        // One flat CreateNode with all unique parents
        uint32_t merged = engine->CreateNode("HOF-extract", parents);
        engine->SetHeapTaint(ret_untag, dynalysis::ELEM_SHALLOW_KEY, merged);
        if (result_taint == 0) result_taint = merged;
      }
    }
  }

  engine->LeaveCallFrame();
  // Don't clear acc taint here — CSA's InlineSetAccTaint(result_taint)
  // will overwrite it with the authoritative value.
  return result_taint;
}

// =======================================================================
// V8VmAdapter — concrete IVmAdapter implementation
// All V8 API usage that was purged from taint-interpreter.cc lives here.
// =======================================================================

uintptr_t V8VmAdapter::GetPhysicalAddrFromMapping(int arg_index) {
  Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
  // GetPhysicalAddrFromMapping already returns an untagged address (or 0).
  return static_cast<uintptr_t>(addr);
}

uint32_t V8VmAdapter::GetTaintFromMapping(int arg_index) {
  return TaintAdapter::GetTaintFromMapping(isolate_, arg_index);
}

uintptr_t V8VmAdapter::GetGlobalProxyAddress() {
  HandleScope scope(isolate_);
  return UNTAG(isolate_->native_context()->global_proxy()->ptr());
}

uintptr_t V8VmAdapter::GetPropertyKey(const char* prop_name) {
  HandleScope scope(isolate_);
  Handle<String> prop_str = isolate_->factory()->InternalizeUtf8String(prop_name);
  // Internalized strings are permanently held by the isolate — pointer is stable.
  return UNTAG(prop_str->ptr());
}

int V8VmAdapter::GetBuiltinCount() {
  return v8::internal::Builtins::kBuiltinCount;
}

const char* V8VmAdapter::GetBuiltinName(int builtin_id) {
  return v8::internal::Builtins::name(
      static_cast<v8::internal::Builtin>(builtin_id));
}

int V8VmAdapter::GetBuiltinId(const char* name) {
  for (int i = 0; i < v8::internal::Builtins::kBuiltinCount; i++) {
    if (strcmp(v8::internal::Builtins::name(
        static_cast<v8::internal::Builtin>(i)), name) == 0) {
      return i;
    }
  }
  return -1;
}

uint8_t* V8VmAdapter::GetBuiltinBitmap() {
  return isolate_->dta_builtin_bitmap();
}

void V8VmAdapter::SetBuiltinBitmap(uint8_t* bitmap) {
  isolate_->set_dta_builtin_bitmap(bitmap);
}

int V8VmAdapter::GetRuntimeCount() {
  return v8::internal::Runtime::kNumFunctions;
}

const char* V8VmAdapter::GetRuntimeName(int runtime_id) {
  auto id = static_cast<v8::internal::Runtime::FunctionId>(runtime_id);
  const v8::internal::Runtime::Function* f = v8::internal::Runtime::FunctionForId(id);
  return f ? f->name : nullptr;
}

uint8_t* V8VmAdapter::GetRuntimeActionTable() {
  return isolate_->dta_runtime_action_table();
}

void V8VmAdapter::SetRuntimeActionTable(uint8_t* table) {
  isolate_->set_dta_runtime_action_table(table);
}

void V8VmAdapter::DeepScanObjectForTaint(uintptr_t obj_addr, int current_depth, int max_depth, std::unordered_set<uint32_t>& found_taints) {
    // GC-safe deep scan: reads V8 object elements/properties directly
    // WITHOUT allocating (no GetOwnKeys, no HandleScope creation that triggers GC).
    if (current_depth > max_depth || obj_addr == 0) return;

    auto* engine = isolate_->taint_engine();
    static const bool dta_dbg_deep = (getenv("DTA_DBG_GHT") != nullptr);

    // 1. Check shadow heap for this object (per-field entries)
    std::vector<uint32_t> heap_taints;
    engine->CollectAllHeapTaints(obj_addr, heap_taints);
    for (uint32_t t : heap_taints) found_taints.insert(t);
    if (dta_dbg_deep) {
        Address ta = static_cast<Address>(obj_addr | kHeapObjectTag);
        Tagged<Object> o(ta);
        const char* ty = "?";
        int elen = -1;
        if (IsHeapObject(o)) {
            if (IsJSArray(o)) { ty = "JSArray"; }
            else if (IsJSObject(o)) { ty = "JSObject"; }
            else if (IsString(o)) { ty = "String"; }
            else if (IsFixedArray(o)) { ty = "FixedArray"; }
            else ty = "HeapOther";
            if (IsJSObject(o)) {
                Tagged<FixedArrayBase> el = Cast<JSObject>(o)->elements();
                if (IsFixedArray(el)) elen = Cast<FixedArray>(el)->length();
            }
        }
        fprintf(stderr, "[DEEP] addr=0x%lx depth=%d type=%s elem_len=%d local_taints=%zu found=%zu\n",
                (unsigned long)obj_addr, current_depth, ty, elen,
                heap_taints.size(), found_taints.size());
    }
    if (!found_taints.empty() && current_depth > 0) return;

    // 2. Walk elements array (array-like objects)
    Address tagged_addr = static_cast<Address>(obj_addr | kHeapObjectTag);
    // Validate before any map read: obj_addr may be a raw slot value passed in
    // by the recursion (unboxed/embedder/foreign field whose low bit is set).
    if (!DtaIsDereferenceableHeapObject(isolate_, tagged_addr)) return;
    Tagged<Object> obj(tagged_addr);
    if (!IsHeapObject(obj) || !IsJSObject(obj)) return;
    Tagged<JSObject> js_obj = Cast<JSObject>(obj);

    Tagged<FixedArrayBase> elements = js_obj->elements();
    if (IsFixedArray(elements)) {
        Tagged<FixedArray> fa = Cast<FixedArray>(elements);
        int len = fa->length();
        if (len > 64) len = 64;
        for (int i = 0; i < len; i++) {
            uintptr_t smi_key = static_cast<uintptr_t>(Smi::FromInt(i).ptr())
                                & ~static_cast<uintptr_t>(1);
            uint32_t t = engine->GetHeapTaint(obj_addr, smi_key);
            if (t != 0) { found_taints.insert(t); continue; }

            Tagged<Object> elem = fa->get(i);
            if (IsSmi(elem)) continue;
            if (!IsHeapObject(elem)) continue;
            uintptr_t elem_addr = elem.ptr() & ~static_cast<uintptr_t>(1);
            t = TaintAdapter::GetHeapTaintForObject(elem.ptr());
            if (t != 0) { found_taints.insert(t); continue; }
            std::vector<uint32_t> et;
            engine->CollectAllHeapTaints(elem_addr, et);
            for (uint32_t ti : et) found_taints.insert(ti);
            if (current_depth + 1 <= max_depth) {
                DeepScanObjectForTaint(elem_addr, current_depth + 1, max_depth, found_taints);
            }
        }
    }

    // 3. Walk in-object properties (named fields stored inline)
    if (IsJSObject(obj)) {
        int n_inobject = js_obj->map()->GetInObjectProperties();
        if (n_inobject > 16) n_inobject = 16;
        for (int i = 0; i < n_inobject; i++) {
            Tagged<Object> prop = js_obj->InObjectPropertyAt(i);
            if (IsSmi(prop) || !IsHeapObject(prop)) continue;
            uintptr_t prop_addr = prop.ptr() & ~static_cast<uintptr_t>(1);
            uint32_t t = TaintAdapter::GetHeapTaintForObject(prop.ptr());
            if (t != 0) { found_taints.insert(t); continue; }
            std::vector<uint32_t> pt;
            engine->CollectAllHeapTaints(prop_addr, pt);
            for (uint32_t ti : pt) found_taints.insert(ti);
            if (current_depth + 1 <= max_depth) {
                DeepScanObjectForTaint(prop_addr, current_depth + 1, max_depth, found_taints);
            }
        }
    }

    // 4. Walk properties backing store (overflow properties not in-object)
    if (IsJSObject(obj)) {
        Tagged<Object> raw_props = js_obj->raw_properties_or_hash();
        if (IsPropertyArray(raw_props)) {
            Tagged<PropertyArray> pa = Cast<PropertyArray>(raw_props);
            int pa_len = pa->length();
            if (pa_len > 32) pa_len = 32;
            for (int i = 0; i < pa_len; i++) {
                Tagged<Object> val = pa->get(i);
                if (IsSmi(val) || !IsHeapObject(val)) continue;
                uintptr_t val_addr = val.ptr() & ~static_cast<uintptr_t>(1);
                uint32_t t = TaintAdapter::GetHeapTaintForObject(val.ptr());
                if (t != 0) { found_taints.insert(t); continue; }
                std::vector<uint32_t> vt;
                engine->CollectAllHeapTaints(val_addr, vt);
                for (uint32_t ti : vt) found_taints.insert(ti);
                if (current_depth + 1 <= max_depth) {
                    DeepScanObjectForTaint(val_addr, current_depth + 1, max_depth, found_taints);
                }
            }
        } else if (IsHeapObject(raw_props) &&
                   js_obj->map()->is_dictionary_map()) {
            // Dictionary-mode object: iterate property values
            Tagged<SwissNameDictionary> dict = Cast<SwissNameDictionary>(raw_props);
            int capacity = dict->Capacity();
            if (capacity > 64) capacity = 64;
            ReadOnlyRoots roots(isolate_);
            for (int i = 0; i < capacity; i++) {
                Tagged<Object> key;
                if (!dict->ToKey(roots, InternalIndex(i), &key)) continue;
                Tagged<Object> val = dict->ValueAt(InternalIndex(i));
                if (IsSmi(val) || !IsHeapObject(val)) continue;
                uintptr_t val_addr = val.ptr() & ~static_cast<uintptr_t>(1);
                uint32_t t = TaintAdapter::GetHeapTaintForObject(val.ptr());
                if (t != 0) { found_taints.insert(t); continue; }
                std::vector<uint32_t> vt;
                engine->CollectAllHeapTaints(val_addr, vt);
                for (uint32_t ti : vt) found_taints.insert(ti);
                if (current_depth + 1 <= max_depth) {
                    DeepScanObjectForTaint(val_addr, current_depth + 1, max_depth, found_taints);
                }
            }
        }
    }
}

// =======================================================================
// DynamicKey + Guard evaluation adapter methods
// =======================================================================
uintptr_t V8VmAdapter::GetDynamicPropertyKey(uintptr_t value_addr) {
    if (value_addr == 0) return 0;
    Address tagged_addr = static_cast<Address>(value_addr | 1);
    Tagged<Object> obj(tagged_addr);
    if (!IsString(obj)) return 0;
    HandleScope scope(isolate_);
    Handle<String> str(Cast<String>(obj), isolate_);
    Handle<String> internalized = isolate_->factory()->InternalizeString(str);
    return UNTAG(internalized->ptr());
}

bool V8VmAdapter::IsConstructCall() {
    // TODO(G1): Implement @is_new guard for Mystra.
    //
    // ARCHITECTURAL CONSTRAINT: Call state is PER-FRAME, not per-Isolate.
    // A global Isolate flag (e.g. dta_is_construct_) is WRONG because:
    //   1. Reentrancy: nested calls (new Foo(bar())) corrupt a global flag.
    //   2. JIT bypass: Maglev/Turboshaft skip CSA handlers — JIT-compiled
    //      code would never set the flag without dedicated IR node emission.
    //   3. Skipbit collision: if Construct hits the skipbit fast-path and
    //      skips the C++ hook, the flag stays stuck at 1.
    //
    // CORRECT APPROACHES (choose one):
    //   A) Stack walk: in C++, walk to the top JavaScriptFrame and call
    //      frame->IsConstructor(). Safe but adds C++ overhead per guard eval.
    //   B) Pipe new.target: pass the new_target register explicitly through
    //      the JIT/CSA trampoline into CallPrepareRuntimeArgs. If new_target
    //      is not undefined, it's a Construct. Requires adding a parameter to
    //      the C ABI function and modifying all 3 Construct handlers + Maglev
    //      DtaCallPreHook emission.
    //
    // CallFrameContext::is_construct and TaintEngine::IsCurrentCallConstruct()
    // are in place for whichever approach is chosen.
    //
    // For V1: return false. Guards using @is_new always take the
    // 'where not @is_new' branch (sound overapproximation).
    return false;
}

bool V8VmAdapter::IsNullOrUndefined(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    if (addr == 0) return true;
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    return ::v8::internal::IsNullOrUndefined(obj);
}

bool V8VmAdapter::IsCallable(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    if (addr == 0) return false;
    if ((addr & 1) == 0) return false;  // Smi can't be callable
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    return ::v8::internal::IsCallable(obj);
}

bool V8VmAdapter::IsPrototypeObject(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    if (addr == 0) return false;
    if ((addr & 1) == 0) return false;  // Smi can't be prototype
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    if (!IsJSObject(obj)) return false;
    return Cast<JSObject>(obj)->map()->is_prototype_map();
}

uintptr_t V8VmAdapter::ReadCallbackFrameArg(uintptr_t frame_ptr, int arg_index) {
    Address fp = static_cast<Address>(frame_ptr);
    // V8 frame layout: arg[i] at caller_sp + (i + 1) * kSystemPointerSize
    // caller_sp = fp + CommonFrameConstants::kCallerSPOffset
    Address caller_sp = fp + CommonFrameConstants::kCallerSPOffset;
    Address arg_slot = caller_sp + (arg_index + 1) * kSystemPointerSize;
    return static_cast<uintptr_t>(*reinterpret_cast<Address*>(arg_slot));
}

uintptr_t V8VmAdapter::GetIdentityHash(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    if (addr == 0) return 0;
    // Re-tag as HeapObject
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    if (IsSmi(obj)) return static_cast<uintptr_t>(addr);
    if (!IsJSReceiver(obj)) return static_cast<uintptr_t>(addr);
    HandleScope scope(isolate_);
    int hash = Object::GetOrCreateHash(obj, isolate_).value();
    return static_cast<uintptr_t>(hash);
}

uintptr_t V8VmAdapter::GetIdentityHashForAddr(uintptr_t addr) {
    if (addr == 0) return 0;
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    if (IsSmi(obj)) return addr;
    if (!IsJSReceiver(obj)) return addr;
    HandleScope scope(isolate_);
    int hash = Object::GetOrCreateHash(obj, isolate_).value();
    return static_cast<uintptr_t>(hash);
}

uintptr_t V8VmAdapter::GetParamRawValue(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    return static_cast<uintptr_t>(addr);
}

uint64_t V8VmAdapter::GetStringContentHash(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    if (addr == 0) return 0;
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    if (IsSmi(obj) || !IsString(obj)) return static_cast<uint64_t>(addr);
    HandleScope scope(isolate_);
    Handle<String> str = handle(Cast<String>(obj), isolate_);
    str = String::Flatten(isolate_, str);
    int length = str->length();
    // FNV-1a hash of UTF-16 content (avoid allocation of UTF-8 buffer)
    uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
    for (int i = 0; i < length; i++) {
        uint16_t ch = str->Get(i);
        hash ^= static_cast<uint64_t>(ch & 0xFF);
        hash *= 1099511628211ULL;  // FNV prime
        hash ^= static_cast<uint64_t>(ch >> 8);
        hash *= 1099511628211ULL;
    }
    return hash;
}

const char* V8VmAdapter::GetTypeTag(int arg_index) {
    Address addr = TaintAdapter::GetPhysicalAddrFromMapping(isolate_, arg_index);
    if (addr == 0) return "undefined";
    // Check Smi first (tagged small integer — lowest bit is 0)
    if ((addr & 1) == 0) return "number";
    Address tagged_addr = static_cast<Address>(addr | 1);
    Tagged<Object> obj(tagged_addr);
    if (IsSmi(obj)) return "number";
    if (IsString(obj)) return "string";
    if (IsJSArray(obj)) return "array";
    if (IsJSFunction(obj)) return "function";
    if (IsBoolean(obj)) return "boolean";
    if (::v8::internal::IsNullOrUndefined(obj)) return "undefined";
    if (IsJSObject(obj)) return "object";
    return "object";
}

// =======================================================================
// Debug tools: Backtrace and Object Dump
// =======================================================================
void V8VmAdapter::PrintStackTrace() {
    v8::Isolate* api_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    v8::Message::PrintCurrentStackTrace(api_isolate, std::cerr);
}

void V8VmAdapter::PrintObject(uintptr_t obj_addr) {
    if (obj_addr == 0) {
        isolate_->dta_logger()->ObjectDump("NULL Pointer");
        return;
    }

    Address tagged_addr = static_cast<Address>(obj_addr | 1);
    Tagged<Object> obj(tagged_addr);

    const char* type_name;
    if (IsSmi(obj)) {
        type_name = "Smi";
    } else if (IsString(obj)) {
        type_name = "String";
    } else if (IsJSTypedArray(obj)) {
        type_name = "JSTypedArray (Node.js Buffer)";
    } else if (IsJSArrayBuffer(obj)) {
        type_name = "JSArrayBuffer";
    } else if (IsJSArray(obj)) {
        type_name = "JSArray";
    } else if (IsJSObject(obj)) {
        type_name = "JSObject";
    } else if (IsContext(obj)) {
        type_name = "Context";
    } else if (IsSharedFunctionInfo(obj)) {
        type_name = "SharedFunctionInfo";
    } else if (IsOddball(obj)) {
        type_name = "Oddball (undefined/null/true/false)";
    } else if (IsMap(obj)) {
        type_name = "Map (HiddenClass)";
    } else {
        type_name = "Unknown HeapObject";
    }
    isolate_->dta_logger()->ObjectDump(type_name);
}

// =======================================================================
// Builtin-to-JS callback heap taint bridge
// Called from DtaRestoreArgs after DtaTransferArgTaintsFromBuf.
// =======================================================================
// HOF EXTRACT on Return: called from Return bytecode handler BEFORE
// the shadow frame is destroyed. If the parent call frame is an HOF
// with EXTRACT rules, stores the callback return taint on the return
// value OBJECT (heap taint). This ensures taint survives Torque-level
// stores into the result array.
//
// This is the per-callback-return interception point — general, no
// Torque instrumentation needed.
// =======================================================================
Address TaintAdapter::HofExtractOnReturn(Address return_value) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return return_value;

  uint32_t acc_taint = engine->GetAccumulatorTaint();
  if (acc_taint == 0) return return_value;

  // Scan up the call stack for an HOF builtin with EXTRACT rules.
  // The parent may be an intermediate builtin (e.g., ArrayIteratorPrototypeNext)
  // between the callback and the actual HOF (ArrayMap).
  const dynalysis::BuiltinRuleDescriptor* hof_desc = nullptr;
  size_t hof_frame_idx = 0;
  size_t stack_top = engine->GetCallStackTop();
  for (size_t i = 1; i <= stack_top && i <= 5; i++) {
    size_t idx = stack_top - i;
    const auto& frame = engine->GetCallStackEntry(idx);
    if (frame.category == dynalysis::TargetCategory::kNativeBuiltin
        && frame.target_id >= 0) {
      auto* desc = dynalysis::TslInterpreter::LookupBuiltin(frame.target_id);
      if (desc && desc->hof.is_hof && !desc->hof.extract_rules.empty()) {
        hof_desc = desc;
        hof_frame_idx = idx;
        break;
      }
    }
  }
  if (!hof_desc) return return_value;

  // Accumulate callback return taint into HOF frame's hof_acc buffer.
  // No per-iteration graph nodes — dedup + one flat CreateNode at post-hook.
  {
    auto& hof_frame = engine->GetMutableCallStackEntry(hof_frame_idx);
    if (hof_frame.hof_acc_count < dynalysis::CallFrameContext::kMaxHofAcc) {
      hof_frame.hof_acc[hof_frame.hof_acc_count++] = acc_taint;
    }
  }

  // Also store taint on the callback return value object (belt-and-suspenders
  // for individual element queries via result-side fallback).
  if (!HAS_SMI_TAG(return_value) && return_value != kNullAddress) {
    uintptr_t addr = UNTAG(static_cast<uintptr_t>(return_value));
    engine->SetHeapTaint(addr, dynalysis::ELEM_WILDCARD_KEY, acc_taint);
    isolate->dta_logger()->HofExtractAddr(
        hof_desc->operation_name, acc_taint, addr);
  }

  return return_value;
}

// =======================================================================
// When all param taints are zero (callback from CSA builtin, no pre-hook
// taint data), scans the frame's actual arguments for heap taint and
// writes to shadow frame params.
// =======================================================================
void TaintAdapter::BridgeCallbackHeapTaint(Address frame_ptr) {
  #define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return;

  // Check if HOF INJECT already handled this callback —
  // DispatchHofInject runs in DtaPushFrameAndLeave before this function.
  if (engine->GetCallStackTop() > 0 &&
      engine->GetTargetCategory() == dynalysis::TargetCategory::kNativeBuiltin) {
    int tid = engine->GetTargetId();
    auto* desc = dynalysis::TslInterpreter::LookupBuiltin(tid);
    if (desc && desc->hof.is_hof && !desc->hof.inject_rules.empty()) {
      return;  // INJECT rules handle this, skip brute-force scan
    }
  }

  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  if (!shadow_base) return;

  // Fast exit: if any of the first 4 user param slots already has taint,
  // the pre-hook worked correctly — no bridging needed.
  // FromParameterIndex(0) = receiver; user params start at index 1.
  constexpr int kFirstUserParamOperand =
      interpreter::Register::FromParameterIndex(1).ToOperand();
  for (int i = 0; i < 4; i++) {
    if (shadow_base[kFirstUserParamOperand + i] != 0) return;
  }

  // Read argument count from the frame.
  // StandardFrameConstants::kArgCOffset = -3 * kSystemPointerSize on x64
  // Value includes receiver: actual_params = argc_with_receiver - 1
  intptr_t argc_with_receiver = *reinterpret_cast<intptr_t*>(
      frame_ptr + StandardFrameConstants::kArgCOffset);
  int argc = static_cast<int>(argc_with_receiver) - 1;  // exclude receiver
  if (argc <= 0) return;

  // V8 frame layout: arg[i] at caller_sp + (i + 1) * kSystemPointerSize
  // caller_sp = fp + CommonFrameConstants::kCallerSPOffset
  Address caller_sp = frame_ptr + CommonFrameConstants::kCallerSPOffset;

  for (int i = 0; i < argc && i < 16; i++) {
    Address arg_slot = caller_sp + (i + 1) * kSystemPointerSize;
    Address tagged_arg = *reinterpret_cast<Address*>(arg_slot);

    // Skip Smis (bit 0 = 0)
    if ((tagged_arg & 1) == 0) continue;

    uintptr_t addr = UNTAG(tagged_arg);
    uint32_t taint = engine->GetAnyWildcardTaint(addr);

    if (taint) {
      shadow_base[kFirstUserParamOperand + i] = taint;
      if (i == 0) {
        *(isolate->shadow_acc_taint_address()) = taint;
      }
    }
  }
  #undef UNTAG
}

// =======================================================================
// Consumer-side heap taint fallback for TaintBinaryOp.
// When shadow frame register taint is 0 but the object has heap taint,
// this returns the heap taint. Handles ThinString indirection too.
// =======================================================================
uint32_t TaintAdapter::GetHeapTaintForObject(Address obj_addr) {
  #define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
  // Skip Smis (bit 0 = 0 in tagged representation)
  if ((obj_addr & 1) == 0) return 0;

  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return 0;

  uintptr_t addr = UNTAG(static_cast<uintptr_t>(obj_addr));
  uint32_t taint = engine->GetAnyWildcardTaint(addr);

  // The String indirection paths below read the object's map. Bail out if the
  // candidate is not a live, dereferenceable heap object (raw slot data, etc.).
  if (!DtaIsDereferenceableHeapObject(isolate, obj_addr)) return taint;

  // ThinString indirection: if this is a ThinString, also check actual string
  if (!taint) {
    Tagged<Object> obj(obj_addr);
    if (IsHeapObject(obj) && IsThinString(Cast<HeapObject>(obj))) {
      Tagged<String> actual = Cast<ThinString>(Cast<HeapObject>(obj))->actual();
      uintptr_t actual_addr = UNTAG(actual.ptr());
      taint = engine->GetAnyWildcardTaint(actual_addr);
    }
  }

  // Flat ConsString indirection: after SlowFlatten, taint migrates to first()
  // but the ConsString object persists at its original address (now flat).
  if (!taint) {
    Tagged<Object> obj(obj_addr);
    if (IsHeapObject(obj) && IsConsString(Cast<HeapObject>(obj))) {
      Tagged<ConsString> cons = Cast<ConsString>(Cast<HeapObject>(obj));
      if (cons->IsFlat()) {
        Tagged<String> first = cons->first();
        uintptr_t first_addr = UNTAG(first.ptr());
        taint = engine->GetAnyWildcardTaint(first_addr);
      }
    }
  }

  // TEMP DEBUG (env DTA_DBG_GHT): trace string-taint lookups so we can see where
  // the execSync command-string taint is lost. Remove once the FN is fixed.
  static const bool dta_dbg_ght = (getenv("DTA_DBG_GHT") != nullptr);
  if (dta_dbg_ght) {
    Tagged<Object> obj(obj_addr);
    if (IsHeapObject(obj) && IsString(Cast<HeapObject>(obj))) {
      Tagged<String> str = Cast<String>(Cast<HeapObject>(obj));
      uint32_t direct = engine->GetAnyWildcardTaint(addr);
      const char* kind = IsThinString(str) ? "THIN"
                       : IsConsString(str) ? "CONS"
                       : IsSlicedString(str) ? "SLICED"
                       : IsInternalizedString(str) ? "INTERNALIZED"
                       : IsSeqString(str) ? "SEQ" : "OTHER";
      int len = str->length();
      char buf[33]; int n = (len < 32) ? len : 32;
      for (int i = 0; i < n; i++) {
        uint16_t c = str->Get(i);
        buf[i] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
      }
      buf[n] = '\0';
      fprintf(stderr,
              "[GHT] addr=0x%lx kind=%s len=%d direct=%u final=%u \"%s\"\n",
              (unsigned long)addr, kind, len, direct, taint, buf);
    }
  }

  return taint;
  #undef UNTAG
}

// =======================================================================
// Dual-Track Taint Resolution for argument taint lookup.
// Returns shadow-frame taint if non-zero, otherwise falls back to
// shadow-heap taint. Handles ThinString indirection.
// =======================================================================
void TaintAdapter::CopyObjectTaint(Address source, Address target) {
  if (HAS_SMI_TAG(source) || HAS_SMI_TAG(target)) return;
  Isolate* isolate = Isolate::TryGetCurrent();
  if (!isolate) return;  // mksnapshot or no isolate
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return;

  uintptr_t src = source & ~static_cast<uintptr_t>(1);
  uintptr_t tgt = target & ~static_cast<uintptr_t>(1);
  engine->CopyAllHeapTaints(src, tgt);
  if (engine->IsObjectTracked(src)) {
    RegisterWeakHandleIfNecessary(isolate, target);
  }
}

uint32_t TaintAdapter::GetEffectiveTaintForArg(Address frame_ptr, int reg_operand, Address obj_addr) {
  Isolate* isolate = GetCurrentInternalIsolate();
  dynalysis::TaintEngine* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return 0;

  uint32_t result = engine->GetEffectiveTaint(
      static_cast<uintptr_t>(frame_ptr),
      reg_operand,
      static_cast<uintptr_t>(obj_addr));

  // ThinString indirection: if heap taint is still 0, check actual string
  if (result == 0 && (obj_addr & 1) != 0) {
    Tagged<Object> obj(obj_addr);
    if (IsHeapObject(obj) && IsThinString(Cast<HeapObject>(obj))) {
      Tagged<String> actual = Cast<ThinString>(Cast<HeapObject>(obj))->actual();
      result = engine->GetEffectiveTaint(
          static_cast<uintptr_t>(frame_ptr),
          reg_operand,
          static_cast<uintptr_t>(actual.ptr()));
    }
  }

  return result;
}

// =======================================================================
// String::Flatten taint migration
// When SlowFlatten creates a new SeqString from a ConsString, migrate
// all heap taint entries from the old ConsString address to the new address.
// =======================================================================
void TaintAdapter::MigrateStringFlattenTaint(Isolate* isolate,
                                              Address cons_addr,
                                              Address flat_addr) {
  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) return;

  #define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
  uintptr_t old_addr = UNTAG(static_cast<uintptr_t>(cons_addr));
  if (!engine->IsObjectTracked(old_addr)) return;

  uintptr_t new_addr = UNTAG(static_cast<uintptr_t>(flat_addr));
  engine->MoveHeapTaint(old_addr, new_addr);
  RegisterWeakHandleIfNecessary(isolate, flat_addr);
  #undef UNTAG
}

// =======================================================================
// Location provider for FlowNode provenance — walks the JS stack to
// extract "basename:line" from the top JavaScript frame.
// =======================================================================
static std::string V8GetLocation(void* ctx) {
  Isolate* isolate = static_cast<Isolate*>(ctx);
  JavaScriptStackFrameIterator it(isolate);
  if (it.done()) return "";

  JavaScriptFrame* frame = it.frame();
  Tagged<JSFunction> fn = frame->function();
  Tagged<SharedFunctionInfo> sfi = fn->shared();
  if (!sfi->has_script(kAcquireLoad)) return "";
  Tagged<HeapObject> script_obj = sfi->script();
  if (!IsScript(script_obj)) return "";

  int pos = frame->position();
  if (pos < 0) return "";

  Tagged<Script> script = Cast<Script>(script_obj);
  Script::PositionInfo info;
  if (!script->GetPositionInfo(pos, &info)) return "";
  int line = info.line + 1;  // 0-based to 1-based

  Tagged<Object> name_obj = script->GetNameOrSourceURL();
  if (!IsString(name_obj)) return "";

  std::unique_ptr<char[]> name_cstr = Cast<String>(name_obj)->ToCString();
  const char* full_path = name_cstr.get();

  // Extract basename
  const char* basename = full_path;
  for (const char* p = full_path; *p; ++p) {
    if (*p == '/' || *p == '\\') basename = p + 1;
  }

  char buf[128];
  snprintf(buf, sizeof(buf), "%.100s:%d", basename, line);
  return std::string(buf);
}

// =======================================================================
// Adapter-layer boot hook — called from Isolate::Init instead of
// TslInterpreter::EagerInitialize(isolate) directly.
// =======================================================================
void TaintAdapter::EagerInitializeForIsolate(Isolate* isolate) {
  V8VmAdapter vm_adapter(isolate);
  dynalysis::TslInterpreter::EagerInitialize(vm_adapter);

  // Initialize var store from tbin v4+ var declarations
  const auto* var_decls = dynalysis::TslInterpreter::GetVarDeclarations();
  if (var_decls && !var_decls->empty() && isolate->taint_engine()) {
    isolate->taint_engine()->InitVarStore(*var_decls);
  }

  // Set DTA_ACTIVE env var so child processes inherit DTA mode
  if (v8_flags.dta_maglev) {
    setenv("DTA_ACTIVE", "1", 0);  // don't overwrite if already set
    // Propagate JSON log path to children
    if (v8_flags.dta_json_log) {
      setenv("DTA_JSON_LOG", v8_flags.dta_json_log, 0);
    }
  }

  // Register location provider for FlowNode provenance
  if (isolate->taint_engine()) {
    isolate->taint_engine()->SetLocationProvider(&V8GetLocation, isolate);
    // Register taint-live latch callback: flips the Isolate's
    // dta_any_taint_live_ byte the first time any taint node is minted, so the
    // inline DtaShadowHeapLoad fast path can skip the heap query until then.
    isolate->taint_engine()->SetTaintLiveCallback(
        [](void* ctx) {
          static_cast<Isolate*>(ctx)->dta_set_any_taint_live();
        },
        isolate);
  }

  // Always-On mode: when --dta-maglev is active, enable tracking from the
  // start so Node.js bootstrap code (path.join, url.parse, etc.) compiles
  // with DTA instrumentation active. This ensures SFI TaintSkipBit learning
  // during bootstrap correctly classifies functions that have taint rules.
  if (v8_flags.dta_maglev && isolate->taint_engine()) {
    isolate->taint_engine()->EnableTracking();

    // [DTA Phase 3] PromiseHook registration deferred — see comment below.
    // Registering a no-op PromiseHook here causes segfault during Node.js
    // bootstrap because FulfillPromise delegates to C++ Runtime_FulfillPromise
    // before the Isolate is fully initialized. The Torque FulfillPromise
    // delegation is in place but requires the hook to be registered AFTER
    // bootstrap completes. For now, Phase 1+2 provide coverage via
    // ResumeGenerator heap taint lookup + DtaBridgeAsyncReturn.
    // TODO: Register PromiseHook after bootstrap via a flag or lazy init.
  }
}

}  // namespace taint
}  // namespace internal
}  // namespace v8
