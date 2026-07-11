#include <algorithm>

#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/runtime/runtime.h"
#include "src/runtime/runtime-utils.h"
#include "src/taint/taint-adapter.h"
#include "src/objects/string-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/interpreter/bytecodes.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_TaintBinaryOpStub) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> result = args.at(0);
  
  PrintF("[Taint Bytecode MVP] TaintBinaryOp Executed! Result Address is: %p\n", 
         reinterpret_cast<void*>((*result).ptr()));

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetTaint) {
  #define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
  // Deep wildcards for recursive contagion through nested property reads.
  // This matches the attacker model: JSON.parse(attacker_input) produces
  // a fully-controlled tree — all nested properties carry taint.
  constexpr uintptr_t ELEM_DEEP_KEY = 0xFFFFFFFFFFFFFFFC;
  constexpr uintptr_t PROP_DEEP_KEY = 0xFFFFFFFFFFFFFFFD;
  HandleScope scope(isolate);
  DCHECK_GE(args.length(), 1);
  Handle<Object> target = args.at(0);

  // 1. Parse optional second argument as taint source label
  std::string source_name = "TaintSource";
  if (args.length() >= 2 && IsString(*args.at(1))) {
      Handle<String> str = args.at<String>(1);
      std::unique_ptr<char[]> utf8_chars = str->ToCString();
      source_name = utf8_chars.get();
  }

  // 2. Create taint node and bind to accumulator
  uint32_t real_id = isolate->taint_engine()->CreateNode(source_name);
  isolate->taint_engine()->SetAccumulatorTaint(real_id);

  // 3. Register weak handle and bind heap taint
  if (!IsSmi(*target)) {
      taint::TaintAdapter::RegisterWeakHandleIfNecessary(isolate, (*target).ptr());
      uintptr_t addr = UNTAG((*target).ptr());
      if (IsString(*target)) {
          // Strings: ELEM_SHALLOW only (original behavior).
          // String taint propagates through shadow_acc (register-level), not heap contagion.
          constexpr uintptr_t ELEM_SHALLOW_KEY = 0xFFFFFFFFFFFFFFFF;
          isolate->taint_engine()->SetHeapTaint(addr, ELEM_SHALLOW_KEY, real_id);
          static const bool dta_dbg_ght = (getenv("DTA_DBG_GHT") != nullptr);
          if (dta_dbg_ght) {
            Tagged<String> s = Cast<String>(*target);
            fprintf(stderr, "[SETTAINT] addr=0x%lx id=%u internalized=%d thin=%d\n",
                    (unsigned long)addr, real_id,
                    IsInternalizedString(s) ? 1 : 0, IsThinString(s) ? 1 : 0);
          }
      } else {
          // Objects/Arrays: both DEEP wildcards for recursive contagion.
          // Matches attacker model: JSON.parse(input) produces fully-controlled tree.
          isolate->taint_engine()->SetHeapTaint(addr, ELEM_DEEP_KEY, real_id);
          isolate->taint_engine()->SetHeapTaint(addr, PROP_DEEP_KEY, real_id);
      }
  }

  return *target;
}

RUNTIME_FUNCTION(Runtime_GetTaint) {
 #define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
  HandleScope scope(isolate);
  DCHECK_GE(args.length(), 1);
  Handle<Object> target = args.at(0);

  // 1. Primary: read from DTA arg taint buffer (execution state).
  //    DtaCallPreHook fills this before the runtime call enters C++.
  //    For CallRuntime, prepend_receiver=0 so index 0 = first arg.
  uint32_t taint_id = 0;
  uint8_t buf_count = *(isolate->dta_arg_count_address());
  for (uint8_t i = 0; i < buf_count && taint_id == 0; i++) {
    taint_id = isolate->dta_arg_taint_buf_address()[i];
  }

  // 2. Fallback: read from CallFrameContext arg mapping (physical register/frame)
  if (taint_id == 0) {
    taint_id = taint::TaintAdapter::GetRuntimeArgTaint(isolate, 1);
  }

  // 3. Fallback: query Shadow Heap wildcards for heap objects (data state)
  if (taint_id == 0 && !IsSmi(*target)) {
      uintptr_t physical_addr = UNTAG((*target).ptr());
      taint_id = isolate->taint_engine()->GetHeapTaint(physical_addr, dynalysis::ELEM_WILDCARD_KEY);
      if (taint_id == 0) {
          taint_id = isolate->taint_engine()->GetHeapTaint(physical_addr, dynalysis::PROP_WILDCARD_KEY);
      }
  }

  if (taint_id != 0) {
      isolate->taint_engine()->PrintFlowTree(taint_id);
  }

  return Smi::FromInt(taint_id);
}

// [DTA Maglev] GC-safe property taint store — called via Runtime stub with ExitFrame.
RUNTIME_FUNCTION(Runtime_DtaSetNamedPropertyTaint) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Address obj_addr = args[0].ptr();
  Address name_addr = args[1].ptr();
  int taint_id = args.smi_value_at(2);
  int key_taint = args.smi_value_at(3);
  taint::TaintAdapter::CallSetNamedPropertyTaint(obj_addr, name_addr,
                                                  static_cast<uint32_t>(taint_id),
                                                  static_cast<uint32_t>(key_taint));
  return ReadOnlyRoots(isolate).undefined_value();
}

// [DTA Maglev] GC-safe post-call taint rule application — called via Runtime stub.
RUNTIME_FUNCTION(Runtime_DtaApplyCallRuleTaint) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Address result_addr = args[0].ptr();
  uint32_t taint = taint::TaintAdapter::CallApplyCallRuleTaint(result_addr);
  return Smi::FromInt(static_cast<int>(taint));
}

// [DTA Maglev] GC-safe call pre-hook — variable-arity Runtime stub.
// Receives actual tagged arg values pushed by DtaCallPreHook::GenerateCode.
// args[0]=target, args[1]=Smi(prepend), args[2]=Smi(first_reg_operand),
// args[3..N+2]=actual tagged arg ValueNodes from SSA graph.
RUNTIME_FUNCTION(Runtime_DtaMaglevCallPreHook) {
  HandleScope scope(isolate);
  DCHECK_GE(args.length(), 3);
  Address target_func = args[0].ptr();
  int prepend_receiver = args.smi_value_at(1);
  int first_reg_operand = args.smi_value_at(2);
  int actual_arg_count = args.length() - 3;

  // Collect actual tagged pointers from GC-safe Arguments object.
  // These are the real arg values from the Maglev SSA graph — correct
  // even though the Maglev frame has no interpreter register file.
  Address arg_addrs[32];
  int safe_count = std::min(actual_arg_count, 32);
  for (int i = 0; i < safe_count; i++) {
    arg_addrs[i] = args[i + 3].ptr();
  }

  taint::TaintAdapter::DtaMaglevCallPreHook(
      target_func, first_reg_operand, safe_count, prepend_receiver, arg_addrs);
  return ReadOnlyRoots(isolate).undefined_value();
}

// [DTA Maglev] Bind shadow_acc taint to a newly created heap object.
// Called after binary ops (e.g., StringConcat) that produce new objects.
// Registers the taint in shadow_heap so GetHeapTaint-based lookups work.
RUNTIME_FUNCTION(Runtime_DtaBindResultTaint) {
  #define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> result = args.at(0);

  uint32_t taint_id = *(isolate->shadow_acc_taint_address());
  if (taint_id != 0 && !IsSmi(*result)) {
    uintptr_t physical_addr = UNTAG((*result).ptr());
    taint::TaintAdapter::RegisterWeakHandleIfNecessary(isolate, (*result).ptr());
    isolate->taint_engine()->SetHeapTaint(physical_addr,
                                          dynalysis::ELEM_WILDCARD_KEY, taint_id);
  }

  return ReadOnlyRoots(isolate).undefined_value();
  #undef UNTAG
}

// [DTA Maglev] Binary op taint propagation — creates derived taint node.
// Called from DtaTaintBinaryOp slow path when (left | right) != 0.
// Args: result_obj (tagged), reg_operand (Smi), op_token (Smi)
RUNTIME_FUNCTION(Runtime_DtaPropagateBinaryOp) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> result = args.at(0);
  int reg_operand = args.smi_value_at(1);
  int op_token = args.smi_value_at(2);

  // Read left_taint from shadow_frame[reg_operand]
  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  uint32_t left_taint = shadow_base ? shadow_base[reg_operand] : 0;
  // Read right_taint from shadow_acc
  uint32_t right_taint = *(isolate->shadow_acc_taint_address());

  // Create derived node via existing PropagateBinaryOp
  Address result_addr = IsSmi(*result) ? 0 : (*result).ptr();
  uint32_t new_taint = taint::TaintAdapter::PropagateBinaryOp(
      left_taint, right_taint, op_token, result_addr);

  // Write new taint ID to shadow_acc
  *(isolate->shadow_acc_taint_address()) = new_taint;

  return Smi::FromInt(static_cast<int>(new_taint));
}

// ===========================================================================
// Generator suspend/resume: save/restore shadow frame taint
// Uses shadow_heap with generator address as object key, operand as field key.
// ===========================================================================
RUNTIME_FUNCTION(Runtime_DtaSuspendGeneratorTaint) {
  // Args: generator, parameter_count (Smi), register_count (Smi)
  DCHECK_EQ(3, args.length());
  Handle<Object> generator = args.at(0);
  int param_count = args.smi_value_at(1);
  int reg_count = args.smi_value_at(2);

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  uintptr_t gen_addr = (*generator).ptr();
  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  if (!shadow_base) return ReadOnlyRoots(isolate).undefined_value();

  // Save parameter taints (parameter operands start at FromParameterIndex(0).ToOperand())
  // Register::FromParameterIndex(i).ToOperand() gives the operand for param i
  constexpr int kParamOperandBase =
      interpreter::Register::FromParameterIndex(0).ToOperand();
  for (int i = 0; i < param_count; i++) {
    int operand = kParamOperandBase + i;
    uint32_t taint = shadow_base[operand];
    if (taint != 0) {
      engine->SetHeapTaint(gen_addr, static_cast<uintptr_t>(operand + 0x10000), taint);
    }
  }

  // Save register taints (register operands are negative: -7, -8, -9, ...)
  // Register(0).ToOperand() = -7 on x64 (kRegisterFileStartOffset)
  // Register(i).ToOperand() = -7 - i
  for (int i = 0; i < reg_count; i++) {
    int operand = -7 - i;  // Register(i).ToOperand() on x64
    uint32_t taint = shadow_base[operand];
    if (taint != 0) {
      engine->SetHeapTaint(gen_addr, static_cast<uintptr_t>(operand + 0x10000), taint);
    }
  }

  // Save shadow_acc
  uint32_t acc_taint = *(isolate->shadow_acc_taint_address());
  if (acc_taint != 0) {
    engine->SetHeapTaint(gen_addr, dynalysis::DTA_GENERATOR_ACC_KEY, acc_taint);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DtaResumeGeneratorTaint) {
  // Args: generator, parameter_count (Smi), register_count (Smi)
  DCHECK_EQ(3, args.length());
  Handle<Object> generator = args.at(0);
  int param_count = args.smi_value_at(1);
  int reg_count = args.smi_value_at(2);

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  uintptr_t gen_addr = (*generator).ptr();
  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  if (!shadow_base) return ReadOnlyRoots(isolate).undefined_value();

  // Restore parameter taints
  constexpr int kResumeParamBase =
      interpreter::Register::FromParameterIndex(0).ToOperand();
  for (int i = 0; i < param_count; i++) {
    int operand = kResumeParamBase + i;
    uint32_t taint = engine->GetHeapTaint(gen_addr, static_cast<uintptr_t>(operand + 0x10000));
    if (taint != 0) {
      shadow_base[operand] = taint;
    }
  }

  // Restore register taints
  for (int i = 0; i < reg_count; i++) {
    int operand = -7 - i;
    uint32_t taint = engine->GetHeapTaint(gen_addr, static_cast<uintptr_t>(operand + 0x10000));
    if (taint != 0) {
      shadow_base[operand] = taint;
    }
  }

  // =========================================================================
  // Restore shadow_acc — priority-based lookup for async/await taint tracking
  // 1. GetHeapTaint(sent_value): resolved value is a heap object with taint
  // 2. Promise taint (DTA_PROMISE_RESOLVED_KEY): async return bridged taint
  // 3. Saved shadow_acc (DTA_GENERATOR_ACC_KEY): fallback for simple cases
  // =========================================================================
  {
    #define UNTAG_ADDR(addr) ((addr) & ~static_cast<uintptr_t>(0x1))
    uint32_t resume_taint = 0;

    // 1. Read the sent_value (resolved value) from generator.input_or_debug_pos
    Tagged<Object> gen = *generator;
    Tagged<Object> sent_value =
        Cast<JSGeneratorObject>(gen)->input_or_debug_pos();

    // Try GetHeapTaint on sent_value (works for strings, objects, arrays, buffers)
    if (!IsSmi(sent_value)) {
      uintptr_t sent_addr = sent_value.ptr();
      resume_taint = engine->GetHeapTaint(UNTAG_ADDR(sent_addr),
                                          dynalysis::ELEM_WILDCARD_KEY);
      if (!resume_taint)
        resume_taint = engine->GetHeapTaint(UNTAG_ADDR(sent_addr),
                                            dynalysis::PROP_WILDCARD_KEY);
    }

    // 2. For async functions: check promise's DTA_PROMISE_RESOLVED_KEY
    //    (set by DtaBridgeAsyncReturn or JSPromise::Fulfill hook)
    if (!resume_taint && IsJSAsyncFunctionObject(gen)) {
      Tagged<JSPromise> promise =
          Cast<JSAsyncFunctionObject>(gen)->promise();
      uintptr_t promise_addr = promise.ptr();
      resume_taint = engine->GetHeapTaint(UNTAG_ADDR(promise_addr),
                                          dynalysis::DTA_PROMISE_RESOLVED_KEY);
      // "Read-and-Burn": clear promise taint entry immediately to avoid
      // accumulating weak handles for short-lived promise objects
      if (resume_taint) {
        engine->SetHeapTaint(UNTAG_ADDR(promise_addr),
                             dynalysis::DTA_PROMISE_RESOLVED_KEY, 0);
      }
    }

    // 3. Fallback: saved shadow_acc from SuspendGenerator
    if (!resume_taint) {
      resume_taint = engine->GetHeapTaint(gen_addr,
                                          dynalysis::DTA_GENERATOR_ACC_KEY);
    }

    if (resume_taint != 0) {
      *(isolate->shadow_acc_taint_address()) = resume_taint;
    }
    #undef UNTAG_ADDR
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// ===========================================================================
// CreateRestParameter: copy arg taints from shadow frame to rest array's
// shadow heap entries. Called after CreateRestParameter creates the JS array.
// ===========================================================================
RUNTIME_FUNCTION(Runtime_DtaCreateRestParameterTaint) {
  DCHECK_EQ(2, args.length());
  Handle<Object> rest_array = args.at(0);
  int formal_count = args.smi_value_at(1);

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  if (IsSmi(*rest_array) || !IsJSArray(*rest_array)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  Tagged<JSArray> arr = Cast<JSArray>(*rest_array);
  int rest_length = IsSmi(arr->length()) ? Smi::ToInt(arr->length()) : 0;
  if (rest_length == 0) return ReadOnlyRoots(isolate).undefined_value();

  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  if (!shadow_base) return ReadOnlyRoots(isolate).undefined_value();

  uintptr_t arr_addr = (*rest_array).ptr() & ~static_cast<uintptr_t>(1);

  // rest[j] = actual_arg[formal_count + j]
  constexpr int kRestParamBase =
      interpreter::Register::FromParameterIndex(0).ToOperand();
  bool any_tainted = false;
  for (int j = 0; j < rest_length && j < 32; j++) {
    // +1 for prepended receiver (CallUndefinedReceiver always prepends)
    int operand = kRestParamBase + 1 + formal_count + j;
    uint32_t taint = shadow_base[operand];
    // [DTA E8] Heap fallback: if frame taint is 0, check the actual arg object
    if (taint == 0) {
      Tagged<FixedArray> elements = Cast<FixedArray>(arr->elements());
      if (j < elements->length()) {
        Tagged<Object> elem = elements->get(j);
        if (!IsSmi(elem)) {
          taint = taint::TaintAdapter::GetHeapTaintForObject(elem.ptr());
        }
      }
    }
    if (taint != 0) {
      uintptr_t smi_key = static_cast<uintptr_t>(Smi::FromInt(j).ptr())
                          & ~static_cast<uintptr_t>(1);
      engine->SetHeapTaint(arr_addr, smi_key, taint);
      any_tainted = true;
    }
  }

  if (any_tainted) {
    taint::TaintAdapter::RegisterWeakHandleIfNecessary(isolate, (*rest_array).ptr());
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// ===========================================================================
// DtaCreateArgumentsTaint: Bridge parameter taint from shadow frame to the
// arguments object's shadow heap entries. Called after CreateMappedArguments
// and CreateUnmappedArguments. Fixes: arguments[i] reads lose frame taint.
// ===========================================================================
RUNTIME_FUNCTION(Runtime_DtaCreateArgumentsTaint) {
  DCHECK_EQ(1, args.length());
  Handle<Object> args_obj = args.at(0);

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  if (IsSmi(*args_obj) || !IsJSObject(*args_obj)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  if (!shadow_base) return ReadOnlyRoots(isolate).undefined_value();

  // Get formal parameter count from the function's SFI
  Tagged<JSObject> obj = Cast<JSObject>(*args_obj);
  int length = 0;
  if (IsJSArgumentsObject(obj)) {
    // Read length from the arguments object
    Tagged<FixedArrayBase> elements = obj->elements();
    length = elements->length();
    if (length > 32) length = 32;
  }
  if (length == 0) {
    // Fallback: try reading actual arg count from frame
    length = static_cast<int>(engine->GetArgMappingCount());
    if (length > 32) length = 32;
  }

  uintptr_t obj_addr = (*args_obj).ptr() & ~static_cast<uintptr_t>(1);
  constexpr int kParamBase =
      interpreter::Register::FromParameterIndex(0).ToOperand();

  bool any_tainted = false;
  for (int i = 0; i < length; i++) {
    // +1 for prepended receiver
    int operand = kParamBase + 1 + i;
    uint32_t taint = shadow_base[operand];
    if (taint != 0) {
      uintptr_t smi_key = static_cast<uintptr_t>(Smi::FromInt(i).ptr())
                          & ~static_cast<uintptr_t>(1);
      engine->SetHeapTaint(obj_addr, smi_key, taint);
      any_tainted = true;
    }
  }

  // Also set ELEM_WILDCARD if any element is tainted (for [].slice.call support)
  if (any_tainted) {
    // Use first found taint as wildcard representative
    for (int i = 0; i < length; i++) {
      int operand = kParamBase + 1 + i;
      uint32_t taint = shadow_base[operand];
      if (taint != 0) {
        engine->SetHeapTaint(obj_addr, dynalysis::ELEM_SHALLOW_KEY, taint);
        break;
      }
    }
    taint::TaintAdapter::RegisterWeakHandleIfNecessary(isolate, (*args_obj).ptr());
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// ===========================================================================
// DtaBridgeAsyncReturn: Bridge return value taint to async function's outer
// promise. Called from BuildAsyncReturn BEFORE InlineAsyncFunctionResolve.
// Stores shadow_acc (return value taint) on the promise using
// DTA_PROMISE_RESOLVED_KEY so ResumeGenerator in the caller finds it.
// No RegisterWeakHandleIfNecessary — "Read-and-Burn" at ResumeGenerator.
// ===========================================================================
RUNTIME_FUNCTION(Runtime_DtaBridgeAsyncReturn) {
  DCHECK_EQ(2, args.length());
  Handle<Object> generator = args.at(0);
  // args[1] is the return value — unused here, taint is in shadow_acc

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Read shadow_acc — this is the taint of the async return value
  uint32_t acc_taint = *(isolate->shadow_acc_taint_address());
  if (acc_taint == 0) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Store taint on the outer promise (no weak handle — read-and-burn)
  Tagged<Object> gen = *generator;
  if (IsJSAsyncFunctionObject(gen)) {
    Tagged<JSPromise> promise =
        Cast<JSAsyncFunctionObject>(gen)->promise();
    uintptr_t promise_addr = promise.ptr() & ~static_cast<uintptr_t>(1);
    engine->SetHeapTaint(promise_addr,
                         dynalysis::DTA_PROMISE_RESOLVED_KEY, acc_taint);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// ===========================================================================
// DtaCopyObjectTaint: Copy shadow heap taint from source to target.
// Called from CloneObject (ES6 object spread) and CopyDataProperties.
// ===========================================================================
RUNTIME_FUNCTION(Runtime_DtaCopyObjectTaint) {
  DCHECK_EQ(2, args.length());
  auto source = args.at(0);
  auto target = args.at(1);

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  if (IsSmi(*source) || IsSmi(*target)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  uintptr_t src_addr = (*source).ptr() & ~static_cast<uintptr_t>(1);
  uintptr_t tgt_addr = (*target).ptr() & ~static_cast<uintptr_t>(1);
  engine->CopyAllHeapTaints(src_addr, tgt_addr);
  if (engine->IsObjectTracked(src_addr)) {
    taint::TaintAdapter::RegisterWeakHandleIfNecessary(isolate, (*target).ptr());
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// =========================================================================
// Bridge taint through CreateIterResultObject.
//
// Called from InvokeIntrinsic handler when the intrinsic is
// _CreateIterResultObject. The intrinsic creates {value, done} but drops
// taint because it's a black-box C++ builtin with no DTA hooks.
//
// Args: iter_result_object (the newly created {value, done}),
//       value_reg_operand (Smi: shadow frame operand of the value register)
//
// Reads shadow_frame[value_reg_operand] to get the value's taint, then
// stores it on the IterResultObject under ELEM_WILDCARD_KEY. The caller's
// LdaNamedProperty(.value) finds it via GetHeapTaintWildcard fallback.
// Also sets shadow_acc so downstream SuspendGenerator captures it.
// =========================================================================
RUNTIME_FUNCTION(Runtime_DtaBridgeIterResultTaint) {
  DCHECK_EQ(2, args.length());
  Handle<Object> iter_result = args.at(0);
  int value_operand = args.smi_value_at(1);

  auto* engine = isolate->taint_engine();
  if (!engine || !engine->IsTrackingActive()) {
    return *iter_result;
  }

  uint32_t* shadow_base = *(isolate->shadow_frame_base_address());
  if (!shadow_base) return *iter_result;

  uint32_t value_taint = shadow_base[value_operand];
  if (value_taint == 0) return *iter_result;

  // Store taint on the IterResultObject under ELEM_WILDCARD_KEY.
  // LdaNamedProperty's CallGetNamedPropertyTaint checks wildcards via
  // GetHeapTaintWildcard (Mode B), so reading .value will find this taint.
  uintptr_t result_addr = (*iter_result).ptr() & ~static_cast<uintptr_t>(1);
  engine->SetHeapTaint(result_addr, dynalysis::ELEM_WILDCARD_KEY, value_taint);
  taint::TaintAdapter::RegisterWeakHandleIfNecessary(isolate, (*iter_result).ptr());

  // Also set shadow_acc so downstream code sees the taint.
  *(isolate->shadow_acc_taint_address()) = value_taint;

  return *iter_result;
}

}  // namespace internal
}  // namespace v8