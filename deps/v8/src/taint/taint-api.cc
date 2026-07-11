// deps/v8/src/taint/taint-api.cc
#include "include/v8-taint.h"
#include "src/api/api-inl.h"
#include "src/execution/isolate.h"
#include "src/taint/taint-core.h"
#include "src/taint/taint-adapter.h"
#include "src/taint/taint-logger.h"

namespace v8 {
namespace taint {

#define UNTAG(addr) ((addr) & ~static_cast<uintptr_t>(0x1))

void SetTaint(Isolate* isolate, Local<Value> value, const char* source_name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::Object> internal_obj = Utils::OpenHandle(*value);

  uint32_t real_id = i_isolate->taint_engine()->CreateNode(source_name);
  i_isolate->taint_engine()->SetAccumulatorTaint(real_id);

  if (!i::IsSmi(*internal_obj)) {
      i::taint::TaintAdapter::RegisterWeakHandleIfNecessary(i_isolate, (*internal_obj).ptr());
      
      constexpr uintptr_t WILDCARD_KEY = 0xFFFFFFFFFFFFFFFF;
      i_isolate->taint_engine()->SetHeapTaint(UNTAG((*internal_obj).ptr()), WILDCARD_KEY, real_id);
  }
}

uint32_t GetTaint(Isolate* isolate, Local<Value> value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::Object> internal_obj = Utils::OpenHandle(*value);

  if (!i::IsSmi(*internal_obj)) {
      uintptr_t physical_addr = UNTAG((*internal_obj).ptr());

      uint32_t t = i_isolate->taint_engine()->GetHeapTaint(physical_addr, dynalysis::ELEM_WILDCARD_KEY);
      if (t == 0) {
          t = i_isolate->taint_engine()->GetHeapTaint(physical_addr, dynalysis::PROP_WILDCARD_KEY);
      }

      if (i_isolate->dta_logger()) {
          i_isolate->dta_logger()->ApiGetTaint(physical_addr, t, 0);
      }

      return t;
  }
  return 0;
}

void PrintFlowTree(Isolate* isolate, uint32_t taint_id) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  if (taint_id != 0) {
      i_isolate->taint_engine()->PrintFlowTree(taint_id);
  }
}

uint32_t GetRuntimeArgTaint(Isolate* isolate, int index) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  return i::taint::TaintAdapter::GetRuntimeArgTaint(i_isolate, index);
}

void EnterAddonContext(const char* module_name) {
  i::taint::TaintAdapter::EnterAddonContext(module_name);
}

void LeaveAddonContext() {
  i::taint::TaintAdapter::LeaveAddonContext();
}

}  // namespace taint
}  // namespace v8