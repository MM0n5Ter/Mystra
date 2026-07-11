// deps/v8/include/v8-taint.h
#ifndef V8_TAINT_H_
#define V8_TAINT_H_

#include "v8.h"

namespace v8 {
namespace taint {

V8_EXPORT void SetTaint(Isolate* isolate, Local<Value> value, const char* source_name = "Node_SetTaint");
V8_EXPORT uint32_t GetTaint(Isolate* isolate, Local<Value> value);
V8_EXPORT void PrintFlowTree(Isolate* isolate, uint32_t taint_id);
V8_EXPORT uint32_t GetRuntimeArgTaint(Isolate* isolate, int index); 

// Node.js Module Load
V8_EXPORT void EnterAddonContext(const char* module_name);
V8_EXPORT void LeaveAddonContext();
}  // namespace taint
}  // namespace v8

#endif  // V8_TAINT_H_