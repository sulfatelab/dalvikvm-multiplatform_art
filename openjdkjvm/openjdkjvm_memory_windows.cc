// Minimal openjdkjvm memory/GC exports for Win64 PE libcore Runtime natives.
// Full OpenjdkJvm.cc is POSIX-heavy; Phase 3 only needs heap queries + explicit GC.

#include "gc/heap.h"
#include "runtime.h"

#include <jni.h>

extern "C" {

__declspec(dllexport) jlong JVM_FreeMemory(void) {
  art::Runtime* runtime = art::Runtime::Current();
  if (runtime == nullptr || runtime->GetHeap() == nullptr) {
    return 0;
  }
  return static_cast<jlong>(runtime->GetHeap()->GetFreeMemory());
}

__declspec(dllexport) jlong JVM_TotalMemory(void) {
  art::Runtime* runtime = art::Runtime::Current();
  if (runtime == nullptr || runtime->GetHeap() == nullptr) {
    return 0;
  }
  return static_cast<jlong>(runtime->GetHeap()->GetTotalMemory());
}

__declspec(dllexport) jlong JVM_MaxMemory(void) {
  art::Runtime* runtime = art::Runtime::Current();
  if (runtime == nullptr || runtime->GetHeap() == nullptr) {
    return 0;
  }
  return static_cast<jlong>(runtime->GetHeap()->GetMaxMemory());
}

__declspec(dllexport) void JVM_GC(void) {
  art::Runtime* runtime = art::Runtime::Current();
  if (runtime == nullptr || runtime->GetHeap() == nullptr) {
    return;
  }
  if (runtime->IsExplicitGcDisabled()) {
    return;
  }
  runtime->GetHeap()->CollectGarbage(/* clear_soft_references */ false);
}

}  // extern "C"
