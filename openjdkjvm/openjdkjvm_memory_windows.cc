// Minimal openjdkjvm memory/GC exports for Windows x64 PE libcore Runtime natives.
// Full OpenjdkJvm.cc is POSIX-heavy; Phase 3 only needs heap queries + explicit GC.

#include "gc/heap.h"
#include "jni/java_vm_ext.h"
#include "nativehelper/scoped_utf_chars.h"
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

__declspec(dllexport) jstring ART_LoadNativeLibrary(JNIEnv* env,
                                                    jstring java_filename,
                                                    jobject java_loader,
                                                    jclass caller) {
  // The standalone Windows x64 openjdkjvm DLL delegates JVM_NativeLoad here so ART
  // retains library ownership and unresolved Java_* lookup works normally.
  ScopedUtfChars filename(env, java_filename);
  if (filename.c_str() == nullptr) {
    return nullptr;
  }

  std::string error_msg;
  art::JavaVMExt* vm = art::Runtime::Current()->GetJavaVM();
  if (vm->LoadNativeLibrary(env, filename.c_str(), java_loader, caller, &error_msg)) {
    return nullptr;
  }

  env->ExceptionClear();
  return env->NewStringUTF(error_msg.c_str());
}

}  // extern "C"
