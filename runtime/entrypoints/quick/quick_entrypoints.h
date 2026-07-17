/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ART_RUNTIME_ENTRYPOINTS_QUICK_QUICK_ENTRYPOINTS_H_
#define ART_RUNTIME_ENTRYPOINTS_QUICK_QUICK_ENTRYPOINTS_H_

#include <jni.h>
#include <cstddef>

#include "base/locks.h"
#include "base/macros.h"
#include "deoptimization_kind.h"
#include "offsets.h"

#define QUICK_ENTRYPOINT_OFFSET(ptr_size, x) \
    Thread::QuickEntryPointOffset<ptr_size>(OFFSETOF_MEMBER(QuickEntryPoints, x))

namespace art HIDDEN {

namespace mirror {
class Array;
class Class;
template<class MirrorType> class CompressedReference;
class Object;
class String;
}  // namespace mirror

class ArtMethod;
template<class MirrorType> class GcRoot;
template<class MirrorType> class StackReference;
class Thread;

// Pointers to functions that are called by quick compiler generated code via thread-local storage.
// Pointers to functions called from quick/managed code via Thread TLS.
// On Win64, managed/quick asm uses the SysV register ABI for ART helpers
// (ART_QUICK_ENTRYPOINT_ABI = sysv_abi). Set* therefore has:
//   - default C++ ABI pointer (libm cos/sin, libc memcpy, nullptr via nullptr_t)
//   - sysv_abi ART helper pointer
// A dedicated nullptr_t overload avoids ambiguous conversion to both ABIs.
struct QuickEntryPoints {
#if defined(_WIN32) && defined(__x86_64__)
#define ENTRYPOINT_ENUM(name, rettype, ...) \
  void* p##name; \
  void Set##name(std::nullptr_t) { p##name = nullptr; } \
  void Set##name(rettype (*fn)(__VA_ARGS__)) { \
    p##name = reinterpret_cast<void*>(fn); \
  } \
  void Set##name(rettype (ART_QUICK_ENTRYPOINT_ABI *fn)(__VA_ARGS__)) { \
    p##name = reinterpret_cast<void*>(fn); \
  }
#else
#define ENTRYPOINT_ENUM(name, rettype, ...) \
  void* p##name; \
  void Set##name(rettype (*fn)(__VA_ARGS__)) { \
    p##name = reinterpret_cast<void*>(fn); \
  }
#endif
#include "quick_entrypoints_list.h"
  QUICK_ENTRYPOINT_LIST(ENTRYPOINT_ENUM)
#undef QUICK_ENTRYPOINT_LIST
#undef ENTRYPOINT_ENUM
};

// JNI entrypoints.
extern mirror::Object* JniDecodeReferenceResult(jobject result, Thread* self)
    REQUIRES_SHARED(Locks::mutator_lock_) HOT_ATTR;

}  // namespace art

#endif  // ART_RUNTIME_ENTRYPOINTS_QUICK_QUICK_ENTRYPOINTS_H_
