/*
 * Copyright (C) 2026 The Android Open Source Project
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

#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_JIT_UNWIND_WINDOWS_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_JIT_UNWIND_WINDOWS_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>

namespace art {
namespace jit {

// Owns immutable one-entry Windows x64 runtime-function tables for JIT allocations.
// Callers serialize access with Locks::jit_lock_. Windows SDK types stay in the
// implementation so common JIT headers carry only opaque addresses and bytes.
class WindowsX64JitUnwindRegistry {
 public:
  WindowsX64JitUnwindRegistry();
  ~WindowsX64JitUnwindRegistry();

  WindowsX64JitUnwindRegistry(const WindowsX64JitUnwindRegistry&) = delete;
  WindowsX64JitUnwindRegistry& operator=(const WindowsX64JitUnwindRegistry&) = delete;

  bool Register(const uint8_t* code,
                size_t code_size,
                const uint8_t* unwind_info,
                const uint8_t* base_address);
  bool Unregister(const uint8_t* code);
  bool Clear();
  size_t Size() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace jit
}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_JIT_UNWIND_WINDOWS_H_
