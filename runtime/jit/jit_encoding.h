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

#ifndef ART_RUNTIME_JIT_JIT_ENCODING_H_
#define ART_RUNTIME_JIT_JIT_ENCODING_H_

#include <cstddef>
#include <cstdint>
#include <limits>

#include "base/macros.h"

namespace art HIDDEN {
namespace jit {

// Encode an x86_64 PC-relative JIT-root displacement without relying on a
// release-mode narrowing conversion. `patch_address` is the address following
// the disp32 field, matching x86_64 RIP-relative addressing.
inline bool EncodeJitRootDisplacement(uintptr_t roots_data,
                                      uint64_t index_in_table,
                                      size_t root_entry_size,
                                      uintptr_t patch_address,
                                      int32_t* displacement) {
  if (displacement == nullptr || root_entry_size == 0u ||
      index_in_table > (std::numeric_limits<uintptr_t>::max() - roots_data) / root_entry_size) {
    return false;
  }

  uintptr_t root_address = roots_data + static_cast<uintptr_t>(index_in_table) * root_entry_size;
  if (root_address >= patch_address) {
    uintptr_t distance = root_address - patch_address;
    if (distance > static_cast<uintptr_t>(std::numeric_limits<int32_t>::max())) {
      return false;
    }
    *displacement = static_cast<int32_t>(distance);
    return true;
  }

  uintptr_t distance = patch_address - root_address;
  constexpr uintptr_t kMinInt32Magnitude =
      static_cast<uintptr_t>(std::numeric_limits<int32_t>::max()) + 1u;
  if (distance > kMinInt32Magnitude) {
    return false;
  }
  *displacement = (distance == kMinInt32Magnitude) ? std::numeric_limits<int32_t>::min()
                                                   : -static_cast<int32_t>(distance);
  return true;
}

// Encode the backward distance from JIT code to its CodeInfo. A non-null
// CodeInfo must be strictly below the code and representable in the uint32_t
// OatQuickMethodHeader field.
inline bool EncodeJitCodeInfoOffset(uintptr_t code_address,
                                    uintptr_t code_info_address,
                                    uint32_t* code_info_offset) {
  if (code_info_offset == nullptr || code_info_address >= code_address) {
    return false;
  }
  uintptr_t distance = code_address - code_info_address;
  if (distance > static_cast<uintptr_t>(std::numeric_limits<uint32_t>::max())) {
    return false;
  }
  *code_info_offset = static_cast<uint32_t>(distance);
  return true;
}

}  // namespace jit
}  // namespace art HIDDEN

#endif  // ART_RUNTIME_JIT_JIT_ENCODING_H_
