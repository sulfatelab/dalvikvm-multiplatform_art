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

#include "jit_unwind_windows.h"

#include <windows.h>

#include <limits>
#include <map>

#include "base/logging.h"

namespace art {
namespace jit {

namespace {

bool RelativeOffset(const uint8_t* address,
                    const uint8_t* base_address,
                    uint32_t* relative_offset) {
  uintptr_t address_value = reinterpret_cast<uintptr_t>(address);
  uintptr_t base_value = reinterpret_cast<uintptr_t>(base_address);
  if (address_value < base_value ||
      address_value - base_value > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  *relative_offset = static_cast<uint32_t>(address_value - base_value);
  return true;
}

bool DeleteFunctionTableAndVerify(const uint8_t* code, PRUNTIME_FUNCTION function) {
  if (RtlDeleteFunctionTable(function) == FALSE) {
    return false;
  }
  DWORD64 ignored_base = 0u;
  return RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(code), &ignored_base, nullptr) == nullptr;
}

}  // namespace

struct Win64JitUnwindRegistry::Impl {
  struct Entry {
    RUNTIME_FUNCTION function = {};
    uint64_t base_address = 0u;
  };

  std::map<const uint8_t*, Entry> entries;
};

Win64JitUnwindRegistry::Win64JitUnwindRegistry() : impl_(std::make_unique<Impl>()) {}

Win64JitUnwindRegistry::~Win64JitUnwindRegistry() {
  CHECK(Clear()) << "Failed to remove all Win64 JIT runtime-function tables";
}

bool Win64JitUnwindRegistry::Register(const uint8_t* code,
                                      size_t code_size,
                                      const uint8_t* unwind_info,
                                      const uint8_t* base_address) {
  if (code == nullptr || code_size == 0u || unwind_info == nullptr || base_address == nullptr ||
      (reinterpret_cast<uintptr_t>(unwind_info) & 3u) != 0u || impl_->entries.count(code) != 0u) {
    return false;
  }

  uint32_t begin_offset;
  uint32_t unwind_offset;
  if (!RelativeOffset(code, base_address, &begin_offset) ||
      !RelativeOffset(unwind_info, base_address, &unwind_offset) ||
      (unwind_offset & 3u) != 0u ||
      code_size > std::numeric_limits<uint32_t>::max() - begin_offset) {
    return false;
  }
  uint32_t end_offset = begin_offset + static_cast<uint32_t>(code_size);

  auto [it, inserted] = impl_->entries.try_emplace(code);
  CHECK(inserted);
  Impl::Entry& entry = it->second;
  entry.function.BeginAddress = begin_offset;
  entry.function.EndAddress = end_offset;
  entry.function.UnwindData = unwind_offset;
  entry.base_address = reinterpret_cast<uint64_t>(base_address);

  if (RtlAddFunctionTable(&entry.function, /*EntryCount=*/ 1u, entry.base_address) == FALSE) {
    impl_->entries.erase(it);
    return false;
  }

  DWORD64 lookup_base = 0u;
  PRUNTIME_FUNCTION lookup =
      RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(code), &lookup_base, nullptr);
  if (lookup == nullptr || lookup_base != entry.base_address ||
      lookup->BeginAddress != entry.function.BeginAddress ||
      lookup->EndAddress != entry.function.EndAddress ||
      lookup->UnwindData != entry.function.UnwindData) {
    CHECK(DeleteFunctionTableAndVerify(code, &entry.function))
        << "Failed to roll back an unresolvable Win64 JIT runtime-function table";
    impl_->entries.erase(it);
    return false;
  }
  return true;
}

bool Win64JitUnwindRegistry::Unregister(const uint8_t* code) {
  auto it = impl_->entries.find(code);
  if (it == impl_->entries.end()) {
    return true;
  }
  if (!DeleteFunctionTableAndVerify(code, &it->second.function)) {
    return false;
  }
  impl_->entries.erase(it);
  return true;
}

bool Win64JitUnwindRegistry::Clear() {
  for (auto it = impl_->entries.begin(); it != impl_->entries.end();) {
    if (!DeleteFunctionTableAndVerify(it->first, &it->second.function)) {
      return false;
    }
    it = impl_->entries.erase(it);
  }
  return true;
}

size_t Win64JitUnwindRegistry::Size() const {
  return impl_->entries.size();
}

}  // namespace jit
}  // namespace art
