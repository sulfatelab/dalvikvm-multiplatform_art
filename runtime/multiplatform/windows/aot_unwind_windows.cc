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

#include "aot_unwind_windows.h"

#include <windows.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>
#include <vector>

#include "android-base/stringprintf.h"
#include "base/logging.h"
#include "multiplatform/windows/aot_test_fault_windows.h"

namespace art {

namespace {

using android::base::StringPrintf;

constexpr uint32_t kHeaderSize = 48u;
constexpr uint32_t kEntrySize = 12u;
constexpr uint32_t kChecksumOffset = 44u;
constexpr uint32_t kImageFileMachineAmd64 = 0x8664u;
constexpr uint32_t kMagic = 0x0a77756fu;  // "ouw\n" in little-endian order.

uint32_t LoadUint32LittleEndian(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8u) |
         (static_cast<uint32_t>(data[2]) << 16u) |
         (static_cast<uint32_t>(data[3]) << 24u);
}

bool RelativeOffset(const uint8_t* address,
                    const uint8_t* base,
                    uint32_t* relative_offset) {
  const uintptr_t address_value = reinterpret_cast<uintptr_t>(address);
  const uintptr_t base_value = reinterpret_cast<uintptr_t>(base);
  if (address_value < base_value ||
      address_value - base_value > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  *relative_offset = static_cast<uint32_t>(address_value - base_value);
  return true;
}

bool IsNonvolatileGpr(uint8_t reg) {
  return reg == 3u || reg == 5u || reg == 6u || reg == 7u ||
         (reg >= 12u && reg <= 15u);
}

bool IsNonvolatileXmm(uint8_t reg) {
  return reg >= 6u && reg <= 15u;
}

bool ValidateUnwindInfo(const uint8_t* data, size_t size, std::string* error_msg) {
  if (size < 4u || data[0] != 1u) {
    *error_msg = "Windows OAT UNWIND_INFO requires version 1 with no flags";
    return false;
  }

  const uint8_t prologue_size = data[1];
  const uint8_t slot_count = data[2];
  const uint8_t frame_register = data[3] & 0x0fu;
  const uint8_t frame_offset = data[3] >> 4u;
  const size_t padded_slot_count = (static_cast<size_t>(slot_count) + 1u) & ~1u;
  const size_t descriptor_size = 4u + padded_slot_count * 2u;
  if (descriptor_size > size) {
    *error_msg = "Windows OAT UNWIND_INFO has truncated unwind codes";
    return false;
  }

  size_t slot = 0u;
  uint16_t previous_code_offset = 256u;
  size_t set_frame_pointer_count = 0u;
  while (slot < slot_count) {
    const uint8_t code_offset = data[4u + slot * 2u];
    const uint8_t operation_and_info = data[5u + slot * 2u];
    const uint8_t operation = operation_and_info & 0x0fu;
    const uint8_t operation_info = operation_and_info >> 4u;
    if (code_offset == 0u || code_offset > prologue_size ||
        code_offset >= previous_code_offset) {
      *error_msg = "Windows OAT UNWIND_INFO has unordered prologue offsets";
      return false;
    }
    previous_code_offset = code_offset;

    size_t used_slots = 1u;
    switch (operation) {
      case 0u:  // UWOP_PUSH_NONVOL.
        if (!IsNonvolatileGpr(operation_info)) {
          *error_msg = "Windows OAT UNWIND_INFO pushes a volatile register";
          return false;
        }
        break;
      case 1u:  // UWOP_ALLOC_LARGE.
        if (operation_info > 1u) {
          *error_msg = "Windows OAT UNWIND_INFO has an invalid UWOP_ALLOC_LARGE";
          return false;
        }
        used_slots = operation_info == 0u ? 2u : 3u;
        break;
      case 2u:  // UWOP_ALLOC_SMALL.
        break;
      case 3u:  // UWOP_SET_FPREG.
        if (operation_info != 0u) {
          *error_msg = "Windows OAT UNWIND_INFO has an invalid UWOP_SET_FPREG";
          return false;
        }
        ++set_frame_pointer_count;
        break;
      case 4u:  // UWOP_SAVE_NONVOL.
        if (!IsNonvolatileGpr(operation_info)) {
          *error_msg = "Windows OAT UNWIND_INFO saves a volatile register";
          return false;
        }
        used_slots = 2u;
        break;
      case 5u:  // UWOP_SAVE_NONVOL_FAR.
        if (!IsNonvolatileGpr(operation_info)) {
          *error_msg = "Windows OAT UNWIND_INFO saves a volatile register";
          return false;
        }
        used_slots = 3u;
        break;
      case 8u:  // UWOP_SAVE_XMM128.
        if (!IsNonvolatileXmm(operation_info)) {
          *error_msg = "Windows OAT UNWIND_INFO saves a volatile XMM register";
          return false;
        }
        used_slots = 2u;
        break;
      case 9u:  // UWOP_SAVE_XMM128_FAR.
        if (!IsNonvolatileXmm(operation_info)) {
          *error_msg = "Windows OAT UNWIND_INFO saves a volatile XMM register";
          return false;
        }
        used_slots = 3u;
        break;
      case 10u:  // UWOP_PUSH_MACHFRAME.
        if (operation_info > 1u) {
          *error_msg = "Windows OAT UNWIND_INFO has an invalid UWOP_PUSH_MACHFRAME";
          return false;
        }
        break;
      default:
        *error_msg = "Windows OAT UNWIND_INFO contains an unsupported unwind operation";
        return false;
    }
    if (used_slots > static_cast<size_t>(slot_count) - slot) {
      *error_msg = "Windows OAT UNWIND_INFO has a truncated multi-slot operation";
      return false;
    }
    slot += used_slots;
  }

  if ((slot_count & 1u) != 0u &&
      (data[4u + static_cast<size_t>(slot_count) * 2u] != 0u ||
       data[5u + static_cast<size_t>(slot_count) * 2u] != 0u)) {
    *error_msg = "Windows OAT UNWIND_INFO has nonzero slot padding";
    return false;
  }
  if (frame_register == 0u) {
    if (frame_offset != 0u || set_frame_pointer_count != 0u) {
      *error_msg = "Windows OAT UNWIND_INFO has an inconsistent frame register";
      return false;
    }
  } else if (!IsNonvolatileGpr(frame_register) || set_frame_pointer_count != 1u) {
    *error_msg = "Windows OAT UNWIND_INFO has an invalid frame register";
    return false;
  }
  if (!std::all_of(data + descriptor_size, data + size, [](uint8_t value) {
        return value == 0u;
      })) {
    *error_msg = "Windows OAT UNWIND_INFO has nonzero trailing bytes";
    return false;
  }
  return true;
}

}  // namespace

struct WindowsAotUnwindRegistry::Impl {
  std::vector<RUNTIME_FUNCTION> functions;
  const uint8_t* base_address = nullptr;
  bool registered = false;

  bool LookupMatches(size_t index) const {
    const RUNTIME_FUNCTION& expected = functions[index];
    DWORD64 lookup_base = 0u;
    PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(base_address) + expected.BeginAddress,
        &lookup_base,
        nullptr);
    return found != nullptr && lookup_base == reinterpret_cast<DWORD64>(base_address) &&
           found->BeginAddress == expected.BeginAddress &&
           found->EndAddress == expected.EndAddress &&
           found->UnwindData == expected.UnwindData;
  }

  template <typename Visitor>
  void VisitSamples(Visitor visitor) const {
    visitor(0u);
    if (functions.size() > 2u) {
      visitor(functions.size() / 2u);
    }
    if (functions.size() > 1u) {
      visitor(functions.size() - 1u);
    }
  }

  void UnregisterOrDie() {
    CHECK(registered);
    CHECK_NE(RtlDeleteFunctionTable(functions.data()), FALSE)
        << "Failed to remove the Windows AOT runtime-function table";
    registered = false;
    VisitSamples([this](size_t index) {
      DWORD64 ignored_base = 0u;
      const DWORD64 pc = reinterpret_cast<DWORD64>(base_address) + functions[index].BeginAddress;
      CHECK(RtlLookupFunctionEntry(pc, &ignored_base, nullptr) == nullptr)
          << "Windows retained a deleted AOT runtime-function table";
    });
  }
};

std::unique_ptr<WindowsAotUnwindRegistry> WindowsAotUnwindRegistry::Create(
    const uint8_t* oat_begin,
    const uint8_t* code_begin,
    const uint8_t* code_end,
      const uint8_t* section_begin,
      const uint8_t* section_end,
      std::string* error_msg) {
  const uintptr_t code_begin_value = reinterpret_cast<uintptr_t>(code_begin);
  const uintptr_t code_end_value = reinterpret_cast<uintptr_t>(code_end);
  const uintptr_t section_begin_value = reinterpret_cast<uintptr_t>(section_begin);
  const uintptr_t section_end_value = reinterpret_cast<uintptr_t>(section_end);
  if (oat_begin == nullptr || code_begin == nullptr || code_end == nullptr ||
      section_begin == nullptr || section_end == nullptr || code_begin_value >= code_end_value ||
      section_begin_value >= section_end_value) {
    *error_msg = "Windows OAT unwind transport has invalid mapped bounds";
    return nullptr;
  }

  uint32_t expected_code_begin;
  uint32_t expected_code_end;
  uint32_t section_oat_offset;
  if (!RelativeOffset(code_begin, oat_begin, &expected_code_begin) ||
      !RelativeOffset(code_end, oat_begin, &expected_code_end) ||
      !RelativeOffset(section_begin, oat_begin, &section_oat_offset)) {
    *error_msg = "Windows OAT unwind transport exceeds 32-bit oatdata-relative offsets";
    return nullptr;
  }
  const size_t section_size = static_cast<size_t>(section_end_value - section_begin_value);
  if (section_size < kHeaderSize ||
      section_size > std::numeric_limits<uint32_t>::max() - section_oat_offset) {
    *error_msg = "Windows OAT unwind section has an invalid size";
    return nullptr;
  }

  const uint32_t magic = LoadUint32LittleEndian(section_begin + 0u);
  const uint32_t version = LoadUint32LittleEndian(section_begin + 4u);
  const uint32_t header_size = LoadUint32LittleEndian(section_begin + 8u);
  const uint32_t target_machine = LoadUint32LittleEndian(section_begin + 12u);
  const uint32_t entry_size = LoadUint32LittleEndian(section_begin + 16u);
  const uint32_t entry_count = LoadUint32LittleEndian(section_begin + 20u);
  const uint32_t entries_offset = LoadUint32LittleEndian(section_begin + 24u);
  const uint32_t unwind_offset = LoadUint32LittleEndian(section_begin + 28u);
  const uint32_t unwind_size = LoadUint32LittleEndian(section_begin + 32u);
  const uint32_t serialized_code_begin = LoadUint32LittleEndian(section_begin + 36u);
  const uint32_t serialized_code_end = LoadUint32LittleEndian(section_begin + 40u);
  const uint32_t stored_checksum = LoadUint32LittleEndian(section_begin + kChecksumOffset);

  const uint64_t entries_end =
      static_cast<uint64_t>(entries_offset) + static_cast<uint64_t>(entry_count) * entry_size;
  const uint64_t expected_unwind_offset = (entries_end + 3u) & ~UINT64_C(3);
  if (magic != kMagic || version != 1u || header_size != kHeaderSize ||
      target_machine != kImageFileMachineAmd64 || entry_size != kEntrySize ||
      entry_count == 0u || entries_offset != kHeaderSize ||
      expected_unwind_offset != unwind_offset ||
      static_cast<uint64_t>(unwind_offset) + unwind_size != section_size ||
      serialized_code_begin != expected_code_begin || serialized_code_end != expected_code_end) {
    *error_msg = "Windows OAT unwind section has an invalid header";
    return nullptr;
  }

  uint32_t checksum = adler32(0L, Z_NULL, 0);
  checksum = adler32(checksum, section_begin, kChecksumOffset);
  static constexpr std::array<uint8_t, sizeof(uint32_t)> kZeroChecksum = {};
  checksum = adler32(checksum, kZeroChecksum.data(), kZeroChecksum.size());
  checksum = adler32(checksum,
                     section_begin + kChecksumOffset + sizeof(uint32_t),
                     static_cast<uInt>(section_size - kHeaderSize));
  if (checksum != stored_checksum) {
    *error_msg = StringPrintf("Windows OAT unwind checksum mismatch: %08x != %08x",
                              stored_checksum,
                              checksum);
    return nullptr;
  }

  std::unique_ptr<Impl> impl = std::make_unique<Impl>();
  impl->base_address = oat_begin;
  impl->functions.reserve(entry_count);
  std::set<uint32_t> unwind_info_offsets;
  uint32_t previous_end = serialized_code_begin;
  const uint32_t unwind_begin_oat_offset = section_oat_offset + unwind_offset;
  const uint32_t section_end_oat_offset = section_oat_offset + static_cast<uint32_t>(section_size);
  for (uint32_t index = 0u; index != entry_count; ++index) {
    const uint8_t* entry = section_begin + entries_offset + static_cast<size_t>(index) * entry_size;
    const uint32_t begin_offset = LoadUint32LittleEndian(entry + 0u);
    const uint32_t end_offset = LoadUint32LittleEndian(entry + 4u);
    const uint32_t unwind_info_offset = LoadUint32LittleEndian(entry + 8u);
    if (begin_offset < serialized_code_begin || begin_offset < previous_end ||
        end_offset <= begin_offset || end_offset > serialized_code_end ||
        (unwind_info_offset & 3u) != 0u || unwind_info_offset < unwind_begin_oat_offset ||
        unwind_info_offset >= section_end_oat_offset) {
      *error_msg = StringPrintf("Windows OAT unwind entry %u is invalid", index);
      return nullptr;
    }
    previous_end = end_offset;
    unwind_info_offsets.insert(unwind_info_offset);
    RUNTIME_FUNCTION function = {};
    function.BeginAddress = begin_offset;
    function.EndAddress = end_offset;
    function.UnwindData = unwind_info_offset;
    impl->functions.push_back(function);
  }

  for (auto it = unwind_info_offsets.begin(); it != unwind_info_offsets.end(); ++it) {
    const uint32_t local_offset = *it - section_oat_offset;
    auto next = std::next(it);
    const uint32_t local_end = next != unwind_info_offsets.end()
        ? *next - section_oat_offset
        : static_cast<uint32_t>(section_size);
    std::string unwind_error;
    if (!ValidateUnwindInfo(section_begin + local_offset, local_end - local_offset, &unwind_error)) {
      *error_msg = StringPrintf("Windows OAT unwind descriptor at offset %u is invalid: %s",
                                *it,
                                unwind_error.c_str());
      return nullptr;
    }
  }

  return std::unique_ptr<WindowsAotUnwindRegistry>(
      new WindowsAotUnwindRegistry(std::move(impl)));
}

WindowsAotUnwindRegistry::WindowsAotUnwindRegistry(std::unique_ptr<Impl>&& impl)
    : impl_(std::move(impl)) {}

WindowsAotUnwindRegistry::~WindowsAotUnwindRegistry() {
  if (impl_->registered) {
    impl_->UnregisterOrDie();
  }
}

bool WindowsAotUnwindRegistry::Register(std::string* error_msg) {
  if (impl_->registered || impl_->functions.empty()) {
    *error_msg = "Windows AOT runtime-function table is already registered or empty";
    return false;
  }
  if (IsWindowsBootAotTestFailure("unwind-registration")) {
    *error_msg = "Injected Windows boot-AOT unwind-registration failure";
    return false;
  }
  if (RtlAddFunctionTable(impl_->functions.data(),
                          static_cast<DWORD>(impl_->functions.size()),
                          reinterpret_cast<DWORD64>(impl_->base_address)) == FALSE) {
    *error_msg = "RtlAddFunctionTable failed for the Windows AOT runtime-function table";
    return false;
  }
  impl_->registered = true;
  bool matches = true;
  impl_->VisitSamples([&](size_t index) { matches = matches && impl_->LookupMatches(index); });
  if (!matches) {
    impl_->UnregisterOrDie();
    *error_msg = "Windows could not resolve the registered AOT runtime-function table";
    return false;
  }
  return true;
}

size_t WindowsAotUnwindRegistry::Size() const {
  return impl_->functions.size();
}

bool WindowsAotUnwindRegistry::IsRegistered() const {
  return impl_->registered;
}

}  // namespace art
