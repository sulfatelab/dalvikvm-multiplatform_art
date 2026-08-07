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

#include "aot_cfg_windows.h"

#include <windows.h>
#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include "android-base/stringprintf.h"

namespace art {

namespace {

using android::base::StringPrintf;

constexpr uint32_t kVersion = 1u;
constexpr uint32_t kHeaderSize = 48u;
constexpr uint32_t kTargetSize = 8u;
constexpr uint32_t kImageFileMachineAmd64 = 0x8664u;
constexpr uint32_t kCompleteTargetSet = 1u << 0;
constexpr uint32_t kQuickMethod = 1u << 0;
constexpr uint32_t kJniStub = 1u << 1;
constexpr uint32_t kBootTrampoline = 1u << 2;
constexpr uint32_t kIndirectCallableThunk = 1u << 3;
constexpr uint32_t kKnownKindFlags =
    kQuickMethod | kJniStub | kBootTrampoline | kIndirectCallableThunk;
constexpr size_t kChecksumOffset = 40u;
constexpr uint32_t kTargetAlignment = 16u;

uint32_t LoadUint32LittleEndian(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8u) |
         (static_cast<uint32_t>(data[2]) << 16u) | (static_cast<uint32_t>(data[3]) << 24u);
}

uint32_t ComputeChecksum(const uint8_t* data, size_t size) {
  static constexpr uint8_t kZeroChecksum[sizeof(uint32_t)] = {};
  uint32_t checksum = adler32(0L, Z_NULL, 0);
  checksum = adler32(checksum, data, static_cast<uInt>(kChecksumOffset));
  checksum = adler32(checksum, kZeroChecksum, static_cast<uInt>(sizeof(kZeroChecksum)));
  checksum = adler32(checksum,
                     data + kChecksumOffset + sizeof(uint32_t),
                     static_cast<uInt>(size - kChecksumOffset - sizeof(uint32_t)));
  return checksum;
}

}  // namespace

struct WindowsAotCfgTable::Impl {
  struct Target {
    uint32_t code_offset;
    uint32_t kind_flags;
  };

  std::vector<Target> targets;
  bool policy_query_succeeded = false;
  bool cfg_enabled = false;
  bool strict_mode = false;
  bool export_suppression = false;
};

std::unique_ptr<WindowsAotCfgTable> WindowsAotCfgTable::Create(const uint8_t* oat_begin,
                                                               const uint8_t* code_begin,
                                                               const uint8_t* code_end,
                                                               const uint8_t* section_begin,
                                                               const uint8_t* section_end,
                                                               std::string* error_msg) {
  if (oat_begin == nullptr || code_begin == nullptr || code_end == nullptr ||
      section_begin == nullptr || section_end == nullptr || error_msg == nullptr) {
    if (error_msg != nullptr) {
      *error_msg = "Windows OAT CFG validation received a null argument";
    }
    return nullptr;
  }

  const uintptr_t oat_address = reinterpret_cast<uintptr_t>(oat_begin);
  const uintptr_t code_address = reinterpret_cast<uintptr_t>(code_begin);
  const uintptr_t code_end_address = reinterpret_cast<uintptr_t>(code_end);
  const uintptr_t section_address = reinterpret_cast<uintptr_t>(section_begin);
  const uintptr_t section_end_address = reinterpret_cast<uintptr_t>(section_end);
  if (code_address < oat_address || code_end_address <= code_address ||
      section_end_address <= section_address) {
    *error_msg = "Windows OAT CFG ranges are invalid";
    return nullptr;
  }
  const size_t section_size = section_end_address - section_address;
  if (section_size < kHeaderSize || section_size > std::numeric_limits<uint32_t>::max()) {
    *error_msg = "Windows OAT CFG section size is invalid";
    return nullptr;
  }
  if (section_begin[0] != 'o' || section_begin[1] != 'c' || section_begin[2] != 'f' ||
      section_begin[3] != 'g') {
    *error_msg = "Windows OAT CFG magic is invalid";
    return nullptr;
  }

  const uint32_t version = LoadUint32LittleEndian(section_begin + 4u);
  const uint32_t header_size = LoadUint32LittleEndian(section_begin + 8u);
  const uint32_t target_machine = LoadUint32LittleEndian(section_begin + 12u);
  const uint32_t flags = LoadUint32LittleEndian(section_begin + 16u);
  const uint32_t target_size = LoadUint32LittleEndian(section_begin + 20u);
  const uint32_t target_count = LoadUint32LittleEndian(section_begin + 24u);
  const uint32_t targets_offset = LoadUint32LittleEndian(section_begin + 28u);
  const uint32_t serialized_code_begin = LoadUint32LittleEndian(section_begin + 32u);
  const uint32_t serialized_code_end = LoadUint32LittleEndian(section_begin + 36u);
  const uint32_t serialized_checksum = LoadUint32LittleEndian(section_begin + kChecksumOffset);
  const uint32_t reserved = LoadUint32LittleEndian(section_begin + 44u);
  if (version != kVersion || header_size != kHeaderSize ||
      target_machine != kImageFileMachineAmd64 || flags != kCompleteTargetSet ||
      target_size != kTargetSize || target_count == 0u || targets_offset != kHeaderSize ||
      reserved != 0u) {
    *error_msg = "Windows OAT CFG version-1 header is invalid";
    return nullptr;
  }

  const uint64_t expected_size =
      static_cast<uint64_t>(targets_offset) + static_cast<uint64_t>(target_count) * target_size;
  if (expected_size != section_size) {
    *error_msg = "Windows OAT CFG target array size is invalid";
    return nullptr;
  }
  if (serialized_checksum != ComputeChecksum(section_begin, section_size)) {
    *error_msg = "Windows OAT CFG checksum is invalid";
    return nullptr;
  }

  const uintptr_t code_begin_delta = code_address - oat_address;
  const uintptr_t code_end_delta = code_end_address - oat_address;
  if (code_begin_delta > std::numeric_limits<uint32_t>::max() ||
      code_end_delta > std::numeric_limits<uint32_t>::max() ||
      serialized_code_begin != code_begin_delta || serialized_code_end != code_end_delta ||
      serialized_code_begin >= serialized_code_end) {
    *error_msg = "Windows OAT CFG code range is invalid";
    return nullptr;
  }

  auto impl = std::make_unique<Impl>();
  impl->targets.reserve(target_count);
  uint32_t previous_offset = 0u;
  for (uint32_t index = 0u; index != target_count; ++index) {
    const uint8_t* entry = section_begin + targets_offset + index * target_size;
    const uint32_t code_offset = LoadUint32LittleEndian(entry);
    const uint32_t kind_flags = LoadUint32LittleEndian(entry + sizeof(uint32_t));
    const uintptr_t target_address = oat_address + code_offset;
    if (code_offset < serialized_code_begin || code_offset >= serialized_code_end ||
        (target_address & (kTargetAlignment - 1u)) != 0u ||
        (index != 0u && code_offset <= previous_offset) || kind_flags == 0u ||
        (kind_flags & ~kKnownKindFlags) != 0u) {
      *error_msg = StringPrintf("Windows OAT CFG target %u is invalid", index);
      return nullptr;
    }
    previous_offset = code_offset;
    impl->targets.push_back(Impl::Target{code_offset, kind_flags});
  }

  PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy = {};
  impl->policy_query_succeeded =
      GetProcessMitigationPolicy(
          GetCurrentProcess(), ProcessControlFlowGuardPolicy, &policy, sizeof(policy)) != FALSE;
  if (impl->policy_query_succeeded) {
    impl->cfg_enabled = policy.EnableControlFlowGuard != 0u;
    impl->strict_mode = policy.StrictMode != 0u;
    impl->export_suppression = policy.EnableExportSuppression != 0u;
  }

  return std::unique_ptr<WindowsAotCfgTable>(new WindowsAotCfgTable(std::move(impl)));
}

WindowsAotCfgTable::WindowsAotCfgTable(std::unique_ptr<Impl>&& impl) : impl_(std::move(impl)) {}

WindowsAotCfgTable::~WindowsAotCfgTable() = default;

size_t WindowsAotCfgTable::TargetCount() const { return impl_->targets.size(); }

bool WindowsAotCfgTable::ContainsTarget(uint32_t code_offset, uint32_t required_kind_flags) const {
  auto it = std::lower_bound(
      impl_->targets.begin(),
      impl_->targets.end(),
      code_offset,
      [](const Impl::Target& target, uint32_t value) { return target.code_offset < value; });
  return it != impl_->targets.end() && it->code_offset == code_offset &&
         (it->kind_flags & required_kind_flags) == required_kind_flags;
}

bool WindowsAotCfgTable::PolicyQuerySucceeded() const { return impl_->policy_query_succeeded; }

bool WindowsAotCfgTable::IsCfgEnabled() const { return impl_->cfg_enabled; }

bool WindowsAotCfgTable::IsStrictMode() const { return impl_->strict_mode; }

bool WindowsAotCfgTable::IsExportSuppressionEnabled() const { return impl_->export_suppression; }

}  // namespace art
