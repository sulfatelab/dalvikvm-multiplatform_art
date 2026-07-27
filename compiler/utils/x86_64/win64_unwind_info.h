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

#ifndef ART_COMPILER_UTILS_X86_64_WIN64_UNWIND_INFO_H_
#define ART_COMPILER_UTILS_X86_64_WIN64_UNWIND_INFO_H_

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <limits>
#include <vector>

namespace art {
namespace x86_64 {

// A Windows-SDK-independent serializer for the subset of x64 UNWIND_INFO used
// by ART's JIT frames. Code offsets are instruction-end offsets from the start
// of the generated method, as required by the PE unwind format.
class Win64UnwindInfoBuilder {
 public:
  Win64UnwindInfoBuilder() = default;

  void Enable() {
    enabled_ = true;
    finalized_ = false;
    valid_ = true;
    prologue_size_ = 0u;
    frame_register_ = 0u;
    frame_offset_ = 0u;
    operations_.clear();
    data_.clear();
  }

  bool IsEnabled() const { return enabled_; }
  bool IsValid() const { return !enabled_ || (finalized_ && valid_); }
  const std::vector<uint8_t>& GetData() const { return data_; }

  void RecordPushNonvolatile(uint8_t reg, size_t code_offset) {
    if (!PrepareOperation(code_offset) || !IsNonvolatileRegister(reg) ||
        std::any_of(operations_.begin(), operations_.end(), [reg](const Operation& operation) {
          return operation.kind == OperationKind::kPushNonvolatile && operation.reg == reg;
        })) {
      Invalidate();
      return;
    }
    operations_.push_back(
        Operation{OperationKind::kPushNonvolatile, static_cast<uint8_t>(code_offset), reg, 0u});
  }

  void RecordStackAllocation(size_t size, size_t code_offset) {
    if (size == 0u) {
      return;
    }
    if (!PrepareOperation(code_offset) || (size & 7u) != 0u ||
        size > std::numeric_limits<uint32_t>::max() ||
        HasOperation(OperationKind::kStackAllocation)) {
      Invalidate();
      return;
    }
    operations_.push_back(Operation{OperationKind::kStackAllocation,
                                    static_cast<uint8_t>(code_offset),
                                    0u,
                                    static_cast<uint32_t>(size)});
  }

  void RecordSetFramePointer(uint8_t reg, uint8_t scaled_offset, size_t code_offset) {
    if (!PrepareOperation(code_offset) || !IsNonvolatileRegister(reg) ||
        scaled_offset > 15u || HasOperation(OperationKind::kSetFramePointer)) {
      Invalidate();
      return;
    }
    frame_register_ = reg;
    frame_offset_ = scaled_offset;
    operations_.push_back(
        Operation{OperationKind::kSetFramePointer, static_cast<uint8_t>(code_offset), reg, 0u});
  }

  void Finalize(size_t prologue_size) {
    if (!enabled_ || finalized_) {
      if (enabled_ && finalized_) {
        Invalidate();
      }
      return;
    }
    finalized_ = true;
    if (!valid_ || prologue_size > std::numeric_limits<uint8_t>::max() ||
        (!operations_.empty() && operations_.back().code_offset > prologue_size)) {
      Invalidate();
      return;
    }
    prologue_size_ = static_cast<uint8_t>(prologue_size);

    std::vector<uint8_t> codes;
    size_t slot_count = 0u;
    for (auto it = operations_.rbegin(); it != operations_.rend(); ++it) {
      const Operation& operation = *it;
      switch (operation.kind) {
        case OperationKind::kPushNonvolatile:
          AppendSlot(&codes, operation.code_offset, /*op=*/ 0u, operation.reg);
          slot_count += 1u;
          break;
        case OperationKind::kStackAllocation:
          AppendStackAllocation(&codes, operation.code_offset, operation.value, &slot_count);
          break;
        case OperationKind::kSetFramePointer:
          AppendSlot(&codes, operation.code_offset, /*op=*/ 3u, /*op_info=*/ 0u);
          slot_count += 1u;
          break;
      }
    }
    if (!valid_ || slot_count > std::numeric_limits<uint8_t>::max()) {
      Invalidate();
      return;
    }

    data_.reserve(std::max<size_t>(8u, 4u + codes.size() + 2u));
    data_.push_back(1u);  // Version 1, flags 0.
    data_.push_back(prologue_size_);
    data_.push_back(static_cast<uint8_t>(slot_count));
    data_.push_back(static_cast<uint8_t>(frame_register_ | (frame_offset_ << 4)));
    data_.insert(data_.end(), codes.begin(), codes.end());
    if ((slot_count & 1u) != 0u) {
      AppendUint16(&data_, 0u);
    }
    while (data_.size() < 8u) {
      data_.push_back(0u);
    }
  }

 private:
  enum class OperationKind : uint8_t {
    kPushNonvolatile,
    kStackAllocation,
    kSetFramePointer,
  };

  struct Operation {
    OperationKind kind;
    uint8_t code_offset;
    uint8_t reg;
    uint32_t value;
  };

  static bool IsNonvolatileRegister(uint8_t reg) {
    // PE register numbers follow the architectural encoding. Windows x64
    // nonvolatile GPRs are RBX, RBP, RSI, RDI, and R12-R15.
    return reg == 3u || reg == 5u || reg == 6u || reg == 7u ||
           (reg >= 12u && reg <= 15u);
  }

  bool HasOperation(OperationKind kind) const {
    return std::any_of(operations_.begin(), operations_.end(), [kind](const Operation& operation) {
      return operation.kind == kind;
    });
  }

  bool PrepareOperation(size_t code_offset) {
    if (!enabled_ || finalized_ || !valid_ || code_offset == 0u ||
        code_offset > std::numeric_limits<uint8_t>::max() ||
        (!operations_.empty() && code_offset <= operations_.back().code_offset)) {
      return false;
    }
    return true;
  }

  static void AppendSlot(std::vector<uint8_t>* out,
                         uint8_t code_offset,
                         uint8_t op,
                         uint8_t op_info) {
    out->push_back(code_offset);
    out->push_back(static_cast<uint8_t>(op | (op_info << 4)));
  }

  static void AppendUint16(std::vector<uint8_t>* out, uint16_t value) {
    out->push_back(static_cast<uint8_t>(value));
    out->push_back(static_cast<uint8_t>(value >> 8));
  }

  void AppendStackAllocation(std::vector<uint8_t>* out,
                             uint8_t code_offset,
                             uint32_t size,
                             size_t* slot_count) {
    if (size <= 128u) {
      AppendSlot(out,
                 code_offset,
                 /*op=*/ 2u,
                 static_cast<uint8_t>((size / 8u) - 1u));
      *slot_count += 1u;
    } else if ((size / 8u) <= std::numeric_limits<uint16_t>::max()) {
      AppendSlot(out, code_offset, /*op=*/ 1u, /*op_info=*/ 0u);
      AppendUint16(out, static_cast<uint16_t>(size / 8u));
      *slot_count += 2u;
    } else {
      AppendSlot(out, code_offset, /*op=*/ 1u, /*op_info=*/ 1u);
      AppendUint16(out, static_cast<uint16_t>(size));
      AppendUint16(out, static_cast<uint16_t>(size >> 16));
      *slot_count += 3u;
    }
  }

  void Invalidate() {
    valid_ = false;
    data_.clear();
  }

  bool enabled_ = false;
  bool finalized_ = false;
  bool valid_ = true;
  uint8_t prologue_size_ = 0u;
  uint8_t frame_register_ = 0u;
  uint8_t frame_offset_ = 0u;
  std::vector<Operation> operations_;
  std::vector<uint8_t> data_;
};

}  // namespace x86_64
}  // namespace art

#endif  // ART_COMPILER_UTILS_X86_64_WIN64_UNWIND_INFO_H_
