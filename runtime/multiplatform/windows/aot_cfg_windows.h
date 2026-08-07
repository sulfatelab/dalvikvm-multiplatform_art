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

#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_CFG_WINDOWS_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_CFG_WINDOWS_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

namespace art {

// Validates one immutable .oat_cfg.windows table and records the process CFG
// policy. W-032 is observation-only: this class never changes CFG target state
// and does not own an operating-system registration handle.
class WindowsAotCfgTable {
 public:
  static std::unique_ptr<WindowsAotCfgTable> Create(const uint8_t* oat_begin,
                                                    const uint8_t* code_begin,
                                                    const uint8_t* code_end,
                                                    const uint8_t* section_begin,
                                                    const uint8_t* section_end,
                                                    std::string* error_msg);

  ~WindowsAotCfgTable();

  WindowsAotCfgTable(const WindowsAotCfgTable&) = delete;
  WindowsAotCfgTable& operator=(const WindowsAotCfgTable&) = delete;

  size_t TargetCount() const;
  bool ContainsTarget(uint32_t code_offset, uint32_t required_kind_flags = 0u) const;
  bool PolicyQuerySucceeded() const;
  bool IsCfgEnabled() const;
  bool IsStrictMode() const;
  bool IsExportSuppressionEnabled() const;

 private:
  struct Impl;

  explicit WindowsAotCfgTable(std::unique_ptr<Impl>&& impl);

  std::unique_ptr<Impl> impl_;
};

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_CFG_WINDOWS_H_
