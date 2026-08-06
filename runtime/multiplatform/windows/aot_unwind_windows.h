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

#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_UNWIND_WINDOWS_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_UNWIND_WINDOWS_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

namespace art {

// Owns one immutable Windows x64 runtime-function table for an OAT component.
// Windows SDK types stay in the implementation. Create() validates the
// serialized transport for both validation-only and executable OAT opens;
// Register() publishes it only for an executable open.
class WindowsAotUnwindRegistry {
 public:
  static std::unique_ptr<WindowsAotUnwindRegistry> Create(
      const uint8_t* oat_begin,
      const uint8_t* code_begin,
      const uint8_t* code_end,
      const uint8_t* section_begin,
      const uint8_t* section_end,
      std::string* error_msg);

  ~WindowsAotUnwindRegistry();

  WindowsAotUnwindRegistry(const WindowsAotUnwindRegistry&) = delete;
  WindowsAotUnwindRegistry& operator=(const WindowsAotUnwindRegistry&) = delete;

  bool Register(std::string* error_msg);
  size_t Size() const;
  bool IsRegistered() const;

 private:
  struct Impl;

  explicit WindowsAotUnwindRegistry(std::unique_ptr<Impl>&& impl);

  std::unique_ptr<Impl> impl_;
};

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_UNWIND_WINDOWS_H_
