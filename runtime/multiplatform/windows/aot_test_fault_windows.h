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

#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_TEST_FAULT_WINDOWS_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_TEST_FAULT_WINDOWS_H_

#include <cstdlib>
#include <cstring>

namespace art {

// Native W-053 test control. Production startup is unchanged unless the
// deliberately test-named environment variable selects one exact checkpoint.
inline bool IsWindowsBootAotTestFailure(const char* checkpoint) {
  const char* value = std::getenv("ART_WINDOWS_X64_TEST_BOOT_AOT_FAILURE");
  return value != nullptr && std::strcmp(value, checkpoint) == 0;
}

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_AOT_TEST_FAULT_WINDOWS_H_
