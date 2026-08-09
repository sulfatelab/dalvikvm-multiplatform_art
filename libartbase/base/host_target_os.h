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

#ifndef ART_LIBARTBASE_BASE_HOST_TARGET_OS_H_
#define ART_LIBARTBASE_BASE_HOST_TARGET_OS_H_

// Compiler and OAT-writer behavior that follows the Windows ABI must cover
// both a native Windows host build and a cross-built Windows target. Keep this
// distinct from kIsTargetWindows, which deliberately excludes host builds.
#if defined(_WIN32) || defined(ART_TARGET_WINDOWS)
#define ART_HOST_OR_TARGET_WINDOWS 1
#else
#define ART_HOST_OR_TARGET_WINDOWS 0
#endif

namespace art {

static constexpr bool kIsHostOrTargetWindows = ART_HOST_OR_TARGET_WINDOWS != 0;

}  // namespace art

#endif  // ART_LIBARTBASE_BASE_HOST_TARGET_OS_H_
