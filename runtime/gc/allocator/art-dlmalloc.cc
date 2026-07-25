/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "art-dlmalloc.h"

#include <cerrno>

#include <android-base/logging.h>

#include "base/bit_utils.h"
#include "gc/allocator/mspace_morecore.h"

// Dispatch dlmalloc growth to the owner attached to each mspace.
static void* art_heap_morecore(void* m, intptr_t increment);
#define MORECORE(x) art_heap_morecore(m, x)

// Custom heap error handling.
#define PROCEED_ON_ERROR 0
static void art_heap_corruption(const char* function);
static void art_heap_usage_error(const char* function, void* p);
#define CORRUPTION_ERROR_ACTION(m) art_heap_corruption(__FUNCTION__)
#define USAGE_ERROR_ACTION(m, p) art_heap_usage_error(__FUNCTION__, p)
#define MALLOC_FAILURE_ACTION errno = ENOMEM;

// Ugly inclusion of C file so that ART specific #defines configure dlmalloc for our use for
// mspaces (regular dlmalloc is still declared in bionic).
//
// ART supplies the complete mspace policy in art-dlmalloc.h. dlmalloc's Win32
// defaults respect embedding-provided HAVE_* values, so keep the real platform
// macros visible while selecting ART-owned MORECORE instead of dlmalloc-owned
// VirtualAlloc mappings.
// MORECORE is defined above as art_heap_morecore. Avoid an accidental sbrk
// dependency on non-Windows hosts as well.
#ifndef LACKS_UNISTD_H
#define LACKS_UNISTD_H 1
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wempty-body"
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#pragma GCC diagnostic ignored "-Wnull-pointer-arithmetic"
#pragma GCC diagnostic ignored "-Wexpansion-to-defined"
// ART dlmalloc lock configuration is explicitly USE_LOCKS=0. Heap mspaces use
// ART-level mutexes and JIT mspaces use Locks::jit_lock_.
#include "dlmalloc.c"  // NOLINT
// Note: dlmalloc.c uses a DEBUG define to drive debug code. This interferes with the DEBUG severity
//       of libbase, so undefine it now.
#undef DEBUG
#pragma GCC diagnostic pop
// Keep the embedded configuration explicit and fail the build on drift.
#if HAVE_MMAP != 0
#error "ART dlmalloc must be built with HAVE_MMAP 0 (use MORECORE within MemMap)"
#endif
#if HAVE_MREMAP != 0
#error "ART dlmalloc must be built with HAVE_MREMAP 0"
#endif
#if HAVE_MORECORE != 1
#error "ART dlmalloc must be built with HAVE_MORECORE 1"
#endif
#if MORECORE_CONTIGUOUS != 1
#error "ART dlmalloc must use page-granular contiguous MORECORE configuration"
#endif
#if USE_LOCKS != 0
#error "ART dlmalloc mspaces must use ART-owned external locks"
#endif
#if ONLY_MSPACES != 1 || MSPACES != 1
#error "ART dlmalloc must be built for mspaces only"
#endif
#if defined(_WIN32) && !defined(WIN32)
#error "dlmalloc must retain Win32 platform detection in ART builds"
#endif

namespace {

static constexpr size_t kArtMspaceProviderMagic = static_cast<size_t>(0x4d535041u);  // "MSPA"

static mstate GetMspaceState(void* mspace) {
  CHECK(mspace != nullptr);
  mstate state = reinterpret_cast<mstate>(mspace);
  CHECK(ok_magic(state)) << "Invalid ART mspace " << mspace;
  return state;
}

static art::gc::allocator::MspaceMoreCoreProvider* GetMspaceProvider(void* mspace) {
  mstate state = GetMspaceState(mspace);
  CHECK_EQ(state->exts, kArtMspaceProviderMagic) << "Unattached ART mspace " << mspace;
  CHECK(state->extp != nullptr) << "Missing MoreCore provider for ART mspace " << mspace;
  return reinterpret_cast<art::gc::allocator::MspaceMoreCoreProvider*>(state->extp);
}

}  // namespace

namespace art {
namespace gc {
namespace allocator {

void* ArtCreateMspaceWithBase(void* base,
                              size_t initial_footprint,
                              MspaceMoreCoreProvider* provider) {
  void* mspace = create_mspace_with_base(base, initial_footprint, /*locked=*/false);
  if (mspace != nullptr && provider != nullptr) {
    ArtAttachMspaceMoreCoreProvider(mspace, provider);
  }
  return mspace;
}

void ArtAttachMspaceMoreCoreProvider(void* mspace, MspaceMoreCoreProvider* provider) {
  CHECK(provider != nullptr);
  mstate state = GetMspaceState(mspace);
  CHECK(state->extp == nullptr);
  CHECK_EQ(state->exts, 0u);
  state->extp = provider;
  state->exts = kArtMspaceProviderMagic;
}

void ArtDetachMspaceMoreCoreProvider(void* mspace, MspaceMoreCoreProvider* provider) {
  mstate state = GetMspaceState(mspace);
  CHECK_EQ(state->exts, kArtMspaceProviderMagic);
  CHECK_EQ(state->extp, provider);
  state->extp = nullptr;
  state->exts = 0u;
}

}  // namespace allocator
}  // namespace gc
}  // namespace art

static void* art_heap_morecore(void* m, intptr_t increment) {
  return GetMspaceProvider(m)->MoreCore(m, increment);
}

static void art_heap_corruption(const char* function) {
  LOG(FATAL) << "Corrupt heap detected in: " << function;
}

static void art_heap_usage_error(const char* function, void* p) {
  LOG(FATAL) << "Incorrect use of function '" << function << "' argument " << p
      << " not expected";
}
