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

#include <android-base/logging.h>

#include "base/bit_utils.h"
#include "gc/space/dlmalloc_space.h"

// ART specific morecore implementation defined in space.cc.
static void* art_heap_morecore(void* m, intptr_t increment);
#define MORECORE(x) art_heap_morecore(m, x)

// Custom heap error handling.
#define PROCEED_ON_ERROR 0
static void art_heap_corruption(const char* function);
static void art_heap_usage_error(const char* function, void* p);
#define CORRUPTION_ERROR_ACTION(m) art_heap_corruption(__FUNCTION__)
#define USAGE_ERROR_ACTION(m, p) art_heap_usage_error(__FUNCTION__, p)

// Ugly inclusion of C file so that ART specific #defines configure dlmalloc for our use for
// mspaces (regular dlmalloc is still declared in bionic).
//
// dlmalloc.c's `#ifdef WIN32` block force-sets HAVE_MMAP=1 / HAVE_MORECORE=0 and uses
// VirtualAlloc for growth. That returns high 64-bit addresses outside ART's MemMap, which
// breaks compressed heap references (32-bit). Keep ART MORECORE (mprotect within the
// non-moving MemMap) by temporarily hiding WIN32/_WIN32 so that configure block is skipped.
// dlmalloc.c also does `#ifndef WIN32` / `#ifdef _WIN32` / `#define WIN32 1`, so both
// macros must be cleared before the include.
#if defined(_WIN32) || defined(WIN32)
#define ART_DLMALLOC_RESTORE_WIN32 1
#ifdef WIN32
#undef WIN32
#endif
#ifdef _WIN32
#undef _WIN32
#endif
#endif
// ART mspace configuration (must win over any later platform defaults inside dlmalloc.c).
// Note: dlmalloc.c may still #define HAVE_* inside a WIN32 block; with WIN32/_WIN32 cleared
// that block is inactive.
#undef HAVE_MMAP
#define HAVE_MMAP 0
#undef HAVE_MREMAP
#define HAVE_MREMAP 0
#undef HAVE_MORECORE
#define HAVE_MORECORE 1
// MORECORE already defined above as art_heap_morecore.
// Avoid accidental sbrk dependency when WIN32 is suppressed.
#ifndef LACKS_UNISTD_H
#define LACKS_UNISTD_H 1
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wempty-body"
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#pragma GCC diagnostic ignored "-Wnull-pointer-arithmetic"
#pragma GCC diagnostic ignored "-Wexpansion-to-defined"
// Force GCC-style spin locks: USE_SPIN_LOCKS=1 enables USE_LOCKS,
// which selects the spin-lock path in dlmalloc.c's lock implementation.
// Spin locks use pure CPU instructions (lock cmpxchg/xchg) — no system calls,
// no pthreads, no InitializeCriticalSection. Works on any writable memory
// including MapViewOfFile section views (J-2 dual-view requirement).
//
// clang --target=x86_64-pc-windows-msvc defines _MSC_VER but not __GNUC__,
// so dlmalloc's spin-lock CAS_LOCK falls to the Win32 interlockedexchange()
// stub — which uses the wrong case. Fix the symbol before inclusion.
#ifndef USE_SPIN_LOCKS
#define USE_SPIN_LOCKS 1
#endif
// clang --target=x86_64-pc-windows-msvc defines _MSC_VER but not __GNUC__.
// Force __GNUC__ so dlmalloc selects the GCC spin-lock path (uses
// __sync_lock_test_and_set / inline asm on x86_64, which clang supports)
// instead of the broken Win32 interlockedexchange() path.
#ifndef __GNUC__
#define ART_DLMALLOC_TMP_GNUC
#define __GNUC__ 4
#define __GNUC_MINOR__ 2
#endif
#include "dlmalloc.c"  // NOLINT
#ifdef ART_DLMALLOC_TMP_GNUC
#undef __GNUC__
#undef __GNUC_MINOR__
#undef ART_DLMALLOC_TMP_GNUC
#endif
// Note: dlmalloc.c uses a DEBUG define to drive debug code. This interferes with the DEBUG severity
//       of libbase, so undefine it now.
#undef DEBUG
#pragma GCC diagnostic pop
#if defined(ART_DLMALLOC_RESTORE_WIN32)
#ifndef _WIN32
#define _WIN32 1
#endif
#ifndef WIN32
#define WIN32 1
#endif
#undef ART_DLMALLOC_RESTORE_WIN32
#endif
// Sanity: if someone reintroduces WIN32 mmap mode, fail the build.
#if HAVE_MMAP
#error "ART dlmalloc must be built with HAVE_MMAP 0 (use MORECORE within MemMap)"
#endif
#if !HAVE_MORECORE
#error "ART dlmalloc must be built with HAVE_MORECORE 1"
#endif

static void* art_heap_morecore(void* m, intptr_t increment) {
  return ::art::gc::allocator::ArtDlMallocMoreCore(m, increment);
}

static void art_heap_corruption(const char* function) {
  LOG(FATAL) << "Corrupt heap detected in: " << function;
}

static void art_heap_usage_error(const char* function, void* p) {
  LOG(FATAL) << "Incorrect use of function '" << function << "' argument " << p
      << " not expected";
}
