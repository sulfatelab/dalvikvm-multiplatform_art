/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "mem_map.h"

#include <algorithm>
#include <io.h>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <windows.h>
// This include needs to be here due to the coding conventions.  Unfortunately
// it drags in the definition of the ERROR macro. Similarly to base/utils.cc,
// undefine the macro here. See also, the comment at android-base/logging.h.
#ifdef ERROR
#undef ERROR
#endif

#include "android-base/logging.h"
#include "android-base/stringprintf.h"
#ifdef PROT_READ
#undef PROT_READ
#endif
#ifdef PROT_WRITE
#undef PROT_WRITE
#endif
#ifdef PROT_EXEC
#undef PROT_EXEC
#endif
#ifdef PROT_NONE
#undef PROT_NONE
#endif
#include "mman.h"

namespace art {

using android::base::StringPrintf;

static off_t allocation_granularity;

namespace {

enum class WindowsMapKind {
  kVirtualAlloc,
  kSectionView,
};

using WindowsOwnerRegistry = std::map<void*, std::weak_ptr<WindowsMapOwner>>;

static WindowsOwnerRegistry& GetWindowsOwnerRegistry() {
  static WindowsOwnerRegistry* registry = new WindowsOwnerRegistry();
  return *registry;
}

static std::mutex& GetWindowsOwnerRegistryLock() {
  static std::mutex* lock = new std::mutex();
  return *lock;
}

static bool QueryWindowsMapping(void* address,
                                MEMORY_BASIC_INFORMATION* info,
                                WindowsMapKind* kind) {
  if (::VirtualQuery(address, info, sizeof(*info)) != sizeof(*info) ||
      info->State == MEM_FREE || info->AllocationBase == nullptr) {
    return false;
  }
  if (info->Type == MEM_PRIVATE) {
    *kind = WindowsMapKind::kVirtualAlloc;
    return true;
  }
  if (info->Type == MEM_MAPPED) {
    *kind = WindowsMapKind::kSectionView;
    return true;
  }
  return false;
}

static bool ReleaseWindowsMapping(void* allocation_base, WindowsMapKind kind) {
  return kind == WindowsMapKind::kVirtualAlloc
      ? ::VirtualFree(allocation_base, 0u, MEM_RELEASE) != FALSE
      : ::UnmapViewOfFile(allocation_base) != FALSE;
}

}  // namespace

struct WindowsMapOwner {
  WindowsMapOwner(void* allocation_base, WindowsMapKind kind)
      : allocation_base(allocation_base), kind(kind) {}

  ~WindowsMapOwner() {
    {
      std::lock_guard<std::mutex> mu(GetWindowsOwnerRegistryLock());
      auto& registry = GetWindowsOwnerRegistry();
      auto it = registry.find(allocation_base);
      if (it != registry.end() && it->second.expired()) {
        registry.erase(it);
      }
    }
    if (!ReleaseWindowsMapping(allocation_base, kind)) {
      const DWORD error = ::GetLastError();
      LOG(FATAL) << StringPrintf(
          "Failed to release Windows mapping owner %p: %lu", allocation_base, error);
    }
  }

  void* const allocation_base;
  const WindowsMapKind kind;
};

static DWORD ProtToPageProtect(int prot) {
  const bool r = (prot & PROT_READ) != 0;
  const bool w = (prot & PROT_WRITE) != 0;
  const bool x = (prot & PROT_EXEC) != 0;
  if (prot == PROT_NONE || (!r && !w && !x)) {
    return PAGE_NOACCESS;
  }
  if (x && w) return PAGE_EXECUTE_READWRITE;
  if (x && r) return PAGE_EXECUTE_READ;
  if (x) return PAGE_EXECUTE;
  if (w) return PAGE_READWRITE;
  return PAGE_READONLY;
}

void MemMap::TargetMMapInit() {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  allocation_granularity = static_cast<off_t>(si.dwAllocationGranularity);
}

void* MemMap::TargetMMap(void* start,
                         size_t len,
                         int prot,
                         int flags,
                         int fd,
                         off_t fd_off,
                         size_t alignment) {
  if (len == 0) {
    errno = EINVAL;
    return MAP_FAILED;
  }

  const bool anonymous = (flags & MAP_ANONYMOUS) != 0 || fd < 0;
  const bool fixed = (flags & MAP_FIXED) != 0;
  DWORD page_prot = ProtToPageProtect(prot);

  // Anonymous mapping through the Windows 10 address-requirements API.
  if (anonymous) {
    constexpr uintptr_t k4GB = 4ull * GB;
    const uintptr_t granularity = allocation_granularity > 0
        ? static_cast<uintptr_t>(allocation_granularity)
        : 64u * 1024u;
    const bool want_low_4gb = (flags & MAP_32BIT) != 0;
    const uintptr_t requested = reinterpret_cast<uintptr_t>(start);

    if (start != nullptr && alignment != 0u && !IsAlignedParam(requested, alignment)) {
      errno = EINVAL;
      return MAP_FAILED;
    }
    if (want_low_4gb &&
        (len > k4GB ||
         (start != nullptr && (requested >= k4GB || len > k4GB - requested)))) {
      errno = ENOMEM;
      return MAP_FAILED;
    }

    if (fixed && start != nullptr) {
      MEMORY_BASIC_INFORMATION info = {};
      if (::VirtualQuery(start, &info, sizeof(info)) == sizeof(info) &&
          info.State != MEM_FREE) {
        const void* allocation_base = info.AllocationBase;
        uintptr_t cursor = requested;
        const uintptr_t end = requested + len;
        while (cursor < end) {
          MEMORY_BASIC_INFORMATION part = {};
          if (::VirtualQuery(reinterpret_cast<void*>(cursor), &part, sizeof(part)) !=
                  sizeof(part) ||
              part.State == MEM_FREE || part.AllocationBase != allocation_base) {
            errno = EINVAL;
            return MAP_FAILED;
          }
          const uintptr_t part_end = reinterpret_cast<uintptr_t>(part.BaseAddress) + part.RegionSize;
          if (part_end <= cursor) {
            errno = EINVAL;
            return MAP_FAILED;
          }
          cursor = std::min(part_end, end);
        }
        DWORD old_protect = 0u;
        if (!::VirtualProtect(start, len, page_prot, &old_protect)) {
          errno = EINVAL;
          return MAP_FAILED;
        }
        return start;
      }
    }

    // Creating a new reservation at an exact address requires allocation-
    // granularity alignment. Reusing a subrange above only requires page
    // alignment and does not create a second reservation.
    if (start != nullptr && !IsAlignedParam(requested, granularity)) {
      errno = EINVAL;
      return MAP_FAILED;
    }

    MEM_ADDRESS_REQUIREMENTS requirements = {};
    MEM_EXTENDED_PARAMETER parameter = {};
    MEM_EXTENDED_PARAMETER* parameters = nullptr;
    ULONG parameter_count = 0u;
    if (start == nullptr && (want_low_4gb || alignment != 0u)) {
      if (want_low_4gb) {
        requirements.LowestStartingAddress = reinterpret_cast<void*>(granularity);
        requirements.HighestEndingAddress =
            reinterpret_cast<void*>(std::numeric_limits<uint32_t>::max());
      }
      requirements.Alignment = alignment;
      parameter.Type = MemExtendedParameterAddressRequirements;
      parameter.Pointer = &requirements;
      parameters = &parameter;
      parameter_count = 1u;
    }

    void* p = ::VirtualAlloc2(::GetCurrentProcess(),
                              start,
                              len,
                              MEM_RESERVE | MEM_COMMIT,
                              page_prot,
                              parameters,
                              parameter_count);
    if (p == nullptr) {
      DWORD error = ::GetLastError();
      errno = (error == ERROR_INVALID_ADDRESS || error == ERROR_INVALID_PARAMETER) ? EINVAL
                                                                                  : ENOMEM;
      return MAP_FAILED;
    }
    if (fixed && p != start) {
      VirtualFree(p, 0, MEM_RELEASE);
      errno = EINVAL;
      return MAP_FAILED;
    }
    const uintptr_t begin = reinterpret_cast<uintptr_t>(p);
    if (want_low_4gb && (begin >= k4GB || len > k4GB - begin)) {
      ::VirtualFree(p, 0u, MEM_RELEASE);
      errno = ENOMEM;
      return MAP_FAILED;
    }
    return p;
  }

  // File-backed mapping.
  size_t padding = static_cast<size_t>(fd_off % allocation_granularity);
  off_t file_offset = fd_off - static_cast<off_t>(padding);
  size_t map_length = len + padding;

  DWORD map_access = 0;
  DWORD view_access = 0;
  if ((prot & PROT_WRITE) != 0) {
    map_access = PAGE_READWRITE;
    if (((flags & MAP_SHARED) != 0) && ((flags & MAP_PRIVATE) == 0)) {
      view_access = FILE_MAP_ALL_ACCESS;
    } else if (((flags & MAP_SHARED) == 0) && ((flags & MAP_PRIVATE) != 0)) {
      view_access = FILE_MAP_COPY | FILE_MAP_READ;
    } else {
      // Default private for ART file maps when flags are ambiguous.
      view_access = FILE_MAP_COPY | FILE_MAP_READ;
      map_access = PAGE_WRITECOPY;
    }
  } else if ((prot & PROT_EXEC) != 0) {
    map_access = PAGE_EXECUTE_READ;
    view_access = FILE_MAP_READ | FILE_MAP_EXECUTE;
  } else {
    map_access = PAGE_READONLY;
    view_access = FILE_MAP_READ;
  }

  HANDLE file_handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
  if (file_handle == INVALID_HANDLE_VALUE) {
    PLOG(ERROR) << "Invalid file descriptor for MapViewOfFile.";
    errno = EBADF;
    return MAP_FAILED;
  }

  LARGE_INTEGER file_length;
  if (!::GetFileSizeEx(file_handle, &file_length)) {
    PLOG(ERROR) << "Couldn't get file size.";
    errno = EINVAL;
    return MAP_FAILED;
  }
  if (((map_access & PAGE_READONLY) != 0 || map_access == PAGE_EXECUTE_READ) &&
      static_cast<ULONGLONG>(file_offset) + map_length >
          static_cast<ULONGLONG>(file_length.QuadPart)) {
    map_length = 0;  // use remaining file size
  }

  HANDLE handle = ::CreateFileMapping(file_handle,
                                      nullptr,
                                      map_access,
                                      0,
                                      0,
                                      nullptr);
  if (handle == nullptr) {
    DWORD error = ::GetLastError();
    PLOG(ERROR) << StringPrintf("Couldn't create file mapping %lx.", error);
    errno = EINVAL;
    return MAP_FAILED;
  }

  DWORD offset_low = static_cast<DWORD>(file_offset & 0xffffffffU);
#ifdef _WIN64
  DWORD offset_high = static_cast<DWORD>(static_cast<uint64_t>(file_offset) >> 32);
#else
  DWORD offset_high = 0;
#endif
  void* view_address = MapViewOfFileEx(handle,
                                       view_access,
                                       offset_high,
                                       offset_low,
                                       map_length,
                                       fixed ? start : (start != nullptr ? start : nullptr));
  if (view_address == nullptr && !fixed && start != nullptr) {
    view_address = MapViewOfFile(handle, view_access, offset_high, offset_low, map_length);
  }
  // Close mapping handle; view keeps a reference.
  ::CloseHandle(handle);
  if (view_address == nullptr) {
    DWORD error = ::GetLastError();
    PLOG(ERROR) << StringPrintf("Couldn't create file view %lx.", error);
    errno = EINVAL;
    return MAP_FAILED;
  }
  if (padding != 0) {
    // Caller asked for offset not aligned to allocation granularity; return interior pointer.
    // Note: Unmap must still use the view base; ART unmaps using the returned pointer for
    // anonymous maps. File maps with unaligned offset are rare in ART.
    view_address = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(view_address) + padding);
  }
  return view_address;
}

int MemMap::TargetMUnmap(void* start, size_t len) {
  UNUSED(len);
  if (start == nullptr) {
    return 0;
  }

  MEMORY_BASIC_INFORMATION info = {};
  WindowsMapKind kind;
  if (!QueryWindowsMapping(start, &info, &kind)) {
    errno = EINVAL;
    return -1;
  }
  {
    std::lock_guard<std::mutex> mu(GetWindowsOwnerRegistryLock());
    auto it = GetWindowsOwnerRegistry().find(info.AllocationBase);
    if (it != GetWindowsOwnerRegistry().end() && !it->second.expired()) {
      LOG(ERROR) << "TargetMUnmap attempted to bypass a live Windows mapping owner at "
                 << info.AllocationBase;
      errno = EINVAL;
      return -1;
    }
  }
  if (ReleaseWindowsMapping(info.AllocationBase, kind)) {
    return 0;
  }
  DWORD error = ::GetLastError();
  LOG(ERROR) << StringPrintf(
      "TargetMUnmap(%p, allocation_base=%p) failed: %lu", start, info.AllocationBase, error);
  errno = EINVAL;
  return -1;
}

int MemMap::TargetMProtect(void* start, size_t len, int prot) {
  DWORD old_protect = 0u;
  if (::VirtualProtect(start, len, ProtToPageProtect(prot), &old_protect)) {
    return 0;
  }
  errno = EINVAL;
  return -1;
}

int MemMap::TargetMDiscard(void* start, size_t len) {
  const DWORD error = ::DiscardVirtualMemory(start, len);
  if (error == ERROR_SUCCESS) {
    return 0;
  }
  ::SetLastError(error);
  errno = error == ERROR_NOT_ENOUGH_MEMORY ? ENOMEM : EINVAL;
  return -1;
}

void MemMap::AcquireWindowsMapOwner() {
  CHECK(IsValid());
  MEMORY_BASIC_INFORMATION info = {};
  WindowsMapKind kind;
  CHECK(QueryWindowsMapping(BaseBegin(), &info, &kind))
      << "No Windows mapping backs MemMap " << BaseBegin();

  std::lock_guard<std::mutex> mu(GetWindowsOwnerRegistryLock());
  auto& registry = GetWindowsOwnerRegistry();
  auto it = registry.find(info.AllocationBase);
  if (it != registry.end()) {
    windows_owner_ = it->second.lock();
    if (windows_owner_ != nullptr) {
      CHECK(windows_owner_->kind == kind);
      return;
    }
  }

  windows_owner_ = std::make_shared<WindowsMapOwner>(info.AllocationBase, kind);
  registry[info.AllocationBase] = windows_owner_;
}


// Pagefile-section helpers for the Win64 JIT dual-view mapping.

void* MemMap::CreatePageFileSection(size_t capacity, std::string* error_msg) {
  DWORD size_hi = static_cast<DWORD>((capacity >> 32) & 0xFFFFFFFFULL);
  DWORD size_lo = static_cast<DWORD>(capacity & 0xFFFFFFFFULL);

  HANDLE hSection = ::CreateFileMappingW(
      INVALID_HANDLE_VALUE,       // paging file
      nullptr,                    // default security
      PAGE_EXECUTE_READWRITE,     // allow RX and RW views
      size_hi,
      size_lo,
      nullptr);                   // unnamed

  if (hSection == nullptr) {
    DWORD error = ::GetLastError();
    *error_msg = android::base::StringPrintf(
        "CreateFileMapping(size=%zu) failed: %lu", capacity, error);
    return nullptr;
  }

  return static_cast<void*>(hSection);
}

MemMap MemMap::MapFileSection(void* hSection,
                              size_t byte_count,
                              int prot,
                              bool low_4gb,
                              size_t start_offset,
                              const char* name,
                              std::string* error_msg) {
  if (hSection == nullptr || byte_count == 0) {
    *error_msg = "MapFileSection: null handle or zero size";
    return Invalid();
  }

  HANDLE h = static_cast<HANDLE>(hSection);
  MEM_EXTENDED_PARAMETER parameter = {};
  MEM_ADDRESS_REQUIREMENTS requirements = {};
  MEM_EXTENDED_PARAMETER* parameters = nullptr;
  ULONG parameter_count = 0u;
  if (low_4gb) {
    const uintptr_t granularity = allocation_granularity > 0
        ? static_cast<uintptr_t>(allocation_granularity)
        : 64u * 1024u;
    requirements.LowestStartingAddress = reinterpret_cast<void*>(granularity);
    requirements.HighestEndingAddress = reinterpret_cast<void*>(
        static_cast<uintptr_t>(std::numeric_limits<uint32_t>::max()));
    requirements.Alignment = 0u;
    parameter.Type = MemExtendedParameterAddressRequirements;
    parameter.Pointer = &requirements;
    parameters = &parameter;
    parameter_count = 1u;
  }

  void* view = MapViewOfFile3(h,
                              /* Process= */ nullptr,
                              /* BaseAddress= */ nullptr,
                              static_cast<ULONG64>(start_offset),
                              byte_count,
                              /* AllocationType= */ 0u,
                              ProtToPageProtect(prot),
                              parameters,
                              parameter_count);

  if (view == nullptr) {
    DWORD error = ::GetLastError();
    *error_msg = android::base::StringPrintf(
        "MapViewOfFile3(offset=%zu, size=%zu, prot=%d, low4g=%d) failed: %lu",
        start_offset, byte_count, prot, low_4gb ? 1 : 0, error);
    errno = (error == ERROR_INVALID_ADDRESS || error == ERROR_INVALID_PARAMETER) ? EINVAL : ENOMEM;
    return Invalid();
  }

  const uintptr_t begin = reinterpret_cast<uintptr_t>(view);
  constexpr uintptr_t k4GB = 4ull * GB;
  if (low_4gb && (begin >= k4GB || byte_count > k4GB - begin)) {
    UnmapViewOfFile(view);
    *error_msg = android::base::StringPrintf(
        "MapViewOfFile3 returned range [%p, %p) outside ART low-4GB limit",
        view,
        reinterpret_cast<void*>(begin + byte_count));
    errno = ENOMEM;
    return Invalid();
  }

  MemMap result(name,
                reinterpret_cast<uint8_t*>(view),
                byte_count,
                view,
                byte_count,
                prot,
                /*reuse=*/false);
  result.AcquireWindowsMapOwner();
  return result;
}

MemMap MemMap::SplitViewAtEnd(uint8_t* new_end,
                              const char* tail_name,
                              int head_prot,
                              int tail_prot,
                              std::string* error_msg) {
  if (!IsValid() || Begin() != BaseBegin() || Size() != BaseSize() ||
      new_end <= Begin() || new_end >= End() ||
      !IsAlignedParam(new_end, GetPageSize())) {
    *error_msg = StringPrintf(
        "SplitViewAtEnd invalid range: map=[%p, %p), split=%p",
        Begin(), End(), new_end);
    errno = EINVAL;
    return Invalid();
  }

  const size_t head_size = static_cast<size_t>(new_end - Begin());
  const size_t tail_size = static_cast<size_t>(End() - new_end);
  DWORD old_head_protection = 0;
  if (!VirtualProtect(Begin(),
                      head_size,
                      ProtToPageProtect(head_prot),
                      &old_head_protection)) {
    const DWORD error = GetLastError();
    *error_msg = StringPrintf(
        "VirtualProtect head(%p, %zu, prot=%d) failed: %lu",
        Begin(), head_size, head_prot, static_cast<unsigned long>(error));
    errno = EINVAL;
    return Invalid();
  }

  DWORD old_tail_protection = 0;
  if (!VirtualProtect(new_end,
                      tail_size,
                      ProtToPageProtect(tail_prot),
                      &old_tail_protection)) {
    const DWORD error = GetLastError();
    DWORD ignored = 0;
    const BOOL restored = VirtualProtect(Begin(), head_size, old_head_protection, &ignored);
    *error_msg = StringPrintf(
        "VirtualProtect tail(%p, %zu, prot=%d) failed: %lu; head restore=%d",
        new_end,
        tail_size,
        tail_prot,
        static_cast<unsigned long>(error),
        restored ? 1 : 0);
    errno = EINVAL;
    return Invalid();
  }

  size_ = head_size;
  base_size_ = head_size;
  prot_ = head_prot;
  MemMap result(tail_name,
                new_end,
                tail_size,
                new_end,
                tail_size,
                tail_prot,
                /*reuse=*/true);
  result.AcquireWindowsMapOwner();
  return result;
}

}  // namespace art
