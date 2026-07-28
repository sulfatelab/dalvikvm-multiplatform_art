#include "stack_windows.h"

#include <windows.h>

#include <limits>

namespace art {

namespace {

constexpr uint32_t kBaseProtectionMask = 0xffu;

void SetFailure(const char** failure,
                uint32_t* win32_error,
                const char* message,
                uint32_t error = 0u) {
  if (failure != nullptr) {
    *failure = message;
  }
  if (win32_error != nullptr) {
    *win32_error = error;
  }
}

bool AddWithoutOverflow(uintptr_t value, size_t increment, uintptr_t* result) {
  if (increment > std::numeric_limits<uintptr_t>::max() - value) {
    return false;
  }
  *result = value + increment;
  return true;
}

bool RegionContains(const Win32MemoryRegion& region, uintptr_t begin, size_t size) {
  uintptr_t region_end = 0u;
  uintptr_t end = 0u;
  return region.region_size != 0u &&
      AddWithoutOverflow(region.base_address, region.region_size, &region_end) &&
      AddWithoutOverflow(begin, size, &end) &&
      begin >= region.base_address && end <= region_end;
}

bool QuerySelectedPage(const Win32StackPageSelection& selection,
                       Win32MemoryRegion* region) {
  return QueryWin32Memory(selection.page_begin, region, nullptr) &&
      region->allocation_base == selection.allocation_base &&
      RegionContains(*region, selection.page_begin, selection.page_size);
}

bool IsProtected(const Win32MemoryRegion& region) {
  return region.state == MEM_COMMIT &&
      region.type == MEM_PRIVATE &&
      region.protect == PAGE_NOACCESS;
}

bool IsWritable(const Win32MemoryRegion& region) {
  return region.state == MEM_COMMIT &&
      region.type == MEM_PRIVATE &&
      region.protect == PAGE_READWRITE;
}

bool RestoreOriginalPage(const Win32StackPageSelection& selection,
                         uint32_t* win32_error) {
  if (selection.original_state == MEM_RESERVE) {
    if (!VirtualFree(reinterpret_cast<void*>(selection.page_begin),
                     selection.page_size,
                     MEM_DECOMMIT)) {
      if (win32_error != nullptr) {
        *win32_error = GetLastError();
      }
      return false;
    }
  } else if (selection.original_state == MEM_COMMIT) {
    DWORD ignored = 0u;
    if (!VirtualProtect(reinterpret_cast<void*>(selection.page_begin),
                        selection.page_size,
                        selection.original_protect,
                        &ignored)) {
      if (win32_error != nullptr) {
        *win32_error = GetLastError();
      }
      return false;
    }
  } else {
    if (win32_error != nullptr) {
      *win32_error = ERROR_INVALID_PARAMETER;
    }
    return false;
  }
  return true;
}

bool IsOriginalPageState(const Win32StackPageSelection& selection,
                         const Win32MemoryRegion& region) {
  return selection.original_state == MEM_RESERVE
      ? region.state == MEM_RESERVE
      : region.state == MEM_COMMIT &&
          region.type == selection.original_type &&
          region.protect == selection.original_protect;
}

bool RestoreAndVerifyOriginalPage(const Win32StackPageSelection& selection,
                                  uint32_t* win32_error) {
  if (!RestoreOriginalPage(selection, win32_error)) {
    return false;
  }
  Win32MemoryRegion region;
  if (!QuerySelectedPage(selection, &region) || !IsOriginalPageState(selection, region)) {
    if (win32_error != nullptr) {
      *win32_error = ERROR_INVALID_DATA;
    }
    return false;
  }
  return true;
}

}  // namespace

bool QueryWin32Memory(uintptr_t address, Win32MemoryRegion* region, void* context) {
  (void)context;
  if (region == nullptr) {
    return false;
  }
  MEMORY_BASIC_INFORMATION memory_info;
  if (VirtualQuery(reinterpret_cast<const void*>(address),
                   &memory_info,
                   sizeof(memory_info)) == 0u) {
    return false;
  }
  region->base_address = reinterpret_cast<uintptr_t>(memory_info.BaseAddress);
  region->allocation_base = reinterpret_cast<uintptr_t>(memory_info.AllocationBase);
  region->region_size = static_cast<size_t>(memory_info.RegionSize);
  region->state = memory_info.State;
  region->protect = memory_info.Protect;
  region->type = memory_info.Type;
  return true;
}

bool SelectWin32StackPage(uintptr_t low,
                          uintptr_t high,
                          size_t system_page_size,
                          size_t protected_size,
                          size_t minimum_bytes_above,
                          Win32MemoryQuery query,
                          void* query_context,
                          Win32StackPageSelection* selection,
                          const char** failure) {
  if (failure != nullptr) {
    *failure = nullptr;
  }
  if (selection == nullptr || query == nullptr) {
    SetFailure(failure, nullptr, "missing selection output or memory query");
    return false;
  }
  *selection = {};
  if (system_page_size == 0u || protected_size != system_page_size || low >= high ||
      (low % system_page_size) != 0u || (high % system_page_size) != 0u) {
    SetFailure(failure, nullptr, "invalid stack or page-size geometry");
    return false;
  }

  uintptr_t candidate = 0u;
  if (!AddWithoutOverflow(low, system_page_size, &candidate) || candidate >= high) {
    SetFailure(failure, nullptr, "stack has no page above the preserved bottom page");
    return false;
  }

  while (candidate < high) {
    Win32MemoryRegion region;
    if (!query(candidate, &region, query_context)) {
      SetFailure(failure, nullptr, "memory query failed while selecting the ART page");
      return false;
    }
    uintptr_t region_end = 0u;
    if (region.region_size == 0u ||
        !AddWithoutOverflow(region.base_address, region.region_size, &region_end) ||
        region.base_address < low || candidate < region.base_address || candidate >= region_end ||
        region_end > high || (region.base_address % system_page_size) != 0u ||
        (region.region_size % system_page_size) != 0u ||
        region.allocation_base != low ||
        (region.state != MEM_RESERVE && region.state != MEM_COMMIT)) {
      SetFailure(failure, nullptr, "candidate region is outside the validated stack allocation");
      return false;
    }

    const uint32_t base_protection = region.protect & kBaseProtectionMask;
    const bool preserve_region = region.state == MEM_COMMIT &&
        (base_protection == PAGE_NOACCESS || (region.protect & PAGE_GUARD) != 0u);
    if (preserve_region) {
      candidate = region_end;
      continue;
    }

    uintptr_t page_end = 0u;
    uintptr_t required_end = 0u;
    if (!AddWithoutOverflow(candidate, protected_size, &page_end) || page_end > region_end ||
        !AddWithoutOverflow(page_end, minimum_bytes_above, &required_end) ||
        required_end > high) {
      SetFailure(failure, nullptr, "selected page leaves insufficient normal stack space");
      return false;
    }

    const bool reserved_candidate = region.state == MEM_RESERVE;
    const bool committed_candidate = region.state == MEM_COMMIT &&
        region.type == MEM_PRIVATE && region.protect == PAGE_READWRITE;
    if (!reserved_candidate && !committed_candidate) {
      SetFailure(failure, nullptr, "first non-guard candidate has unsupported state or protection");
      return false;
    }

    selection->allocation_base = low;
    selection->page_begin = candidate;
    selection->page_size = protected_size;
    selection->excluded_low_size = static_cast<size_t>(candidate - low);
    selection->original_state = region.state;
    selection->original_protect = region.protect;
    selection->original_type = region.type;
    return true;
  }

  SetFailure(failure, nullptr, "no suitable page exists in the validated stack allocation");
  return false;
}

bool InspectWin32StackLayout(uintptr_t low,
                             uintptr_t high,
                             size_t system_page_size,
                             size_t stack_guarantee_size,
                             size_t minimum_usable_size,
                             Win32MemoryQuery query,
                             void* query_context,
                             Win32StackLayout* layout,
                             const char** failure) {
  if (failure != nullptr) {
    *failure = nullptr;
  }
  if (layout == nullptr || system_page_size == 0u || minimum_usable_size < system_page_size ||
      low >= high ||
      stack_guarantee_size > std::numeric_limits<size_t>::max() - (system_page_size - 1u)) {
    SetFailure(failure, nullptr, "missing layout output or insufficient usable size");
    return false;
  }
  *layout = {};

  // Windows keeps the final page of the stack reservation for terminal
  // overflow detection. Reuse the fixed-page selector only to identify the
  // first suitable page above that page and any adjacent no-access/guard
  // prefix. SelectWin32StackPage() is read-only; this does not install an ART
  // page or alter the system stack mapping.
  Win32StackPageSelection selection;
  if (!SelectWin32StackPage(low,
                            high,
                            system_page_size,
                            system_page_size,
                            minimum_usable_size - system_page_size,
                            query,
                            query_context,
                            &selection,
                            failure)) {
    return false;
  }

  const size_t rounded_stack_guarantee =
      ((stack_guarantee_size + system_page_size - 1u) / system_page_size) * system_page_size;
  if (rounded_stack_guarantee > std::numeric_limits<size_t>::max() - selection.excluded_low_size ||
      system_page_size > std::numeric_limits<size_t>::max() - selection.excluded_low_size -
                             rounded_stack_guarantee) {
    SetFailure(failure, nullptr, "stack prefix, guarantee, and guard overflow");
    return false;
  }
  // SetThreadStackGuarantee() describes usable exception-dispatch stack above
  // Windows' separate terminal inaccessible prefix. They are consecutive
  // regions, not alternative descriptions of the same low bytes.
  // The live PAGE_GUARD immediately above that recovery region is consumed as
  // Windows grows the stack. Debit that page as well so ART's own reserve is
  // fully usable before native overflow dispatch begins.
  const size_t excluded_low_size =
      selection.excluded_low_size + rounded_stack_guarantee + system_page_size;
  const size_t stack_size = static_cast<size_t>(high - low);
  if (excluded_low_size > stack_size || minimum_usable_size > stack_size - excluded_low_size) {
    SetFailure(failure, nullptr, "stack guarantee leaves insufficient usable stack");
    return false;
  }
  uintptr_t usable_begin = 0u;
  if (!AddWithoutOverflow(low, excluded_low_size, &usable_begin)) {
    SetFailure(failure, nullptr, "usable stack address overflow");
    return false;
  }
  layout->allocation_base = selection.allocation_base;
  layout->usable_begin = usable_begin;
  layout->memory_excluded_low_size = selection.excluded_low_size;
  layout->stack_guarantee_size = rounded_stack_guarantee;
  layout->excluded_low_size = excluded_low_size;
  return true;
}

bool InstallWin32StackPage(uintptr_t low,
                           uintptr_t high,
                           size_t system_page_size,
                           size_t protected_size,
                           size_t minimum_bytes_above,
                           Win32StackPageRecord* record,
                           const char** failure,
                           uint32_t* win32_error) {
  if (failure != nullptr) {
    *failure = nullptr;
  }
  if (win32_error != nullptr) {
    *win32_error = 0u;
  }
  if (record == nullptr || record->state != Win32StackPageState::kNotInstalled) {
    SetFailure(failure, win32_error, "stack page record is missing or already installed");
    return false;
  }

  Win32StackPageSelection selection;
  if (!SelectWin32StackPage(low,
                            high,
                            system_page_size,
                            protected_size,
                            minimum_bytes_above,
                            QueryWin32Memory,
                            nullptr,
                            &selection,
                            failure)) {
    return false;
  }

  if (selection.original_state == MEM_RESERVE) {
    void* committed = VirtualAlloc(reinterpret_cast<void*>(selection.page_begin),
                                   selection.page_size,
                                   MEM_COMMIT,
                                   PAGE_READWRITE);
    if (committed != reinterpret_cast<void*>(selection.page_begin)) {
      SetFailure(failure, win32_error, "VirtualAlloc could not commit the selected ART page",
                 GetLastError());
      return false;
    }
  }

  record->selection = selection;
  record->state = Win32StackPageState::kWritableForStackOverflow;
  if (!ProtectWin32StackPage(record, failure, win32_error)) {
    const char* saved_failure = failure != nullptr ? *failure : nullptr;
    const uint32_t saved_error = win32_error != nullptr ? *win32_error : 0u;
    uint32_t rollback_error = 0u;
    if (RestoreAndVerifyOriginalPage(selection, &rollback_error)) {
      *record = {};
      if (failure != nullptr) {
        *failure = saved_failure;
      }
      if (win32_error != nullptr) {
        *win32_error = saved_error;
      }
      return false;
    }
    SetFailure(failure,
               win32_error,
               "protecting the ART page failed and original state could not be restored",
               rollback_error != 0u ? rollback_error : saved_error);
    // Keep the record populated. Thread teardown can retry direct restoration
    // regardless of whether the page is currently writable or protected.
    return false;
  }
  return true;
}

bool UnprotectWin32StackPage(Win32StackPageRecord* record,
                             const char** failure,
                             uint32_t* win32_error) {
  if (failure != nullptr) {
    *failure = nullptr;
  }
  if (win32_error != nullptr) {
    *win32_error = 0u;
  }
  if (record == nullptr || record->state != Win32StackPageState::kProtected) {
    SetFailure(failure, win32_error, "ART stack page is not protected");
    return false;
  }
  DWORD old_protect = 0u;
  if (!VirtualProtect(reinterpret_cast<void*>(record->selection.page_begin),
                      record->selection.page_size,
                      PAGE_READWRITE,
                      &old_protect)) {
    SetFailure(failure, win32_error, "VirtualProtect could not make the ART page writable",
               GetLastError());
    return false;
  }
  if (old_protect != PAGE_NOACCESS) {
    DWORD ignored = 0u;
    (void)VirtualProtect(reinterpret_cast<void*>(record->selection.page_begin),
                         record->selection.page_size,
                         old_protect,
                         &ignored);
    SetFailure(failure,
               win32_error,
               "ART stack page had unexpected protection before unprotect",
               ERROR_INVALID_DATA);
    return false;
  }
  Win32MemoryRegion region;
  if (!QuerySelectedPage(record->selection, &region) || !IsWritable(region)) {
    DWORD ignored = 0u;
    (void)VirtualProtect(reinterpret_cast<void*>(record->selection.page_begin),
                         record->selection.page_size,
                         PAGE_NOACCESS,
                         &ignored);
    SetFailure(failure,
               win32_error,
               "ART stack page did not become private read/write",
               ERROR_INVALID_DATA);
    return false;
  }
  record->state = Win32StackPageState::kWritableForStackOverflow;
  return true;
}

bool ProtectWin32StackPage(Win32StackPageRecord* record,
                           const char** failure,
                           uint32_t* win32_error) {
  if (failure != nullptr) {
    *failure = nullptr;
  }
  if (win32_error != nullptr) {
    *win32_error = 0u;
  }
  if (record == nullptr ||
      record->state != Win32StackPageState::kWritableForStackOverflow) {
    SetFailure(failure, win32_error, "ART stack page is not writable");
    return false;
  }
  DWORD old_protect = 0u;
  if (!VirtualProtect(reinterpret_cast<void*>(record->selection.page_begin),
                      record->selection.page_size,
                      PAGE_NOACCESS,
                      &old_protect)) {
    SetFailure(failure, win32_error, "VirtualProtect could not protect the ART page",
               GetLastError());
    return false;
  }
  if (old_protect != PAGE_READWRITE) {
    DWORD ignored = 0u;
    (void)VirtualProtect(reinterpret_cast<void*>(record->selection.page_begin),
                         record->selection.page_size,
                         old_protect,
                         &ignored);
    SetFailure(failure,
               win32_error,
               "ART stack page was not private read/write before protect",
               ERROR_INVALID_DATA);
    return false;
  }
  Win32MemoryRegion region;
  if (!QuerySelectedPage(record->selection, &region) || !IsProtected(region)) {
    DWORD ignored = 0u;
    (void)VirtualProtect(reinterpret_cast<void*>(record->selection.page_begin),
                         record->selection.page_size,
                         PAGE_READWRITE,
                         &ignored);
    SetFailure(failure,
               win32_error,
               "ART stack page did not become PAGE_NOACCESS",
               ERROR_INVALID_DATA);
    return false;
  }
  record->state = Win32StackPageState::kProtected;
  return true;
}

bool RestoreWin32StackPage(Win32StackPageRecord* record,
                           const char** failure,
                           uint32_t* win32_error) {
  if (failure != nullptr) {
    *failure = nullptr;
  }
  if (win32_error != nullptr) {
    *win32_error = 0u;
  }
  if (record == nullptr) {
    SetFailure(failure, win32_error, "stack page record is missing");
    return false;
  }
  if (record->state == Win32StackPageState::kNotInstalled) {
    return true;
  }
  if (!RestoreAndVerifyOriginalPage(record->selection, win32_error)) {
    SetFailure(failure,
               nullptr,
               record->selection.original_state == MEM_RESERVE
                   ? "ART stack page could not be decommitted to its original reserved state"
                   : "ART stack page could not be restored to its original committed state");
    return false;
  }
  *record = {};
  return true;
}

}  // namespace art
