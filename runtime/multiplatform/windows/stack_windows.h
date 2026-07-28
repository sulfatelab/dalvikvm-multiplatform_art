#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_STACK_WINDOWS_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_STACK_WINDOWS_H_

#include <cstddef>
#include <cstdint>

namespace art {

enum class Win32StackPageState : uint8_t {
  kNotInstalled,
  kProtected,
  kWritableForStackOverflow,
};

struct Win32MemoryRegion {
  uintptr_t base_address = 0u;
  uintptr_t allocation_base = 0u;
  size_t region_size = 0u;
  uint32_t state = 0u;
  uint32_t protect = 0u;
  uint32_t type = 0u;
};

using Win32MemoryQuery = bool (*)(uintptr_t address,
                                  Win32MemoryRegion* region,
                                  void* context);

struct Win32StackPageSelection {
  uintptr_t allocation_base = 0u;
  uintptr_t page_begin = 0u;
  size_t page_size = 0u;
  size_t excluded_low_size = 0u;
  uint32_t original_state = 0u;
  uint32_t original_protect = 0u;
  uint32_t original_type = 0u;
};

struct Win32StackLayout {
  uintptr_t allocation_base = 0u;
  uintptr_t usable_begin = 0u;
  size_t excluded_low_size = 0u;
};

struct Win32StackPageRecord {
  Win32StackPageSelection selection;
  Win32StackPageState state = Win32StackPageState::kNotInstalled;
};

bool QueryWin32Memory(uintptr_t address, Win32MemoryRegion* region, void* context);

bool SelectWin32StackPage(uintptr_t low,
                          uintptr_t high,
                          size_t system_page_size,
                          size_t protected_size,
                          size_t minimum_bytes_above,
                          Win32MemoryQuery query,
                          void* query_context,
                          Win32StackPageSelection* selection,
                          const char** failure);

bool InspectWin32StackLayout(uintptr_t low,
                             uintptr_t high,
                             size_t system_page_size,
                             size_t minimum_usable_size,
                             Win32MemoryQuery query,
                             void* query_context,
                             Win32StackLayout* layout,
                             const char** failure);

bool InstallWin32StackPage(uintptr_t low,
                           uintptr_t high,
                           size_t system_page_size,
                           size_t protected_size,
                           size_t minimum_bytes_above,
                           Win32StackPageRecord* record,
                           const char** failure,
                           uint32_t* win32_error);

bool UnprotectWin32StackPage(Win32StackPageRecord* record,
                             const char** failure,
                             uint32_t* win32_error);

bool ProtectWin32StackPage(Win32StackPageRecord* record,
                           const char** failure,
                           uint32_t* win32_error);

bool RestoreWin32StackPage(Win32StackPageRecord* record,
                           const char** failure,
                           uint32_t* win32_error);

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_STACK_WINDOWS_H_
