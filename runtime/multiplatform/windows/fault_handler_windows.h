/*
 * Win32 ART fault-dispatch data shared by the Windows sigchain and x86
 * adapter. The view is non-owning and valid only during the exception
 * callback.
 */
#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_FAULT_HANDLER_WINDOWS_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_FAULT_HANDLER_WINDOWS_H_

#include <cstdint>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace art {

// These values are part of the documented Windows exception ABI, kept here so
// the record classifier can be tested without including the Windows SDK.
inline constexpr uint32_t kWin32ExceptionAccessViolation = 0xC0000005u;
inline constexpr uint32_t kWin32ExceptionNonContinuable = 0x00000001u;
inline constexpr uintptr_t kWin32FaultRead = 0u;
inline constexpr uintptr_t kWin32FaultWrite = 1u;
inline constexpr uintptr_t kWin32FaultExecute = 8u;

struct Win32FaultRecordView {
  uint32_t exception_code = 0u;
  uint32_t exception_flags = 0u;
  uint32_t number_parameters = 0u;
  uintptr_t exception_address = 0u;
  uintptr_t context_rip = 0u;
  uintptr_t access_type = 0u;
  uintptr_t fault_address = 0u;
};

// This validation is allocation-free and does not inspect the faulting
// address. Range, thread, and generated-code checks belong to FaultManager.
inline bool IsWin32ManagedFaultRecord(const Win32FaultRecordView& view) {
  return view.exception_code == kWin32ExceptionAccessViolation &&
      (view.exception_flags & kWin32ExceptionNonContinuable) == 0u &&
      view.number_parameters >= 2u &&
      (view.access_type == kWin32FaultRead || view.access_type == kWin32FaultWrite) &&
      view.exception_address != 0u &&
      view.context_rip == view.exception_address;
}

#if defined(_WIN32)
struct WindowsFaultContext {
  CONTEXT* context = nullptr;
  ULONG_PTR access_type = 0u;
};
#endif

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_FAULT_HANDLER_WINDOWS_H_
