/*
 * Win32 ART port: Thread OS hooks (replaces thread_linux.cc host path).
 */
#include "thread.h"

#include <windows.h>

#include <limits>

#include "base/logging.h"

namespace art HIDDEN {

void Thread::SetUpAlternateSignalStack() {
  // No sigaltstack on Windows; VEH uses the faulting thread stack.
  VLOG(threads) << "SetUpAlternateSignalStack: no-op on Windows";
}

void Thread::TearDownAlternateSignalStack() {
  // no-op
}

void Thread::MadviseAwayAlternateSignalStack() {
  // no-op
}

bool Thread::InspectWin32StackLayout(uint8_t* read_stack_base,
                                     size_t read_stack_size,
                                     size_t minimum_usable_size,
                                     size_t* excluded_low_size) {
  if (excluded_low_size == nullptr) {
    return false;
  }
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);
  const size_t system_page_size = static_cast<size_t>(system_info.dwPageSize);
  if (system_page_size > std::numeric_limits<ULONG>::max() / kWin32MinimumStackGuaranteePages) {
    LOG(ERROR) << "Invalid Windows x64 system page size for the stack guarantee";
    return false;
  }
  const ULONG minimum_stack_guarantee =
      static_cast<ULONG>(system_page_size * kWin32MinimumStackGuaranteePages);
  ULONG previous_stack_guarantee = 0u;
  if (!SetThreadStackGuarantee(&previous_stack_guarantee)) {
    LOG(ERROR) << "Unable to query the Windows x64 thread stack guarantee: error=" << GetLastError();
    return false;
  }
  if (previous_stack_guarantee < minimum_stack_guarantee) {
    ULONG requested_stack_guarantee = minimum_stack_guarantee;
    if (!SetThreadStackGuarantee(&requested_stack_guarantee)) {
      LOG(ERROR) << "Unable to set the Windows x64 thread stack guarantee to " << minimum_stack_guarantee
                 << " bytes: error=" << GetLastError();
      return false;
    }
  }
  ULONG stack_guarantee_size = 0u;
  if (!SetThreadStackGuarantee(&stack_guarantee_size)) {
    LOG(ERROR) << "Unable to verify the Windows x64 thread stack guarantee: error=" << GetLastError();
    return false;
  }
  if (stack_guarantee_size < minimum_stack_guarantee) {
    LOG(ERROR) << "Windows x64 thread stack guarantee is below the requested minimum: actual="
               << stack_guarantee_size << " minimum=" << minimum_stack_guarantee;
    return false;
  }
  const uintptr_t low = reinterpret_cast<uintptr_t>(read_stack_base);
  if (read_stack_size > std::numeric_limits<uintptr_t>::max() - low) {
    return false;
  }
  const uintptr_t high = low + read_stack_size;
  const char* failure = nullptr;
  Win32StackLayout layout;
  if (!art::InspectWin32StackLayout(low,
                                    high,
                                    system_page_size,
                                    static_cast<size_t>(stack_guarantee_size),
                                    minimum_usable_size,
                                    QueryWin32Memory,
                                    nullptr,
                                    &layout,
                                    &failure)) {
    LOG(ERROR) << "Unable to inspect Windows x64 stack layout: "
               << (failure != nullptr ? failure : "unknown failure");
    return false;
  }
  VLOG(threads) << "Windows x64 stack layout memory_prefix=" << layout.memory_excluded_low_size
                << " stack_guarantee=" << layout.stack_guarantee_size
                << " excluded_low=" << layout.excluded_low_size;
  *excluded_low_size = layout.excluded_low_size;
  return true;
}

bool Thread::RestoreWin32StackProtection() {
  const char* failure = nullptr;
  uint32_t win32_error = 0u;
  if (!RestoreWin32StackPage(&win32_stack_page_, &failure, &win32_error)) {
    LOG(ERROR) << "Unable to restore Win32 ART stack protection: "
               << (failure != nullptr ? failure : "unknown failure")
               << " error=" << win32_error;
    return false;
  }
  return true;
}

}  // namespace art
