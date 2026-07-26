/*
 * Win64 ART port: Thread OS hooks (replaces thread_linux.cc host path).
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

bool Thread::InstallWin32StackProtection(uint8_t* read_stack_base,
                                         size_t read_stack_size,
                                         size_t protected_size,
                                         size_t minimum_bytes_above,
                                         size_t* excluded_low_size) {
  if (excluded_low_size == nullptr) {
    return false;
  }
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);
  const size_t system_page_size = static_cast<size_t>(system_info.dwPageSize);
  const uintptr_t low = reinterpret_cast<uintptr_t>(read_stack_base);
  if (read_stack_size > std::numeric_limits<uintptr_t>::max() - low) {
    return false;
  }
  const uintptr_t high = low + read_stack_size;
  const char* failure = nullptr;
  uint32_t win32_error = 0u;
  if (!InstallWin32StackPage(low,
                             high,
                             system_page_size,
                             protected_size,
                             minimum_bytes_above,
                             &win32_stack_page_,
                             &failure,
                             &win32_error)) {
    LOG(ERROR) << "Unable to install Win64 ART stack protection: "
               << (failure != nullptr ? failure : "unknown failure")
               << " error=" << win32_error;
    return false;
  }
  *excluded_low_size = win32_stack_page_.selection.excluded_low_size;
  return true;
}

bool Thread::RestoreWin32StackProtection() {
  const char* failure = nullptr;
  uint32_t win32_error = 0u;
  if (!RestoreWin32StackPage(&win32_stack_page_, &failure, &win32_error)) {
    LOG(ERROR) << "Unable to restore Win64 ART stack protection: "
               << (failure != nullptr ? failure : "unknown failure")
               << " error=" << win32_error;
    return false;
  }
  return true;
}

}  // namespace art
