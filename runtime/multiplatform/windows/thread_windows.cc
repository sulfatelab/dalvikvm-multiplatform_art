/*
 * Win32 ART port: Thread OS hooks (replaces thread_linux.cc host path).
 */
#include "thread.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <limits>

#include "arch/instruction_set.h"
#include "base/logging.h"
#include "thread-current-inl.h"

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
#if defined(ART_WIN32_STACK_HIGH_WATER)
  Win32StackOverflowHighWater& record = tlsPtr_.win32_stack_overflow_high_water;
  record.stack_low = low;
  record.guarantee_top = low + layout.memory_excluded_low_size + layout.stack_guarantee_size;
  record.native_boundary = layout.usable_begin;
  record.default_stack_end =
      layout.usable_begin + GetStackOverflowReservedBytes(kRuntimeQuickCodeISA);
  record.stack_guarantee_size = layout.stack_guarantee_size;
  record.art_reserved_size = GetStackOverflowReservedBytes(kRuntimeQuickCodeISA);
#endif
  *excluded_low_size = layout.excluded_low_size;
  return true;
}

#if defined(ART_WIN32_STACK_HIGH_WATER)
bool Thread::DumpWin32StackOverflowHighWater(const char* label) {
  Win32StackOverflowHighWater& record = tlsPtr_.win32_stack_overflow_high_water;
  constexpr size_t kPointCount =
      static_cast<size_t>(Win32StackOverflowHighWaterPoint::kCount);
  const bool quick =
      record.rsp[static_cast<size_t>(Win32StackOverflowHighWaterPoint::kQuickEntrypoint)] != 0u;
  const Win32StackOverflowHighWaterPoint common_required[] = {
      Win32StackOverflowHighWaterPoint::kExplicitCheck,
      Win32StackOverflowHighWaterPoint::kThrowEntrypoint,
      Win32StackOverflowHighWaterPoint::kExpandedStackEnd,
      Win32StackOverflowHighWaterPoint::kExceptionConstruction,
      Win32StackOverflowHighWaterPoint::kExceptionConstructed,
      Win32StackOverflowHighWaterPoint::kDefaultStackEndRestored,
  };
  bool complete = record.sequence != 0u && record.native_boundary != 0u;
  for (Win32StackOverflowHighWaterPoint point : common_required) {
    complete = complete && record.rsp[static_cast<size_t>(point)] != 0u;
  }
  if (quick) {
    complete = complete &&
        record.rsp[static_cast<size_t>(Win32StackOverflowHighWaterPoint::kQuickFrame)] != 0u &&
        record.rsp[static_cast<size_t>(Win32StackOverflowHighWaterPoint::kQuickDelivery)] != 0u &&
        record.rsp[static_cast<size_t>(Win32StackOverflowHighWaterPoint::kLongJump)] != 0u;
  }

  uintptr_t lowest = std::numeric_limits<uintptr_t>::max();
  for (size_t index = 0u; index != kPointCount; ++index) {
    if (record.rsp[index] != 0u) {
      lowest = std::min(lowest, record.rsp[index]);
    }
  }
  if (lowest == std::numeric_limits<uintptr_t>::max()) {
    lowest = 0u;
  }
  complete = complete && lowest != 0u &&
      lowest >= record.native_boundary && lowest >= record.guarantee_top;

  auto signed_delta = [](uintptr_t first, uintptr_t second) -> int64_t {
    return first >= second ? static_cast<int64_t>(first - second)
                           : -static_cast<int64_t>(second - first);
  };
  const int64_t margin_to_guarantee = signed_delta(lowest, record.guarantee_top);
  const int64_t margin_to_native = signed_delta(lowest, record.native_boundary);
  // A check may fire before RSP enters ART's reserved interval, especially in
  // an unoptimized build with a large caller frame. Keep the raw boundary
  // margin above, but saturate the reserve accounting at the interval edge.
  const uintptr_t reserve_sample = std::min(lowest, record.default_stack_end);
  const int64_t art_reserve_remaining = signed_delta(reserve_sample, record.native_boundary);
  const int64_t art_reserve_used = signed_delta(record.default_stack_end, reserve_sample);
  std::fprintf(
      stdout,
      "stack_overflow_high_water label=%s sequence=%llu path=%s complete=%u "
      "stack_low=0x%llx guarantee=%llu guarantee_top=0x%llx native_boundary=0x%llx "
      "default_stack_end=0x%llx art_reserve=%llu lowest_rsp=0x%llx "
      "margin_to_guarantee=%lld margin_to_native=%lld "
      "art_reserve_used=%lld art_reserve_remaining=%lld "
      "explicit_check=0x%llx quick_entry=0x%llx quick_frame=0x%llx "
      "throw_entry=0x%llx expanded=0x%llx construct=0x%llx constructed=0x%llx "
      "restored=0x%llx delivery=0x%llx long_jump=0x%llx\n",
      label != nullptr ? label : "(null)",
      static_cast<unsigned long long>(record.sequence),
      quick ? "quick" : "switch",
      complete ? 1u : 0u,
      static_cast<unsigned long long>(record.stack_low),
      static_cast<unsigned long long>(record.stack_guarantee_size),
      static_cast<unsigned long long>(record.guarantee_top),
      static_cast<unsigned long long>(record.native_boundary),
      static_cast<unsigned long long>(record.default_stack_end),
      static_cast<unsigned long long>(record.art_reserved_size),
      static_cast<unsigned long long>(lowest),
      static_cast<long long>(margin_to_guarantee),
      static_cast<long long>(margin_to_native),
      static_cast<long long>(art_reserve_used),
      static_cast<long long>(art_reserve_remaining),
      static_cast<unsigned long long>(record.rsp[0]),
      static_cast<unsigned long long>(record.rsp[1]),
      static_cast<unsigned long long>(record.rsp[2]),
      static_cast<unsigned long long>(record.rsp[3]),
      static_cast<unsigned long long>(record.rsp[4]),
      static_cast<unsigned long long>(record.rsp[5]),
      static_cast<unsigned long long>(record.rsp[6]),
      static_cast<unsigned long long>(record.rsp[7]),
      static_cast<unsigned long long>(record.rsp[8]),
      static_cast<unsigned long long>(record.rsp[9]));
  std::fflush(stdout);
  for (size_t index = 0u; index != kPointCount; ++index) {
    record.rsp[index] = 0u;
  }
  record.active = 0u;
  return complete;
}

extern "C" __declspec(dllexport) int artWin32DumpStackOverflowHighWater(const char* label) {
  Thread* self = Thread::Current();
  return self != nullptr && self->DumpWin32StackOverflowHighWater(label) ? 1 : 0;
}
#endif

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
