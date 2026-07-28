#include "sigchain.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>

#include "runtime/multiplatform/windows/fault_handler_windows.h"

namespace art {

namespace {

std::mutex g_registration_mutex;
SigchainAction g_action_storage = {};
std::atomic<SigchainAction*> g_published_action{nullptr};
PVOID g_veh_handle = nullptr;

[[noreturn]] void FailUnsupported(const char* operation, int signal) {
  std::fprintf(stderr,
               "Windows x64 sigchain: %s does not support signal %d\n",
               operation,
               signal);
  std::abort();
}

LONG CALLBACK ManagedFaultVeh(EXCEPTION_POINTERS* info) {
  if (info == nullptr || info->ExceptionRecord == nullptr || info->ContextRecord == nullptr) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  EXCEPTION_RECORD* record = info->ExceptionRecord;
  CONTEXT* context = info->ContextRecord;
  Win32FaultRecordView view = {};
  view.exception_code = record->ExceptionCode;
  view.exception_flags = record->ExceptionFlags;
  view.number_parameters = record->NumberParameters;
  view.exception_address = reinterpret_cast<uintptr_t>(record->ExceptionAddress);
  view.context_rip = static_cast<uintptr_t>(context->Rip);
  if (record->NumberParameters >= 2u) {
    view.access_type = static_cast<uintptr_t>(record->ExceptionInformation[0]);
    view.fault_address = static_cast<uintptr_t>(record->ExceptionInformation[1]);
  }
  if (!IsWin32ManagedFaultRecord(view)) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  SigchainAction* action = g_published_action.load(std::memory_order_acquire);
  if (action == nullptr || action->sc_sigaction == nullptr) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  siginfo_t siginfo = {};
  siginfo.si_signo = SIGSEGV;
  siginfo.si_code = SEGV_ACCERR;
  siginfo.si_addr = reinterpret_cast<void*>(view.fault_address);
  WindowsFaultContext fault_context = {context, view.access_type};
  return action->sc_sigaction(SIGSEGV, &siginfo, &fault_context)
      ? EXCEPTION_CONTINUE_EXECUTION
      : EXCEPTION_CONTINUE_SEARCH;
}

void InstallFirstVehLocked() {
  if (g_veh_handle != nullptr) {
    return;
  }
  PVOID handle = AddVectoredExceptionHandler(1u, ManagedFaultVeh);
  if (handle == nullptr) {
    std::fprintf(stderr,
                 "Windows x64 sigchain: AddVectoredExceptionHandler failed error=%lu\n",
                 GetLastError());
    std::abort();
  }
  g_veh_handle = handle;
}

}  // namespace

extern "C" void AddSpecialSignalHandlerFn(int signal, SigchainAction* sa) {
  if (signal != SIGSEGV || sa == nullptr || sa->sc_sigaction == nullptr) {
    FailUnsupported("AddSpecialSignalHandlerFn", signal);
  }

  std::lock_guard<std::mutex> lock(g_registration_mutex);
  if (g_published_action.load(std::memory_order_relaxed) != nullptr) {
    std::fprintf(stderr, "Windows x64 sigchain: duplicate SIGSEGV special action\n");
    std::abort();
  }
  g_action_storage = *sa;
  InstallFirstVehLocked();
  g_published_action.store(&g_action_storage, std::memory_order_release);
}

extern "C" void RemoveSpecialSignalHandlerFn(int signal,
                                               bool (*fn)(int, siginfo_t*, void*)) {
  if (signal != SIGSEGV || fn == nullptr) {
    FailUnsupported("RemoveSpecialSignalHandlerFn", signal);
  }

  std::lock_guard<std::mutex> lock(g_registration_mutex);
  SigchainAction* action = g_published_action.load(std::memory_order_relaxed);
  if (action == nullptr || action->sc_sigaction != fn) {
    std::fprintf(stderr, "Windows x64 sigchain: removing an unpublished SIGSEGV action\n");
    std::abort();
  }
  g_published_action.store(nullptr, std::memory_order_release);
  PVOID handle = g_veh_handle;
  g_veh_handle = nullptr;
  if (handle != nullptr && RemoveVectoredExceptionHandler(handle) == 0u) {
    std::fprintf(stderr,
                 "Windows x64 sigchain: RemoveVectoredExceptionHandler failed error=%lu\n",
                 GetLastError());
    std::abort();
  }
}

extern "C" void EnsureFrontOfChain(int signal) {
  if (signal != SIGSEGV) {
    FailUnsupported("EnsureFrontOfChain", signal);
  }

  std::lock_guard<std::mutex> lock(g_registration_mutex);
  if (g_published_action.load(std::memory_order_relaxed) == nullptr) {
    return;
  }
  PVOID new_handle = AddVectoredExceptionHandler(1u, ManagedFaultVeh);
  if (new_handle == nullptr) {
    std::fprintf(stderr,
                 "Windows x64 sigchain: promotion AddVectoredExceptionHandler failed error=%lu\n",
                 GetLastError());
    return;
  }
  PVOID old_handle = g_veh_handle;
  g_veh_handle = new_handle;
  if (old_handle != nullptr && RemoveVectoredExceptionHandler(old_handle) == 0u) {
    std::fprintf(stderr,
                 "Windows x64 sigchain: promotion removal failed error=%lu\n",
                 GetLastError());
    std::abort();
  }
}

extern "C" void SkipAddSignalHandler(bool) {
  // Windows has no signal interposition layer to skip. The managed action is
  // still explicitly registered by FaultManager when -Xno-sig-chain is off.
}

}  // namespace art
