#include "runtime.h"

#include <windows.h>
#include <dbghelp.h>

#include <atomic>
#include <cstdio>
#include <iostream>
#include <string>

#include "base/logging.h"
#include "cet_compat.h"

#pragma comment(lib, "dbghelp.lib")

namespace art HIDDEN {

namespace {
std::atomic<bool> g_veh_installed{false};
std::atomic<bool> g_uef_installed{false};
PVOID g_veh_handle = nullptr;
LPTOP_LEVEL_EXCEPTION_FILTER g_prev_uef = nullptr;

static bool ReadablePtr(const void* p, size_t n) {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
    return false;
  }
  if (mbi.State != MEM_COMMIT) {
    return false;
  }
  const DWORD prot = mbi.Protect & 0xff;
  if (prot == PAGE_NOACCESS || prot == PAGE_EXECUTE) {
    return false;
  }
  const uintptr_t begin = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
  const uintptr_t end = begin + mbi.RegionSize;
  const uintptr_t addr = reinterpret_cast<uintptr_t>(p);
  return addr >= begin && (addr + n) <= end;
}

static void DumpException(EXCEPTION_POINTERS* info, const char* tag) {
  if (info == nullptr || info->ExceptionRecord == nullptr) {
    return;
  }
  const DWORD code = info->ExceptionRecord->ExceptionCode;
  std::cerr << tag << ": exception 0x" << std::hex << code
            << " at " << info->ExceptionRecord->ExceptionAddress;
  if (info->ExceptionRecord->NumberParameters >= 2) {
    std::cerr << " access=" << info->ExceptionRecord->ExceptionInformation[0]
              << " fault_addr="
              << reinterpret_cast<void*>(info->ExceptionRecord->ExceptionInformation[1]);
  }
  if (info->ContextRecord != nullptr) {
    const CONTEXT* c = info->ContextRecord;
    std::cerr << "\n  rip=" << reinterpret_cast<void*>(c->Rip)
              << " rsp=" << reinterpret_cast<void*>(c->Rsp)
              << " rbp=" << reinterpret_cast<void*>(c->Rbp)
              << " rax=" << reinterpret_cast<void*>(c->Rax)
              << " rcx=" << reinterpret_cast<void*>(c->Rcx)
              << " rdx=" << reinterpret_cast<void*>(c->Rdx);
    const uint64_t* sp = reinterpret_cast<const uint64_t*>(static_cast<uintptr_t>(c->Rsp));
    std::cerr << "\n  stack[0..15]:";
    for (int i = 0; i < 16; ++i) {
      uint64_t v = 0xDEADBEEFDEADBEEFULL;
      const void* slot = static_cast<const void*>(sp + i);
      if (ReadablePtr(slot, sizeof(uint64_t))) {
        v = sp[i];
      }
      if ((i % 4) == 0) {
        std::cerr << "\n    +" << std::hex << (i * 8) << ":";
      }
      std::cerr << " " << reinterpret_cast<void*>(v);
    }
  }
  std::cerr << std::dec << std::endl;
  std::cerr.flush();
}

static void TryWriteMiniDump(EXCEPTION_POINTERS* info) {
  // Best-effort dump under run/crash if present; never throw from filter.
  char cwd[MAX_PATH];
  if (GetCurrentDirectoryA(sizeof(cwd), cwd) == 0) {
    return;
  }
  std::string dir = std::string(cwd) + "\\run\\crash";
  CreateDirectoryA((std::string(cwd) + "\\run").c_str(), nullptr);
  CreateDirectoryA(dir.c_str(), nullptr);
  char path[MAX_PATH];
  SYSTEMTIME st;
  GetLocalTime(&st);
  snprintf(path, sizeof(path),
           "%s\\art-%04u%02u%02u-%02u%02u%02u.dmp",
           dir.c_str(),
           (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
           (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
  HANDLE file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    std::cerr << "ART Win64 crash: CreateFile dump failed for " << path << std::endl;
    return;
  }
  MINIDUMP_EXCEPTION_INFORMATION mei;
  mei.ThreadId = GetCurrentThreadId();
  mei.ExceptionPointers = info;
  mei.ClientPointers = FALSE;
  const BOOL ok = MiniDumpWriteDump(GetCurrentProcess(),
                                    GetCurrentProcessId(),
                                    file,
                                    MiniDumpWithDataSegs,
                                    info ? &mei : nullptr,
                                    nullptr,
                                    nullptr);
  CloseHandle(file);
  if (ok) {
    std::cerr << "ART Win64 crash: minidump written to " << path << std::endl;
  } else {
    std::cerr << "ART Win64 crash: MiniDumpWriteDump failed err=" << GetLastError() << std::endl;
  }
  std::cerr.flush();
}

LONG CALLBACK ArtVectoredHandler(EXCEPTION_POINTERS* info) {
  if (info == nullptr || info->ExceptionRecord == nullptr) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  const DWORD code = info->ExceptionRecord->ExceptionCode;
  if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  // First-chance diagnostics for AV/stack/illegal; still continue search so
  // language/runtime handlers can run when present.
  if (code == EXCEPTION_ACCESS_VIOLATION ||
      code == EXCEPTION_STACK_OVERFLOW ||
      code == EXCEPTION_ILLEGAL_INSTRUCTION ||
      code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
    DumpException(info, "ART Win64 VEH");
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI ArtUnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
  DumpException(info, "ART Win64 UEF");
  TryWriteMiniDump(info);
  // Preserve an embedding application's fatal policy after ART's best-effort
  // diagnostics. Returning search with no predecessor lets Windows apply its
  // normal unhandled-exception policy.
  LPTOP_LEVEL_EXCEPTION_FILTER predecessor = g_prev_uef;
  if (predecessor != nullptr && predecessor != ArtUnhandledExceptionFilter) {
    return predecessor(info);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
}  // namespace

bool Runtime::CheckPlatformProcessPolicy() {
  const UserShadowStackPolicyObservation observation = QueryUserShadowStackPolicy();
  const UserShadowStackPolicyDecision decision =
      EvaluateUserShadowStackPolicy(observation);
  if (UserShadowStackPolicyAllowsArt(decision)) {
    return true;
  }

  LOG(ERROR) << "ART Win64 startup rejected: incompatible CET user-shadow-stack "
             << "process policy must be disabled before process creation; HSP "
             << "compatibility/audit/strict modes, context-IP validation, and "
             << "non-CET binary blocking are unsupported. decision="
             << UserShadowStackPolicyDecisionName(decision)
             << " build="
             << (observation.windows_build_known ? observation.windows_build : 0u)
             << " flags=0x" << std::hex << observation.flags
             << " known_incompatible=0x"
             << KnownIncompatibleUserShadowStackPolicyFlags(observation.flags)
             << " error=" << std::dec << observation.query_error;
  return false;
}

void Runtime::InitPlatformSignalHandlers() {
  if (!g_veh_installed.exchange(true)) {
    g_veh_handle = AddVectoredExceptionHandler(1, ArtVectoredHandler);
    if (g_veh_handle == nullptr) {
      LOG(WARNING) << "AddVectoredExceptionHandler failed";
    }
  }
  if (!g_uef_installed.exchange(true)) {
    g_prev_uef = SetUnhandledExceptionFilter(ArtUnhandledExceptionFilter);
  }
}

void Runtime::ShutdownPlatformSignalHandlers() {
  if (g_uef_installed.exchange(false)) {
    // There is no getter for the process UEF. Preserve a filter installed by
    // an embedding application after ART rather than blindly restoring the
    // filter that preceded ART.
    LPTOP_LEVEL_EXCEPTION_FILTER current = SetUnhandledExceptionFilter(nullptr);
    SetUnhandledExceptionFilter(current == ArtUnhandledExceptionFilter ? g_prev_uef : current);
    g_prev_uef = nullptr;
  }
  if (g_veh_installed.exchange(false)) {
    PVOID handle = g_veh_handle;
    g_veh_handle = nullptr;
    if (handle != nullptr && RemoveVectoredExceptionHandler(handle) == 0) {
      LOG(WARNING) << "RemoveVectoredExceptionHandler failed: " << GetLastError();
    }
  }
}

}  // namespace art
