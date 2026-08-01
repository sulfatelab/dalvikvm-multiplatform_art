#include "runtime.h"

#include <windows.h>
#include <dbghelp.h>

#include <atomic>
#include <cstdarg>
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
std::atomic<bool> g_fatal_unwind_trace_enabled{false};
PVOID g_veh_handle = nullptr;
LPTOP_LEVEL_EXCEPTION_FILTER g_prev_uef = nullptr;
thread_local bool g_fatal_unwind_trace_active = false;

constexpr size_t kFatalUnwindTraceFrameLimit = 32u;

static bool EnvironmentFlagEnabled(const wchar_t* name) {
  wchar_t value[2] = {};
  const DWORD length = GetEnvironmentVariableW(name, value, 2u);
  return length == 1u && value[0] == L'1';
}

static void WriteFatalUnwindTraceLine(const char* format, ...) {
  char buffer[2048];
  va_list args;
  va_start(args, format);
  const int formatted = vsnprintf(buffer, sizeof(buffer) - 2u, format, args);
  va_end(args);
  if (formatted < 0) {
    return;
  }
  size_t length = static_cast<size_t>(formatted);
  if (length > sizeof(buffer) - 2u) {
    length = sizeof(buffer) - 2u;
  }
  buffer[length++] = '\r';
  buffer[length++] = '\n';

  HANDLE stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
  if (stderr_handle == nullptr || stderr_handle == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0u;
  WriteFile(stderr_handle, buffer, static_cast<DWORD>(length), &written, nullptr);
}

static bool ReadablePtr(const void* p, size_t n) {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
    return false;
  }
  if (mbi.State != MEM_COMMIT) {
    return false;
  }
  if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u) {
    return false;
  }
  const DWORD prot = mbi.Protect & 0xff;
  if (prot == PAGE_NOACCESS || prot == PAGE_EXECUTE) {
    return false;
  }
  const uintptr_t begin = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
  const uintptr_t end = begin + mbi.RegionSize;
  const uintptr_t addr = reinterpret_cast<uintptr_t>(p);
  return addr >= begin && addr <= end && n <= end - addr;
}

static const char* ModulePathForAddress(DWORD64 address,
                                        DWORD64* module_base,
                                        char* path,
                                        DWORD path_size) {
  *module_base = 0u;
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) == 0 ||
      mbi.AllocationBase == nullptr) {
    return "-";
  }
  *module_base = reinterpret_cast<DWORD64>(mbi.AllocationBase);
  const DWORD length =
      GetModuleFileNameA(reinterpret_cast<HMODULE>(mbi.AllocationBase), path, path_size);
  if (length == 0u || length >= path_size) {
    return "-";
  }
  path[length] = '\0';
  return path;
}

static void DumpFatalUnwindTrace(EXCEPTION_POINTERS* info) {
  if (!g_fatal_unwind_trace_enabled.load(std::memory_order_relaxed) ||
      g_fatal_unwind_trace_active ||
      info == nullptr ||
      info->ExceptionRecord == nullptr ||
      info->ContextRecord == nullptr) {
    return;
  }

  g_fatal_unwind_trace_active = true;
  CONTEXT context = *info->ContextRecord;
  ULONG_PTR stack_low = 0u;
  ULONG_PTR stack_high = 0u;
  GetCurrentThreadStackLimits(&stack_low, &stack_high);
  WriteFatalUnwindTraceLine(
      "ART_WINDOWS_X64_UNWIND_TRACE begin code=0x%08lx thread=%lu low=0x%llx high=0x%llx",
      static_cast<unsigned long>(info->ExceptionRecord->ExceptionCode),
      static_cast<unsigned long>(GetCurrentThreadId()),
      static_cast<unsigned long long>(stack_low),
      static_cast<unsigned long long>(stack_high));

  const char* stop_reason = "frame_limit";
  size_t completed_frames = 0u;
  for (size_t frame = 0u; frame < kFatalUnwindTraceFrameLimit; ++frame) {
    const DWORD64 pc = context.Rip;
    const DWORD64 rsp = context.Rsp;
    if (pc == 0u) {
      stop_reason = "zero_pc";
      break;
    }
    if ((rsp & (sizeof(uint64_t) - 1u)) != 0u) {
      stop_reason = "unaligned_rsp";
      break;
    }
    if (rsp < stack_low || rsp >= stack_high) {
      stop_reason = "rsp_out_of_stack";
      break;
    }

    DWORD64 image_base = 0u;
    PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(pc, &image_base, nullptr);
    char module_path[MAX_PATH + 1u] = {};
    DWORD64 module_base = 0u;
    const char* module = ModulePathForAddress(pc, &module_base, module_path, MAX_PATH);
    const DWORD64 module_rva = module_base == 0u ? 0u : pc - module_base;
    if (function == nullptr) {
      WriteFatalUnwindTraceLine(
          "ART_WINDOWS_X64_UNWIND_TRACE frame=%llu pc=0x%llx rsp=0x%llx lookup=0 "
          "module_base=0x%llx rva=0x%llx module=%s",
          static_cast<unsigned long long>(frame),
          static_cast<unsigned long long>(pc),
          static_cast<unsigned long long>(rsp),
          static_cast<unsigned long long>(module_base),
          static_cast<unsigned long long>(module_rva),
          module);
      const uint64_t* return_slot = reinterpret_cast<const uint64_t*>(rsp);
      if (!ReadablePtr(return_slot, sizeof(*return_slot))) {
        stop_reason = "leaf_return_unreadable";
        break;
      }
      context.Rip = *return_slot;
      context.Rsp = rsp + sizeof(*return_slot);
      WriteFatalUnwindTraceLine(
          "ART_WINDOWS_X64_UNWIND_TRACE step=%llu kind=leaf next_pc=0x%llx next_rsp=0x%llx",
          static_cast<unsigned long long>(frame),
          static_cast<unsigned long long>(context.Rip),
          static_cast<unsigned long long>(context.Rsp));
    } else {
      WriteFatalUnwindTraceLine(
          "ART_WINDOWS_X64_UNWIND_TRACE frame=%llu pc=0x%llx rsp=0x%llx lookup=1 "
          "image=0x%llx begin=0x%08lx end=0x%08lx unwind=0x%08lx "
          "module_base=0x%llx rva=0x%llx module=%s",
          static_cast<unsigned long long>(frame),
          static_cast<unsigned long long>(pc),
          static_cast<unsigned long long>(rsp),
          static_cast<unsigned long long>(image_base),
          static_cast<unsigned long>(function->BeginAddress),
          static_cast<unsigned long>(function->EndAddress),
          static_cast<unsigned long>(function->UnwindData),
          static_cast<unsigned long long>(module_base),
          static_cast<unsigned long long>(module_rva),
          module);
      PVOID handler_data = nullptr;
      DWORD64 establisher_frame = 0u;
      RtlVirtualUnwind(UNW_FLAG_NHANDLER,
                       image_base,
                       pc,
                       function,
                       &context,
                       &handler_data,
                       &establisher_frame,
                       nullptr);
      WriteFatalUnwindTraceLine(
          "ART_WINDOWS_X64_UNWIND_TRACE step=%llu kind=virtual next_pc=0x%llx "
          "next_rsp=0x%llx establisher=0x%llx",
          static_cast<unsigned long long>(frame),
          static_cast<unsigned long long>(context.Rip),
          static_cast<unsigned long long>(context.Rsp),
          static_cast<unsigned long long>(establisher_frame));
    }

    ++completed_frames;
    if (context.Rip == pc && context.Rsp == rsp) {
      stop_reason = "no_progress";
      break;
    }
    if (context.Rsp <= rsp) {
      stop_reason = "non_increasing_rsp";
      break;
    }
  }
  WriteFatalUnwindTraceLine(
      "ART_WINDOWS_X64_UNWIND_TRACE end frames=%llu reason=%s final_pc=0x%llx final_rsp=0x%llx",
      static_cast<unsigned long long>(completed_frames),
      stop_reason,
      static_cast<unsigned long long>(context.Rip),
      static_cast<unsigned long long>(context.Rsp));
  g_fatal_unwind_trace_active = false;
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
    std::cerr << "ART Win32 crash: CreateFile dump failed for " << path << std::endl;
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
    std::cerr << "ART Win32 crash: minidump written to " << path << std::endl;
  } else {
    std::cerr << "ART Win32 crash: MiniDumpWriteDump failed err=" << GetLastError() << std::endl;
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
    DumpException(info, "ART Win32 VEH");
    if (code == EXCEPTION_ACCESS_VIOLATION) {
      DumpFatalUnwindTrace(info);
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI ArtUnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
  DumpException(info, "ART Win32 UEF");
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

  LOG(ERROR) << "ART Win32 startup rejected: incompatible CET user-shadow-stack "
             << "process policy must be disabled before process creation; HSP "
             << "compatibility/audit/strict modes, context-IP validation, and "
             << "non-CET binary blocking are unsupported. decision="
             << UserShadowStackPolicyDecisionName(decision)
             << " build="
             << (observation.windows_build_known ? observation.windows_build : 0u)
             << " flags=0x" << std::hex << observation.flags
             << " known_incompatible=0x"
             << KnownIncompatibleUserShadowStackPolicyFlags(observation.flags)
             << " error=" << std::dec << observation.query_error
             << " test_policy_forced=" << observation.test_policy_forced
             << " test_policy_input_valid=" << observation.test_policy_input_valid
             << " test_forced_flags=0x" << std::hex << observation.test_forced_flags;
  return false;
}

void Runtime::InitPlatformSignalHandlers() {
  g_fatal_unwind_trace_enabled.store(
      EnvironmentFlagEnabled(L"ART_WINDOWS_X64_FATAL_UNWIND_TRACE"),
      std::memory_order_relaxed);
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
  g_fatal_unwind_trace_enabled.store(false, std::memory_order_relaxed);
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
