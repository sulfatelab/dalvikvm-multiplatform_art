#include "cet_compat.h"

#include <windows.h>
#include <mdvm_windows_utf8.h>

#include <cstring>

namespace art {

namespace {

bool QueryWindowsBuild(uint32_t* build) {
  using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);

  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return false;
  }
  auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
      GetProcAddress(ntdll, "RtlGetVersion"));
  if (rtl_get_version == nullptr) {
    return false;
  }

  OSVERSIONINFOW version = {};
  version.dwOSVersionInfoSize = sizeof(version);
  if (rtl_get_version(&version) != 0) {
    return false;
  }
  *build = version.dwBuildNumber;
  return true;
}

template <typename Setter>
uint32_t PolicyFlags(Setter setter) {
  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy = {};
  setter(&policy);
  return policy.Flags;
}

}  // namespace

bool ParseTestUserShadowStackPolicy(const char* value, uint32_t* forced_flags) {
  if (value == nullptr || forced_flags == nullptr) {
    return false;
  }
  struct Entry {
    const char* name;
    uint32_t flags;
  };
  const Entry entries[] = {
      {"enable-user-shadow-stack",
       PolicyFlags([](auto* policy) { policy->EnableUserShadowStack = 1; })},
      {"audit-user-shadow-stack",
       PolicyFlags([](auto* policy) { policy->AuditUserShadowStack = 1; })},
      {"set-context-ip-validation",
       PolicyFlags([](auto* policy) { policy->SetContextIpValidation = 1; })},
      {"audit-set-context-ip-validation",
       PolicyFlags([](auto* policy) { policy->AuditSetContextIpValidation = 1; })},
      {"strict-user-shadow-stack",
       PolicyFlags([](auto* policy) { policy->EnableUserShadowStackStrictMode = 1; })},
      {"block-non-cet-binaries",
       PolicyFlags([](auto* policy) { policy->BlockNonCetBinaries = 1; })},
      {"block-non-cet-binaries-non-ehcont",
       PolicyFlags([](auto* policy) { policy->BlockNonCetBinariesNonEhcont = 1; })},
      {"audit-block-non-cet-binaries",
       PolicyFlags([](auto* policy) { policy->AuditBlockNonCetBinaries = 1; })},
      {"relaxed-context-ip-validation",
       PolicyFlags([](auto* policy) { policy->SetContextIpValidationRelaxedMode = 1; })},
      {"dynamic-apis-out-of-proc-only",
       PolicyFlags([](auto* policy) { policy->CetDynamicApisOutOfProcOnly = 1; })},
      {"reserved-low", PolicyFlags([](auto* policy) { policy->ReservedFlags = 1u; })},
      {"reserved-high",
       PolicyFlags([](auto* policy) { policy->ReservedFlags = 1u << 21; })},
      {"reserved-all",
       PolicyFlags([](auto* policy) { policy->ReservedFlags = (1u << 22) - 1u; })},
  };
  for (const Entry& entry : entries) {
    if (std::strcmp(value, entry.name) == 0) {
      *forced_flags = entry.flags;
      return true;
    }
  }
  return false;
}

UserShadowStackPolicyObservation QueryUserShadowStackPolicy() {
  UserShadowStackPolicyObservation observation = {};
  observation.windows_build_known = QueryWindowsBuild(&observation.windows_build);

  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy = {};
  SetLastError(ERROR_SUCCESS);
  observation.query_succeeded =
      GetProcessMitigationPolicy(GetCurrentProcess(),
                                 ProcessUserShadowStackPolicy,
                                 &policy,
                                 sizeof(policy)) != FALSE;
  observation.flags = policy.Flags;
  observation.query_error = observation.query_succeeded ? ERROR_SUCCESS : GetLastError();

  wchar_t forced_policy[64] = {};
  SetLastError(ERROR_SUCCESS);
  const DWORD forced_length = GetEnvironmentVariableW(
      L"ART_WINDOWS_X64_TEST_FORCE_CET_POLICY",
      forced_policy,
      sizeof(forced_policy) / sizeof(forced_policy[0]));
  const DWORD forced_error = forced_length == 0u ? GetLastError() : ERROR_SUCCESS;
  if (forced_length != 0u || forced_error != ERROR_ENVVAR_NOT_FOUND) {
    observation.test_policy_forced = true;
    char* forced_policy_utf8 =
        forced_length != 0u &&
            forced_length < sizeof(forced_policy) / sizeof(forced_policy[0])
            ? mdvm_utf16_to_utf8_alloc(forced_policy)
            : nullptr;
    observation.test_policy_input_valid = forced_policy_utf8 != nullptr &&
        ParseTestUserShadowStackPolicy(forced_policy_utf8, &observation.test_forced_flags);
    free(forced_policy_utf8);
    if (observation.test_policy_input_valid) {
      observation.flags |= observation.test_forced_flags;
    }
  }
  return observation;
}

uint32_t KnownIncompatibleUserShadowStackPolicyFlags(uint32_t flags) {
  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY observed = {};
  observed.Flags = flags;

  // Inspect only fields defined by the SDK. CetDynamicApisOutOfProcOnly does
  // not enable HSP or context-IP validation, and ReservedFlags has no defined
  // policy meaning, so neither belongs in ART's incompatibility decision.
  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY incompatible = {};
  incompatible.EnableUserShadowStack = observed.EnableUserShadowStack;
  incompatible.AuditUserShadowStack = observed.AuditUserShadowStack;
  incompatible.SetContextIpValidation = observed.SetContextIpValidation;
  incompatible.AuditSetContextIpValidation = observed.AuditSetContextIpValidation;
  incompatible.EnableUserShadowStackStrictMode = observed.EnableUserShadowStackStrictMode;
  incompatible.BlockNonCetBinaries = observed.BlockNonCetBinaries;
  incompatible.BlockNonCetBinariesNonEhcont = observed.BlockNonCetBinariesNonEhcont;
  incompatible.AuditBlockNonCetBinaries = observed.AuditBlockNonCetBinaries;
  incompatible.SetContextIpValidationRelaxedMode = observed.SetContextIpValidationRelaxedMode;
  return incompatible.Flags;
}

UserShadowStackPolicyDecision EvaluateUserShadowStackPolicy(
    const UserShadowStackPolicyObservation& observation) {
  if (observation.test_policy_forced && !observation.test_policy_input_valid) {
    return UserShadowStackPolicyDecision::kUnexpectedQueryFailure;
  }
  if (!observation.windows_build_known) {
    return UserShadowStackPolicyDecision::kWindowsVersionUnavailable;
  }
  if (observation.query_succeeded) {
    return KnownIncompatibleUserShadowStackPolicyFlags(observation.flags) == 0u
               ? UserShadowStackPolicyDecision::kDisabled
               : UserShadowStackPolicyDecision::kIncompatible;
  }
  if (observation.windows_build < kUserShadowStackPolicyFirstBuild &&
      observation.query_error == ERROR_INVALID_PARAMETER) {
    return UserShadowStackPolicyDecision::kUnavailableOnOlderWindows;
  }
  return UserShadowStackPolicyDecision::kUnexpectedQueryFailure;
}

bool UserShadowStackPolicyAllowsArt(UserShadowStackPolicyDecision decision) {
  return decision == UserShadowStackPolicyDecision::kDisabled ||
         decision == UserShadowStackPolicyDecision::kUnavailableOnOlderWindows;
}

const char* UserShadowStackPolicyDecisionName(UserShadowStackPolicyDecision decision) {
  switch (decision) {
    case UserShadowStackPolicyDecision::kDisabled:
      return "disabled";
    case UserShadowStackPolicyDecision::kUnavailableOnOlderWindows:
      return "unavailable-on-older-windows";
    case UserShadowStackPolicyDecision::kIncompatible:
      return "incompatible";
    case UserShadowStackPolicyDecision::kUnexpectedQueryFailure:
      return "unexpected-query-failure";
    case UserShadowStackPolicyDecision::kWindowsVersionUnavailable:
      return "windows-version-unavailable";
  }
  return "unknown";
}

}  // namespace art
