#include "cet_compat.h"

#include <windows.h>

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

}  // namespace

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
