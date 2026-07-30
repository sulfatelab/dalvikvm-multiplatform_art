#ifndef ART_RUNTIME_MULTIPLATFORM_WINDOWS_CET_COMPAT_H_
#define ART_RUNTIME_MULTIPLATFORM_WINDOWS_CET_COMPAT_H_

#include <cstdint>

namespace art {

inline constexpr uint32_t kUserShadowStackPolicyFirstBuild = 19041u;

struct UserShadowStackPolicyObservation {
  bool windows_build_known;
  uint32_t windows_build;
  bool query_succeeded;
  uint32_t flags;
  uint32_t query_error;
  // Probe-only input may add policy bits to the OS observation. It can never
  // clear an active process policy or turn a failed query into a success.
  bool test_policy_forced = false;
  bool test_policy_input_valid = true;
  uint32_t test_forced_flags = 0u;
};

enum class UserShadowStackPolicyDecision : uint8_t {
  kDisabled,
  kUnavailableOnOlderWindows,
  kIncompatible,
  kUnexpectedQueryFailure,
  kWindowsVersionUnavailable,
};

UserShadowStackPolicyObservation QueryUserShadowStackPolicy();

bool ParseTestUserShadowStackPolicy(const char* value, uint32_t* forced_flags);

uint32_t KnownIncompatibleUserShadowStackPolicyFlags(uint32_t flags);

UserShadowStackPolicyDecision EvaluateUserShadowStackPolicy(
    const UserShadowStackPolicyObservation& observation);

bool UserShadowStackPolicyAllowsArt(UserShadowStackPolicyDecision decision);

const char* UserShadowStackPolicyDecisionName(UserShadowStackPolicyDecision decision);

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_CET_COMPAT_H_
