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
};

enum class UserShadowStackPolicyDecision : uint8_t {
  kDisabled,
  kUnavailableOnOlderWindows,
  kEnabledOrAudited,
  kUnexpectedQueryFailure,
  kWindowsVersionUnavailable,
};

UserShadowStackPolicyObservation QueryUserShadowStackPolicy();

UserShadowStackPolicyDecision EvaluateUserShadowStackPolicy(
    const UserShadowStackPolicyObservation& observation);

bool UserShadowStackPolicyAllowsArt(UserShadowStackPolicyDecision decision);

const char* UserShadowStackPolicyDecisionName(UserShadowStackPolicyDecision decision);

}  // namespace art

#endif  // ART_RUNTIME_MULTIPLATFORM_WINDOWS_CET_COMPAT_H_
