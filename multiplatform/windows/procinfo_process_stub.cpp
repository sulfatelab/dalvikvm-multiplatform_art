#include <procinfo/process.h>
#include <string>
#include <cstdarg>
namespace android {
namespace procinfo {
bool SetError(std::string* error, int errno_value, const char* fmt, ...) {
  if (!error) return false;
  (void)errno_value;
  va_list ap;
  va_start(ap, fmt);
  char buf[512];
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  *error = buf;
  return false;
}
#if defined(__linux__)
// real impl elsewhere
#endif
}  // namespace procinfo
}  // namespace android
