#include "sigchain.h"

namespace art {

extern "C" void AddSpecialSignalHandlerFn(int, SigchainAction*) {}
extern "C" void RemoveSpecialSignalHandlerFn(int, bool (*)(int, siginfo_t*, void*)) {}
extern "C" void EnsureFrontOfChain(int) {}
extern "C" void SkipAddSignalHandler(bool) {}

}  // namespace art
