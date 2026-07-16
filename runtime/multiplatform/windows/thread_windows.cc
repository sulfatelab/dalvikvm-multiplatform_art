/*
 * Win64 ART port: Thread OS hooks (replaces thread_linux.cc host path).
 */
#include "thread.h"
#include "base/logging.h"

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

}  // namespace art
