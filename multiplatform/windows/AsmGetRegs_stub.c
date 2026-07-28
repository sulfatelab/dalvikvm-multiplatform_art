/* Windows x64: replace Linux GAS AsmGetRegsX86_64.S with a C stub. */
#include <stdint.h>
#include <string.h>
void AsmGetRegs(void* reg_data) {
  /* Phase 1: zero register capture (unwinder will be limited). */
  if (reg_data) memset(reg_data, 0, 136);
}
