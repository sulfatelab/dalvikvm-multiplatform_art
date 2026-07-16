/* Stubs for AES-NI symbols when AesOpt.c is excluded. */
#include <stddef.h>
#include <stdint.h>
#define MY_FAST_CALL
void MY_FAST_CALL AesCbc_Encode_Intel(uint32_t* p, unsigned char* data, size_t numBlocks) {
  (void)p;(void)data;(void)numBlocks;
}
void MY_FAST_CALL AesCbc_Decode_Intel(uint32_t* p, unsigned char* data, size_t numBlocks) {
  (void)p;(void)data;(void)numBlocks;
}
void MY_FAST_CALL AesCtr_Code_Intel(uint32_t* p, unsigned char* data, size_t numBlocks) {
  (void)p;(void)data;(void)numBlocks;
}
