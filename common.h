#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

// Чтение 32-битного значения в формате little-endian
FORCE_INLINE uint32_t ReadLE32(const unsigned char *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Запись 32-битного значения в формате little-endian
FORCE_INLINE void WriteLE32(unsigned char *p, uint32_t v) {
  p[0] = (unsigned char)(v & 0xff);
  p[1] = (unsigned char)((v >> 8) & 0xff);
  p[2] = (unsigned char)((v >> 16) & 0xff);
  p[3] = (unsigned char)((v >> 24) & 0xff);
}

// Запись 64-битного значения в формате little-endian
FORCE_INLINE void WriteLE64(unsigned char *p, uint64_t v) {
  p[0] = (unsigned char)(v & 0xff);
  p[1] = (unsigned char)((v >> 8) & 0xff);
  p[2] = (unsigned char)((v >> 16) & 0xff);
  p[3] = (unsigned char)((v >> 24) & 0xff);
  p[4] = (unsigned char)((v >> 32) & 0xff);
  p[5] = (unsigned char)((v >> 40) & 0xff);
  p[6] = (unsigned char)((v >> 48) & 0xff);
  p[7] = (unsigned char)((v >> 56) & 0xff);
}

#ifndef ASSERT
#define ASSERT(x) do { } while(0)
#endif

#endif // CRYPTO_COMMON_H
