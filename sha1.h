/* 
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SHA1_CTX {
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len);
void SHA1Final(uint8_t digest[20], SHA1_CTX *context);

#ifdef __cplusplus
};
#endif

#endif /* __SHA1_H__ */