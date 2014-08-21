/* 
 * Functions to implement RFC-2104 (HMAC with SHA-1 hashes).
 * Placed into the public domain.
 */

#ifndef __HMAC_SHA1_H__
#define __HMAC_SHA1_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void hmac_sha1(const uint8_t *text, int text_len,
               const uint8_t *key, int key_len,
               uint8_t digest[20]);

#ifdef __cplusplus
};
#endif

#endif /* __HMAC_SHA1_H__ */
