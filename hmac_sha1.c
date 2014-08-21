/* 
 * Functions to implement RFC-2104 (HMAC with SHA-1 hashes).
 * Placed into the public domain.
 */

#include "hmac_sha1.h"
#include "sha1.h"
#include <memory.h>

/* 
 * Encode a string using HMAC - see RFC-2104 for details.
 */
void hmac_sha1(const uint8_t *text, int text_len,
               const uint8_t *key, int key_len,
               uint8_t digest[20])
{
  SHA1_CTX context;
  uint8_t k_ipad[65]; /* inner padding - key XORd with ipad */
  uint8_t k_opad[65]; /* outer padding - key XORd with opad */
  uint8_t tk[20];
  int i;

  /* if key is longer than 64 bytes reset it to key=SHA1(key) */
  if (key_len > 64) {
    SHA1_CTX tctx;

    SHA1Init(&tctx);
    SHA1Update(&tctx, key, key_len);
    SHA1Final(tk, &tctx);

    key = tk;
    key_len = 20;
  }

  /*
   * the HMAC_SHA1 transform looks like:
   *
   * SHA1(K XOR opad, SHA1(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected
   */

  /* start out by storing key in pads */
  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  /* XOR key with ipad and opad values */
  for (i = 0; i < 64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  /* perform inner SHA1 */
  SHA1Init(&context);                   /* init context for 1st pass */
  SHA1Update(&context, k_ipad, 64);     /* start with inner pad */
  SHA1Update(&context, text, text_len); /* then text of datagram */
  SHA1Final(digest, &context);          /* finish up 1st pass */

  /* perform outer MD5 */
  SHA1Init(&context);                   /* init context for 2nd pass */
  SHA1Update(&context, k_opad, 64);     /* start with outer pad */
  SHA1Update(&context, digest, 20);     /* then results of 1st hash */
  SHA1Final(digest, &context);          /* finish up 2nd pass */
}
