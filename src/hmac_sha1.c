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

#ifdef HMAC_SHA1_TEST
#include <stdio.h>
#include <stdlib.h>

int test(int n,
         const uint8_t *key, size_t key_len,
         const uint8_t *data, size_t data_len,
         const uint8_t *digest) {
  uint8_t out[20];
  hmac_sha1(key, key_len, data, data_len, out);
  if (memcmp(digest, out, 20) != 0) {
    size_t i;
    printf("hash %d mismatch. expected:\n", n);
    for (i = 0; i < 20; i++)
      printf("%02x ", digest[i] & 0xFF);
    printf("\ncomputed:\n");
    for (i = 0; i < 20; i++)
      printf("%02x ", out[i] & 0xFF);
    printf("\n");
    return 1;
  }
  return 0;
}

int main()
{
  struct {
    const char *key;
    size_t key_len;
    const char *data;
    size_t data_len;
    const char *digest;
  } tests[] = {
    { "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16,
      "Hi There", 8,
      "\x67\x5b\x0b\x3a\x1b\x4d\xdf\x4e\x12\x48"
      "\x72\xda\x6c\x2f\x63\x2b\xfe\xd9\x57\xe9" },
    { "Jefe", 4,
      "what do ya want for nothing?", 28,
      "\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74"
      "\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79" },
    { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 16,
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD", 50,
      "\xd7\x30\x59\x4d\x16\x7e\x35\xd5\x95\x6f"
      "\xd8\x00\x3d\x0d\xb3\xd3\xf4\x6d\xc7\xbb" },
  };
  int i;

  for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
    if(test(i+1, (uint8_t*)tests[i].data, tests[i].data_len,
            (uint8_t*)tests[i].key, tests[i].key_len,
            (uint8_t*)tests[i].digest)) {
      return 1;
    }
  }

  printf("ok\n");
  return 0;
}

#endif