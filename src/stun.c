/* Copyright (c) 2014 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

#include "stun.h"
#include "sha1.h"
#include "hmac_sha1.h"
#include "crc32.h"
#include "md5.h"

/* Include these for sockaddr_in and sockaddr_in6 */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define UNUSED(x) ((void)(x))

static uint64_t htonll(uint64_t value) {
  int num = 42;
  if(*(char *)&num == 42) { /* test little endian */
    return (((uint64_t)htonl((uint32_t)value)) << 32)
           | htonl((uint32_t)(value >> 32));
  } else {
    return value;
  }
}

static uint64_t ntohll(uint64_t value) {
  return htonll(value);
}

static void store_padding(uint8_t *p, size_t n, uint8_t pad) {
  if ((n & 0x03) > 0) {
    memset(p, pad, 4-(n & 0x03));
  }
}

static struct {
  int err_code;
  const char *err_msg;
} err_msg_map[] = {
  { STUN_ERROR_TRY_ALTERNATE,		         "Try Alternate"}, 
  { STUN_ERROR_BAD_REQUEST,		           "Bad Request"},
  { STUN_ERROR_UNAUTHORIZED,		         "Unauthorized"},
  { STUN_ERROR_FORBIDDEN,		             "Forbidden"},
  { STUN_ERROR_UNKNOWN_ATTRIBUTE,	       "Unknown Attribute"},
  { STUN_ERROR_ALLOCATION_MISMATCH,	     "Allocation Mismatch"},
  { STUN_ERROR_STALE_NONCE,		           "Stale Nonce"},
  { STUN_ERROR_TRANSITIONING,		         "Active Destination Already Set"},
  { STUN_ERROR_WRONG_CREDENTIALS,	       "Wrong Credentials"},
  { STUN_ERROR_UNSUPP_TRANSPORT_PROTO,   "Unsupported Transport Protocol"},
  { STUN_ERROR_OPER_TCP_ONLY,		         "Operation for TCP Only"},
  { STUN_ERROR_CONNECTION_FAILURE,	     "Connection Failure"},
  { STUN_ERROR_CONNECTION_TIMEOUT,	     "Connection Timeout"},
  { STUN_ERROR_ALLOCATION_QUOTA_REACHED, "Allocation Quota Reached"},
  { STUN_ERROR_ROLE_CONFLICT,		         "Role Conflict"},
  { STUN_ERROR_SERVER_ERROR,		         "Server Error"},
  { STUN_ERROR_INSUFFICIENT_CAPACITY,	   "Insufficient Capacity"},
  { STUN_ERROR_GLOBAL_FAILURE,	         "Global Failure"},
};

const char *stun_get_err_reason(int err_code) {
  int first = 0;
  int n = sizeof(err_msg_map) / sizeof(err_msg_map[0]);

  /* Find error message using binary search */
  while (n > 0) {
    int half = n/2;
    int mid = first + half;

    if (err_msg_map[mid].err_code < err_code) {
      first = mid+1;
      n -= (half+1);
    } else if (err_msg_map[mid].err_code > err_code) {
      n = half;
    } else {
      return err_msg_map[mid].err_msg;
    }
  }

  return NULL;
}

void stun_msg_hdr_init(struct stun_msg_hdr *msg_hdr, uint16_t type,
                       const uint8_t tsx_id[12]) {
  memset(msg_hdr, 0, sizeof(struct stun_msg_hdr));
  msg_hdr->type = htons(type);
  msg_hdr->magic = htonl(STUN_MAGIC_COOKIE);
  memcpy(&msg_hdr->tsx_id, tsx_id, sizeof(msg_hdr->tsx_id));
}

size_t stun_msg_len(const struct stun_msg_hdr *msg_hdr) {
  return 20 + ntohs(msg_hdr->length);
}

uint16_t stun_msg_type(const struct stun_msg_hdr *msg_hdr) {
  return ntohs(msg_hdr->type);
}

uint8_t *stun_msg_end(struct stun_msg_hdr *msg_hdr) {
  uint8_t *begin = (uint8_t *)msg_hdr;
  return begin + stun_msg_len(msg_hdr);
}

void stun_attr_hdr_init(struct stun_attr_hdr *hdr, uint16_t type,
                        uint16_t length) {
  hdr->type = htons(type);
  hdr->length = htons(length);
}

uint8_t *stun_attr_end(struct stun_attr_hdr *attr_hdr) {
  uint8_t *begin = (uint8_t *)attr_hdr;
  return begin + stun_attr_block_len(attr_hdr);
}

int stun_attr_sockaddr_init(struct stun_attr_sockaddr *attr,
                            uint16_t type, const struct sockaddr *addr) {
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
    stun_attr_hdr_init(&attr->hdr, type, 8);
    attr->__unused = 0;
    attr->family = STUN_IPV4;
    attr->port = addr_in->sin_port;
    memcpy(&attr->addr.v4, &addr_in->sin_addr, 4);
    return STUN_OK;
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
    stun_attr_hdr_init(&attr->hdr, type, 20);
    attr->__unused = 0;
    attr->family = STUN_IPV6;
    attr->port = addr_in6->sin6_port;
    memcpy(&attr->addr.v6, &addr_in6->sin6_addr, 16);
    return STUN_OK;
  } else {
    return STUN_ERR_NOT_SUPPORTED;
  }
}

int stun_attr_xor_sockaddr_init(struct stun_attr_sockaddr *attr,
                                uint16_t type, const struct sockaddr *addr,
                                const struct stun_msg_hdr *hdr) {
  uint8_t *p;
  uint8_t *begin = (uint8_t *)attr;
  int status = stun_attr_sockaddr_init(attr, type, addr);
  if (status != STUN_OK)
    return status;
  p = begin + 4 + 2; /* advance to the port */
  *(uint16_t *)p ^= htons((uint16_t)(STUN_MAGIC_COOKIE >> 16));
  p += 2; /* advance the port */
  *(uint32_t *)p ^= htonl(STUN_MAGIC_COOKIE);
  p += 4; /* advance the address */
  if (attr->family == STUN_IPV6) {
    /* rest of IPv6 address has to be XOR'ed with the transaction id */
    *p++ ^= hdr->tsx_id[0];  *p++ ^= hdr->tsx_id[1];
    *p++ ^= hdr->tsx_id[2];  *p++ ^= hdr->tsx_id[3];
    *p++ ^= hdr->tsx_id[4];  *p++ ^= hdr->tsx_id[5];
    *p++ ^= hdr->tsx_id[6];  *p++ ^= hdr->tsx_id[7];
    *p++ ^= hdr->tsx_id[8];  *p++ ^= hdr->tsx_id[9];
    *p++ ^= hdr->tsx_id[10]; *p++ ^= hdr->tsx_id[11];
  }
  return STUN_OK;
}

void stun_attr_varsize_init(struct stun_attr_varsize *attr, uint16_t type,
                            const uint8_t *buf, size_t buf_size, uint8_t pad) {
  uint8_t *p = (uint8_t *)attr;
  stun_attr_hdr_init(&attr->hdr, type, (uint16_t)buf_size);
  memcpy(attr->value, buf, buf_size);
  store_padding(p + 4 + buf_size, buf_size, pad);
}

void stun_attr_uint32_init(struct stun_attr_uint32 *attr, uint16_t type,
                           uint32_t value) {
  stun_attr_hdr_init(&attr->hdr, type, 4);
  attr->value = htonl(value);
}

void stun_attr_uint64_init(struct stun_attr_uint64 *attr, uint16_t type,
                           uint64_t value) {
  stun_attr_hdr_init(&attr->hdr, type, 8);
  attr->value = htonll(value);
}

void stun_attr_errcode_init(struct stun_attr_errcode *attr, int err_code,
                            const char *err_reason, uint8_t pad) {
  int reason_len;
  uint8_t *p = (uint8_t *)attr;
  reason_len = strlen(err_reason);
  stun_attr_hdr_init(&attr->hdr, STUN_ERROR_CODE, (uint16_t)(4 + reason_len));
  attr->__unused = 0;
  attr->err_class = (uint8_t)(err_code / 100);
  attr->err_code = err_code % 100;
  memcpy(attr->err_reason, err_reason, reason_len);
  store_padding(p + 4 + 4 + reason_len, reason_len, pad);
}

void stun_attr_unknown_init(struct stun_attr_unknown *attr,
                            const uint16_t *unknown_codes, size_t count,
                            uint8_t pad) {
  uint8_t *p = (uint8_t *)attr;
  stun_attr_hdr_init(&attr->hdr, STUN_UNKNOWN_ATTRIBUTES,
      (uint16_t)(count << 1));
  memcpy(attr->attrs, unknown_codes, count << 1);
  store_padding(p + 4 + (count << 1), (count << 1), pad);
}

void stun_attr_msgint_init(struct stun_attr_msgint *attr,
                           const struct stun_msg_hdr *msg_hdr,
                           const uint8_t *key, size_t key_len) {
  uint8_t *p = (uint8_t *)msg_hdr;
  uint8_t *p_end = p + stun_msg_len(msg_hdr) - 24;
  hmac_sha1(p, p_end - p, key, key_len, attr->hmac);
}

void stun_attr_fingerprint_init(struct stun_attr_uint32 *attr,
                                const struct stun_msg_hdr *msg_hdr) {
  uint8_t *p = (uint8_t *)msg_hdr;
  uint8_t *p_end = p + stun_msg_len(msg_hdr) - 8;
  uint32_t value = crc32(0, p, p_end - p) ^ STUN_XOR_FINGERPRINT;
  attr->value = htonl(value);
}

void stun_msg_add_attr(struct stun_msg_hdr *msg_hdr,
                       const struct stun_attr_hdr *attr_hdr) {
  size_t attr_len = stun_attr_block_len(attr_hdr);
  msg_hdr->length = htons(ntohs(msg_hdr->length) + (uint16_t)attr_len);
}

int stun_attr_sockaddr_add(struct stun_msg_hdr *msg_hdr,
                           uint16_t type, const struct sockaddr *addr) {
  struct stun_attr_sockaddr *attr =
      (struct stun_attr_sockaddr *)stun_msg_end(msg_hdr);
  int status = stun_attr_sockaddr_init(attr, type, addr);
  if (status != STUN_OK)
    return status;
  stun_msg_add_attr(msg_hdr, &attr->hdr);
  return STUN_OK;
}

int stun_attr_xor_sockaddr_add(struct stun_msg_hdr *msg_hdr,
                               uint16_t type, const struct sockaddr *addr) {
  struct stun_attr_sockaddr *attr =
      (struct stun_attr_sockaddr *)stun_msg_end(msg_hdr);
  int status = stun_attr_xor_sockaddr_init(attr, type, addr, msg_hdr);
  if (status != STUN_OK)
    return status;
  stun_msg_add_attr(msg_hdr, &attr->hdr);
  return STUN_OK;
}

void stun_attr_varsize_add(struct stun_msg_hdr *msg_hdr, uint16_t type,
                           const uint8_t *buf, size_t buf_size, uint8_t pad) {
  struct stun_attr_varsize *attr =
      (struct stun_attr_varsize *)stun_msg_end(msg_hdr);
  stun_attr_varsize_init(attr, type, buf, buf_size, pad);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
}

void stun_attr_uint32_add(struct stun_msg_hdr *msg_hdr, uint16_t type,
                          uint32_t value) {
  struct stun_attr_uint32 *attr =
      (struct stun_attr_uint32 *)stun_msg_end(msg_hdr);
  stun_attr_uint32_init(attr, type, value);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
}

void stun_attr_uint64_add(struct stun_msg_hdr *msg_hdr, uint16_t type,
                          uint64_t value) {
  struct stun_attr_uint64 *attr =
      (struct stun_attr_uint64 *)stun_msg_end(msg_hdr);
  stun_attr_uint64_init(attr, type, value);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
}

void stun_attr_errcode_add(struct stun_msg_hdr *msg_hdr, int err_code,
                           const char *err_reason, uint8_t pad) {
  struct stun_attr_errcode *attr =
      (struct stun_attr_errcode *)stun_msg_end(msg_hdr);
  stun_attr_errcode_init(attr, err_code, err_reason, pad);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
}

void stun_attr_unknown_add(struct stun_msg_hdr *msg_hdr,
                           const uint16_t *unknown_codes, size_t count,
                           uint8_t pad) {
  struct stun_attr_unknown *attr =
      (struct stun_attr_unknown *)stun_msg_end(msg_hdr);
  stun_attr_unknown_init(attr, unknown_codes, count, pad);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
}

void stun_attr_msgint_add(struct stun_msg_hdr *msg_hdr,
                          const uint8_t *key, size_t key_len) {
  struct stun_attr_msgint *attr =
      (struct stun_attr_msgint *)stun_msg_end(msg_hdr);
  stun_attr_hdr_init(&attr->hdr, STUN_MESSAGE_INTEGRITY, 20);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
  stun_attr_msgint_init(attr, msg_hdr, key, key_len);
}

void stun_attr_fingerprint_add(struct stun_msg_hdr *msg_hdr) {
  struct stun_attr_uint32 *attr =
      (struct stun_attr_uint32 *)stun_msg_end(msg_hdr);
  stun_attr_hdr_init(&attr->hdr, STUN_FINGERPRINT, 4);
  stun_msg_add_attr(msg_hdr, &attr->hdr);
  stun_attr_fingerprint_init(attr, msg_hdr);
}

int stun_msg_verify(const struct stun_msg_hdr *msg_hdr, size_t msg_size) {
  size_t msg_len;
  const uint8_t *p = (const uint8_t*)msg_hdr;
  const uint8_t *p_end;
  const struct stun_attr_hdr *attr_hdr;

  /* First byte of STUN message is always 0x00 or 0x01. */
  if (*p != 0x00 && *p != 0x01)
	  return 0;

  /* Check the length, it cannot exceed the message size. */
  msg_len = stun_msg_len(msg_hdr);
  if (msg_len > msg_size)
    return 0;

  /* STUN message is always padded to the nearest 4 bytes, thus
   * the last two bits of the length field are always zero.
   */
  if ((msg_len & 0x03) != 0)
	  return 0;

  /* Check if the attribute lengths don't exceed the message length. */
  p_end = p + msg_len;
  p += sizeof(struct stun_msg_hdr);
  if (p == p_end)
    return 1; /* It's an empty message, nothing else to check */
  do {
    attr_hdr = (const struct stun_attr_hdr *)p;
    p += stun_attr_block_len(attr_hdr);
  } while (p < p_end);
  if (p != p_end)
    return 0;

	/* If FINGERPRINT is the last attribute, check if is valid */
  if (ntohs(attr_hdr->type) == STUN_FINGERPRINT) {
    uint32_t value;
    const struct stun_attr_uint32 *attr_uint32 =
        (const struct stun_attr_uint32 *)attr_hdr;
    p_end = (uint8_t*)attr_hdr;
    p = (uint8_t*)msg_hdr;
    value = crc32(0, p, p_end - p) ^ STUN_XOR_FINGERPRINT;
    if (ntohl(attr_uint32->value) != value)
      return 0;
  }

  return 1; /* all is well */
}

size_t stun_attr_len(const struct stun_attr_hdr *attr_hdr) {
  return ntohs(attr_hdr->length);
}

size_t stun_attr_block_len(const struct stun_attr_hdr *attr_hdr) {
  return 4 + ((stun_attr_len(attr_hdr) + 3) & (~3));
}

uint16_t stun_attr_type(const struct stun_attr_hdr *attr_hdr) {
  return ntohs(attr_hdr->type);
}

struct stun_attr_hdr *stun_msg_next_attr(struct stun_msg_hdr *msg_hdr,
                                         struct stun_attr_hdr *attr_hdr) {
  uint8_t *p;
  uint8_t *p_end = stun_msg_end(msg_hdr);
  if (!attr_hdr) {
    p = ((uint8_t*)msg_hdr) + sizeof(struct stun_msg_hdr);
  } else {
    p = ((uint8_t*)attr_hdr) + stun_attr_block_len(attr_hdr);
  }
  if (p >= p_end)
    return NULL;
  return (struct stun_attr_hdr *)p;
}

int stun_attr_sockaddr_read(const struct stun_attr_sockaddr *attr,
                            struct sockaddr *addr) {
  if (attr->family == STUN_IPV4) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    sin->sin_family = AF_INET;
    sin->sin_port = attr->port;
    memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
    memcpy(&sin->sin_addr, &attr->addr.v4, 4);
    return STUN_OK;
  } else if (attr->family == STUN_IPV6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    memset(sin6, 0, sizeof(struct sockaddr_in6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = attr->port;
    memcpy(&sin6->sin6_addr, &attr->addr.v6, 16);
    return STUN_OK;
  } else {
    return STUN_ERR_BAD_ADDR_FAMILY;
  }
}

int stun_attr_xor_sockaddr_read(const struct stun_attr_sockaddr *attr,
                                const struct stun_msg_hdr *msg_hdr,
                                struct sockaddr *addr) {
  int status = stun_attr_sockaddr_read(attr, addr);
  if (status < STUN_OK)
    return status;
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    sin->sin_port ^= htons((uint16_t)(STUN_MAGIC_COOKIE >> 16));
    *((uint32_t*)&sin->sin_addr) ^= htonl(STUN_MAGIC_COOKIE);
  } else {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    uint8_t *p = (uint8_t*)&sin6->sin6_addr;
    sin6->sin6_port ^= htons((uint16_t)(STUN_MAGIC_COOKIE >> 16));
    *((uint32_t*)p) ^= htonl(STUN_MAGIC_COOKIE);
    p += 4;
    /* rest of IPv6 address has to be XOR'ed with the transaction id */
    *p++ ^= msg_hdr->tsx_id[0];  *p++ ^= msg_hdr->tsx_id[1];
    *p++ ^= msg_hdr->tsx_id[2];  *p++ ^= msg_hdr->tsx_id[3];
    *p++ ^= msg_hdr->tsx_id[4];  *p++ ^= msg_hdr->tsx_id[5];
    *p++ ^= msg_hdr->tsx_id[6];  *p++ ^= msg_hdr->tsx_id[7];
    *p++ ^= msg_hdr->tsx_id[8];  *p++ ^= msg_hdr->tsx_id[9];
    *p++ ^= msg_hdr->tsx_id[10]; *p++ ^= msg_hdr->tsx_id[11];
  }
  return STUN_OK;
}

const uint8_t *stun_attr_varsize_read(const struct stun_attr_varsize *attr) {
  return attr->value;
}

uint32_t stun_attr_uint32_read(const struct stun_attr_uint32 *attr) {
  return ntohl(attr->value);
}

uint64_t stun_attr_uint64_read(const struct stun_attr_uint32 *attr) {
  return ntohll(attr->value);
}

int stun_attr_errcode_status(const struct stun_attr_errcode *attr) {
  return attr->err_class * 100 + attr->err_code;
}

const char *stun_attr_errcode_reason(const struct stun_attr_errcode *attr) {
  return attr->err_reason;
}

size_t stun_attr_errcode_reason_len(const struct stun_attr_errcode *attr) {
  return stun_attr_len(&attr->hdr) - sizeof(struct stun_attr_hdr);
}

uint16_t *stun_attr_unknown_next(const struct stun_attr_unknown *attr,
                                 uint16_t *unk_it) {
  uint8_t *p;
  uint8_t *p_end = stun_attr_end((struct stun_attr_hdr *)attr);
  if (!unk_it) {
    p = ((uint8_t*)attr) + sizeof(struct stun_attr_hdr);
  } else {
    p = ((uint8_t*)unk_it) + sizeof(uint16_t);
  }
  if (p >= p_end)
    return NULL;
  return (uint16_t *)p;
}

void stun_key(const char *username, const char *realm, const char *password,
              uint8_t key[16]) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, username, strlen(username));
  MD5_Update(&ctx, ":", 1);
  MD5_Update(&ctx, realm, strlen(realm));
  MD5_Update(&ctx, ":", 1);
  MD5_Update(&ctx, password, strlen(password));
  MD5_Final(key, &ctx);
}
