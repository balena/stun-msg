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

/* Include these for sockaddr_in and sockaddr_in6 */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif


#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define UNUSED(x) ((void)(x))

static uint8_t padding_byte = 0;

static uint8_t *store_uint16(uint8_t *p, uint16_t value) {
  *(uint16_t*)p = htons(value);
  return p + 2;
}

static uint8_t *store_uint32(uint8_t *p, uint32_t value) {
  *(uint32_t*)p = htonl(value);
  return p + 4;
}

static uint8_t *store_uint64(uint8_t *p, uint64_t value) {
  *(uint32_t*)p = htonl((uint32_t)(value >> 32));
  p += 4;
  *(uint32_t*)p = htonl((uint32_t)(value & 0xfffffffful));
  return p + 4;
}

static uint8_t *read_uint16(uint8_t *p, uint16_t *value) {
  *value = ntohs(*(uint16_t *)p);
  return p + 2;
}

static uint8_t *read_uint32(uint8_t *p, uint32_t *value) {
  *value = ntohl(*(uint32_t *)p);
  return p + 4;
}

static uint8_t *read_uint64(uint8_t *p, uint64_t *value) {
  *value = ((uint64_t)ntohl(*(uint32_t *)p)) << 32;
  p += 4;
  *value |= ((uint64_t)ntohl(*(uint32_t *)p)) & 0xfffffffful;
  return p;
}

static uint8_t *store_padding(uint8_t *p, size_t n) {
  if ((n & 0x03) > 0) {
    uint8_t pad[3];
    memset(pad, padding_byte, 3);
    memcpy(p, pad, 4-(n & 0x03));
    p += 4 - (n & 0x03);
  }
  return p;
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

static uint8_t *attr_empty_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                  const struct stun_msg *msg);
static uint8_t *attr_sockaddr_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                     const struct stun_msg *msg);
static uint8_t *attr_sockaddr_xor_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                         const struct stun_msg *msg);
static uint8_t *attr_string_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg);
static uint8_t *attr_binary_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg);
static uint8_t *attr_uint32_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg);
static uint8_t *attr_uint64_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg);
static uint8_t *attr_errcode_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                    const struct stun_msg *msg);
static uint8_t *attr_unknown_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                    const struct stun_msg *msg);
static uint8_t *attr_msgint_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg);

struct attr_desc {
  const char *name;
  uint8_t *(*encode)(const struct stun_attr_hdr *, uint8_t *, const struct stun_msg *);
  int (*decode)(const struct stun_attr_hdr *, uint8_t **, uint8_t *, const struct stun_msg *);
};

static struct attr_desc mandatory_attr_desc[] = {
  /* 0x0000 is not assigned */
  { NULL, NULL },

  /* 0x0001 STUN_MAPPED_ADDRESS */
  { "MAPPED-ADDRESS", &attr_sockaddr_encode, },

  /* 0x0002 STUN_RESPONSE_ADDRESS */
  { "RESPONSE-ADDRESS", &attr_sockaddr_encode, },

  /* 0x0003 STUN_CHANGE_REQUEST */
  { "CHANGE-REQUEST", &attr_uint32_encode, },

  /* 0x0004 STUN_SOURCE_ADDRESS */
  { "SOURCE-ADDRESS", &attr_sockaddr_encode, },

  /* 0x0005 STUN_CHANGED_ADDRESS */
  { "CHANGED-ADDRESS", &attr_sockaddr_encode, },

  /* 0x0006 STUN_USERNAME */
  { "USERNAME", &attr_string_encode, },

  /* 0x0007 STUN_PASSWORD */
  { "PASSWORD", &attr_string_encode, },

  /* 0x0008 STUN_MESSAGE_INTEGRITY */
  { "MESSAGE-INTEGRITY", &attr_msgint_encode, },

  /* 0x0009 STUN_ERROR_CODE */
  { "ERROR-CODE", &attr_errcode_encode, },

  /* 0x000A STUN_UNKNOWN_ATTRIBUTES */
  { "UNKNOWN-ATTRIBUTES", &attr_unknown_encode, },

  /* 0x000B STUN_REFLECTED_FROM */
  { "REFLECTED-FROM", &attr_sockaddr_encode, },

  /* 0x000C STUN_CHANNEL_NUMBER */
  { "CHANNEL-NUMBER", &attr_uint32_encode, },

  /* 0x000D STUN_LIFETIME */
  { "LIFETIME", &attr_uint32_encode, },

  /* 0x000E is reserved */
  { NULL, NULL },

  /* 0x000F is reserved */
  { NULL, NULL },

  /* 0x0010 STUN_BANDWIDTH */
  { "BANDWIDTH", &attr_uint32_encode, },

  /* 0x0011 is not assigned */
  { NULL, NULL },

  /* 0x0012 STUN_XOR_PEER_ADDRESS */
  { "XOR-PEER-ADDRESS", &attr_sockaddr_xor_encode, },

  /* 0x0013 STUN_DATA */
  { "DATA", &attr_binary_encode, },

  /* 0x0014 STUN_REALM */
  { "REALM", &attr_string_encode, },

  /* 0x0015 STUN_NONCE */
  { "NONCE", &attr_string_encode, },

  /* 0x0016 STUN_XOR_RELAYED_ADDRESS */
  { "XOR-RELAYED-ADDRESS", &attr_sockaddr_xor_encode, },

  /* 0x0017 STUN_REQ_ADDRESS_FAMILY */
  { "REQ-ADDRESS-FAMILY", &attr_uint32_encode, },

  /* 0x0018 STUN_EVEN_PORT */
  { "EVEN-PORT", &attr_uint32_encode, },

  /* 0x0019 STUN_REQUESTED_TRANSPORT */
  { "REQUESTED-TRANSPORT", &attr_uint32_encode, },

  /* 0x001A STUN_DONT_FRAGMENT */
  { "DONT-FRAGMENT", &attr_empty_encode, },

  /* 0x001B is not assigned */
  { NULL, NULL },

  /* 0x001C is not assigned */
  { NULL, NULL },

  /* 0x001D is not assigned */
  { NULL, NULL },

  /* 0x001E is not assigned */
  { NULL, NULL },

  /* 0x001F is not assigned */
  { NULL, NULL },

  /* 0x0020 STUN_XOR_MAPPED_ADDRESS */
  { "XOR-MAPPED-ADDRESS", &attr_sockaddr_xor_encode, },

  /* 0x0021 STUN_TIMER_VAL */
  { "TIMER-VAL", &attr_uint32_encode, },

  /* 0x0022 STUN_RESERVATION_TOKEN */
  { "RESERVATION-TOKEN", &attr_uint64_encode, },

  /* 0x0023 STUN_XOR_REFLECTED_FROM */
  { "XOR-REFLECTED-FROM", &attr_sockaddr_xor_encode, },

  /* 0x0024 STUN_PRIORITY */
  { "PRIORITY", &attr_uint32_encode, },

  /* 0x0025 STUN_USE_CANDIDATE */
  { "USE-CANDIDATE", &attr_empty_encode, },

  /* 0x0026 STUN_PADDING */
  { "PADDING", &attr_binary_encode, },

  /* 0x0027 STUN_RESPONSE_PORT */
  { "RESPONSE-PORT", &attr_uint32_encode, },

  /* 0x0028 is reserved */
  { NULL, NULL },

  /* 0x0029 is reserved */
  { NULL, NULL },

  /* 0x002A STUN_CONNECTION_ID */
  { "CONNECTION-ID", &attr_string_encode, },
};

#define STUN_EXTENDED_ATTR_START 0x8021

static struct attr_desc extended_attr_desc[] = {

  /* 0x8021 is not assigned */
  { NULL, NULL },

  /* 0x8022 STUN_SOFTWARE */
  { "SOFTWARE", &attr_string_encode, },

  /* 0x8023 STUN_ALTERNATE_SERVER */
  { "ALTERNATE-SERVER", &attr_sockaddr_encode, },

  /* 0x8024 is reserved */
  { NULL, NULL },

  /* 0x8025 is not assigned */
  { NULL, NULL },

  /* 0x8026 is reserved */
  { NULL, NULL },

  /* 0x8027 is not assigned */
  { NULL, NULL },

  /* 0x8028 STUN_FINGERPRINT */
  { "FINGERPRINT", &attr_uint32_encode, },

  /* 0x8029 STUN_ICE_CONTROLLED */
  { "ICE-CONTROLLED", &attr_uint64_encode, },

  /* 0x802A STUN_ICE_CONTROLLING */
  { "ICE-CONTROLLING", &attr_uint64_encode, },

  /* 0x802B STUN_RESPONSE_ORIGIN */
  { "RESPONSE-ORIGIN", &attr_sockaddr_encode, },

  /* 0x802C STUN_OTHER_ADDRESS */
  { "OTHER-ADDRESS", &attr_sockaddr_encode, },
};

static uint8_t *attr_empty_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                  const struct stun_msg *msg) {
  UNUSED(msg);
  p = store_uint16(p, hdr->type);
  p = store_uint16(p, hdr->length);
  return p;
}

static uint8_t *attr_sockaddr_encode(const struct stun_attr_hdr *hdr,
                                     uint8_t *p, const struct stun_msg *msg) {
  size_t n;
  struct stun_attr_sockaddr *attr_sockaddr = (struct stun_attr_sockaddr *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  *p++ = 0; /* padding */
  *p++ = attr_sockaddr->family;
  p = store_uint16(p, attr_sockaddr->port);
  n = attr_sockaddr->family == STUN_IPV4 ? 4 : 16;
  memcpy(p, &attr_sockaddr->addr, n);
  return p + n;
}

static uint8_t *attr_sockaddr_xor_encode(const struct stun_attr_hdr *hdr,
                                         uint8_t *p,
                                         const struct stun_msg *msg) {
  uint8_t *begin = p;
  struct stun_attr_sockaddr *attr_sockaddr = (struct stun_attr_sockaddr *)hdr;
  p = attr_sockaddr_encode(hdr, p, msg);
  p = begin + 4 + 2; /* advance to the port */
  *(uint16_t *)p ^= htons((uint16_t)(STUN_MAGIC_COOKIE >> 16));
  p += 2; /* advance the port */
  *(uint32_t *)p ^= htonl(STUN_MAGIC_COOKIE);
  p += 4; /* advance the address */
  if (attr_sockaddr->family == STUN_IPV6) {
    /* rest of IPv6 address has to be XOR'ed with the transaction id */
    *p++ ^= msg->tsx_id[0];  *p++ ^= msg->tsx_id[1];
    *p++ ^= msg->tsx_id[2];  *p++ ^= msg->tsx_id[3];
    *p++ ^= msg->tsx_id[4];  *p++ ^= msg->tsx_id[5];
    *p++ ^= msg->tsx_id[6];  *p++ ^= msg->tsx_id[7];
    *p++ ^= msg->tsx_id[8];  *p++ ^= msg->tsx_id[9];
    *p++ ^= msg->tsx_id[10]; *p++ ^= msg->tsx_id[11];
  }
  return p;
}

static uint8_t *attr_string_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg) {
  struct stun_attr_string *attr_string = (struct stun_attr_string *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  memcpy(p, attr_string->value, hdr->length);
  p = store_padding(p + hdr->length, hdr->length);
  return p;
}

static uint8_t *attr_binary_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg) {
  struct stun_attr_binary *attr_binary = (struct stun_attr_binary *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  memcpy(p, attr_binary->value, hdr->length);
  p = store_padding(p + hdr->length, hdr->length);
  return p;
}

static uint8_t *attr_uint32_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg) {
  struct stun_attr_uint32 *attr_uint32 = (struct stun_attr_uint32 *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  p = store_uint32(p, attr_uint32->value);
  return p;
}

static uint8_t *attr_uint64_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg) {
  struct stun_attr_uint64 *attr_uint64 = (struct stun_attr_uint64 *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  p = store_uint64(p, attr_uint64->value);
  return p;
}

static uint8_t *attr_errcode_encode(const struct stun_attr_hdr *hdr,
                                    uint8_t *p, const struct stun_msg *msg) {
  int n;
  struct stun_attr_errcode *attr_errcode = (struct stun_attr_errcode *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  *(uint16_t *)p = 0; p += 2; /* padding */
  *p++ = attr_errcode->err_class;
  *p++ = attr_errcode->err_code;
  n = hdr->length - 4;
  memcpy(p, attr_errcode->err_reason, n);
  p = store_padding(p + n, n);
  return p;
}

static uint8_t *attr_unknown_encode(const struct stun_attr_hdr *hdr,
                                    uint8_t *p, const struct stun_msg *msg) {
  uint16_t i, n;
  struct stun_attr_unknown *attr_unknown = (struct stun_attr_unknown *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  n = hdr->length >> 1;
  for (i = 0; i < n; i++) {
    *(uint16_t *)p = htons(attr_unknown->attrs[i]);
    p += 2;
  }
  p = store_padding(p, hdr->length);
  return p;
}

static uint8_t *attr_msgint_encode(const struct stun_attr_hdr *hdr, uint8_t *p,
                                   const struct stun_msg *msg) {
  struct stun_attr_msgint *attr_msgint = (struct stun_attr_msgint *)hdr;
  p = attr_empty_encode(hdr, p, msg);
  memcpy(p, attr_msgint->hmac, 20);
  p += 20;
  return p;
}

static void stun_attr_init(struct stun_attr_hdr *hdr, uint16_t type,
                           uint16_t length) {
  hdr->type = type;
  hdr->length = length;
}

static const struct attr_desc *find_attr_desc(uint16_t type)
{
  struct attr_desc *desc;
  if (type < ARRAY_SIZE(mandatory_attr_desc)) {
    desc = &mandatory_attr_desc[type];
  } else if (type >= STUN_EXTENDED_ATTR_START
             && type < STUN_EXTENDED_ATTR_START +
                       ARRAY_SIZE(extended_attr_desc)) {
    desc = &extended_attr_desc[type-0x8021];
  } else {
    return NULL;
  }
  return desc->name == NULL ? NULL : desc;
}

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

void stun_msg_init(struct stun_msg *msg, uint16_t type,
                   const uint8_t tsx_id[12]) {
  memset(msg, 0, sizeof(struct stun_msg));
  msg->type = type;
  msg->magic = STUN_MAGIC_COOKIE;
  memcpy(&msg->tsx_id, tsx_id, sizeof(msg->tsx_id));
}

void stun_attr_empty_init(struct stun_attr_empty *attr, uint16_t type) {
  stun_attr_init(&attr->hdr, type, 0);
}

int stun_attr_sockaddr_init(struct stun_attr_sockaddr *attr, uint16_t type,
                            const struct sockaddr *addr) {
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
    stun_attr_init(&attr->hdr, type, 8);
    attr->padding = 0;
    attr->family = STUN_IPV4;
    attr->port = ntohs(addr_in->sin_port);
    memcpy(&attr->addr.v4, &addr_in->sin_addr, 4);
    return STUN_OK;
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
    stun_attr_init(&attr->hdr, type, 20);
    attr->padding = 0;
    attr->family = STUN_IPV6;
    attr->port = ntohs(addr_in6->sin6_port);
    memcpy(&attr->addr.v6, &addr_in6->sin6_addr, 16);
    return STUN_OK;
  } else {
    return STUN_ERR_NOT_SUPPORTED;
  }
}

int stun_attr_string_init(struct stun_attr_string *attr, uint16_t type,
                          const char *str, size_t size) {
  if (size > STUN_MAX_STR_SIZE)
    return STUN_ERR_NO_MEMORY;
  stun_attr_init(&attr->hdr, type, (uint16_t)size);
  memcpy(attr->value, str, size);
  return STUN_OK;
}

int stun_attr_binary_init(struct stun_attr_binary *attr, uint16_t type,
                          const uint8_t *buf, size_t size) {
  if (size > STUN_MAX_BIN_SIZE)
    return STUN_ERR_NO_MEMORY;
  stun_attr_init(&attr->hdr, type, (uint16_t)size);
  memcpy(attr->value, buf, size);
  return STUN_OK;
}

void stun_attr_uint32_init(struct stun_attr_uint32 *attr, uint16_t type,
                           uint32_t value) {
  stun_attr_init(&attr->hdr, type, sizeof(uint32_t));
  attr->value = value;
}

void stun_attr_uint64_init(struct stun_attr_uint64 *attr, uint16_t type,
                           uint64_t value) {
  stun_attr_init(&attr->hdr, type, sizeof(uint64_t));
  attr->value = value;
}

int stun_attr_errcode_init(struct stun_attr_errcode *attr, int err_code,
                           const char *err_reason) {
  int reason_len;
  if (err_code < 300 || err_code > 699)
    return STUN_ERR_INVALID_ARG;
  reason_len = strlen(err_reason);
  if (reason_len > STUN_MAX_STR_SIZE)
    return STUN_ERR_NO_MEMORY;
  stun_attr_init(&attr->hdr, STUN_ERROR_CODE, (uint16_t)(reason_len + 4));
  attr->padding = 0;
  attr->err_class = (uint8_t)(err_code / 100);
  attr->err_code = err_code % 100;
  memcpy(attr->err_reason, err_reason, reason_len);
  return STUN_OK;
}

int stun_attr_unknown_init(struct stun_attr_unknown *attr,
                           const uint16_t *unknown_codes, size_t count) {
  if (count > STUN_MAX_ATTRS)
    return STUN_ERR_NO_MEMORY;
  stun_attr_init(&attr->hdr, STUN_UNKNOWN_ATTRIBUTES, (uint16_t)(count << 1));
  memcpy(attr->attrs, unknown_codes, count << 1);
  return STUN_OK;
}

void stun_attr_msgint_init(struct stun_attr_msgint *attr) {
  stun_attr_init(&attr->hdr, STUN_MESSAGE_INTEGRITY, 20);
  memset(attr->hmac, 0, 20);
}

int stun_msg_add_attr(struct stun_msg *msg, struct stun_attr_hdr *attr) {
  if (msg->attr_count == STUN_MAX_ATTRS)
    return STUN_ERR_NO_MEMORY;
  msg->attrs[msg->attr_count++] = attr;
  msg->length += 4 + ((attr->length + 3) & (~3));
  return STUN_OK;
}

void stun_set_padding_byte(uint8_t byte) {
  padding_byte = byte;
}

int stun_msg_encode(const struct stun_msg *msg,
                    void *buffer, size_t bufferlen,
                    const uint8_t *key, int key_len) {
  size_t i;
  uint8_t *p, *p_len;
  struct stun_attr_msgint *msgint;
  struct stun_attr_uint32 *fingerprint;

  if (buffer == NULL)
    return msg->length + 20;
  if ((size_t)(msg->length + 20) > bufferlen)
    return STUN_ERR_NO_MEMORY;

  p = (uint8_t *)buffer;

  /* Copy the STUN message header */
  p_len = p = store_uint16(p, msg->type);
  p = store_uint16(p, 0); /* add a dummy value for now */
  p = store_uint32(p, msg->magic);
  memcpy(p, msg->tsx_id, sizeof(msg->tsx_id));
  p += sizeof(msg->tsx_id);

  msgint = NULL;
  fingerprint = NULL;
  for (i = 0; i < msg->attr_count; ++i) {
    const struct attr_desc *desc;
    struct stun_attr_hdr *hdr = msg->attrs[i];

    if (hdr->type == STUN_MESSAGE_INTEGRITY) {
      msgint = (struct stun_attr_msgint *)hdr;
      continue;
    } else if (hdr->type == STUN_FINGERPRINT) {
      fingerprint = (struct stun_attr_uint32 *)hdr;
      continue;
    }

    desc = find_attr_desc(hdr->type);
    if (!desc)
      return STUN_ERR_UNKNOWN_ATTRIBUTE;

    p = (*desc->encode)(hdr, p, msg);
  }

  /* MESSAGE-INTEGRITY must be always the last attribute */
  if (msgint) {
    if (!key)
      return STUN_ERR_KEY_NOTAVAIL;
    /* The length doesn't include the FINGERPRINT size, when available */
    store_uint16(p_len, (uint16_t)((p - (uint8_t *)buffer) - 20 + 24));
    hmac_sha1((uint8_t *)buffer, p - (uint8_t *)buffer,
              key, key_len, msgint->hmac);
    p = attr_msgint_encode(&msgint->hdr, p, msg);
  }

  /* Store the length now */
  store_uint16(p_len, msg->length);

  /* Oh, no, FINGERPRINT must be the last one, after MESSAGE-INTEGRITY */
  if (fingerprint) {
    fingerprint->value = crc32(0, (uint8_t *)buffer, p - (uint8_t *)buffer);
    fingerprint->value ^= STUN_XOR_FINGERPRINT;
    p = attr_uint32_encode(&fingerprint->hdr, p, msg);
  }

  return p - (uint8_t *)buffer;
}

int stun_msg_decode(struct stun_msg *msg, void *packet, size_t packetlen,
                    void *buffer, size_t bufferlen,
                    const uint8_t *key, int key_len,
                    struct stun_attr_unknown *unknown_attr) {
  int status;
  uint8_t *p_msgint, *p_fingerprint;
  uint8_t *p = (uint8_t *)packet;
  uint8_t *p_end = p + packetlen;
  uint8_t *buf = (uint8_t *)buffer;
  uint8_t *buf_end = buf + bufferlen;
  struct stun_attr_msgint *msgint = NULL;
  struct stun_attr_uint32 *fingerprint = NULL;

  /* The message must be of least the header size */
  if (packetlen < 20)
    return STUN_ERR_TOO_SMALL;

  /* First byte of STUN message is always 0x00 or 0x01. */
  if (*p != 0x00 && *p != 0x01)
    return STUN_ERR_BAD_TYPE;

  p = read_uint16(p, &msg->type);
  p = read_uint16(p, &msg->length);

  /* Check the length */
  if ((size_t)(msg->length + 20) > packetlen)
    return STUN_ERR_TOO_SMALL;

  p = read_uint32(p, &msg->magic);
  memcpy(msg->tsx_id, p, sizeof(msg->tsx_id));
  p += sizeof(msg->tsx_id);

  stun_attr_empty_init((struct stun_attr_empty *)unknown_attr,
      STUN_UNKNOWN_ATTRIBUTES);

  msg->attr_count = 0;
  while (p != p_end) {
    const struct attr_desc *desc;
    struct stun_attr_hdr *hdr = (struct stun_attr_hdr *)buf;
    p = read_uint16(p, &hdr->type);
    p = read_uint16(p, &hdr->length);

    if (fingerprint || (msgint && hdr->type != STUN_FINGERPRINT)) {
      return STUN_ERR_TRAIL_ATTRIBUTES;
    }

    desc = find_attr_desc(hdr->type);
    if (!desc) {
      /* Store unknown attributes for creating an error response */
      unknown_attr->attrs[unknown_attr->hdr.length >> 1] = hdr->type;
      unknown_attr->hdr.length += 2;
      if ((unknown_attr->hdr.length >> 1) == STUN_MAX_ATTRS)
        return STUN_ERR_UNKNOWN_ATTRIBUTE;
    } else {
      /* Decode the attributes using the provided buffer */
      status = (*desc->decode)(hdr, &buf, buf_end, msg);
      if (status < STUN_OK)
        return status;

      if (hdr->type == STUN_MESSAGE_INTEGRITY) {
        msgint = (struct stun_attr_msgint*)hdr;
        p_msgint = p - 4;
      } else if (hdr->type == STUN_FINGERPRINT) {
        fingerprint = (struct stun_attr_uint32*)hdr;
        p_fingerprint = p - 4;
      }
    }

    /* Set the parsed attribute and point to next attribute */
    msg->attrs[msg->attr_count++] = hdr;
    p += (hdr->length + 3) & (~3);
  }

  if (unknown_attr->hdr.length > 0)
    return STUN_ERR_UNKNOWN_ATTRIBUTE;

  /* Check the MESSAGE-INTEGRITY if present */
  if (msgint && key) {
    uint8_t hmac[20];
    hmac_sha1((uint8_t *)packet, p_msgint - (uint8_t *)packet, key,
              key_len, hmac);
    if (memcmp(hmac, msgint->hmac, 20) != 0)
      return STUN_ERR_BAD_MSGINT;
  }

  /* Check the FINGERPRINT if present */
  if (fingerprint) {
    uint32_t value = crc32(0, (uint8_t *)packet,
        p_fingerprint - (uint8_t *)buffer);
    value ^= STUN_XOR_FINGERPRINT;
    if (value != fingerprint->value)
      return STUN_ERR_BAD_FINGERPRINT;
  }

  return STUN_OK;
}