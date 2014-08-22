/* Copyright (c) 2014 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

#ifndef __STUN_H__
#define __STUN_H__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward the sockaddr declaration */
struct sockaddr;

/* Used to demultiplex STUN and RTP */
#define STUN_CHECK(pkt) \
  ((((uint8_t *) pkt)[0] & 0xC0) == 0x00)

/* STUN magic cookie */
#define STUN_MAGIC_COOKIE 0x2112A442ul

/* STUN XOR fingerprint */
#define STUN_XOR_FINGERPRINT 0x5354554euL

/* Retrieve the STUN method from the message-type field of the STUN message */
#define STUN_GET_METHOD(msg_type) ((msg_type) & 0xFEEF)

/* Determine if the message type is a request */
#define STUN_IS_REQUEST(msg_type) (((msg_type) & 0x0110) == 0x0000)

/* Determine if the message type is a successful response */
#define STUN_IS_SUCCESS_RESPONSE(msg_type) (((msg_type) & 0x0110) == 0x0100)

/* Determine if the message type is an error response */
#define STUN_IS_ERROR_RESPONSE(msg_type) (((msg_type) & 0x0110) == 0x0110)

/* Determine if the message type is a response */
#define STUN_IS_RESPONSE(msg_type) (((msg_type) & 0x0100) == 0x0100)

/* Determine if the message type is an indication message */
#define STUN_IS_INDICATION(msg_type) (((msg_type) & 0x0110) == 0x0010)

enum stun_msg_type {
  STUN_BINDING_REQUEST                   = 0x0001,
  STUN_BINDING_RESPONSE                  = 0x0101,
  STUN_BINDING_ERROR_RESPONSE            = 0x0111,
  STUN_BINDING_INDICATION                = 0x0011,
  STUN_SHARED_SECRET_REQUEST             = 0x0002,
  STUN_SHARED_SECRET_RESPONSE            = 0x0102,
  STUN_SHARED_SECRET_ERROR_RESPONSE      = 0x0112,
  STUN_ALLOCATE_REQUEST                  = 0x0003,
  STUN_ALLOCATE_RESPONSE                 = 0x0103,
  STUN_ALLOCATE_ERROR_RESPONSE           = 0x0113,
  STUN_REFRESH_REQUEST                   = 0x0004,
  STUN_REFRESH_RESPONSE                  = 0x0104,
  STUN_REFRESH_ERROR_RESPONSE            = 0x0114,
  STUN_SEND_INDICATION                   = 0x0016,
  STUN_DATA_INDICATION                   = 0x0017,
  STUN_CREATE_PERM_REQUEST               = 0x0008,
  STUN_CREATE_PERM_RESPONSE              = 0x0108,
  STUN_CREATE_PERM_ERROR_RESPONSE        = 0x0118,
  STUN_CHANNEL_BIND_REQUEST              = 0x0009,
  STUN_CHANNEL_BIND_RESPONSE             = 0x0109,
  STUN_CHANNEL_BIND_ERROR_RESPONSE       = 0x0119,
  STUN_CONNECT_REQUEST                   = 0x000A,
  STUN_CONNECT_RESPONSE                  = 0x010A,
  STUN_CONNECT_ERROR_RESPONSE            = 0x011A,
  STUN_CONNECTION_BIND_REQUEST           = 0x000B,
  STUN_CONNECTION_BIND_RESPONSE          = 0x010B,
  STUN_CONNECTION_BIND_ERROR_RESPONSE    = 0x011B,
  STUN_CONNECTION_ATTEMPT_REQUEST        = 0x000C,
  STUN_CONNECTION_ATTEMPT_RESPONSE       = 0x010C,
  STUN_CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C,
};

enum stun_attr_type {
  STUN_MAPPED_ADDRESS      = 0x0001,
  STUN_RESPONSE_ADDRESS    = 0x0002,
  STUN_CHANGE_REQUEST      = 0x0003,
  STUN_SOURCE_ADDRESS      = 0x0004,
  STUN_CHANGED_ADDRESS     = 0x0005,
  STUN_USERNAME            = 0x0006,
  STUN_PASSWORD            = 0x0007,
  STUN_MESSAGE_INTEGRITY   = 0x0008,
  STUN_ERROR_CODE          = 0x0009,
  STUN_UNKNOWN_ATTRIBUTES  = 0x000A,
  STUN_REFLECTED_FROM      = 0x000B,
  STUN_CHANNEL_NUMBER      = 0x000C,
  STUN_LIFETIME            = 0x000D,
  STUN_BANDWIDTH           = 0x0010,
  STUN_XOR_PEER_ADDRESS    = 0x0012,
  STUN_DATA                = 0x0013,
  STUN_REALM               = 0x0014,
  STUN_NONCE               = 0x0015,
  STUN_XOR_RELAYED_ADDRESS = 0x0016,
  STUN_REQ_ADDRESS_FAMILY  = 0x0017,
  STUN_EVEN_PORT           = 0x0018,
  STUN_REQUESTED_TRANSPORT = 0x0019,
  STUN_DONT_FRAGMENT       = 0x001A,
  STUN_XOR_MAPPED_ADDRESS  = 0x0020,
  STUN_TIMER_VAL           = 0x0021,
  STUN_RESERVATION_TOKEN   = 0x0022,
  STUN_XOR_REFLECTED_FROM  = 0x0023,
  STUN_PRIORITY            = 0x0024,
  STUN_USE_CANDIDATE       = 0x0025,
  STUN_PADDING             = 0x0026,
  STUN_RESPONSE_PORT       = 0x0027,
  STUN_CONNECTION_ID       = 0x002A,
  STUN_SOFTWARE            = 0x8022,
  STUN_ALTERNATE_SERVER    = 0x8023,
  STUN_FINGERPRINT         = 0x8028,
  STUN_ICE_CONTROLLED      = 0x8029,
  STUN_ICE_CONTROLLING     = 0x802A,
  STUN_RESPONSE_ORIGIN     = 0x802B,
  STUN_OTHER_ADDRESS       = 0x802C,
};

enum stun_error_code_type {
  STUN_ERROR_TRY_ALTERNATE            = 300,
  STUN_ERROR_BAD_REQUEST              = 400,
  STUN_ERROR_UNAUTHORIZED             = 401,
  STUN_ERROR_FORBIDDEN                = 403,
  STUN_ERROR_UNKNOWN_ATTRIBUTE        = 420,
  STUN_ERROR_ALLOCATION_MISMATCH      = 437,
  STUN_ERROR_STALE_NONCE              = 438,
  STUN_ERROR_TRANSITIONING            = 439,
  STUN_ERROR_WRONG_CREDENTIALS        = 441,
  STUN_ERROR_UNSUPP_TRANSPORT_PROTO   = 442,
  STUN_ERROR_OPER_TCP_ONLY            = 445,
  STUN_ERROR_CONNECTION_FAILURE       = 446,
  STUN_ERROR_CONNECTION_TIMEOUT       = 447,
  STUN_ERROR_ALLOCATION_QUOTA_REACHED = 486,
  STUN_ERROR_ROLE_CONFLICT            = 487,
  STUN_ERROR_SERVER_ERROR             = 500,
  STUN_ERROR_INSUFFICIENT_CAPACITY    = 508,
  STUN_ERROR_GLOBAL_FAILURE           = 600,
};

/* STUN address families */
enum stun_addr_family {
  STUN_IPV4 = 0x01,
  STUN_IPV6 = 0x02
};

#pragma pack(1)

struct stun_msg_hdr {
  uint16_t type;                               /* message type */
  uint16_t length;                             /* message length */
  uint32_t magic;                              /* magic cookie */
  uint8_t tsx_id[12];                          /* transaction id */
};

struct stun_attr_hdr {
  uint16_t type;                               /* attribute type */
  uint16_t length;                             /* length, no padding */
};

struct stun_attr_sockaddr {
  struct stun_attr_hdr hdr;
  uint8_t __unused;
  uint8_t family;                              /* IPv4 = 1, IPv6 = 2 */
  uint16_t port;
  union {
    uint8_t v4[4];
    uint8_t v6[16];
  } addr;
};

struct stun_attr_varsize {
  struct stun_attr_hdr hdr;
  uint8_t value[1];                            /* variable size value */
};

struct stun_attr_uint32 {
  struct stun_attr_hdr hdr;
  uint32_t value;                              /* single 32-bit value */
};

/* Used for 64-bits attribute */
struct stun_attr_uint64 {
  struct stun_attr_hdr hdr;
  uint64_t value;                              /* single 64-bit value */
};

/* Used for MESSAGE-INTEGRITY attribute */
struct stun_attr_msgint {
  struct stun_attr_hdr hdr;
  uint8_t hmac[20];                            /* HMAC-SHA1 hash */
};

struct stun_attr_errcode {
  struct stun_attr_hdr hdr;
  uint16_t __unused;
  uint8_t err_class;                           /* code / 100 */
  uint8_t err_code;                            /* code % 100 */
  char err_reason[1];
};

struct stun_attr_unknown {
  struct stun_attr_hdr hdr;
  uint16_t attrs[1];                           /* list of 16-bit values */
};

#pragma pack()

/* Gets the size of a sockaddr attribute, given the address type */
#define STUN_ATTR_SOCKADDR_SIZE(x) (4 + 4 + ((x) == STUN_IPV4 ? 4 : 16))

/* Gets the size of a varsize attribute, given the string/payload length */
#define STUN_ATTR_VARSIZE_SIZE(x) (4 + (((x) + 3) & (~3)))

/* Gets the size of an ERROR-CODE attribute, given the reason phrase length */
#define STUN_ATTR_ERROR_CODE_SIZE(x) (4 + 4 + (((x) + 3) & (~3)))

/* Gets the size of a UNKNOWN attribute, given the number of attributes */
#define STUN_ATTR_UNKNOWN_SIZE(x) (4 + ((((x) << 1) + 3) & (~3)))

/* Gets the size of a 32-bit attribute */
#define STUN_ATTR_UINT32_SIZE (4 + 4)

/* Gets the size of a 64-bit attribute */
#define STUN_ATTR_UINT64_SIZE (4 + 8)

/* Gets the size of a MESSAGE-INTEGRITY attribute */
#define STUN_ATTR_MSGINT_SIZE (4 + 20)

/* Gets the size of a FINGERPRINT attribute */
#define STUN_ATTR_FINGERPRINT_SIZE STUN_ATTR_UINT32_SIZE

/* The returned values from the below functions */
enum stun_status_type {
  STUN_OK                    = 0,
  STUN_ERR_NOT_SUPPORTED     = -1,
  STUN_ERR_NO_MEMORY         = -2,
  STUN_ERR_INVALID_ARG       = -3,
  STUN_ERR_UNKNOWN_ATTRIBUTE = -4,
  STUN_ERR_TOO_SMALL         = -5,
  STUN_ERR_BAD_TYPE          = -6,
  STUN_ERR_TRAIL_ATTRIBUTES  = -7,
  STUN_ERR_BAD_MSGINT        = -8,
  STUN_ERR_BAD_FINGERPRINT   = -9,
  STUN_ERR_PWD_NOTAVAIL      = -10,
  STUN_ERR_BAD_ADDR_FAMILY   = -11,
};

/* Get STUN standard reason phrase for the specified error code. NULL is
 * returned for unknown error codes.
 */
const char *stun_get_err_reason(int err_code);

/* Initializes a STUN message. */
void stun_msg_hdr_init(struct stun_msg_hdr *msg_hdr, uint16_t type,
                       const uint8_t tsx_id[12]);

/* Gets the STUN message type. */
uint16_t stun_msg_type(const struct stun_msg_hdr *msg_hdr);

/* Gets the STUN message length (including header). */
size_t stun_msg_len(const struct stun_msg_hdr *msg_hdr);

/* Gets the STUN message end. */
uint8_t *stun_msg_end(struct stun_msg_hdr *msg_hdr);

/* Initializes a generic attribute header */
void stun_attr_hdr_init(struct stun_attr_hdr *attr_hdr, uint16_t type,
                        uint16_t length);

/* Gets the STUN attribute end. */
uint8_t *stun_attr_end(struct stun_attr_hdr *attr_hdr);

/* Initializes a sockaddr attribute */
int stun_attr_sockaddr_init(struct stun_attr_sockaddr *sockaddr_attr,
                            uint16_t type, const struct sockaddr *addr);

/* Initializes a XOR'ed sockaddr attribute */
int stun_attr_xor_sockaddr_init(struct stun_attr_sockaddr *sockaddr_attr,
                                uint16_t type, const struct sockaddr *addr,
                                const struct stun_msg_hdr *msg_hdr);

/* Initializes a varsize attribute. Check macro STUN_ATTR_VARSIZE_SIZE for
 * the correct attribute size.
 */
void stun_attr_varsize_init(struct stun_attr_varsize *attr, uint16_t type,
                            const uint8_t *buf, size_t buf_size, uint8_t pad);

/* Initializes a 32-bit attribute */
void stun_attr_uint32_init(struct stun_attr_uint32 *attr, uint16_t type,
                           uint32_t value);

/* Initializes a 64-bit attribute */
void stun_attr_uint64_init(struct stun_attr_uint64 *attr, uint16_t type,
                           uint64_t value);

/* Initializes an ERROR-CODE attribute */
void stun_attr_errcode_init(struct stun_attr_errcode *attr, int err_code,
                            const char *err_reason, uint8_t pad);

/* Initializes an UNKNOWN-ATTRIBUTES attribute */
void stun_attr_unknown_init(struct stun_attr_unknown *attr,
                            const uint16_t *unknown_codes, size_t count,
                            uint8_t pad);

/* Initializes a MESSAGE-INTEGRITY attribute. Note that this attribute must be
 * the next to last one in a STUN message, before FINGERPRINT. It also expects
 * that you already have added the provided attribute to the message header.
 *
 * This function will calculate the HMAC-SHA1 digest from the message using the
 * supplied password. If the message contains USERNAME and REALM attributes,
 * then the key will be MD5(username ":" realm ":" password). Otherwise the
 * hash key is simply the input password.
 */
void stun_attr_msgint_init(struct stun_attr_msgint *attr,
                           const struct stun_msg_hdr *msg_hdr,
                           const uint8_t *key, size_t key_len);

/* Initializes a FINGERPRINT attribute. Note that this attribute must be the
 * last one in a STUN message, right after the MESSAGE-INTEGRITY. It also
 * expects that you already have added the provided attribute to the message
 * header.
 */
void stun_attr_fingerprint_init(struct stun_attr_uint32 *attr,
                                const struct stun_msg_hdr *msg_hdr);

/* Appends an attribute to the STUN message header. */
void stun_msg_add_attr(struct stun_msg_hdr *msg_hdr,
                       const struct stun_attr_hdr *attr);

/* Adds a sockaddr attribute to the message end */
int stun_attr_sockaddr_add(struct stun_msg_hdr *msg_hdr,
                           uint16_t type, const struct sockaddr *addr);

/* Adds a XOR'ed sockaddr attribute to the message end */
int stun_attr_xor_sockaddr_add(struct stun_msg_hdr *msg_hdr,
                               uint16_t type, const struct sockaddr *addr);

/* Adds a varsize attribute to the message end */
void stun_attr_varsize_add(struct stun_msg_hdr *msg_hdr, uint16_t type,
                           const uint8_t *buf, size_t buf_size, uint8_t pad);

/* Adds a 32-bit attribute to the message end */
void stun_attr_uint32_add(struct stun_msg_hdr *msg_hdr, uint16_t type,
                          uint32_t value);

/* Adds a 64-bit attribute to the message end */
void stun_attr_uint64_add(struct stun_msg_hdr *msg_hdr, uint16_t type,
                          uint64_t value);

/* Adds an ERROR-CODE attribute to the message end */
void stun_attr_errcode_add(struct stun_msg_hdr *msg_hdr, int err_code,
                           const char *err_reason, uint8_t pad);

/* Adds an UNKNOWN-ATTRIBUTES attribute to the message end */
void stun_attr_unknown_add(struct stun_msg_hdr *msg_hdr,
                           const uint16_t *unknown_codes, size_t count,
                           uint8_t pad);

/* Adds a MESSAGE-INTEGRITY to the message end */
void stun_attr_msgint_add(struct stun_msg_hdr *msg_hdr,
                          const uint8_t *key, size_t key_len);

/* Adds a FINGERPRINT attribute to the message end */
void stun_attr_fingerprint_add(struct stun_msg_hdr *msg_hdr);

/* Check the validity of an incoming STUN packet. Peforms several checks,
 * including the MESSAGE-INTEGRITY, if available.
 */
int stun_msg_verify(const struct stun_msg_hdr *msg_hdr, size_t msg_size);

/* Gets the attribute length (inner length, no padding) */
size_t stun_attr_len(const struct stun_attr_hdr *attr_hdr);

/* Gets the attribute block length (with padding) */
size_t stun_attr_block_len(const struct stun_attr_hdr *attr_hdr);

/* Gets the attribute type */
uint16_t stun_attr_type(const struct stun_attr_hdr *attr_hdr);

/* Iterates over the existing STUN message attributes. Passing a NULL
 * current attribute, you point to the first attribute.
 *
 * Returns the next STUN attribute, or NULL past the last one.
 */
struct stun_attr_hdr *stun_msg_next_attr(struct stun_msg_hdr *msg_hdr,
                                         struct stun_attr_hdr *attr_hdr);

/* Reads a sockaddr attribute. Returns error case the address family
 * is unknown (should be STUN_IPV4 or STUN_IPV6).
 */
int stun_attr_sockaddr_read(const struct stun_attr_sockaddr *attr,
                            struct sockaddr *addr);

/* Reads a XOR'red sockaddr attribute. Returns error case the address family
 * is unknown (should be STUN_IPV4 or STUN_IPV6).
 */
int stun_attr_xor_sockaddr_read(const struct stun_attr_sockaddr *attr,
                                const struct stun_msg_hdr *msg_hdr,
                                struct sockaddr *addr);

/* Reads a varsize attribute. The length is returned by stun_attr_len */
const uint8_t *stun_attr_varsize_read(const struct stun_attr_varsize *attr);

/* Reads a 32-bit attribute */
uint32_t stun_attr_uint32_read(const struct stun_attr_uint32 *attr);

/* Reads a 64-bit attribute */
uint64_t stun_attr_uint64_read(const struct stun_attr_uint32 *attr);

/* Gets the status code from the ERROR-CODE attribute */
int stun_attr_errcode_status(const struct stun_attr_errcode *attr);

/* Gets the reason phrase from the ERROR-CODE attribute */
const char *stun_attr_errcode_reason(const struct stun_attr_errcode *attr);

/* Gets the reason phrase length from the ERROR-CODE attribute */
size_t stun_attr_errcode_reason_len(const struct stun_attr_errcode *attr);

/* Enumerates the unknown attributes. Passing unk_it as NULL
 * starts the iteration.
 */
uint16_t *stun_attr_unknown_next(const struct stun_attr_unknown *attr,
                                 uint16_t *unk_it);

/* Calculates the key used for long term credentials for using with the
 * MESSAGE-INTEGRITY attribute; MD5(user:realm:pass).
 */
void stun_key(const char *username, const char *realm, const char *password,
              uint8_t key[16]);

#ifdef __cplusplus
};
#endif

#endif // __STUN_H__
