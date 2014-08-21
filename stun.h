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

/* Used to define the max number of attributes accepted */
#define STUN_MAX_ATTRS 16

/* Used to define the max string size accepted */
#define STUN_MAX_STR_SIZE 128

/* Used to define the max binary size accepted */
#define STUN_MAX_BIN_SIZE 2048

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

/* The STUN attribute header */
struct stun_attr_hdr {
  uint16_t type;
  uint16_t length;
};

/* The STUN message */
struct stun_msg {

  /* STUN Message Type */
  uint16_t type;

  /* Message Length */
  uint16_t length;

  /* Magic Cookie */
  uint32_t magic;

  /* Transaction ID */
  uint8_t tsx_id[12];

  /* Attributes count */
  size_t attr_count;

  /* Attribute list */
  struct stun_attr_hdr *attrs[STUN_MAX_ATTRS];
};

/* Used for empty STUN attributes */
struct stun_attr_empty {
  struct stun_attr_hdr hdr;
};

/* STUN address families */
enum stun_addr_family {
  STUN_IPV4 = 0x01,
  STUN_IPV6 = 0x02
};

/* Used for representing address attributes */
struct stun_attr_sockaddr {
  struct stun_attr_hdr hdr;
  uint8_t padding;
  uint8_t family;
  uint16_t port;
  union {
    uint8_t v4[4];
    uint8_t v6[16];
  } addr;
};

/* Used for representing string-like attributes */
struct stun_attr_string {
  struct stun_attr_hdr hdr;
  char value[STUN_MAX_STR_SIZE];
};

/* Used for representing binary attributes */
struct stun_attr_binary {
  struct stun_attr_hdr hdr;
  uint8_t value[STUN_MAX_BIN_SIZE];
};

/* Used for 32-bits attribute */
struct stun_attr_uint32 {
  struct stun_attr_hdr hdr;
  uint32_t value;
};

/* Used for 64-bits attribute */
struct stun_attr_uint64 {
  struct stun_attr_hdr hdr;
  uint64_t value;
};

/* Used for MESSAGE-INTEGRITY attribute */
struct stun_attr_msgint {
  struct stun_attr_hdr hdr;
  uint8_t hmac[20];
};

/* Used for the ERROR-CODE attribute */
struct stun_attr_errcode {
  struct stun_attr_hdr hdr;
  uint16_t padding;
  uint8_t err_class;
  uint8_t err_code;
  char err_reason[STUN_MAX_STR_SIZE];
};

/* Used for the UNKNOWN-ATTRIBUTES attribute */
struct stun_attr_unknown {
  struct stun_attr_hdr hdr;
  uint16_t attrs[STUN_MAX_ATTRS];
};

/* The returned values from the below functions */
enum stun_status_type {
  STUN_OK                    = 0,
  STUN_ERR_NOT_SUPPORTED     = -1,
  STUN_ERR_NO_MEMORY         = -2,
  STUN_ERR_INVALID_ARG       = -3,
  STUN_ERR_UNKNOWN_ATTRIBUTE = -4,
  STUN_ERR_TOO_SMALL         = -5,
  STUN_ERR_BAD_TYPE          = -6,
};

/* Get STUN standard reason phrase for the specified error code. NULL is
 * returned for unknown error codes.
 */
const char *stun_get_err_reason(int err_code);

/* Initializes a STUN message.
 */
void stun_msg_init(struct stun_msg *msg, uint16_t type,
                   const uint8_t tsx_id[12]);

/* Initializes an empty attribute */
void stun_attr_empty_init(struct stun_attr_empty *attr, uint16_t type);

/* Initializes a sockaddr attribute */
int stun_attr_sockaddr_init(struct stun_attr_sockaddr *attr, uint16_t type,
                            const struct sockaddr *addr);

/* Initializes a string-like attribute. Returns non-zero for errors. */
int stun_attr_string_init(struct stun_attr_string *attr, uint16_t type,
                          const char *str, size_t size);

/* Initializes a binary-like attribute. Returns non-zero for errors. */
int stun_attr_binary_init(struct stun_attr_binary *attr, uint16_t type,
                          const uint8_t *buf, size_t size);

/* Initializes a 32-bit attribute */
void stun_attr_uint32_init(struct stun_attr_uint32 *attr, uint16_t type,
                           uint32_t value);

/* Initializes a 64-bit attribute */
void stun_attr_uint64_init(struct stun_attr_uint64 *attr, uint16_t type,
                           uint64_t value);

/* Initializes an ERROR-CODE attribute */
int stun_attr_errcode_init(struct stun_attr_errcode *attr, int err_code,
                           const char *err_reason);

/* Initializes an UNKNOWN-ATTRIBUTES attribute */
int stun_attr_unknown_init(struct stun_attr_unknown *attr,
                           const uint16_t *unknown_codes, size_t count);

/* Initializes a MESSAGE-INTEGRITY attribute. Note that the HMAC-SHA1 hash is
 * effectively calculated only when the message is encoded.
 */
void stun_attr_msgint_init(struct stun_attr_msgint *attr);

/* Adds a STUN attribute to the given message. Note that the passed attribute
 * must exist until the moment you call stun_msg_encode.
 */
int stun_msg_add_attr(struct stun_msg *msg, struct stun_attr_hdr *attr);

/* Encodes the STUN message to a packet buffer. This function will take care
 * about calculating the MESSAGE-INTEGRITY digest as well as FINGERPRINT value,
 * if these attributes are present in the message.
 *
 * If the application wants to apply credential to the message, it must include
 * a blank MESSAGE-INTEGRITY attribute in the message, in any order (the
 * encoder will put the attribute as the last one, before FINGERPRINT, if it
 * exists). This function will calculate the HMAC-SHA1 digest from the message
 * using the supplied key parameter.
 *
 * If FINGERPRINT attribute is present (any order), this function will
 * calculate the FINGERPRINT CRC attribute for the message.
 *
 * Returns a negative value in case of errors, or STUN_OK if succeeded.
 */
int stun_msg_encode(const struct stun_msg *msg, void *buffer,
                    const uint8_t *key, int key_len,
                    size_t bufferlen);

/* Decodes the STUN message from the packet buffer. This function will change
 * the data available in the buffer, and the STUN message will point to
 * the input buffer.
 *
 * Returns a negative value in case of errors, or STUN_OK if succeeded.
 */
int stun_msg_decode(struct stun_msg *msg, void *packet, size_t packetlen,
                    void *buffer, size_t bufferlen,
                    struct stun_attr_unknown *unknown_attr);

int stun_attr_sockaddr_read(const struct stun_attr_sockaddr *attr,
                            struct sockaddr *addr);

int stun_attr_string_read(const struct stun_attr_string *attr,
                          char *str, size_t max_size);

int stun_attr_uint32_read(const struct stun_attr_uint32 *attr,
                          uint32_t *value);

int stun_attr_uint64_read(const struct stun_attr_uint32 *attr,
                          uint64_t *value);

int stun_attr_errcode_read(const struct stun_attr_errcode *attr,
                           int *status_code, char *err_reason,
                           size_t reason_max);

int stun_attr_unknown_read(const struct stun_attr_unknown *attr,
                           uint16_t *uknown_codes, size_t max_count);

#ifdef __cplusplus
};
#endif

#endif // __STUN_H__
