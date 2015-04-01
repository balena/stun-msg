/* Copyright (c) 2015 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

%module stunmsg_c

%inline %{
#if defined(linux)
#include <arpa/inet.h>
#elif defined(_WIN32)
#else
#endif
%}

%{
#include "stun/msg.h"
%}

%include "typemaps.i"

/* STUN magic cookie */
#define STUN_MAGIC_COOKIE 0x2112A442ul

enum _stun_msg_type {
/* Type                                  | Value    | Reference */
  STUN_BINDING_REQUEST                   = 0x0001, /* RFC 5389  */
  STUN_BINDING_RESPONSE                  = 0x0101, /* RFC 5389  */
  STUN_BINDING_ERROR_RESPONSE            = 0x0111, /* RFC 5389  */
  STUN_BINDING_INDICATION                = 0x0011, /* RFC 5389  */
  STUN_SHARED_SECRET_REQUEST             = 0x0002, /* RFC 5389  */
  STUN_SHARED_SECRET_RESPONSE            = 0x0102, /* RFC 5389  */
  STUN_SHARED_SECRET_ERROR_RESPONSE      = 0x0112, /* RFC 5389  */
  STUN_ALLOCATE_REQUEST                  = 0x0003, /* RFC 5766  */
  STUN_ALLOCATE_RESPONSE                 = 0x0103, /* RFC 5766  */
  STUN_ALLOCATE_ERROR_RESPONSE           = 0x0113, /* RFC 5766  */
  STUN_REFRESH_REQUEST                   = 0x0004, /* RFC 5766  */
  STUN_REFRESH_RESPONSE                  = 0x0104, /* RFC 5766  */
  STUN_REFRESH_ERROR_RESPONSE            = 0x0114, /* RFC 5766  */
  STUN_SEND_INDICATION                   = 0x0016, /* RFC 5766  */
  STUN_DATA_INDICATION                   = 0x0017, /* RFC 5766  */
  STUN_CREATE_PERM_REQUEST               = 0x0008, /* RFC 5766  */
  STUN_CREATE_PERM_RESPONSE              = 0x0108, /* RFC 5766  */
  STUN_CREATE_PERM_ERROR_RESPONSE        = 0x0118, /* RFC 5766  */
  STUN_CHANNEL_BIND_REQUEST              = 0x0009, /* RFC 5766  */
  STUN_CHANNEL_BIND_RESPONSE             = 0x0109, /* RFC 5766  */
  STUN_CHANNEL_BIND_ERROR_RESPONSE       = 0x0119, /* RFC 5766  */
  STUN_CONNECT_REQUEST                   = 0x000A, /* RFC 6062  */
  STUN_CONNECT_RESPONSE                  = 0x010A, /* RFC 6062  */
  STUN_CONNECT_ERROR_RESPONSE            = 0x011A, /* RFC 6062  */
  STUN_CONNECTION_BIND_REQUEST           = 0x000B, /* RFC 6062  */
  STUN_CONNECTION_BIND_RESPONSE          = 0x010B, /* RFC 6062  */
  STUN_CONNECTION_BIND_ERROR_RESPONSE    = 0x011B, /* RFC 6062  */
  STUN_CONNECTION_ATTEMPT_REQUEST        = 0x000C, /* RFC 6062  */
  STUN_CONNECTION_ATTEMPT_RESPONSE       = 0x010C, /* RFC 6062  */
  STUN_CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C, /* RFC 6062  */
};

enum _stun_attr_type {
/* Attribute                    | Value  | Type                     | Reference */
  STUN_ATTR_MAPPED_ADDRESS      = 0x0001, /* stun_attr_sockaddr     | RFC 5389  */
  STUN_ATTR_RESPONSE_ADDRESS    = 0x0002, /* stun_attr_sockaddr     | RFC 5389  */
  STUN_ATTR_CHANGE_REQUEST      = 0x0003, /* stun_attr_uint32       | RFC 5780  */
  STUN_ATTR_SOURCE_ADDRESS      = 0x0004, /* stun_attr_sockaddr     | RFC 5389  */
  STUN_ATTR_CHANGED_ADDRESS     = 0x0005, /* stun_attr_sockaddr     | RFC 5389  */
  STUN_ATTR_USERNAME            = 0x0006, /* stun_attr_varsize      | RFC 5389  */
  STUN_ATTR_PASSWORD            = 0x0007, /* stun_attr_varsize      | RFC 5389  */
  STUN_ATTR_MESSAGE_INTEGRITY   = 0x0008, /* stun_attr_msgint       | RFC 5389  */
  STUN_ATTR_ERROR_CODE          = 0x0009, /* stun_attr_errcode      | RFC 5389  */
  STUN_ATTR_UNKNOWN_ATTRIBUTES  = 0x000A, /* stun_attr_unknown      | RFC 5389  */
  STUN_ATTR_REFLECTED_FROM      = 0x000B, /* stun_attr_sockaddr     | RFC 5389  */
  STUN_ATTR_CHANNEL_NUMBER      = 0x000C, /* stun_attr_uint32       | RFC 5766  */
  STUN_ATTR_LIFETIME            = 0x000D, /* stun_attr_uint32       | RFC 5766  */
  STUN_ATTR_BANDWIDTH           = 0x0010, /* stun_attr_uint32       | RFC 5766  */
  STUN_ATTR_XOR_PEER_ADDRESS    = 0x0012, /* stun_attr_xor_sockaddr | RFC 5766  */
  STUN_ATTR_DATA                = 0x0013, /* stun_attr_varsize      | RFC 5766  */
  STUN_ATTR_REALM               = 0x0014, /* stun_attr_varsize      | RFC 5389  */
  STUN_ATTR_NONCE               = 0x0015, /* stun_attr_varsize      | RFC 5389  */
  STUN_ATTR_XOR_RELAYED_ADDRESS = 0x0016, /* stun_attr_xor_sockaddr | RFC 5766  */
  STUN_ATTR_REQ_ADDRESS_FAMILY  = 0x0017, /* stun_attr_uint8        | RFC 6156  */
  STUN_ATTR_EVEN_PORT           = 0x0018, /* stun_attr_uint8_pad    | RFC 5766  */
  STUN_ATTR_REQUESTED_TRANSPORT = 0x0019, /* stun_attr_uint32       | RFC 5766  */
  STUN_ATTR_DONT_FRAGMENT       = 0x001A, /* empty                  | RFC 5766  */
  STUN_ATTR_XOR_MAPPED_ADDRESS  = 0x0020, /* stun_attr_xor_sockaddr | RFC 5389  */
  STUN_ATTR_TIMER_VAL           = 0x0021, /* stun_attr_uint32       | RFC 5766  */
  STUN_ATTR_RESERVATION_TOKEN   = 0x0022, /* stun_attr_uint64       | RFC 5766  */
  STUN_ATTR_PRIORITY            = 0x0024, /* stun_attr_uint32       | RFC 5245  */
  STUN_ATTR_USE_CANDIDATE       = 0x0025, /* empty                  | RFC 5245  */
  STUN_ATTR_PADDING             = 0x0026, /* stun_attr_varsize      | RFC 5780  */
  STUN_ATTR_RESPONSE_PORT       = 0x0027, /* stun_attr_uint16_pad   | RFC 5780  */
  STUN_ATTR_CONNECTION_ID       = 0x002A, /* stun_attr_uint32       | RFC 6062  */
  STUN_ATTR_SOFTWARE            = 0x8022, /* stun_attr_varsize      | RFC 5389  */
  STUN_ATTR_ALTERNATE_SERVER    = 0x8023, /* stun_attr_sockaddr     | RFC 5389  */
  STUN_ATTR_FINGERPRINT         = 0x8028, /* stun_attr_uint32       | RFC 5389  */
  STUN_ATTR_ICE_CONTROLLED      = 0x8029, /* stun_attr_uint64       | RFC 5245  */
  STUN_ATTR_ICE_CONTROLLING     = 0x802A, /* stun_attr_uint64       | RFC 5245  */
  STUN_ATTR_RESPONSE_ORIGIN     = 0x802B, /* stun_attr_sockaddr     | RFC 5780  */
  STUN_ATTR_OTHER_ADDRESS       = 0x802C, /* stun_attr_sockaddr     | RFC 5780  */
};

enum _stun_error_code_type {
/* Code                                | Value | Reference */
  STUN_ERROR_TRY_ALTERNATE             = 300, /* RFC 5389  */
  STUN_ERROR_BAD_REQUEST               = 400, /* RFC 5389  */
  STUN_ERROR_UNAUTHORIZED              = 401, /* RFC 5389  */
  STUN_ERROR_FORBIDDEN                 = 403, /* RFC 5766  */
  STUN_ERROR_UNKNOWN_ATTRIBUTE         = 420, /* RFC 5389  */
  STUN_ERROR_ALLOCATION_MISMATCH       = 437, /* RFC 5766  */
  STUN_ERROR_STALE_NONCE               = 438, /* RFC 5389  */
  STUN_ERROR_ADDR_FAMILY_NOT_SUPP      = 440, /* RFC 6156  */
  STUN_ERROR_WRONG_CREDENTIALS         = 441, /* RFC 5766  */
  STUN_ERROR_UNSUPP_TRANSPORT_PROTO    = 442, /* RFC 5766  */
  STUN_ERROR_PEER_ADD_FAMILY_MISMATCH  = 443, /* RFC 6156  */
  STUN_ERROR_CONNECTION_ALREADY_EXISTS = 446, /* RFC 6062  */
  STUN_ERROR_CONNECTION_FAILURE        = 447, /* RFC 6062  */
  STUN_ERROR_ALLOCATION_QUOTA_REACHED  = 486, /* RFC 5766  */
  STUN_ERROR_ROLE_CONFLICT             = 487, /* RFC 5245  */
  STUN_ERROR_SERVER_ERROR              = 500, /* RFC 5389  */
  STUN_ERROR_INSUFFICIENT_CAPACITY     = 508, /* RFC 5766  */
};

/* STUN address families */
enum _stun_addr_family {
  STUN_IPV4 = 0x01,
  STUN_IPV6 = 0x02
};

const char *stun_err_reason(int err_code);
const char *stun_method_name(uint16_t type);
const char *stun_class_name(uint16_t type);

%typemap(in) stun_msg_hdr * {
  if (!PyByteArray_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expected a bytearray");
    return NULL;
  }
  if (PyByteArray_GET_SIZE($input) < sizeof(stun_msg_hdr)) {
    PyErr_SetString(PyExc_ValueError, "Size mismatch."
                    " Expected at least 20 bytes");
    return NULL;
  }
  $1 = (stun_msg_hdr*)PyByteArray_AS_STRING($input);
}

%typemap(in) uint8_t {
  $1 = (uint8_t)PyInt_AsLong($input);
}

%typemap(in) uint16_t {
  $1 = (uint16_t)PyInt_AsLong($input);
}

%typemap(in) uint32_t {
  $1 = (uint32_t)PyInt_AsLong($input);
}

%typemap(in) uint64_t {
  $1 = (uint64_t)PyLong_AsUnsignedLongLong($input);
}

%typemap(out) uint16_t {
  $result = PyInt_FromLong($1);
}

%typemap(in) const uint8_t[12] {
  if (!PyByteArray_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expected a bytearray");
    return NULL;
  }
  if (PyByteArray_GET_SIZE($input) != 12) {
    PyErr_SetString(PyExc_ValueError, "Size mismatch."
                    " Expected 12 bytes");
    return NULL;
  }
  $1 = (uint8_t*)PyByteArray_AS_STRING($input);
}

%typemap(in) (const void *Buf, size_t BufSize) {
  if (PyByteArray_Check($input)) {
    $1 = PyByteArray_AsString($input);
    $2 = (size_t)PyByteArray_Size($input);
  } else if (PyString_Check($input)) {
    $1 = PyString_AsString($input);
    $2 = (size_t)PyString_Size($input);
  } else {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected bytearray or string object");
    return NULL;
  }
}

%typemap(in) (const uint16_t *unknown_codes, size_t count) {
  PyObject *fast = PySequence_Fast($input, "Type mismatch."
                                   " Expected a sequence of integers");
  Py_ssize_t i, len = PySequence_Fast_GET_SIZE(fast);
  uint16_t *result = (uint16_t *)malloc(len * sizeof(uint16_t));
  for (i = 0; i < len; i++) {
    PyObject *elem = PySequence_Fast_GET_ITEM(fast, i);
    result[i] = (uint16_t)PyInt_AsLong(elem);
  }
  $1 = result;
  $2 = len;
}

%typemap(freearg) (const uint16_t *unknown_codes, size_t count) {
  free($1);
}

%typemap(in) const struct sockaddr *addr {
  const char *addr;
  int port;
  struct sockaddr_in sa_in;
  struct sockaddr_in6 sa_in6;
  PyObject *fast = PySequence_Fast($input, "Type mismatch."
                                   " Expected a (addr, port) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (addr, port) sequence");
    return NULL;
  }
  addr = PyString_AsString(PySequence_Fast_GET_ITEM(fast, 0));
  port = (int)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (inet_pton(AF_INET, addr, &sa_in.sin_addr)) {
    sa_in.sin_family = AF_INET;
    sa_in.sin_port = htons((unsigned short)port);
    memset(&sa_in.sin_zero, 0, sizeof(sa_in.sin_zero));
    $1 = (struct sockaddr *)malloc(sizeof(sa_in));
    memcpy($1, &sa_in, sizeof(sa_in));
  } else if (inet_pton(AF_INET6, addr, &sa_in6.sin6_addr)) {
    sa_in6.sin6_family = AF_INET6;
    sa_in6.sin6_port = htons((unsigned short)port);
    sa_in6.sin6_flowinfo = 0L;
    sa_in6.sin6_scope_id = 0L;
    $1 = (struct sockaddr *)malloc(sizeof(sa_in6));
    memcpy($1, &sa_in6, sizeof(sa_in6));
  } else {
    PyErr_SetString(PyExc_ValueError, "Invalid IP address");
    return NULL;
  }
}

%typemap(freearg) const struct sockaddr *addr {
  free($1);
}

void stun_msg_hdr_init(stun_msg_hdr *msg_hdr, uint16_t type,
                       const uint8_t tsx_id[12]);

uint16_t stun_msg_type(const stun_msg_hdr *msg_hdr);
size_t stun_msg_len(const stun_msg_hdr *msg_hdr);

void stun_attr_empty_add(stun_msg_hdr *msg_hdr, uint16_t type);
int stun_attr_sockaddr_add(stun_msg_hdr *msg_hdr, uint16_t type,
                           const struct sockaddr *addr);
int stun_attr_xor_sockaddr_add(stun_msg_hdr *msg_hdr, uint16_t type,
                               const struct sockaddr *addr);
void stun_attr_varsize_add(stun_msg_hdr *msg_hdr, uint16_t type,
                           const void *Buf, size_t BufSize, uint8_t pad);
void stun_attr_uint8_add(stun_msg_hdr *msg_hdr, uint16_t type, uint8_t value);
void stun_attr_uint8_pad_add(stun_msg_hdr *msg_hdr, uint16_t type,
                             uint8_t value, uint8_t pad);
void stun_attr_uint16_add(stun_msg_hdr *msg_hdr, uint16_t type,
                          uint16_t value);
void stun_attr_uint16_pad_add(stun_msg_hdr *msg_hdr, uint16_t type,
                              uint16_t value, uint8_t pad);
void stun_attr_uint32_add(stun_msg_hdr *msg_hdr, uint16_t type,
                          uint32_t value);
void stun_attr_uint64_add(stun_msg_hdr *msg_hdr, uint16_t type,
                          uint64_t value);
void stun_attr_errcode_add(stun_msg_hdr *msg_hdr, int err_code,
                           const char *err_reason, uint8_t pad);
void stun_attr_unknown_add(stun_msg_hdr *msg_hdr,
                           const uint16_t *unknown_codes, size_t count,
                           uint8_t pad);
void stun_attr_msgint_add(stun_msg_hdr *msg_hdr,
                          const void *Buf, size_t BufSize);
void stun_attr_fingerprint_add(stun_msg_hdr *msg_hdr);

int stun_msg_verify(const stun_msg_hdr *msg_hdr, size_t msg_size);

%typemap(in) const stun_attr_hdr * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_hdr*)(&b[index]);
}

size_t stun_attr_len(const stun_attr_hdr *attr_hdr);
size_t stun_attr_block_len(const stun_attr_hdr *attr_hdr);
uint16_t stun_attr_type(const stun_attr_hdr *attr_hdr);

inline %{
PyObject *next_attr(const stun_msg_hdr *msg_hdr, size_t index) {
  const stun_attr_hdr *attr_hdr = (index == 0) ? NULL :
      (const stun_attr_hdr *)&((const uint8_t *)msg_hdr)[index];
  const stun_attr_hdr *result = stun_msg_next_attr(msg_hdr, attr_hdr);
  if (result == NULL) {
    Py_RETURN_NONE;
  }
  return PyInt_FromSsize_t((const uint8_t*)result - (const uint8_t*)msg_hdr);
}

PyObject *find_attr(const stun_msg_hdr *msg_hdr, uint16_t type) {
  const stun_attr_hdr *result = stun_msg_find_attr(msg_hdr, type);
  if (result == NULL) {
    Py_RETURN_NONE;
  }
  return PyInt_FromSsize_t((const uint8_t*)result - (const uint8_t*)msg_hdr);
}
%}

PyObject *next_attr(const stun_msg_hdr *msg_hdr, size_t index);
PyObject *find_attr(const stun_msg_hdr *msg_hdr, uint16_t type);

%typemap(argout) struct sockaddr *SockAddrOut {
  PyObject *o, *o2, *o3;
  PyObject *result_addr, *result_port;
  if ($1->sa_family == AF_INET) {
    char addr[INET_ADDRSTRLEN];
    struct sockaddr_in *sin = (struct sockaddr_in *)$1;
    inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr));
    result_addr = PyString_FromString(addr);
    result_port = PyInt_FromLong(ntohs(sin->sin_port));
  } else if ($1->sa_family == AF_INET6) {
    char addr[INET6_ADDRSTRLEN];
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)$1;
    inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof(addr));
    result_addr = PyString_FromString(addr);
    result_port = PyInt_FromLong(ntohs(sin6->sin6_port));
  } else {
    Py_RETURN_NONE;
  }
  o = PyTuple_New(2);
  PyTuple_SET_ITEM(o, 0, result_addr);
  PyTuple_SET_ITEM(o, 1, result_port);
  if ((!$result) || ($result == Py_None)) {
    $result = o;
  } else {
    if (!PyTuple_Check($result)) {
      PyObject *o2 = $result;
      $result = PyTuple_New(1);
      PyTuple_SetItem($result, 0, o2);
    }
    o3 = PyTuple_New(1);
    PyTuple_SetItem(o3, 0, o);
    o2 = $result;
    $result = PySequence_Concat(o2,o3);
    Py_DECREF(o2);
    Py_DECREF(o3);
  }
}

%typemap(in,numinputs=0) struct sockaddr *SockAddrOut(struct sockaddr temp) {
  $1 = &temp;
}

%typemap(in) const stun_attr_sockaddr * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_sockaddr*)(&b[index]);
}

int stun_attr_sockaddr_read(const stun_attr_sockaddr *attr,
                            struct sockaddr *SockAddrOut);
int stun_attr_xor_sockaddr_read(const stun_attr_xor_sockaddr *attr,
                                const stun_msg_hdr *msg_hdr,
                                struct sockaddr *SockAddrOut);

%typemap(in) const stun_attr_varsize * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_varsize*)(&b[index]);
}

inline %{
PyObject *string_read(const stun_attr_varsize *attr) {
  size_t len = stun_attr_len(&attr->hdr);
  const void *data = stun_attr_varsize_read(attr);
  return PyString_FromStringAndSize((const char*)data, len);
}
%}
PyObject *string_read(const stun_attr_varsize *attr);

inline %{
PyObject *data_read(const stun_attr_varsize *attr) {
  size_t len = stun_attr_len(&attr->hdr);
  const void *data = stun_attr_varsize_read(attr);
  return PyByteArray_FromStringAndSize((const char*)data, len);
}
%}
PyObject *data_read(const stun_attr_varsize *attr);

%typemap(in) const stun_attr_uint8 * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_uint8*)(&b[index]);
}
uint8_t stun_attr_uint8_read(const stun_attr_uint8 *attr);

%typemap(in) const stun_attr_uint16 * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_uint16*)(&b[index]);
}
uint16_t stun_attr_uint16_read(const stun_attr_uint16 *attr);

%typemap(in) const stun_attr_uint32 * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_uint32*)(&b[index]);
}
uint32_t stun_attr_uint32_read(const stun_attr_uint32 *attr);

%typemap(in) const stun_attr_uint64 * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_uint64*)(&b[index]);
}
uint64_t stun_attr_uint64_read(const stun_attr_uint64 *attr);

%typemap(in) const stun_attr_errcode * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_errcode*)(&b[index]);
}
int stun_attr_errcode_status(const stun_attr_errcode *attr);

%inline %{
PyObject *errcode_reason(const stun_attr_errcode *attr) {
  return PyString_FromStringAndSize(
    stun_attr_errcode_reason(attr), stun_attr_errcode_reason_len(attr));
}
%}
PyObject *errcode_reason(const stun_attr_errcode *attr);

%typemap(in) const stun_attr_unknown * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_unknown*)(&b[index]);
}
size_t stun_attr_unknown_count(const stun_attr_unknown *attr);
uint16_t stun_attr_unknown_get(const stun_attr_unknown *attr, size_t n);

%typemap(in) const stun_attr_msgint * {
  char *b;
  size_t index;
  PyObject *p, *fast = PySequence_Fast($input, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
  if (PySequence_Fast_GET_SIZE(fast) != 2) {
    PyErr_SetString(PyExc_ValueError, "Type mismatch."
                    " Expected a (bytearray, index) sequence");
    return NULL;
  }
  p = PySequence_Fast_GET_ITEM(fast, 0);
  b = PyByteArray_AsString(p);
  index = (size_t)PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
  if (index >= PyByteArray_Size(p)) {
    PyErr_SetString(PyExc_ValueError, "Wrong index");
    return NULL;
  }
  $1 = (stun_attr_msgint*)(&b[index]);
}
int stun_attr_msgint_check(const stun_attr_msgint *msgint,
                           const stun_msg_hdr *msg_hdr,
                           const uint8_t *key, size_t key_len);

%typemap(argout) uint8_t *KeyOut {
  $result = PyString_FromStringAndSize((const char*)$1, 16);
}
%typemap(in,numinputs=0) uint8_t *KeyOut(uint8_t temp[16]) {
  $1 = temp;
}
void stun_genkey(const void *Buf, size_t BufSize,
                 const void *Buf, size_t BufSize,
                 const void *Buf, size_t BufSize,
                 uint8_t *KeyOut);

int stun_attr_fingerprint_check(const stun_attr_uint32 *fingerprint,
                                const stun_msg_hdr *msg_hdr);

%inline %{
int stun_attr_sockaddr_size(int addr_type) {
  return STUN_ATTR_SOCKADDR_SIZE(addr_type);
}

int stun_attr_varsize_size(int length) {
  return STUN_ATTR_VARSIZE_SIZE(length);
}

int stun_attr_error_code_size(int reason_length) {
  return STUN_ATTR_ERROR_CODE_SIZE(reason_length);
}

int stun_attr_unknown_size(int count) {
  return STUN_ATTR_UNKNOWN_SIZE(count);
}
%}

%constant stun_attr_uint8_size  (4+4) 
%constant stun_attr_uint16_size (4+4)
%constant stun_attr_uint32_size (4+4)
%constant stun_attr_uint64_size (4+8)
%constant stun_attr_msgint_size (4+20)
%constant stun_attr_fingerprint_size (4+4)

int stun_attr_sockaddr_size(int addr_type);
int stun_attr_varsize_size(int length);
int stun_attr_error_code_size(int reason_length);
int stun_attr_unknown_size(int count);

