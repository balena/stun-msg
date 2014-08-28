/* Copyright (c) 2014 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

#ifndef STUN_MESSAGE_H_
#define STUN_MESSAGE_H_

#include <stun/msg.h>
#include <vector>
#include <string>

// Forward sockaddr declarations;
struct sockaddr_in;
struct sockaddr_in6;

namespace stun {

namespace attribute {

class decoded {
 public:
  decoded(const stun_msg_hdr *msg_hdr, const stun_attr_hdr *attr_hdr)
      : msg_hdr_(msg_hdr), attr_hdr_(attr_hdr) {}

  uint16_t type() const {
    return stun_attr_type(attr_hdr_);
  }

  decoded next() const {
    return decoded(msg_hdr_, stun_msg_next_attr(msg_hdr_, attr_hdr_));
  }

  const stun_msg_hdr *msg_hdr() const {
    return msg_hdr_;
  }

  const stun_attr_hdr *attr_ptr() const {
    return attr_hdr_;
  }

  const uint8_t *data() const {
    return reinterpret_cast<const uint8_t*>(attr_hdr_) + sizeof(stun_attr_hdr);
  }

  size_t size() const {
    return stun_attr_len(attr_hdr_);
  }

  bool to_sockaddr(struct sockaddr *addr) const {
    return stun_attr_sockaddr_read(
        reinterpret_cast<const stun_attr_sockaddr*>(attr_hdr_), addr)
            ? true : false;
  }

  bool to_xor_sockaddr(struct sockaddr *addr) const {
    return stun_attr_xor_sockaddr_read(
        reinterpret_cast<const stun_attr_xor_sockaddr*>(attr_hdr_), msg_hdr_,
            addr) ? true : false;
  }

  std::string to_string() const {
    return std::string(reinterpret_cast<const char*>(data()), size());
  }

  uint8_t uint8_value() const {
    return stun_attr_uint8_read(
        reinterpret_cast<const stun_attr_uint8*>(attr_hdr_));
  }

  uint16_t uint16_value() const {
    return stun_attr_uint16_read(
        reinterpret_cast<const stun_attr_uint16*>(attr_hdr_));
  }

  uint32_t uint32_value() const {
    return stun_attr_uint32_read(
        reinterpret_cast<const stun_attr_uint32*>(attr_hdr_));
  }

  uint64_t uint64_value() const {
    return stun_attr_uint64_read(
        reinterpret_cast<const stun_attr_uint64*>(attr_hdr_));
  }

  int status_code() {
    const stun_attr_errcode *errcode =
        reinterpret_cast<const stun_attr_errcode *>(attr_hdr_);
    return stun_attr_errcode_status(errcode);
  }

  std::string reason_phrase() const {
    const stun_attr_errcode *errcode =
        reinterpret_cast<const stun_attr_errcode *>(attr_hdr_);
    const char *str = stun_attr_errcode_reason(errcode);
    size_t str_len = stun_attr_errcode_reason_len(errcode);
    return std::string(str, str_len);
  }

  size_t unknown_size() const {
    const stun_attr_unknown *unknown =
        reinterpret_cast<const stun_attr_unknown *>(attr_hdr_);
    return stun_attr_unknown_count(unknown);
  }

  uint16_t unknown_get(size_t n) const {
    const stun_attr_unknown *unknown =
        reinterpret_cast<const stun_attr_unknown *>(attr_hdr_);
    return stun_attr_unknown_get(unknown, n);
  }

  template<typename char_type>
  bool check_integrity(const char_type *key_begin,
                       const char_type *key_end) const {
    const stun_attr_msgint *msgint =
        reinterpret_cast<const stun_attr_msgint *>(attr_hdr_);
    return stun_attr_msgint_check(msgint, msg_hdr_,
        reinterpret_cast<const uint8_t*>(key_begin),
            key_end - key_begin) ? true : false;
  }

  bool check_integrity(const std::string &key) const {
    return check_integrity(key.data(), key.data() + key.size());
  }

 private:
  const stun_msg_hdr *msg_hdr_;
  const stun_attr_hdr *attr_hdr_;
};

namespace bits {

struct empty {
  empty(uint16_t type)
      : type_(type) {}
  size_t size() const { return sizeof(stun_attr_hdr); }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_empty_add(msg_hdr, type_);
  }
  uint16_t type_;
};

struct socket_address {
  socket_address(uint16_t type, const sockaddr *addr)
      : type_(type), addr_(addr) {}
  size_t size() const {
    return STUN_ATTR_SOCKADDR_SIZE(STUN_IPV6); // worst case
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_sockaddr_add(msg_hdr, type_, addr_);
  }
  uint16_t type_;
  const sockaddr *addr_;
};

struct xor_socket_address {
  xor_socket_address(uint16_t type, const sockaddr *addr)
      : type_(type), addr_(addr) {}
  size_t size() const {
    return STUN_ATTR_SOCKADDR_SIZE(STUN_IPV6);
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_xor_sockaddr_add(msg_hdr, type_, addr_);
  }
  uint16_t type_;
  const sockaddr *addr_;
};

template<typename char_type>
struct varsize {
  varsize(uint16_t type, const char_type *begin,
               const char_type *end, uint8_t pad)
      : type_(type), begin_(begin), end_(end), pad_(pad) {}
  size_t size() const {
    return STUN_ATTR_VARSIZE_SIZE(end_ - begin_);
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_varsize_add(msg_hdr, type_,
        reinterpret_cast<const uint8_t*>(begin_),
            end_ - begin_, pad_);
  }
  uint16_t type_;
  const char_type *begin_;
  const char_type *end_;
  uint8_t pad_;
};

struct u8 {
  u8(uint16_t type, uint8_t value)
      : type_(type), value_(value) {}
  size_t size() const {
    return STUN_ATTR_UINT8_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_uint8_add(msg_hdr, type_, value_);
  }
  uint16_t type_;
  uint8_t value_;
};

struct u8_pad {
  u8_pad(uint16_t type, uint8_t value, uint8_t pad)
      : type_(type), value_(value), pad_(pad) {}
  size_t size() const {
    return STUN_ATTR_UINT8_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_uint8_pad_add(msg_hdr, type_, value_, pad_);
  }
  uint16_t type_;
  uint8_t value_;
  uint8_t pad_;
};

struct u16 {
  u16(uint16_t type, uint16_t value)
      : type_(type), value_(value) {}
  size_t size() const {
    return STUN_ATTR_UINT16_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_uint16_add(msg_hdr, type_, value_);
  }
  uint16_t type_;
  uint16_t value_;
};

struct u16_pad {
  u16_pad(uint16_t type, uint16_t value, uint8_t pad)
      : type_(type), value_(value), pad_(pad) {}
  size_t size() const {
    return STUN_ATTR_UINT16_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_uint16_pad_add(msg_hdr, type_, value_, pad_);
  }
  uint16_t type_;
  uint16_t value_;
  uint8_t pad_;
};

struct u32 {
  u32(uint16_t type, uint32_t value)
      : type_(type), value_(value) {}
  size_t size() const {
    return STUN_ATTR_UINT32_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_uint32_add(msg_hdr, type_, value_);
  }
  uint16_t type_;
  uint32_t value_;
};

struct u64 {
  u64(uint16_t type, uint64_t value)
      : type_(type), value_(value) {}
  size_t size() const {
    return STUN_ATTR_UINT64_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_uint64_add(msg_hdr, type_, value_);
  }
  uint16_t type_;
  uint64_t value_;
};

struct errcode {
  errcode(int status_code, const char *reason, uint8_t pad)
      : status_code_(status_code), reason_(reason), pad_(pad) {}
  size_t size() const {
    return STUN_ATTR_ERROR_CODE_SIZE(strlen(reason_));
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_errcode_add(msg_hdr, status_code_, reason_, pad_);
  }
  int status_code_;
  const char *reason_;
  uint8_t pad_;
};

struct unknown {
  unknown(const uint16_t *begin, const uint16_t *end, uint8_t pad)
      : begin_(begin), end_(end), pad_(pad) {}
  size_t size() const {
    return STUN_ATTR_UNKNOWN_SIZE((end_ - begin_) >> 1);
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_unknown_add(msg_hdr, begin_, (end_ - begin_) >> 1, pad_);
  }
  const uint16_t *begin_;
  const uint16_t *end_;
  uint8_t pad_;
};

struct msgint {
  msgint(const uint8_t *key, size_t key_len)
      : key_(key), key_len_(key_len) {}
  size_t size() const {
    return STUN_ATTR_MSGINT_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_msgint_add(msg_hdr, key_, key_len_);
  }
  const uint8_t *key_;
  size_t key_len_;
};

struct fingerprint {
  fingerprint() {}
  size_t size() const {
    return STUN_ATTR_FINGERPRINT_SIZE;
  }
  void append(stun_msg_hdr *msg_hdr) const {
    stun_attr_fingerprint_add(msg_hdr);
  }
};

} // namespace bits

namespace type {

enum attribute_type {
  mapped_address      = STUN_ATTR_MAPPED_ADDRESS,
  response_address    = STUN_ATTR_RESPONSE_ADDRESS,
  change_request      = STUN_ATTR_CHANGE_REQUEST,
  source_address      = STUN_ATTR_SOURCE_ADDRESS,
  changed_address     = STUN_ATTR_CHANGED_ADDRESS,
  username            = STUN_ATTR_USERNAME,
  password            = STUN_ATTR_PASSWORD,
  message_integrity   = STUN_ATTR_MESSAGE_INTEGRITY,
  error_code          = STUN_ATTR_ERROR_CODE,
  unknown_attributes  = STUN_ATTR_UNKNOWN_ATTRIBUTES,
  reflected_from      = STUN_ATTR_REFLECTED_FROM,
  channel_number      = STUN_ATTR_CHANNEL_NUMBER,
  lifetime            = STUN_ATTR_LIFETIME,
  bandwidth           = STUN_ATTR_BANDWIDTH,
  xor_peer_address    = STUN_ATTR_XOR_PEER_ADDRESS,
  data                = STUN_ATTR_DATA,
  realm               = STUN_ATTR_REALM,
  nonce               = STUN_ATTR_NONCE,
  xor_relayed_address = STUN_ATTR_XOR_RELAYED_ADDRESS,
  req_address_family  = STUN_ATTR_REQ_ADDRESS_FAMILY,
  even_port           = STUN_ATTR_EVEN_PORT,
  requested_transport = STUN_ATTR_REQUESTED_TRANSPORT,
  dont_fragment       = STUN_ATTR_DONT_FRAGMENT,
  xor_mapped_address  = STUN_ATTR_XOR_MAPPED_ADDRESS,
  timer_val           = STUN_ATTR_TIMER_VAL,
  reservation_token   = STUN_ATTR_RESERVATION_TOKEN,
  priority            = STUN_ATTR_PRIORITY,
  use_candidate       = STUN_ATTR_USE_CANDIDATE,
  padding             = STUN_ATTR_PADDING,
  response_port       = STUN_ATTR_RESPONSE_PORT,
  connection_id       = STUN_ATTR_CONNECTION_ID,
  software            = STUN_ATTR_SOFTWARE,
  alternate_server    = STUN_ATTR_ALTERNATE_SERVER,
  fingerprint         = STUN_ATTR_FINGERPRINT,
  ice_controlled      = STUN_ATTR_ICE_CONTROLLED,
  ice_controlling     = STUN_ATTR_ICE_CONTROLLING,
  response_origin     = STUN_ATTR_RESPONSE_ORIGIN,
  other_address       = STUN_ATTR_OTHER_ADDRESS,
};

} // namespace type


#define STUNXX_ATTRIBUTE_STRING_LIKE(name)                                    \
bits::varsize<char> name(const char *data, uint8_t pad = 0) {                 \
  return bits::varsize<char>(attribute::type::name, data,                     \
      data + strlen(data), pad);                                              \
}                                                                             \
bits::varsize<char> name(const std::string &s, uint8_t pad = 0) {             \
  return bits::varsize<char>(attribute::type::name, s.data(),                 \
      s.data() + s.size(), pad);                                              \
}                                                                             \
bits::varsize<char> name(const char *begin, const char *end,                  \
                         uint8_t pad = 0) {                                   \
  return bits::varsize<char>(attribute::type::name, begin, end, pad);         \
}

#define STUNXX_ATTRIBUTE_DATA_LIKE(name)                                      \
bits::varsize<uint8_t> name(const uint8_t *data, size_t data_len,             \
                            uint8_t pad = 0) {                                \
  return bits::varsize<uint8_t>(attribute::type::name, data,                  \
      data + data_len, pad);                                                  \
}                                                                             \
bits::varsize<uint8_t> name(const uint8_t *begin, const uint8_t *end,         \
                            uint8_t pad = 0) {                                \
  return bits::varsize<uint8_t>(attribute::type::name, begin, end, pad);      \
}

#define STUNXX_ATTRIBUTE_SOCKADDR_LIKE(name)                                  \
bits::socket_address name(const sockaddr *addr) {                             \
  return bits::socket_address(attribute::type::name, addr);                   \
}                                                                             \
bits::socket_address name(const sockaddr &addr) {                             \
  return bits::socket_address(attribute::type::name, &addr);                  \
}                                                                             \
bits::socket_address name(const sockaddr_in *addr) {                          \
  return bits::socket_address(attribute::type::name, (sockaddr*)addr);        \
}                                                                             \
bits::socket_address name(const sockaddr_in &addr) {                          \
  return bits::socket_address(attribute::type::name, (sockaddr*)&addr);       \
}                                                                             \
bits::socket_address name(const sockaddr_in6 *addr) {                         \
  return bits::socket_address(attribute::type::name, (sockaddr*)addr);        \
}                                                                             \
bits::socket_address name(const sockaddr_in6 &addr) {                         \
  return bits::socket_address(attribute::type::name, (sockaddr*)&addr);       \
}

#define STUNXX_ATTRIBUTE_XOR_SOCKADDR_LIKE(name)                              \
bits::xor_socket_address name(const sockaddr *addr) {                         \
  return bits::xor_socket_address(attribute::type::name, addr);               \
}                                                                             \
bits::xor_socket_address name(const sockaddr &addr) {                         \
  return bits::xor_socket_address(attribute::type::name, &addr);              \
}                                                                             \
bits::xor_socket_address name(const sockaddr_in *addr) {                      \
  return bits::xor_socket_address(attribute::type::name, (sockaddr*)addr);    \
}                                                                             \
bits::xor_socket_address name(const sockaddr_in &addr) {                      \
  return bits::xor_socket_address(attribute::type::name, (sockaddr*)&addr);   \
}                                                                             \
bits::xor_socket_address name(const sockaddr_in6 *addr) {                     \
  return bits::xor_socket_address(attribute::type::name, (sockaddr*)addr);    \
}                                                                             \
bits::xor_socket_address name(const sockaddr_in6 &addr) {                     \
  return bits::xor_socket_address(attribute::type::name, (sockaddr*)&addr);   \
}

#define STUNXX_ATTRIBUTE_EMPTY_LIKE(name)                                     \
bits::empty name() {                                                          \
  return bits::empty(attribute::type::name);                                  \
}

#define STUNXX_ATTRIBUTE_UINT8_LIKE(name)                                     \
bits::u8 name(uint8_t value) {                                                \
  return bits::u8(attribute::type::name, value);                              \
}

#define STUNXX_ATTRIBUTE_UINT8_PAD_LIKE(name)                                 \
bits::u8_pad name(uint8_t value, uint8_t pad = 0) {                           \
  return bits::u8_pad(attribute::type::name, value, pad);                     \
}

#define STUNXX_ATTRIBUTE_UINT16_LIKE(name)                                    \
bits::u16 name(uint16_t value) {                                              \
  return bits::u16(attribute::type::name, value);                             \
}

#define STUNXX_ATTRIBUTE_UINT16_PAD_LIKE(name)                                \
bits::u16_pad name(uint16_t value, uint8_t pad = 0) {                         \
  return bits::u16_pad(attribute::type::name, value, pad);                    \
}

#define STUNXX_ATTRIBUTE_UINT32_LIKE(name)                                    \
bits::u32 name(uint32_t value) {                                              \
  return bits::u32(attribute::type::name, value);                             \
}

#define STUNXX_ATTRIBUTE_UINT64_LIKE(name)                                    \
bits::u64 name(uint64_t value) {                                              \
  return bits::u64(attribute::type::name, value);                             \
}

STUNXX_ATTRIBUTE_SOCKADDR_LIKE(mapped_address)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(response_address)
STUNXX_ATTRIBUTE_UINT32_LIKE(change_request)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(source_address)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(changed_address)
STUNXX_ATTRIBUTE_STRING_LIKE(username)
STUNXX_ATTRIBUTE_STRING_LIKE(password)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(reflected_from)
STUNXX_ATTRIBUTE_UINT32_LIKE(channel_number)
STUNXX_ATTRIBUTE_UINT32_LIKE(lifetime)
STUNXX_ATTRIBUTE_UINT32_LIKE(bandwidth)
STUNXX_ATTRIBUTE_XOR_SOCKADDR_LIKE(xor_peer_address)
STUNXX_ATTRIBUTE_DATA_LIKE(data)
STUNXX_ATTRIBUTE_STRING_LIKE(realm)
STUNXX_ATTRIBUTE_STRING_LIKE(nonce)
STUNXX_ATTRIBUTE_XOR_SOCKADDR_LIKE(xor_relayed_address)
STUNXX_ATTRIBUTE_UINT8_LIKE(req_address_family)
STUNXX_ATTRIBUTE_UINT8_PAD_LIKE(even_port)
STUNXX_ATTRIBUTE_UINT32_LIKE(requested_transport)
STUNXX_ATTRIBUTE_EMPTY_LIKE(dont_fragment)
STUNXX_ATTRIBUTE_XOR_SOCKADDR_LIKE(xor_mapped_address)
STUNXX_ATTRIBUTE_UINT32_LIKE(timer_val)
STUNXX_ATTRIBUTE_UINT64_LIKE(reservation_token)
STUNXX_ATTRIBUTE_UINT32_LIKE(priority)
STUNXX_ATTRIBUTE_EMPTY_LIKE(use_candidate)
STUNXX_ATTRIBUTE_DATA_LIKE(padding)
STUNXX_ATTRIBUTE_UINT16_PAD_LIKE(response_port)
STUNXX_ATTRIBUTE_UINT32_LIKE(connection_id)
STUNXX_ATTRIBUTE_STRING_LIKE(software)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(alternate_server)
STUNXX_ATTRIBUTE_UINT64_LIKE(ice_controlled)
STUNXX_ATTRIBUTE_UINT64_LIKE(ice_controlling)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(response_origin)
STUNXX_ATTRIBUTE_SOCKADDR_LIKE(other_address)

#undef STUNXX_ATTRIBUTE_STRING_LIKE
#undef STUNXX_ATTRIBUTE_DATA_LIKE
#undef STUNXX_ATTRIBUTE_SOCKADDR_LIKE
#undef STUNXX_ATTRIBUTE_XOR_SOCKADDR_LIKE
#undef STUNXX_ATTRIBUTE_EMPTY_LIKE
#undef STUNXX_ATTRIBUTE_UINT8_LIKE
#undef STUNXX_ATTRIBUTE_UINT8_PAD_LIKE
#undef STUNXX_ATTRIBUTE_UINT16_LIKE
#undef STUNXX_ATTRIBUTE_UINT16_PAD_LIKE
#undef STUNXX_ATTRIBUTE_UINT32_LIKE
#undef STUNXX_ATTRIBUTE_UINT64_LIKE

bits::errcode error_code(int status_code, const char *reason,
                         uint8_t pad = 0) {
  return bits::errcode(status_code, reason, pad);
}

bits::unknown unknown_attributes(const uint16_t *data, size_t count,
                                 uint8_t pad = 0) {
  return bits::unknown(data, data + count, pad);
}

bits::unknown unknown_attributes(const uint16_t *begin,
                                 const uint16_t *end,
                                 uint8_t pad = 0) {
  return bits::unknown(begin, end, pad);
}

bits::msgint message_integrity(const char *key) {
  return bits::msgint(reinterpret_cast<const uint8_t*>(key), strlen(key));
}

bits::msgint message_integrity(const std::string &key) {
  return bits::msgint(reinterpret_cast<const uint8_t*>(key.c_str()),
      key.size());
}

bits::msgint message_integrity(const uint8_t *key, size_t key_len) {
  return bits::msgint(key, key_len);
}

bits::fingerprint fingerprint() {
  return bits::fingerprint();
}

} // namespace attribute

class message {
 public:
  class iterator {
   public:
    typedef iterator self_type;
    typedef size_t difference_type;
    typedef size_t size_type;
    typedef attribute::decoded value_type;
    typedef attribute::decoded* pointer;
    typedef attribute::decoded& reference;
    typedef std::forward_iterator_tag iterator_category;

    iterator(const stun_msg_hdr *msg_hdr, const uint8_t *ptr)
        : attr_(msg_hdr, reinterpret_cast<const stun_attr_hdr*>(ptr)) {}

    self_type operator++() {
      self_type it = *this;
      attr_ = attr_.next();
      return it;
    }

    self_type operator++(int) {
      attr_ = attr_.next();
      return *this;
    }

    const reference operator*() {
      return attr_;
    }
    const pointer operator->() {
      return &attr_;
    }

    bool operator==(const self_type& rhs) {
      return attr_.attr_ptr() == rhs.attr_.attr_ptr();
    }
    bool operator!=(const self_type& rhs) {
      return attr_.attr_ptr() != rhs.attr_.attr_ptr();
    }

   private:
    attribute::decoded attr_;
  };

  enum type {
    binding_request                   = STUN_BINDING_REQUEST,
    binding_response                  = STUN_BINDING_RESPONSE,
    binding_error_response            = STUN_BINDING_ERROR_RESPONSE,
    binding_indication                = STUN_BINDING_INDICATION,
    shared_secret_request             = STUN_SHARED_SECRET_REQUEST,
    shared_secret_response            = STUN_SHARED_SECRET_RESPONSE,
    shared_secret_error_response      = STUN_SHARED_SECRET_ERROR_RESPONSE,
    allocate_request                  = STUN_ALLOCATE_REQUEST,
    allocate_response                 = STUN_ALLOCATE_RESPONSE,
    allocate_error_response           = STUN_ALLOCATE_ERROR_RESPONSE,
    refresh_request                   = STUN_REFRESH_REQUEST,
    refresh_response                  = STUN_REFRESH_RESPONSE,
    refresh_error_response            = STUN_REFRESH_ERROR_RESPONSE,
    send_indication                   = STUN_SEND_INDICATION,
    data_indication                   = STUN_DATA_INDICATION,
    create_perm_request               = STUN_CREATE_PERM_REQUEST,
    create_perm_response              = STUN_CREATE_PERM_RESPONSE,
    create_perm_error_response        = STUN_CREATE_PERM_ERROR_RESPONSE,
    channel_bind_request              = STUN_CHANNEL_BIND_REQUEST,
    channel_bind_response             = STUN_CHANNEL_BIND_RESPONSE,
    channel_bind_error_response       = STUN_CHANNEL_BIND_ERROR_RESPONSE,
    connect_request                   = STUN_CONNECT_REQUEST,
    connect_response                  = STUN_CONNECT_RESPONSE,
    connect_error_response            = STUN_CONNECT_ERROR_RESPONSE,
    connection_bind_request           = STUN_CONNECTION_BIND_REQUEST,
    connection_bind_response          = STUN_CONNECTION_BIND_RESPONSE,
    connection_bind_error_response    = STUN_CONNECTION_BIND_ERROR_RESPONSE,
    connection_attempt_request        = STUN_CONNECTION_ATTEMPT_REQUEST,
    connection_attempt_response       = STUN_CONNECTION_ATTEMPT_RESPONSE,
    connection_attempt_error_response = STUN_CONNECTION_ATTEMPT_ERROR_RESPONSE,
  };

  message()
      : buffer_(sizeof(stun_msg_hdr), 0) {}

  message(uint16_t type, const uint8_t tsx_id[12])
      : buffer_(sizeof(stun_msg_hdr), 0) {
    stun_msg_hdr_init(hdr(), type, tsx_id);
  }

  void resize(size_t size) { buffer_.resize(size); }
  size_t capacity() const { return buffer_.size(); }

  uint8_t *data() { return buffer_.data(); }
  size_t size() const {
    return stun_msg_len(hdr());
  }

  uint16_t type() const {
    return stun_msg_type(hdr());
  }

  template<typename AttributeType>
  void push_back(const AttributeType &attr) {
    buffer_.resize(size() + attr.size());
    attr.append(reinterpret_cast<stun_msg_hdr*>(buffer_.data()));
  }

  iterator begin() const {
    return iterator(hdr(), buffer_.data() + sizeof(stun_msg_hdr));
  }

  iterator end() const {
    return iterator(hdr(), stun_msg_end(hdr()));
  }

 private:
  std::vector<uint8_t> buffer_;

  stun_msg_hdr *hdr() {
    return reinterpret_cast<stun_msg_hdr*>(buffer_.data());
  }
  const stun_msg_hdr *hdr() const {
    return reinterpret_cast<const stun_msg_hdr*>(buffer_.data());
  }
};

message &operator << (message &msg, const attribute::bits::empty &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::socket_address &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::xor_socket_address &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::varsize<char> &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::varsize<uint8_t> &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::u8 &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::u8_pad &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::u16 &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::u16_pad &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::u32 &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::u64 &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::errcode &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::unknown &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::msgint &attr) {
  msg.push_back(attr);
  return msg;
}
message &operator << (message &msg, const attribute::bits::fingerprint &attr) {
  msg.push_back(attr);
  return msg;
}

} // namespace stun

#endif // STUN_MESSAGE_H_
