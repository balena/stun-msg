# Introduction #

STUN-based client and servers are much easier to implement when you have a
message encoder/decoder. This library has been written aiming to provide you a
simple STUN message encoder/decoder.

This documentation describes the C library. If your code is in C++, then
reference to the [C++ documentation](HowToUseCxx.md).


# The C library #

`stun-msg` is a cross-platform C library for encoding and decoding STUN
messages.

It's objective is to ease the work of handling STUN messages, abstracting the
low-level concepts of padding, conversions from/to system types, checksums and
integrity checking.

The library is portable and works across most operating systems, depending
on the **C standard library** and a very small portion of the networking library
of the system (**BSD sockets** or **Windows sockets**), specifically for encoding
and decoding IP addresses using `struct sockaddr`, `struct sockaddr_in` and
`struct sockaddr_in6`.

The library has been tested on the following platforms and compilers:

  * 32-bit and 64-bit Windows, using Visual C++ 2010 and above.
  * Windows using MinGW.
  * Windows using Cygwin.
  * Linux, using gcc 4.0 and above.
  * Mac OSX 10.6+, using gcc 4.0 and above.

It may also work on other platforms, though not yet tested.


## Dependencies ##

`stun-msg` depends on the following system libraries:

  * **C standard library**;
  * **BSD sockets** or **Windows sockets** library;

A note, case you need to support older Visual Studio versions: the library is
based on the header `stdint.h`, available on
[msinttypes](https://code.google.com/p/msinttypes/) project.


# Encoding STUN messages #

First, the basics. All you have to do is to allocate some memory and start
calling the encoding functions. Check the **STUN Binding Request** example below:

```
#include <stun/msg.h>

int send_stun_request(/* ... */) {
  int status;

  size_t buf_len = /* buffer size */;
  uint8_t *buf = /* allocated on you own */

  /* Initialize the STUN message header */
  stun_msg_hdr *msg_hdr = (stun_msg_hdr *)buf;
  stun_msg_hdr_init(msg_hdr, STUN_BINDING_REQUEST, tsx_id);  

  /* Add a SOFTWARE attribute, which is of type variable-size */
  stun_attr_varsize_add(msg_hdr, STUN_SOFTWARE, software_name,
        strlen(software_name), 0);

  /* Add a PRIORITY attribute, which is of type 32-bits */
  stun_attr_uint32_add(msg_hdr, STUN_PRIORITY, 0x6e0001fful);

  /* Add a ICE-CONTROLLED attribute, which is of type 64-bits */
  stun_attr_uint64_add(msg_hdr, STUN_ICE_CONTROLLED, 0x932ff9b151263b36ull);

  /* Add a USERNAME attribute, which is of type variable-size */
  stun_attr_varsize_add(msg_hdr, STUN_USERNAME, username,
        strlen(username), 0);

  /* Appends a MESSAGE-INTEGRITY attribute */
  stun_attr_msgint_add(msg_hdr, key, strlen(key));

  /* Appends a FINGERPRINT attribute as last one */
  stun_attr_fingerprint_add(msg_hdr);

  /* Now, the buffer is set, send the message */

  return status;
}
```

This library assumes you provide allocated memory sufficiently sized to
accommodate the whole STUN message. This decision is based on the fact that you
may already have your own ways to allocate memory using the heap, stack, memory
pools, C or C++ libraries, so it won't interfere with your work.

It follows below two approaches for allocating memory using C.

## Stack allocation ##

There are cases where you have fixed sizes (or at least a maximum for each
attribute length), and then you may opt to allocate the buffer on the stack.
Check how to do this:

```
#include <stun/msg.h>

const char software_name[] = "my server";
const size_t max_username_length = 20;

int send_stun_request(/* ... */) {
  uint8_t buf[sizeof(stun_msg_hdr) /* STUN header size */
    + STUN_ATTR_VARSIZE_SIZE(sizeof(software_name) - 1)
    + STUN_ATTR_UINT32_SIZE
    + STUN_ATTR_UINT64_SIZE
    + STUN_ATTR_VARSIZE_SIZE(max_username_length)
    + STUN_ATTR_MSGINT_SIZE
    + STUN_ATTR_FINGERPRINT_SIZE];

  size_t buf_len = sizeof(buf); /* Note that for variable sized
                                 * usernames, sizeof(buf) may not be
                                 * correct, see below
                                 */

  stun_msg_hdr *msg_hdr = (stun_msg_hdr *)buf;

  /* Initialize the STUN message here */

  /* If the username has variable sizes, obtain the final
   * STUN message size this way:
   */
  buf_len = stun_msg_len(msg_hdr);
}
```


## Dynamic C (re)allocation ##

There will exist other cases where you want to provide more flexibility to the
application, then you can allocate on the heap this way:

```
#include <stun/msg.h>

int send_stun_request(/* ... */) {
  size_t buf_len = sizeof(stun_msg_hdr);
  uint8_t *buffer = (uint8_t *)malloc(buf_len);

  /* Initialize the STUN message header */
  stun_msg_hdr *msg_hdr = (stun_msg_hdr *)buf;
  stun_msg_hdr_init(msg_hdr, STUN_BINDING_REQUEST, tsx_id);  

  /* Add a SOFTWARE attribute, which is of type variable-size */
  buf_len += STUN_ATTR_VARSIZE_SIZE(strlen(software_name));
  msg_hdr = (stun_msg_hdr *)realloc(buf, buf_len);
  stun_attr_varsize_add(msg_hdr, STUN_SOFTWARE, software_name,
        strlen(software_name), 0);

  /* ... */
}
```


# Decoding STUN messages #

The decoding part is the easiest. On your program, you will have to start
receiving data from stream or datagram sockets.

Indeed, they will force you do adopt different reading approaches.

## Datagram sockets ##

For datagram sockets you usually allocate a max permitted memory block size,
and simply parse it. In this case, you can do the following:

```
#include <stun/msg.h>

void parse_incoming_message(uint8_t *packet, size_t packet_len) {
  stun_msg_hdr *msg_hdr = (stun_msg_hdr *)packet;
  stun_attr_hdr *attr_hdr = NULL;

  /* First of all, you will want to check if this is indeed a
   * STUN message. This function will check the first bytes of the
   * message, and check the size of each attribute against buffer
   * overflow attempts. Also, if a FINGERPRINT attribute is present,
   * it's going to be checked as well.
   */
  if (!stun_msg_verify(msg_hdr, packet_len)) {
    abort("Invalid STUN message");
  }

  /* Read the message type */
  switch (stun_msg_type(msg_hdr)) {
    case STUN_BINDING_REQUEST:
      /* ... */
      break;
    case STUN_BINDING_RESPONSE:
      /* ... */
      break;
    /* etc... */
  }

  /* Iterate over the message attributes */
  while ((attr_hdr = stun_msg_next_attr(msg_hdr, attr_hdr)) != NULL) {
    /* First, check the attribute type */
    switch (stun_attr_type(attr_hdr)) {
      case STUN_SOFTWARE:
        /* ... */
        break;
      case STUN_USERNAME:
        /* ... */
        break;
      case STUN_XOR_MAPPED_ADDRESS:
        /* ... */
        break;
      /* etc... */
    }
  }
}
```

## Stream sockets ##

The strategy here is to read the STUN message header first (or at least the 4
initial bytes, namely the message type and the length), then obtain the full
message size, and read the remaining.

Here's one approach:

```
#include <stun/msg.h>

void read_socket(/* ... */) {
  int status;
  size_t msg_len = sizeof(stun_msg_hdr);
  stun_msg_hdr *msg_hdr =
    (stun_msg_hdr *)malloc(buf_len);
  size_t done;
  uint8_t *buf;

  /* First, read the STUN message header */
  done = 0;
  buf = (uint8_t *)msg_hdr;
  do {
    status = recv(sockfd, buf + done, msg_len - done, 0);
    if (status > 0) {
      done += status;
    } else {
      /* handle error */
    }
  } while (done < msg_len);

  /* Now the STUN message header is complete */
  msg_len = stun_msg_len(msg_hdr);
  todo = msg_len - sizeof(stun_msg_hdr);
  msg_hdr = (stun_msg_hdr *)realloc(msg_hdr, buf_len);

  /* Read the message remaining */
  buf = (uint8_t *)msg_hdr;
  do {
    status = recv(sockfd, buf + done, msg_len - done, 0);
    if (status > 0) {
      done += status;
    } else {
      /* handle error */
    }
  } while (done < msg_len);

  /* Parse the message as in datagram socket */
}
```

# The several STUN attribute types #

It follows below a list of all attributes supported by the library, along it's types and values:

| **Attribute**               | **Value** | **Type Name**                | **Type**                   | **Reference** |
|:----------------------------|:----------|:-----------------------------|:---------------------------|:--------------|
| MAPPED-ADDRESS            | 0x0001  | `STUN_MAPPED_ADDRESS`      | `stun_attr_sockaddr`     | [RFC5389](http://www.iana.org/go/rfc5389) |
| RESPONSE-ADDRESS          | 0x0002  | `STUN_RESPONSE_ADDRESS`    | `stun_attr_sockaddr`     | [RFC5389](http://www.iana.org/go/rfc5389) |
| CHANGE-REQUEST            | 0x0003  | `STUN_CHANGE_REQUEST`      | `stun_attr_uint32`       | [RFC5780](http://www.iana.org/go/rfc5780) |
| SOURCE-ADDRESS            | 0x0004  | `STUN_SOURCE_ADDRESS`      | `stun_attr_sockaddr`     | [RFC5389](http://www.iana.org/go/rfc5389) |
| CHANGED-ADDRESS           | 0x0005  | `STUN_CHANGED_ADDRESS`     | `stun_attr_sockaddr`     | [RFC5389](http://www.iana.org/go/rfc5389) |
| USERNAME                  | 0x0006  | `STUN_USERNAME`            | `stun_attr_varsize`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| PASSWORD                  | 0x0007  | `STUN_PASSWORD`            | `stun_attr_varsize`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| MESSAGE-INTEGRITY         | 0x0008  | `STUN_MESSAGE_INTEGRITY`   | `stun_attr_msgint`       | [RFC5389](http://www.iana.org/go/rfc5389) |
| ERROR-CODE                | 0x0009  | `STUN_ERROR_CODE`          | `stun_attr_errcode`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| UNKNOWN-ATTRIBUTES        | 0x000A  | `STUN_UNKNOWN_ATTRIBUTES`  | `stun_attr_unknown`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| REFLECTED-FROM            | 0x000B  | `STUN_REFLECTED_FROM`      | `stun_attr_sockaddr`     | [RFC5389](http://www.iana.org/go/rfc5389) |
| CHANNEL-NUMBER            | 0x000C  | `STUN_CHANNEL_NUMBER`      | `stun_attr_uint32`       | [RFC5766](http://www.iana.org/go/rfc5766) |
| LIFETIME                  | 0x000D  | `STUN_LIFETIME`            | `stun_attr_uint32`       | [RFC5766](http://www.iana.org/go/rfc5766) |
| BANDWIDTH                 | 0x0010  | `STUN_BANDWIDTH`           | `stun_attr_uint32`       | [RFC5766](http://www.iana.org/go/rfc5766) |
| XOR-PEER-ADDRESS          | 0x0012  | `STUN_XOR_PEER_ADDRESS`    | `stun_attr_xor_sockaddr` | [RFC5766](http://www.iana.org/go/rfc5766) |
| DATA                      | 0x0013  | `STUN_DATA`                | `stun_attr_varsize`      | [RFC5766](http://www.iana.org/go/rfc5766) |
| REALM                     | 0x0014  | `STUN_REALM`               | `stun_attr_varsize`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| NONCE                     | 0x0015  | `STUN_NONCE`               | `stun_attr_varsize`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| XOR-RELAYED-ADDRESS       | 0x0016  | `STUN_XOR_RELAYED_ADDRESS` | `stun_attr_xor_sockaddr` | [RFC5766](http://www.iana.org/go/rfc5766) |
| REQUESTED-ADDRESS-FAMILY  | 0x0017  | `STUN_REQ_ADDRESS_FAMILY`  | `stun_attr_uint8`        | [RFC6156](http://www.iana.org/go/rfc6156) |
| EVEN-PORT                 | 0x0018  | `STUN_EVEN_PORT`           | `stun_attr_uint8_pad`    | [RFC5766](http://www.iana.org/go/rfc5766) |
| REQUESTED-TRANSPORT       | 0x0019  | `STUN_REQUESTED_TRANSPORT` | `stun_attr_uint32`       | [RFC5766](http://www.iana.org/go/rfc5766) |
| DONT-FRAGMENT             | 0x001A  | `STUN_DONT_FRAGMENT`       | **empty**                  | [RFC5766](http://www.iana.org/go/rfc5766) |
| XOR-MAPPED-ADDRESS        | 0x0020  | `STUN_XOR_MAPPED_ADDRESS`  | `stun_attr_xor_sockaddr` | [RFC5389](http://www.iana.org/go/rfc5389) |
| TIMER-VAL                 | 0x0021  | `STUN_TIMER_VAL`           | `stun_attr_uint32`       | [RFC5766](http://www.iana.org/go/rfc5766) |
| RESERVATION-TOKEN         | 0x0022  | `STUN_RESERVATION_TOKEN`   | `stun_attr_uint64`       | [RFC5766](http://www.iana.org/go/rfc5766) |
| PRIORITY                  | 0x0024  | `STUN_PRIORITY`            | `stun_attr_uint32`       | [RFC5245](http://www.iana.org/go/rfc5245) |
| USE-CANDIDATE             | 0x0025  | `STUN_USE_CANDIDATE`       | **empty**                  | [RFC5245](http://www.iana.org/go/rfc5245) |
| PADDING                   | 0x0026  | `STUN_PADDING`             | `stun_attr_varsize`      | [RFC5780](http://www.iana.org/go/rfc5780) |
| RESPONSE-PORT             | 0x0027  | `STUN_RESPONSE_PORT`       | `stun_attr_uint16_pad`   | [RFC5780](http://www.iana.org/go/rfc5780) |
| CONNECTION-ID             | 0x002A  | `STUN_CONNECTION_ID`       | `stun_attr_uint32`       | [RFC6062](http://www.iana.org/go/rfc6062) |
| SOFTWARE                  | 0x8022  | `STUN_SOFTWARE`            | `stun_attr_varsize`      | [RFC5389](http://www.iana.org/go/rfc5389) |
| ALTERNATE-SERVER          | 0x8023  | `STUN_ALTERNATE_SERVER`    | `stun_attr_sockaddr`     | [RFC5389](http://www.iana.org/go/rfc5389) |
| FINGERPRINT               | 0x8028  | `STUN_FINGERPRINT`         | `stun_attr_uint32`       | [RFC5389](http://www.iana.org/go/rfc5389) |
| ICE-CONTROLLED            | 0x8029  | `STUN_ICE_CONTROLLED`      | `stun_attr_uint64`       | [RFC5245](http://www.iana.org/go/rfc5245) |
| ICE-CONTROLLING           | 0x802A  | `STUN_ICE_CONTROLLING`     | `stun_attr_uint64`       | [RFC5245](http://www.iana.org/go/rfc5245) |
| RESPONSE-ORIGIN           | 0x802B  | `STUN_RESPONSE_ORIGIN`     | `stun_attr_sockaddr`     | [RFC5780](http://www.iana.org/go/rfc5780) |
| OTHER-ADDRESS             | 0x802C  | `STUN_OTHER_ADDRESS`       | `stun_attr_sockaddr`     | [RFC5780](http://www.iana.org/go/rfc5780) |

Remember that XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS and XOR-MAPPED-ADDRESS
attributes must use the following functions:

```
/* Initializes a XOR'ed sockaddr attribute */
int stun_attr_xor_sockaddr_init(stun_attr_xor_sockaddr *attr,
                                uint16_t type, const struct sockaddr *addr,
                                const stun_msg_hdr *msg_hdr);

/* Adds a XOR'ed sockaddr attribute to the message end */
int stun_attr_xor_sockaddr_add(stun_msg_hdr *msg_hdr,
                               uint16_t type, const struct sockaddr *addr);


/* Reads a XOR'red sockaddr attribute. Returns error case the address family
 * is unknown (should be STUN_IPV4 or STUN_IPV6).
 */
int stun_attr_xor_sockaddr_read(const stun_attr_xor_sockaddr *attr,
                                const stun_msg_hdr *msg_hdr,
                                struct sockaddr *addr);
```