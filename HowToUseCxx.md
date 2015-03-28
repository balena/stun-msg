# Introduction #

STUN-based client and servers are much easier to implement when you have a
message encoder/decoder. This library has been written aiming to provide you a
simple STUN message encoder/decoder.

This documentation describes the C++ library. If your code is in C, then
reference to the [C documentation](HowToUseC.md).


# The C++ library #

In short, `stun-msg.c++` is a cross-platform C++ library for encoding and
decoding STUN messages. The C++ API provides the same support available on the
C library, but it has been adapted to ease the object-oriented programming, and
provide type safety.

`stun-msg.c++` is a header-only library built on top of the `stun-msg` C
library, so when integrating into your code, you will need both.


## Dependencies ##

`stun-msg.c++` depends on the following libraries:

  * `stun-msg` C library;
  * C++ **Standard Template Library**;


# The namespaces #

Everything in stun-msg C++ library resides in the `stun` namespace, or a
sub-namespace of it:

  * `stun`: There is where core classes reside. The most important classes here are the `message` and `message_piece`.
  * `stun::attribute`: This is where the functions used for encoding STUN messages reside. There are several functions, named after the STUN attribute names, like `username`, `xor_peer_address`, `data`, `realm`, `nonce` and `xor_relayed_address`. These functions are overloaded to adapt to different usages on your program.
  * `stun::attribute::type`: This namespace contains the STUN message attribute enumeration `attribute_type`.
  * `stun::attribute::decoding`: This namespace contains STUN message decoding helpers for each supported attribute.


# Encoding STUN messages #

The memory allocation is performed automatically by the `stun::message` class,
in heap. Check the **STUN Binding Request** example below:

```
#include <stun++/message.h>

int send_stun_request(/* ... */) {
  // Create the STUN message object
  stun::message msg(stun::message::binding_request, tsx_id);

  // Add a SOFTWARE attribute
  msg << stun::attribute::software(software_name);

  // Add a PRIORITY attribute
  msg << stun::attribute::priority(0x6e0001fful);

  // Add a ICE-CONTROLLED attribute
  msg << stun::attribute::ice_controlled(0x932ff9b151263b36ull);

  // Add a USERNAME attribute
  msg << stun::attribute::username(username);

  // Appends a MESSAGE-INTEGRITY attribute
  msg << stun::attribute::message_integrity(key);

  // Appends a FINGERPRINT attribute as last attribute
  msg << stun::attribute::fingerprint();

  // Now, send the message
  send(msg.data(), msg.size());

  return status;
}
```


# Decoding STUN messages #

The decoding part is simple, but it will depend on the socket type you're
working on.

## Datagram sockets ##

For datagram sockets you usually allocate a max permitted memory block size,
and simply begin parsing it. In this case, you can do the following:

```
#include <stun++/message.h>

void receive_message(/* ... */) {
  stun::message msg;

  // Allocate a 2k memory block
  msg.resize(2*1024);

  // Receive network data directly into your STUN message block
  size_t bytes = receive(msg.data(), msg.capacity());

  // Reduce the size to the packet size
  msg.resize(bytes);

  // Check if this is a STUN message
  if (!msg.verify()) {
    abort("Invalid STUN message");
  }

  // Read the message type
  switch (msg.type()) {
    case stun::message::binding_request:
      // ...
      break;
    case stun::message::binding_response:
      // ...
      break;
    // etc...
  }

  // Iterate over the message attributes
  using namespace stun::attribute;
  for (stun::message::iterator i = msg.begin(), ie = msg.end(); i != ie; i++) {
    // First, check the attribute type
    switch (i->type()) {
      case type::software:
        software = i->to<type::software>().to_string();
        break;
      case type::username:
        username = i->to<type::username>().to_string();
        break;
      case type::xor_mapped_address:
        sockaddr_storage address;
        i->to<type::xor_mapped_address>().to_sockaddr((sockaddr*)&address));
        break;
      // etc...
    }
  }
}
```

## Stream sockets ##

First receive the STUN message header, then the rest of the message:

```
#include <stun++/message.h>

void receive_message(/* ... */) {
  stun::message msg;

  // Receive network data directly into your STUN message block. The default
  // constructor already allocates the size needed to receive the STUN message
  // header (20 bytes).
  size_t bytes = receive(msg.data(), msg.capacity());
  if (bytes < stun::message::header_size)
    abort("STUN message truncated");

  // Now, get the total message size and receive the attribute block
  if (msg.size() > msg.capacity()) {
    size_t read_bytes = msg.size();
    msg.resize(msg.size());
    receive(msg.data() + read_bytes, msg.size() - read_bytes);
  }

  // Handle the message ...
}
```

## The `message_piece` ##

The `stun::message_piece` class is basically a pointer to a STUN message that
is owned elsewhere with a length of how many bytes from the other buffer form
the message block.

Use this class when you're decoding STUN messages and the memory has been
allocated by other means, like when you're mixing STUN protocol with other
protocols, like SIP or RTP.
