/* 
 * COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 * code or tables extracted from it, as desired without restriction.
 */

#ifndef __CRC32_H__
#define __CRC32_H__

#include <stdint.h>

uint32_t crc32(uint32_t crc, const void *buf, size_t size);

#endif /* __CRC32_H__ */
