/*-
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 *
 *  First, the polynomial itself and its table of feedback terms.  The
 *  polynomial is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0
 *
 *  Note that we take it "backwards" and put the highest-order term in
 *  the lowest-order bit.  The X^32 term is "implied"; the LSB is the
 *  X^31 term, etc.  The X^0 term (usually shown as "+1") results in
 *  the MSB being 1
 *
 *  Note that the usual hardware shift register implementation, which
 *  is what we're using (we're merely optimizing it by doing eight-bit
 *  chunks at a time) shifts bits into the lowest-order term.  In our
 *  implementation, that means shifting towards the right.  Why do we
 *  do it this way?  Because the calculated CRC must be transmitted in
 *  order from highest-order term to lowest-order term.  UARTs transmit
 *  characters in order from LSB to MSB.  By storing the CRC this way
 *  we hand it to the UART in the order low-byte to high-byte; the UART
 *  sends each low-bit to hight-bit; and the result is transmission bit
 *  by bit from highest- to lowest-order term without requiring any bit
 *  shuffling on our part.  Reception works similarly
 *
 *  The feedback terms table consists of 256, 32-bit entries.  Notes
 *
 *      The table can be generated at runtime if desired; code to do so
 *      is shown later.  It might not be obvious, but the feedback
 *      terms simply represent the results of eight shift/xor opera
 *      tions for all combinations of data and CRC register values
 *
 *      The values must be right-shifted by eight bits by the "updcrc
 *      logic; the shift must be unsigned (bring in zeroes).  On some
 *      hardware you could probably optimize the shift in assembler by
 *      using byte-swap instructions
 *      polynomial $edb88320
 *
 *
 * CRC32 code derived from work by Gary S. Brown.
 */

#include "crc32.h"

static uint32_t crc32_tab[] = {
  0x00000000ul, 0x77073096ul, 0xee0e612cul, 0x990951baul, 0x076dc419ul, 0x706af48ful,
  0xe963a535ul, 0x9e6495a3ul, 0x0edb8832ul, 0x79dcb8a4ul, 0xe0d5e91eul, 0x97d2d988ul,
  0x09b64c2bul, 0x7eb17cbdul, 0xe7b82d07ul, 0x90bf1d91ul, 0x1db71064ul, 0x6ab020f2ul,
  0xf3b97148ul, 0x84be41deul, 0x1adad47dul, 0x6ddde4ebul, 0xf4d4b551ul, 0x83d385c7ul,
  0x136c9856ul, 0x646ba8c0ul, 0xfd62f97aul, 0x8a65c9ecul, 0x14015c4ful, 0x63066cd9ul,
  0xfa0f3d63ul, 0x8d080df5ul, 0x3b6e20c8ul, 0x4c69105eul, 0xd56041e4ul, 0xa2677172ul,
  0x3c03e4d1ul, 0x4b04d447ul, 0xd20d85fdul, 0xa50ab56bul, 0x35b5a8faul, 0x42b2986cul,
  0xdbbbc9d6ul, 0xacbcf940ul, 0x32d86ce3ul, 0x45df5c75ul, 0xdcd60dcful, 0xabd13d59ul,
  0x26d930acul, 0x51de003aul, 0xc8d75180ul, 0xbfd06116ul, 0x21b4f4b5ul, 0x56b3c423ul,
  0xcfba9599ul, 0xb8bda50ful, 0x2802b89eul, 0x5f058808ul, 0xc60cd9b2ul, 0xb10be924ul,
  0x2f6f7c87ul, 0x58684c11ul, 0xc1611dabul, 0xb6662d3dul, 0x76dc4190ul, 0x01db7106ul,
  0x98d220bcul, 0xefd5102aul, 0x71b18589ul, 0x06b6b51ful, 0x9fbfe4a5ul, 0xe8b8d433ul,
  0x7807c9a2ul, 0x0f00f934ul, 0x9609a88eul, 0xe10e9818ul, 0x7f6a0dbbul, 0x086d3d2dul,
  0x91646c97ul, 0xe6635c01ul, 0x6b6b51f4ul, 0x1c6c6162ul, 0x856530d8ul, 0xf262004eul,
  0x6c0695edul, 0x1b01a57bul, 0x8208f4c1ul, 0xf50fc457ul, 0x65b0d9c6ul, 0x12b7e950ul,
  0x8bbeb8eaul, 0xfcb9887cul, 0x62dd1ddful, 0x15da2d49ul, 0x8cd37cf3ul, 0xfbd44c65ul,
  0x4db26158ul, 0x3ab551ceul, 0xa3bc0074ul, 0xd4bb30e2ul, 0x4adfa541ul, 0x3dd895d7ul,
  0xa4d1c46dul, 0xd3d6f4fbul, 0x4369e96aul, 0x346ed9fcul, 0xad678846ul, 0xda60b8d0ul,
  0x44042d73ul, 0x33031de5ul, 0xaa0a4c5ful, 0xdd0d7cc9ul, 0x5005713cul, 0x270241aaul,
  0xbe0b1010ul, 0xc90c2086ul, 0x5768b525ul, 0x206f85b3ul, 0xb966d409ul, 0xce61e49ful,
  0x5edef90eul, 0x29d9c998ul, 0xb0d09822ul, 0xc7d7a8b4ul, 0x59b33d17ul, 0x2eb40d81ul,
  0xb7bd5c3bul, 0xc0ba6cadul, 0xedb88320ul, 0x9abfb3b6ul, 0x03b6e20cul, 0x74b1d29aul,
  0xead54739ul, 0x9dd277aful, 0x04db2615ul, 0x73dc1683ul, 0xe3630b12ul, 0x94643b84ul,
  0x0d6d6a3eul, 0x7a6a5aa8ul, 0xe40ecf0bul, 0x9309ff9dul, 0x0a00ae27ul, 0x7d079eb1ul,
  0xf00f9344ul, 0x8708a3d2ul, 0x1e01f268ul, 0x6906c2feul, 0xf762575dul, 0x806567cbul,
  0x196c3671ul, 0x6e6b06e7ul, 0xfed41b76ul, 0x89d32be0ul, 0x10da7a5aul, 0x67dd4accul,
  0xf9b9df6ful, 0x8ebeeff9ul, 0x17b7be43ul, 0x60b08ed5ul, 0xd6d6a3e8ul, 0xa1d1937eul,
  0x38d8c2c4ul, 0x4fdff252ul, 0xd1bb67f1ul, 0xa6bc5767ul, 0x3fb506ddul, 0x48b2364bul,
  0xd80d2bdaul, 0xaf0a1b4cul, 0x36034af6ul, 0x41047a60ul, 0xdf60efc3ul, 0xa867df55ul,
  0x316e8eeful, 0x4669be79ul, 0xcb61b38cul, 0xbc66831aul, 0x256fd2a0ul, 0x5268e236ul,
  0xcc0c7795ul, 0xbb0b4703ul, 0x220216b9ul, 0x5505262ful, 0xc5ba3bbeul, 0xb2bd0b28ul,
  0x2bb45a92ul, 0x5cb36a04ul, 0xc2d7ffa7ul, 0xb5d0cf31ul, 0x2cd99e8bul, 0x5bdeae1dul,
  0x9b64c2b0ul, 0xec63f226ul, 0x756aa39cul, 0x026d930aul, 0x9c0906a9ul, 0xeb0e363ful,
  0x72076785ul, 0x05005713ul, 0x95bf4a82ul, 0xe2b87a14ul, 0x7bb12baeul, 0x0cb61b38ul,
  0x92d28e9bul, 0xe5d5be0dul, 0x7cdcefb7ul, 0x0bdbdf21ul, 0x86d3d2d4ul, 0xf1d4e242ul,
  0x68ddb3f8ul, 0x1fda836eul, 0x81be16cdul, 0xf6b9265bul, 0x6fb077e1ul, 0x18b74777ul,
  0x88085ae6ul, 0xff0f6a70ul, 0x66063bcaul, 0x11010b5cul, 0x8f659efful, 0xf862ae69ul,
  0x616bffd3ul, 0x166ccf45ul, 0xa00ae278ul, 0xd70dd2eeul, 0x4e048354ul, 0x3903b3c2ul,
  0xa7672661ul, 0xd06016f7ul, 0x4969474dul, 0x3e6e77dbul, 0xaed16a4aul, 0xd9d65adcul,
  0x40df0b66ul, 0x37d83bf0ul, 0xa9bcae53ul, 0xdebb9ec5ul, 0x47b2cf7ful, 0x30b5ffe9ul,
  0xbdbdf21cul, 0xcabac28aul, 0x53b39330ul, 0x24b4a3a6ul, 0xbad03605ul, 0xcdd70693ul,
  0x54de5729ul, 0x23d967bful, 0xb3667a2eul, 0xc4614ab8ul, 0x5d681b02ul, 0x2a6f2b94ul,
  0xb40bbe37ul, 0xc30c8ea1ul, 0x5a05df1bul, 0x2d02ef8dul
};

uint32_t crc32(uint32_t crc, const void *buf, size_t size)
{
  const uint8_t *p = (uint8_t *)buf;
  crc = crc ^ ~0UL;

  while (size--)
    crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

  return crc ^ ~0UL;
}
