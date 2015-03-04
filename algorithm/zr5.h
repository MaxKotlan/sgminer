#ifndef ZR5_H
#define ZR5_H

#include "miner.h"

#define ZR5_VERSION_MASK  0x00007FFF
#define ZR5_POK_BOOL_MASK 0x00008000
#define ZR5_POK_DATA_MASK 0xFFFF0000

#define ZR5_BLAKE	  0
#define ZR5_GROESTL	1
#define ZR5_JH		  2
#define ZR5_SKEIN	  3

extern const int zr5_order[][4];

extern void zr5_hash(void *state, const void *input);
extern int zr5_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce);
extern void zr5_regenhash(struct work *work);

#endif /* ZR5_H */
