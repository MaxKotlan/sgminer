/*-
 * Copyright 2015 ziftrCOIN, LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sph/sph_blake.h"
#include "sph/sph_groestl.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"
#include "sph/sph_skein.h"

#include "zr5.h"
#include "util.h"

//ziftr coin order
const int zr5_order[][4] =
{
    {0, 1, 2, 3},
    {0, 1, 3, 2},
    {0, 2, 1, 3},
    {0, 2, 3, 1},
    {0, 3, 1, 2},
    {0, 3, 2, 1},
    {1, 0, 2, 3},
    {1, 0, 3, 2},
    {1, 2, 0, 3},
    {1, 2, 3, 0},
    {1, 3, 0, 2},
    {1, 3, 2, 0},
    {2, 0, 1, 3},
    {2, 0, 3, 1},
    {2, 1, 0, 3},
    {2, 1, 3, 0},
    {2, 3, 0, 1},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {3, 0, 2, 1},
    {3, 1, 0, 2},
    {3, 1, 2, 0},
    {3, 2, 0, 1},
    {3, 2, 1, 0}
};

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct
{
  sph_keccak512_context   keccak1;
  sph_blake512_context    blake1;
  sph_groestl512_context  groestl1;
  sph_jh512_context       jh1;
  sph_skein512_context    skein1;
} ZR5hash_context_holder;

static ZR5hash_context_holder base_contexts;

void init_ZR5hash_contexts()
{
  sph_keccak512_init(&base_contexts.keccak1);
  sph_blake512_init(&base_contexts.blake1);
  sph_groestl512_init(&base_contexts.groestl1);
  sph_jh512_init(&base_contexts.jh1);
  sph_skein512_init(&base_contexts.skein1);
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
  uint32_t i;

  for (i = 0; i < len; i++)
    dst[i] = htobe32(src[i]);
}


void zr5_hash(void *state, const void *input)
{
  init_ZR5hash_contexts();

  ZR5hash_context_holder ctx;

  uint32_t hashA[16], hashB[16];
  memcpy(&ctx, &base_contexts, sizeof(base_contexts));

  //keccak first to get the order
  sph_keccak512 (&ctx.keccak1, input, 80);
  sph_keccak512_close(&ctx.keccak1, hashA);

  void *in, *out;
  unsigned int order = (unsigned int)(hashA[0] % 24);

  int r = 0;
  do {
    in = (void *)(((r % 2) == 0) ? hashA : hashB );
    out = (void *)(((r % 2) == 0) ? hashB : hashA );

    switch(zr5_order[order][r]) {
      case ZR5_BLAKE:
        sph_blake512 (&ctx.blake1, in, 64);
        sph_blake512_close (&ctx.blake1, out);
        break;

      case ZR5_GROESTL:
        sph_groestl512 (&ctx.groestl1, in, 64);
        sph_groestl512_close(&ctx.groestl1, out);
        break;

      case ZR5_JH:
        sph_jh512 (&ctx.jh1, in, 64);
        sph_jh512_close(&ctx.jh1, out);
        break;

      case ZR5_SKEIN:
        sph_skein512 (&ctx.skein1, in, 64);
        sph_skein512_close(&ctx.skein1, out);
        break;
    }
  } while(++r < 4);

  memcpy(state, out, 32);
}

static const uint32_t diff1targ = 0x0000ffff;

/* Used externally as confirmation of correct OCL code */
int zr5_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8], hash[8];

	*((uint32_t *)(pdata + 76)) = nonce;//htole32(nonce);
  printf("nonce data: %s\n\n", bin2hex((unsigned char *)pdata, 80));

	zr5_hash(ohash, pdata);
/*	be32enc_vect(data, (const uint32_t *)pdata, 19);
	//data[19] = htobe32(nonce);
  printf("be32enc: %s\n\n", bin2hex((unsigned char *)data, 80));
	ziftr_hash(ohash, data);*/

  printf("hash data: %s\n\n", bin2hex((unsigned char *)ohash, 32));

//	tmp_hash7 = be32toh(hash[7]);
	tmp_hash7 = ohash[7];

  printf("htarget %08lx diff1 %08lx hash %08lx\n",
    (long unsigned int)Htarg,
		(long unsigned int)diff1targ,
		(long unsigned int)tmp_hash7);

	applog(LOG_DEBUG, "htarget %08lx diff1 %08lx hash %08lx",
    (long unsigned int)Htarg,
		(long unsigned int)diff1targ,
		(long unsigned int)tmp_hash7);

	if (tmp_hash7 > diff1targ)
		return -1;

	if (tmp_hash7 > Htarg)
		return 0;

	return 1;
}

void zr5_regenhash(struct work *work)
{
  uint32_t data[20];
  uint32_t res[8];
  uint32_t *nonce = (uint32_t *)(work->data + 76);
  uint32_t *ohash = (uint32_t *)(work->hash);

  uint32_t n = *nonce;
  memcpy(data, work->data, 76);

  uint32_t version = data[0];
  data[19] = n;

  //hash first to get PoK
  zr5_hash(res, data);

  //apply PoK to header
  data[0] = version | (res[0] & ZR5_POK_DATA_MASK);

  //apply PoK to work->data header also so it's included in return hash -- probably should be done elsewhere...
  *((uint32_t *)work->data) = data[0];

  //final hash
  zr5_hash(ohash, data);
}

//[FIXME] -- cpu function... just in case we ever need it
bool scanhash_zr5(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
		     unsigned char *pdata, unsigned char __maybe_unused *phash1,
		     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	//uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	//be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1)
  {
    uint32_t ostate[8];

    *nonce = ++n;
    //data[19] = (n);
    zr5_hash(ostate, pdata);
    tmp_hash7 = (ostate[7]);

    applog(LOG_INFO, "data7 %08lx",	(long unsigned int)pdata[7]);

    if (unlikely(tmp_hash7 <= Htarg)) {
      //((uint32_t *)pdata)[19] = htobe32(n);
      //*nonce = n;
      printf("%08lx: %08lx <= %08lx\n", n, tmp_hash7, Htarg);
      *last_nonce = n;
      ret = true;
      break;
    }
    else if (unlikely((n >= max_nonce) || thr->work_restart)) {
      printf("%08lx: >= %08lx\n", n, max_nonce);
      *last_nonce = n;
      break;
    }
	}

  printf("done.\n");

	return ret;
}
