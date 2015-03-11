/*
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
#include "algorithm.h"
#include "ocl.h"
#include "ocl/build_kernel.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sph/sph_blake.h"
#include "sph/sph_groestl.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"
#include "sph/sph_skein.h"

#include "zr5.h"
#include "findnonce.h"
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
  uint32_t *ohash = (uint32_t *)(work->hash);
  uint32_t *nonce = (uint32_t *)(work->data + 76);
  uint32_t n = *nonce;

  if (work->stratum) {
    flip80(data, work->data);
  }
  else {
    memcpy(data, work->data, 76);
  }

  applog(LOG_DEBUG, "regenhash data: %s", bin2hex((unsigned char *)data, 80));
  applog(LOG_DEBUG, "regenhash nonce: %08lx (%lu)", n, n);

  *((uint32_t *)data) &= (~ZR5_POK_DATA_MASK);
  uint32_t version = data[0];
  data[19] = n;

  //hash first to get PoK
  zr5_hash(res, data);

  //apply PoK to header
  data[0] = version | (res[0] & ZR5_POK_DATA_MASK);
  data[19] = n;

  //apply PoK to work->data header also so it's included in return hash -- probably should be done elsewhere...
  if(!work->stratum) {
    *((uint32_t *)work->data) = data[0];
  }

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

/************************************************************************
 * OPENCL implementation
 *************************************************************************/

#define KERNEL_KECCAK_PREP1 clState->extra_kernels[0]
#define KERNEL_KECCAK_PREP2 clState->extra_kernels[1]
#define KERNEL_KECCAK clState->extra_kernels[2]
#define KERNEL_KECCAK_FINAL clState->extra_kernels[3]
#define KERNEL_BLAKE clState->extra_kernels[4]
#define KERNEL_GROESTL clState->extra_kernels[5]
#define KERNEL_JH clState->extra_kernels[6]
#define KERNEL_SKEIN clState->extra_kernels[7]
#define KERNEL_ZR5_FINAL clState->extra_kernels[8]

//initialize kernels and buffers
cl_int init_zr5_kernel(struct __clState *clState, struct cgpu_info *cgpu)
{
  cl_int status;

  clState->kernel = NULL;

  //initialize kernels
  clState->n_extra_kernels = cgpu->algorithm.n_extra_kernels;
  if (unlikely((clState->extra_kernels = (cl_kernel *)malloc(sizeof(cl_kernel) * clState->n_extra_kernels)) == NULL)) {
    quit(1, "malloc failed on clState->extra_kernels.");
  }

  KERNEL_KECCAK_PREP1 = clCreateKernel(clState->program, "keccak_prep1", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_KECCAK_PREP1) failed.", status);
    goto out;
  }

  KERNEL_KECCAK_PREP2 = clCreateKernel(clState->program, "keccak_prep2", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_KECCAK_PREP2) failed.", status);
    goto out;
  }

  KERNEL_KECCAK = clCreateKernel(clState->program, "keccakf", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_KECCAK) failed.", status);
    goto out;
  }

  KERNEL_KECCAK_FINAL = clCreateKernel(clState->program, "keccak_final", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_KECCAK_FINAL) failed.", status);
    goto out;
  }

  KERNEL_BLAKE = clCreateKernel(clState->program, "zr5_blake", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_BLAKE) failed.", status);
    goto out;
  }

  KERNEL_GROESTL = clCreateKernel(clState->program, "zr5_groestl", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_GROESTL) failed.", status);
    goto out;
  }

  KERNEL_JH = clCreateKernel(clState->program, "zr5_jh", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_JH) failed.", status);
    goto out;
  }

  KERNEL_SKEIN = clCreateKernel(clState->program, "zr5_skein", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_SKEIN) failed.", status);
    goto out;
  }

  KERNEL_ZR5_FINAL = clCreateKernel(clState->program, "zr5_final", &status);
  if (unlikely(status != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_ZR5_FINAL) failed.", status);
    goto out;
  }

  size_t bufsize;
  size_t globalThreads[1];
  size_t localThreads[1] = { clState->wsize };
  int64_t hashes;

  //compute number of threads we will use
  set_threads_hashes(clState->vwidth, clState->compute_shaders, &hashes, globalThreads, localThreads[0], &cgpu->intensity, &cgpu->xintensity, &cgpu->rawintensity, &cgpu->algorithm);

  //create keccak state buffer 200 bytes * worksize
//  bufsize = (clState->wsize * 200);
  bufsize = (globalThreads[0] * 200);
  clState->CLbuffer0 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, bufsize, NULL, &status);
  if (unlikely(status != CL_SUCCESS && !clState->CLbuffer0)) {
    applog(LOG_ERR, "Error %d: clCreateBuffer (CLbuffer0) failed.", status);
    goto out;
  }
  applog(LOG_DEBUG, "Keccak State Buffer Size: %lu RW", bufsize);

  //hash buffer size - 64bytes * worksize
//  bufsize = (clState->wsize * 64);
  bufsize = (globalThreads[0] * 64);
  clState->padbuffer8 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, bufsize, NULL, &status);
  if (unlikely(status != CL_SUCCESS && !clState->padbuffer8)) {
    applog(LOG_ERR, "Error %d: clCreateBuffer (padbuffer8) failed.", status);
    goto out;
  }
  applog(LOG_DEBUG, "Hashes Buffer Size: %lu RW", bufsize);

  //flags buffer size - 2bytes * worksize
//  bufsize = (clState->wsize * 2);
  bufsize = (globalThreads[0] * 2);
  clState->flagsbuffer = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, bufsize, NULL, &status);
  if (unlikely(status != CL_SUCCESS && !clState->padbuffer8)) {
    applog(LOG_ERR, "Error %d: clCreateBuffer (flagsbuffer) failed.", status);
    goto out;
  }
  applog(LOG_DEBUG, "Hashes Flags Buffer Size: %lu RW", bufsize);

  //output buffer
  bufsize = BUFFERSIZE;
  clState->outputBuffer = clCreateBuffer(clState->context, CL_MEM_WRITE_ONLY, BUFFERSIZE, NULL, &status);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: clCreateBuffer (outputBuffer)", status);
    goto out;
  }
  applog(LOG_DEBUG, "Output Buffer Size: %lu W", bufsize);

  return CL_SUCCESS;

out:
  zr5_cleanup(clState);

  return status;
}

//enqueue buffers and kernels
cl_int queue_zr5_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
  cl_kernel *kernel;
  unsigned int num = 0;
  cl_ulong le_target;
  cl_int status = 0;
  unsigned short i;
  unsigned char data[80];
  size_t globalThreads[1];
  size_t localThreads[1] = { clState->wsize };
  size_t *p_global_work_offset = NULL;

  //set global work offset
  if (clState->goffset) {
      p_global_work_offset = (size_t *)&blk->nonce;
  }

  //set global thread count
  globalThreads[0] = threads;

  //set hash target
  le_target = ((uint64_t *)blk->work->target)[3];

  //getwork sends the data in the correct order already... stratum sends in reverse
  if (blk->work->stratum) {
    flip80(data, blk->work->data);
  }
  else {
    memcpy(data, blk->work->data, 80);
  }

//  applog(LOG_DEBUG, "data: %s", bin2hex(data, 80));

  //setup default keccak state buffer
  size_t keccak_offset = blk->nonce * 200;  //offset of buffer area we are working with
  size_t tmp_size = threads * 200;          //keccak state buffer size needed

  //if exists but not the correct size needed, free the buffer and recreate
  if(clState->keccak_state != NULL && clState->keccak_size != tmp_size) {
    free(clState->keccak_state);
    clState->keccak_size = 0;
    clState->keccak_state = NULL;
  }

  //if buffer doesn't exist create it
  if (clState->keccak_state == NULL) {
    clState->keccak_size = tmp_size; //glob threads * 200 bytes
    if (unlikely((clState->keccak_state = (cl_ulong *)malloc(tmp_size)) == NULL)) {
      quit(1, "Malloc Failed on keccak_state. Tried to allocate %lu bytes", tmp_size);
    }
  }

  //zero out the keccak state buffer
  memset(clState->keccak_state, 0, tmp_size);

  //copy input data into the first 72 bytes of each work item state buffer
  uint64_t idx;
  for (idx=0;idx<threads;++idx) {
    memcpy((((unsigned char *)clState->keccak_state)+(idx * 200)), data, 72);
  }

  for (i=0;i<2;++i) {
    //push default keccak state
    if (unlikely((status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, false, 0, clState->keccak_size, clState->keccak_state, 0, NULL, NULL)) != CL_SUCCESS)) {
      applog(LOG_ERR, "Error %d: clEnqueueWriteBuffer(CLbuffer0) failed.", status);
      goto out;
    }

    //run prep1 only on 2nd zr5 pass...
    if (i == 1) {
      kernel = &(KERNEL_KECCAK_PREP1);
      num = 0;
      CL_SET_ARG(clState->CLbuffer0);
      CL_SET_ARG(clState->padbuffer8);

      //enqueue
      if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0,  NULL, NULL)) != CL_SUCCESS)) {
        applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK_PREP1) failed.", status);
        goto out;
      }
    }

    //keccakf pass1
    kernel = &(KERNEL_KECCAK);
    num = 0;
    CL_SET_ARG(clState->CLbuffer0);

    //enqueue
    if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0, NULL, NULL)) != CL_SUCCESS)) {
      applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK #%d:0) failed.", status, i);
      goto out;
    }

    //keccak prep 2
    kernel = &(KERNEL_KECCAK_PREP2);
    num = 0;
    CL_SET_ARG(clState->CLbuffer0);
    CL_SET_ARG(*(cl_ulong *)(data + 72));

    //enqueue
    if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0, NULL, NULL)) != CL_SUCCESS)) {
      applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK_PREP2 #%d) failed.", status, i);
      goto out;
    }

    //keccakf pass2
    kernel = &(KERNEL_KECCAK);
    num = 0;
    CL_SET_ARG(clState->CLbuffer0);

    //enqueue
    if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0, NULL, NULL)) != CL_SUCCESS)) {
      applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK #%d:1) failed.", status, i);
      goto out;
    }

    //keccak final
    kernel = &(KERNEL_KECCAK_FINAL);
    num = 0;
    CL_SET_ARG(clState->CLbuffer0);
    CL_SET_ARG(clState->padbuffer8);
    CL_SET_ARG(clState->flagsbuffer);

    //enqueue
    if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0, NULL, NULL)) != CL_SUCCESS)) {
      applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK_FINAL #%d) failed.", status, i);
      goto out;
    }

    //run other algos
    unsigned short pass;
    for(pass=0;pass<4;++pass) {
      unsigned short algo;
      kernel = &(KERNEL_BLAKE);

      for(algo=0;algo<4;++algo) {
        num = 0;
        CL_SET_ARG(clState->padbuffer8);
        CL_SET_ARG(clState->flagsbuffer);
        CL_SET_ARG(pass);

        if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0, NULL, NULL)) != CL_SUCCESS)) {
          applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(pass = %d, algo = %d) failed.", status, pass, algo);
          goto out;
        }

        ++kernel;
      }
    }
  }

  //ZR5 final
  kernel = &(KERNEL_ZR5_FINAL);
  num = 0;
  CL_SET_ARG(clState->padbuffer8);
  CL_SET_ARG(clState->outputBuffer);
  CL_SET_ARG(le_target);

  //enqueue
  if (unlikely((status = clEnqueueNDRangeKernel(clState->commandQueue, *kernel, 1, p_global_work_offset, globalThreads, localThreads, 0,  NULL, NULL)) != CL_SUCCESS)) {
    applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK_FINAL) failed.", status);
    goto out;
  }

out:
  return status;
}

void zr5_cleanup(struct __clState *clState)
{
  if(clState->keccak_state) {
    free(clState->keccak_state);
  }
  clState->keccak_size = 0;

  if(clState->outputBuffer) {
    clReleaseMemObject(clState->outputBuffer);
  }

  if(clState->flagsbuffer) {
    clReleaseMemObject(clState->flagsbuffer);
  }

  if(clState->padbuffer8) {
    clReleaseMemObject(clState->padbuffer8);
  }

  if(clState->CLbuffer0) {
    clReleaseMemObject(clState->CLbuffer0);
  }

  int i;
  for (i=0;i<clState->n_extra_kernels;++i) {
    if (clState->extra_kernels[i]) {
      clReleaseKernel(clState->extra_kernels[i]);
    }
  }

  free(clState->extra_kernels);
  clState->n_extra_kernels = 0;
}

void zr5_compiler_options(struct _build_kernel_data *data, struct cgpu_info *cgpu, struct _algorithm_t *algorithm)
{
  char buf[255];
  sprintf(buf, " -D SPH_COMPACT_BLAKE_64=%d ", ((opt_blake_compact)?1:0));
  strcat(data->compiler_options, buf);

  sprintf(buf, "%s", ((opt_blake_compact)?"bc":""));
  strcat(data->binary_filename, buf);
}
