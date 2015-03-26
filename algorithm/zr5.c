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

#define KERNEL_KECCAK clState->extra_kernels[0]
#define KERNEL_BLAKE clState->extra_kernels[1]
#define KERNEL_GROESTL clState->extra_kernels[2]
#define KERNEL_JH clState->extra_kernels[3]
#define KERNEL_SKEIN clState->extra_kernels[4]
#define KERNEL_ZR5_FINAL clState->extra_kernels[5]

// Create kernel objects and allocate necessary buffers
cl_int init_zr5_kernel(struct __clState *clState, struct cgpu_info *cgpu)
{
	cl_int status;
	int64_t hashes;
	clState->kernel = NULL;
	size_t globalThreads, localThreads = clState->wsize;
	
	// Allocate space for kernels
	clState->n_extra_kernels = cgpu->algorithm.n_extra_kernels;
	clState->extra_kernels = (cl_kernel *)malloc(sizeof(cl_kernel) * clState->n_extra_kernels);
	if(!clState->extra_kernels) quit(1, "Failed to allocate memory for kernel handles.");
	
	// Create kernel handles and store in new buffer
	KERNEL_KECCAK = clCreateKernel(clState->program, "ZR5_Keccak", &status);
	
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_KECCAK) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	KERNEL_BLAKE = clCreateKernel(clState->program, "zr5_blake", &status);
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_BLAKE) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	KERNEL_GROESTL = clCreateKernel(clState->program, "zr5_groestl", &status);
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_GROESTL) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	KERNEL_JH = clCreateKernel(clState->program, "zr5_jh", &status);
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_JH) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	KERNEL_SKEIN = clCreateKernel(clState->program, "zr5_skein", &status);
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_SKEIN) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	KERNEL_ZR5_FINAL = clCreateKernel(clState->program, "zr5_final", &status);
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateKernel(KERNEL_ZR5_FINAL) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	// Calculate raw number of threads using algorithm, intensity options, and card info
	set_threads_hashes(clState->vwidth, clState->compute_shaders, &hashes, &globalThreads, localThreads, &cgpu->intensity, &cgpu->xintensity, &cgpu->rawintensity, &cgpu->algorithm);
	
	// Allocate input buffer, hash state buffer, flags buffer, and output buffer
	clState->CLbuffer0 = clCreateBuffer(clState->context, CL_MEM_READ_ONLY, 80, NULL, &status);
	
	if(unlikely(status != CL_SUCCESS))
	{
		applog(LOG_ERR, "Error %d: clCreateBuffer (CLbuffer0) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	// Hash state buffer size - one hash per work item, so 64 bytes * threads
	clState->padbuffer8 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, globalThreads << 6, NULL, &status);
	if(unlikely(status != CL_SUCCESS && !clState->padbuffer8))
	{
		applog(LOG_ERR, "Error %d: clCreateBuffer (padbuffer8) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	// flags buffer size - one is needed for every hash as well, so 2 bytes * threads
	clState->flagsbuffer = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, globalThreads << 1, NULL, &status);
	if(unlikely(status != CL_SUCCESS && !clState->padbuffer8))
	{
		applog(LOG_ERR, "Error %d: clCreateBuffer (flagsbuffer) failed.", status);
		zr5_cleanup(clState);
		return status;
	}
	
	// The usual output buffer
	clState->outputBuffer = clCreateBuffer(clState->context, CL_MEM_WRITE_ONLY, BUFFERSIZE, NULL, &status);
	if(status != CL_SUCCESS)
	{
		applog(LOG_ERR, "Error %d: clCreateBuffer (outputBuffer)", status);
		zr5_cleanup(clState);
		return status;
	}
	
	return CL_SUCCESS;
}

// Write work data to GPU and enqueue kernels
cl_int queue_zr5_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
	cl_ulong le_target = ((uint64_t *)blk->work->target)[3];
	size_t *p_global_work_offset = NULL;
	cl_ulong keccak_state[9];
	unsigned char data[80];
	cl_int status;
	
	// Global work offset apparently may or may not be needed
	if(clState->goffset) p_global_work_offset = (size_t *)&blk->nonce;

	// Stupid stratum fucks the endianness
	if(blk->work->stratum) flip80(data, blk->work->data);
	else memcpy(data, blk->work->data, 80);
	
	memcpy(keccak_state, data, 80);
	
	status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, false, 0, 80, keccak_state, 0, NULL, NULL);
	
	if(status != CL_SUCCESS)
	{
		applog(LOG_ERR, "Error %d: clEnqueueWriteBuffer(CLbuffer0) failed.", status);
		return status;
	}
	
	for(cl_ushort ZR5Round = 0; ZR5Round < 2; ++ZR5Round)
	{
		cl_uint CompilerBugFix = 1;
		
		// Keccak is always first
		clSetKernelArg(KERNEL_KECCAK, 0, sizeof(cl_mem), &clState->CLbuffer0);
		clSetKernelArg(KERNEL_KECCAK, 1, sizeof(cl_mem), &clState->padbuffer8);
		clSetKernelArg(KERNEL_KECCAK, 2, sizeof(cl_mem), &clState->flagsbuffer);
		clSetKernelArg(KERNEL_KECCAK, 3, sizeof(cl_ushort), &ZR5Round);
		clSetKernelArg(KERNEL_KECCAK, 4, sizeof(cl_uint), &CompilerBugFix);
		
		cl_event KeccakComplete;
		
		status = clEnqueueNDRangeKernel(clState->commandQueue, clState->extra_kernels[0], 1, p_global_work_offset, (size_t *)&threads, &clState->wsize, 0, NULL, &KeccakComplete);
		
		if(status != CL_SUCCESS)
		{
			applog(LOG_ERR, "Error %d while enqueuing Keccak kernel for ZR5 round %d.", status, ZR5Round);
			return status;
		}
		
		clWaitForEvents(1, &KeccakComplete);
		clReleaseEvent(KeccakComplete);
		
		cl_event AuxAlgosComplete[4];
		
		// Run all other algos - ones that aren't needed are no-op kernels
		for(cl_ushort pass = 0; pass < 4; ++pass)
		{
			for(int x = 0; x < 4; ++x)
			{
				clSetKernelArg(clState->extra_kernels[x + 1], 0, sizeof(cl_mem), &clState->padbuffer8);
				clSetKernelArg(clState->extra_kernels[x + 1], 1, sizeof(cl_mem), &clState->flagsbuffer);
				clSetKernelArg(clState->extra_kernels[x + 1], 2, sizeof(cl_ushort), &pass);

				status = clEnqueueNDRangeKernel(clState->commandQueue, clState->extra_kernels[x + 1], 1, p_global_work_offset, (size_t *)&threads, &clState->wsize, 0, NULL, AuxAlgosComplete + x);
				
				if(status != CL_SUCCESS)
				{
					applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(pass = %d, algo = %d) failed.", status, pass, x);
					return status;
				}
			}
			
			clWaitForEvents(4, AuxAlgosComplete);
			
			for(int x = 0; x < 4; ++x) clReleaseEvent(AuxAlgosComplete[x]);
		}
	}
	
	// Now check all the results for winners with the final kernel
	clSetKernelArg(KERNEL_ZR5_FINAL, 0, sizeof(cl_mem), &clState->padbuffer8);
	clSetKernelArg(KERNEL_ZR5_FINAL, 1, sizeof(cl_mem), &clState->outputBuffer);
	clSetKernelArg(KERNEL_ZR5_FINAL, 2, sizeof(cl_ulong), &le_target);
	
	status = clEnqueueNDRangeKernel(clState->commandQueue, KERNEL_ZR5_FINAL, 1, p_global_work_offset, (size_t *)&threads, &clState->wsize, 0,  NULL, NULL);
	
	if(status != CL_SUCCESS)
	{
		applog(LOG_ERR, "Error %d: clEnqueueNDRangeKernel(KERNEL_KECCAK_FINAL) failed.", status);
		return status;
	}
	
	return CL_SUCCESS;
}

void zr5_cleanup(struct __clState *clState)
{
	if(clState->outputBuffer) clReleaseMemObject(clState->outputBuffer);

	if(clState->flagsbuffer) clReleaseMemObject(clState->flagsbuffer);

	if(clState->padbuffer8) clReleaseMemObject(clState->padbuffer8);

	if(clState->CLbuffer0) clReleaseMemObject(clState->CLbuffer0);

	for(int i = 0; i < clState->n_extra_kernels; ++i)
		if(clState->extra_kernels[i]) clReleaseKernel(clState->extra_kernels[i]);

	free(clState->extra_kernels);
	clState->n_extra_kernels = 0;
}

// Despite the name of this function, I can also use it to change the
// name of the kernel binary file to be produced/searched for in here.
void zr5_compiler_options(struct _build_kernel_data *data, struct cgpu_info *cgpu, struct _algorithm_t *algorithm)
{
	return;
}
