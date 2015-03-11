#ifndef OCL_H
#define OCL_H

#include "config.h"

#include <stdbool.h>
#ifdef __APPLE_CC__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include "miner.h"

#define CL_SET_BLKARG(blkvar) status |= clSetKernelArg(*kernel, num++, sizeof(uint), (void *)&blk->blkvar)
#define CL_SET_VARG(args, var) status |= clSetKernelArg(*kernel, num++, args * sizeof(uint), (void *)var)
#define CL_SET_ARG_N(n, var) do { status |= clSetKernelArg(*kernel, n, sizeof(var), (void *)&var); } while (0)
#define CL_SET_ARG_0(var) CL_SET_ARG_N(0, var)
#define CL_SET_ARG(var) CL_SET_ARG_N(num++, var)
#define CL_NEXTKERNEL_SET_ARG_N(n, var) do { kernel++; CL_SET_ARG_N(n, var); } while (0)
#define CL_NEXTKERNEL_SET_ARG_0(var) CL_NEXTKERNEL_SET_ARG_N(0, var)
#define CL_NEXTKERNEL_SET_ARG(var) CL_NEXTKERNEL_SET_ARG_N(num++, var)

typedef struct __clState {
  cl_context context;
  cl_kernel kernel;
  cl_kernel *extra_kernels;
  size_t n_extra_kernels;
  cl_command_queue commandQueue;
  cl_program program;
  cl_mem outputBuffer;
  cl_mem CLbuffer0;
  cl_mem padbuffer8;
  cl_mem flagsbuffer;
  unsigned char cldata[80];
  cl_ulong *keccak_state;
  size_t keccak_size;
  bool hasBitAlign;
  bool goffset;
  cl_uint vwidth;
  size_t max_work_size;
  size_t wsize;
  size_t compute_shaders;
} _clState;

extern int clDevicesNum(void);
extern _clState *initCl(unsigned int gpu, char *name, size_t nameSize, algorithm_t *algorithm);

#endif /* OCL_H */
