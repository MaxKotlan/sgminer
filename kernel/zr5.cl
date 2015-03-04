/*
 * ZR5 kernel implementation.
 */

#ifdef __ECLIPSE_EDITOR__
  #include "OpenCLKernel.hpp"
#endif

#ifndef ZR5_CL
#define ZR5_CL

#if __ENDIAN_LITTLE__
  #define SPH_LITTLE_ENDIAN 1
#else
  #define SPH_BIG_ENDIAN 1
#endif

#define SPH_UPTR sph_u64
typedef unsigned int sph_u32;
typedef int sph_s32;

#ifndef __OPENCL_VERSION__
  typedef unsigned long long sph_u64;
  typedef long long sph_s64;
#else
  typedef unsigned long sph_u64;
  typedef long sph_s64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x) ((sph_u32)(x ## U))
#define SPH_T32(x) (as_uint(x))
#define SPH_ROTL32(x, n) rotate(as_uint(x), as_uint(n))
#define SPH_ROTR32(x, n) SPH_ROTL32(x, (32 - (n)))

#define SPH_C64(x) ((sph_u64)(x ## UL))
#define SPH_T64(x) (as_ulong(x))
#define SPH_ROTL64(x, n) rotate(as_ulong(x), (n) & 0xFFFFFFFFFFFFFFFFUL)
#define SPH_ROTR64(x, n) SPH_ROTL64(x, (64 - (n)))

#define SPH_JH_64 1
#define SPH_SMALL_FOOTPRINT_GROESTL 0
#define SPH_GROESTL_BIG_ENDIAN 0

#ifndef SPH_COMPACT_BLAKE_64
  #define SPH_COMPACT_BLAKE_64 0
#endif

#include "blake.cl"
#include "groestl.cl"
#include "jh.cl"
#include "skein.cl"

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)

#if SPH_BIG_ENDIAN
  #define DEC64E(x) (x)
  #define DEC64BE(x) (*(const __global sph_u64 *) (x))
#else
  #define DEC64E(x) SWAP8(x)
  #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x))
#endif

#define SHL(x, n) ((x) << (n))
#define SHR(x, n) ((x) >> (n))

typedef union {
  unsigned char h1[64];
  uint h4[16];
  ulong h8[8];
} hash_t;

#define ZR5_POK_DATA_MASK 0xFFFF0000

//ZR5 order
static const __constant uint ZR5_ORDER[24][4] =
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

#define ZR5_BLAKE 0
#define ZR5_GROESTL 1
#define ZR5_JH 2
#define ZR5_SKEIN 3

#define KECCAK_ROUNDS 24

typedef ulong keccak_state_t[25];

__constant ulong keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

#define rotl64_1(x, y) ((x) << (y) | ((x) >> (64 - (y))))
#define rotl64_2(x, y) rotl64_1(((x) >> 32) | ((x) << 32), (y))
#define bitselect(a, b, c) ((a) ^ ((c) & ((b) ^ (a))))

void wolf_keccakf(ulong *s)
{
  uint i;

	#pragma unroll 24
  for (i = 0; i < 24; ++i)
  {
    ulong bc[5], tmp1, tmp2;

    bc[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20] ^ rotl64_1(s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22], 1);
    bc[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21] ^ rotl64_1(s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23], 1);
    bc[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22] ^ rotl64_1(s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24], 1);
    bc[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23] ^ rotl64_1(s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20], 1);
    bc[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24] ^ rotl64_1(s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21], 1);
    tmp1 = s[1] ^ bc[0];

    s[0] ^= bc[4];
    s[1] = rotl64_2(s[6] ^ bc[0], 12);
    s[6] = rotl64_1(s[9] ^ bc[3], 20);
    s[9] = rotl64_2(s[22] ^ bc[1], 29);
    s[22] = rotl64_2(s[14] ^ bc[3], 7);
    s[14] = rotl64_1(s[20] ^ bc[4], 18);
    s[20] = rotl64_2(s[2] ^ bc[1], 30);
    s[2] = rotl64_2(s[12] ^ bc[1], 11);
    s[12] = rotl64_1(s[13] ^ bc[2], 25);
    s[13] = rotl64_1(s[19] ^ bc[3], 8);
    s[19] = rotl64_2(s[23] ^ bc[2], 24);
    s[23] = rotl64_2(s[15] ^ bc[4], 9);
    s[15] = rotl64_1(s[4] ^ bc[3], 27);
    s[4] = rotl64_1(s[24] ^ bc[3], 14);
    s[24] = rotl64_1(s[21] ^ bc[0], 2);
    s[21] = rotl64_2(s[8] ^ bc[2], 23);
    s[8] = rotl64_2(s[16] ^ bc[0], 13);
    s[16] = rotl64_2(s[5] ^ bc[4], 4);
    s[5] = rotl64_1(s[3] ^ bc[2], 28);
    s[3] = rotl64_1(s[18] ^ bc[2], 21);
    s[18] = rotl64_1(s[17] ^ bc[1], 15);
    s[17] = rotl64_1(s[11] ^ bc[0], 10);
    s[11] = rotl64_1(s[7] ^ bc[1], 6);
    s[7] = rotl64_1(s[10] ^ bc[4], 3);
    s[10] = rotl64_1(tmp1, 1);

    tmp1 = s[0]; tmp2 = s[1]; s[0] = bitselect(s[0] ^ s[2], s[0], s[1]); s[1] = bitselect(s[1] ^ s[3], s[1], s[2]); s[2] = bitselect(s[2] ^ s[4], s[2], s[3]); s[3] = bitselect(s[3] ^ tmp1, s[3], s[4]); s[4] = bitselect(s[4] ^ tmp2, s[4], tmp1);
    tmp1 = s[5]; tmp2 = s[6]; s[5] = bitselect(s[5] ^ s[7], s[5], s[6]); s[6] = bitselect(s[6] ^ s[8], s[6], s[7]); s[7] = bitselect(s[7] ^ s[9], s[7], s[8]); s[8] = bitselect(s[8] ^ tmp1, s[8], s[9]); s[9] = bitselect(s[9] ^ tmp2, s[9], tmp1);
    tmp1 = s[10]; tmp2 = s[11]; s[10] = bitselect(s[10] ^ s[12], s[10], s[11]); s[11] = bitselect(s[11] ^ s[13], s[11], s[12]); s[12] = bitselect(s[12] ^ s[14], s[12], s[13]); s[13] = bitselect(s[13] ^ tmp1, s[13], s[14]); s[14] = bitselect(s[14] ^ tmp2, s[14], tmp1);
    tmp1 = s[15]; tmp2 = s[16]; s[15] = bitselect(s[15] ^ s[17], s[15], s[16]); s[16] = bitselect(s[16] ^ s[18], s[16], s[17]); s[17] = bitselect(s[17] ^ s[19], s[17], s[18]); s[18] = bitselect(s[18] ^ tmp1, s[18], s[19]); s[19] = bitselect(s[19] ^ tmp2, s[19], tmp1);
    tmp1 = s[20]; tmp2 = s[21]; s[20] = bitselect(s[20] ^ s[22], s[20], s[21]); s[21] = bitselect(s[21] ^ s[23], s[21], s[22]); s[22] = bitselect(s[22] ^ s[24], s[22], s[23]); s[23] = bitselect(s[23] ^ tmp1, s[23], s[24]); s[24] = bitselect(s[24] ^ tmp2, s[24], tmp1);
    s[0] ^= keccakf_rndc[i];
  }
}

void zr5_keccak(const ulong *data, hash_t *hash)
{
  ulong state[25] = {
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0
  };

	{
	  uint i;

		#pragma unroll 1
		for(i = 0; i < 9; ++i) {
			state[i] = data[i];
		}
	}

  wolf_keccakf(state);

  state[0] ^= data[9];
  state[1] ^= 1;
  state[8] ^= SPH_C64(0x8000000000000000);

  wolf_keccakf(state);

  hash->h8[0] = (state[0]);
  hash->h8[1] = (state[1]);
  hash->h8[2] = (state[2]);
  hash->h8[3] = (state[3]);
  hash->h8[4] = (state[4]);
  hash->h8[5] = (state[5]);
  hash->h8[6] = (state[6]);
  hash->h8[7] = (state[7]);
}

void zr5_blake(hash_t *hash)
{
  sph_u64 H0 = SPH_C64(0x6A09E667F3BCC908), H1 = SPH_C64(0xBB67AE8584CAA73B);
  sph_u64 H2 = SPH_C64(0x3C6EF372FE94F82B), H3 = SPH_C64(0xA54FF53A5F1D36F1);
  sph_u64 H4 = SPH_C64(0x510E527FADE682D1), H5 = SPH_C64(0x9B05688C2B3E6C1F);
  sph_u64 H6 = SPH_C64(0x1F83D9ABFB41BD6B), H7 = SPH_C64(0x5BE0CD19137E2179);

  sph_u64 S0 = 0, S1 = 0, S2 = 0, S3 = 0;
  sph_u64 T0 = SPH_C64(0xFFFFFFFFFFFFFC00) + (64 << 3), T1 = 0xFFFFFFFFFFFFFFFF;

  if ((T0 = SPH_T64(T0 + 1024)) < 1024)  {
    T1 = SPH_T64(T1 + 1);
  }

  sph_u64 M0, M1, M2, M3, M4, M5, M6, M7;
  sph_u64 M8, M9, MA, MB, MC, MD, ME, MF;
  sph_u64 V0, V1, V2, V3, V4, V5, V6, V7;
  sph_u64 V8, V9, VA, VB, VC, VD, VE, VF;
  M0 = SWAP8(hash->h8[0]);
  M1 = SWAP8(hash->h8[1]);
  M2 = SWAP8(hash->h8[2]);
  M3 = SWAP8(hash->h8[3]);
  M4 = SWAP8(hash->h8[4]);
  M5 = SWAP8(hash->h8[5]);
  M6 = SWAP8(hash->h8[6]);
  M7 = SWAP8(hash->h8[7]);
  M8 = 0x8000000000000000;
  M9 = 0;
  MA = 0;
  MB = 0;
  MC = 0;
  MD = 1;
  ME = 0;
  MF = 0x200;

  COMPRESS64;

  hash->h8[0] = SWAP8(H0);
  hash->h8[1] = SWAP8(H1);
  hash->h8[2] = SWAP8(H2);
  hash->h8[3] = SWAP8(H3);
  hash->h8[4] = SWAP8(H4);
  hash->h8[5] = SWAP8(H5);
  hash->h8[6] = SWAP8(H6);
  hash->h8[7] = SWAP8(H7);
}

// groestl
void zr5_groestl(hash_t *hash)
{
  sph_u64 H[16] = {
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 512
  };
  sph_u64 m[16] = {
    0, 0, 0, 0,
    0, 0, 0, 0,
    0x80, 0, 0, 0,
    0, 0, 0, SPH_C64(0x100000000000000)
  };
  sph_u64 g[16];
  uint i;

  #if USE_LE
    H[15] = ((sph_u64)(512 & 0xFF) << 56) | ((sph_u64)(512 & 0xFF00) << 40);
  #endif

  #pragma unroll 1
  for(i=0; i<8; ++i) {
    m[i] = hash->h8[i];
    g[i] = m[i] ^ H[i];
  }

  #pragma unroll 1
  for(; i<16; ++i) {
    g[i] = m[i] ^ H[i];
  }

  PERM_BIG_P(g);
  PERM_BIG_Q(m);

  sph_u64 xH[16];

  #pragma unroll 16
  for(i=0; i<16; ++i) {
    xH[i] = (H[i] ^= (g[i] ^ m[i]));
  }

  PERM_BIG_P(xH);

  #pragma unroll 1
  for (i=0; i<8; ++i) {
    hash->h8[i] = (H[i+8] ^ xH[i+8]);
  }
}

// jh
#define h0h jh_state[0]
#define h0l jh_state[1]
#define h1h jh_state[2]
#define h1l jh_state[3]
#define h2h jh_state[4]
#define h2l jh_state[5]
#define h3h jh_state[6]
#define h3l jh_state[7]
#define h4h jh_state[8]
#define h4l jh_state[9]
#define h5h jh_state[10]
#define h5l jh_state[11]
#define h6h jh_state[12]
#define h6l jh_state[13]
#define h7h jh_state[14]
#define h7l jh_state[15]

void zr5_jh(hash_t *hash)
{
  sph_u64 jh_state[16] = {
		C64e(0x6fd14b963e00aa17), C64e(0x636a2e057a15d543),
		C64e(0x8a225e8d0c97ef0b), C64e(0xe9341259f2b3c361),
		C64e(0x891da0c1536f801e), C64e(0x2aa9056bea2b6d80),
		C64e(0x588eccdb2075baa6), C64e(0xa90f3a76baf83bf7),
		C64e(0x0169e60541e34a69), C64e(0x46b58a8e2e6fe65a),
		C64e(0x1047a7d0c1843c24), C64e(0x3b6e71b12d5ac199),
		C64e(0xcf57f6ec9db1f856), C64e(0xa706887c5716b156),
		C64e(0xe3c2fcdfe68517fb), C64e(0x545a4678cc8cdd4b)
	};
  sph_u64 tmp;

	h0h ^= hash->h8[0];
	h0l ^= hash->h8[1];
	h1h ^= hash->h8[2];
	h1l ^= hash->h8[3];
	h2h ^= hash->h8[4];
	h2l ^= hash->h8[5];
	h3h ^= hash->h8[6];
	h3l ^= hash->h8[7];

	E8;

	h4h ^= hash->h8[0];
	h4l ^= hash->h8[1];
	h5h ^= hash->h8[2];
	h5l ^= hash->h8[3];
	h6h ^= hash->h8[4];
	h6l ^= hash->h8[5];
	h7h ^= hash->h8[6];
	h7l ^= hash->h8[7];

	h0h ^= 0x80;
	h3l ^= 0x2000000000000;

	E8;

  hash->h8[0] = (h4h ^ 0x80);
  hash->h8[1] = (h4l);
  hash->h8[2] = (h5h);
  hash->h8[3] = (h5l);
  hash->h8[4] = (h6h);
  hash->h8[5] = (h6l);
  hash->h8[6] = (h7h);
  hash->h8[7] = (h7l ^ 0x2000000000000);
}

// skein
void zr5_skein(hash_t *hash)
{
  sph_u64 bcount = 0;

  sph_u64 h0 = SPH_C64(0x4903ADFF749C51CE);
  sph_u64 h1 = SPH_C64(0x0D95DE399746DF03);
	sph_u64 h2 = SPH_C64(0x8FD1934127C79BCE);
  sph_u64 h3 = SPH_C64(0x9A255629FF352CB1);
	sph_u64 h4 = SPH_C64(0x5DB62599DF6CA7B0);
  sph_u64 h5 = SPH_C64(0xEABE394CA9D5C3F4);
	sph_u64 h6 = SPH_C64(0x991112C71A75B523);
  sph_u64 h7 = SPH_C64(0xAE18A40B660FCC33);

  sph_u64 m0 = (hash->h8[0]);
  sph_u64 m1 = (hash->h8[1]);
  sph_u64 m2 = (hash->h8[2]);
  sph_u64 m3 = (hash->h8[3]);
  sph_u64 m4 = (hash->h8[4]);
  sph_u64 m5 = (hash->h8[5]);
  sph_u64 m6 = (hash->h8[6]);
  sph_u64 m7 = (hash->h8[7]);

  UBI_BIG(480, 64);

  bcount = 0;
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = 0;

  UBI_BIG(510, 8);

  hash->h8[0] = (h0);
  hash->h8[1] = (h1);
  hash->h8[2] = (h2);
  hash->h8[3] = (h3);
  hash->h8[4] = (h4);
  hash->h8[5] = (h5);
  hash->h8[6] = (h6);
  hash->h8[7] = (h7);
}

void zr5_hash(const ulong *data, hash_t *hash)
{
  uint order = 0;
  uint r = 0;

  zr5_keccak(data, hash);

  order = (((uint *)hash->h8)[0] % 24);

  do {
    switch(ZR5_ORDER[order][r]) {
      case ZR5_BLAKE:
        zr5_blake(hash);
        break;
      case ZR5_GROESTL:
        zr5_groestl(hash);
        break;
      case ZR5_JH:
        zr5_jh(hash);
        break;
      case ZR5_SKEIN:
        zr5_skein(hash);
        break;
    };
  } while(++r < 4);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global ulong *block, __global hash_t *hashes)
{
  uint gid = get_global_id(0);
	hash_t hash;
  ulong data[10];

	//get data out of global
	{
		uint i;

		#pragma unroll 1
		for(i=0;i<10;++i) {
			data[i] = block[i];
		}
	}

  *((uint *)data) &= (~ZR5_POK_DATA_MASK);
  ((uint *)data)[19] = gid;

  //run first zr5 hash to get PoK
  zr5_hash(data, &hash);

	//send data to global -- all we need to pass to next phase is hash[0]
	{
		__global hash_t *hashp = &(hashes[gid - get_global_offset(0)]);
		hashp->h8[0] = hash.h8[0];
	}

/*	#pragma unroll 1
	for(i=0;i<8;++i) {
		hashp->h8[i] = hash.h8[i];
	}*/
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search1(__global ulong *block, __global hash_t *hashes, __global uint *output, const ulong target)
{
  uint gid = get_global_id(0);
  ulong data[10];
	hash_t hash;

	//get data out of global
	{
		uint i;
		#pragma unroll 1
		for(i=0;i<10;++i) {
			data[i] = block[i];
		}
	}

  //add the PoK to the final hash
	{
	  __global hash_t *hashp = &(hashes[gid - get_global_offset(0)]);

		*((uint *)data) &= (~ZR5_POK_DATA_MASK);
		*((uint *)data) ^= (((__global uint *)hashp->h8)[0] & ZR5_POK_DATA_MASK);
		((uint *)data)[19] = gid;
	}

  //run final hash
  zr5_hash(data, &hash);

	bool found = (hash.h8[3] <= target);

	if(found) {
		output[atomic_add(output + 0xFF, 1)] = gid;
	}
}


#endif // ZR5_CL