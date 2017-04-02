/*
 * intrin_sequential_enc8.h
 * Copied and modified from Shay Gueron's code from intrinsic.h
 *
 * Copyright(c) 2014, Intel Corp.
 * Developers and authors: Shay Gueron (1) (2)
 * (1) University of Haifa, Israel
 * (2) Intel, Israel
 * IPG, Architecture, Israel Development Center, Haifa, Israel
 */

#include "../constants.h"

#ifndef INTRIN_SEQUENTIAL_ENC8_H_
#define INTRIN_SEQUENTIAL_ENC8_H_

#ifdef USE_PIPELINED_AES_NI

#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>

#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif

#if defined(__INTEL_COMPILER)
# include <ia32intrin.h>
#elif defined(__GNUC__)
# include <emmintrin.h>
# include <smmintrin.h>
#endif

typedef struct KEY_SCHEDULE
{
	ALIGN16 unsigned char KEY[16*15];
	unsigned int nr;
} ROUND_KEYS;

#ifdef __cplusplus
extern "C" {
#endif

	void intrin_sequential_gen_rnd8(unsigned char* ctr_buf, const unsigned long long ctr, unsigned char* CT,
		int n_aesiters, int nkeys, ROUND_KEYS* ks);
	void intrin_sequential_ks4(ROUND_KEYS* ks, unsigned char* key_bytes, int nkeys);
	void intrin_sequential_enc8(const unsigned char* PT, unsigned char* CT, int aes_niters, int nkeys, ROUND_KEYS* ks);

#ifdef __cplusplus
};
#endif
#endif /* USE_PIPELINED_AES_NI */

#endif /* INTRIN_SEQUENTIAL_ENC8_H_ */
