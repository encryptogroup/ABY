/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright(c) 2013 Ted Krovetz.
* This file was taken from the SCAPI project, where it was taken from the file ocb.c written by Ted Krovetz.
* Some changes and additions may have been made and only part of the file written by Ted Krovetz has been copied 
* only for the use of this project.
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/

// Copyright(c) 2013 Ted Krovetz.




#ifndef TED_FILE
#define TED_FILE

#include "../constants.h"

#ifdef USE_PIPELINED_AES_NI

#include <wmmintrin.h>
#include "Config.h"


#include <iostream>
#include <stdlib.h>
using namespace std;


typedef struct { block rd_key[15]; int rounds; } AES_KEY;
#define ROUNDS(ctx) ((ctx)->rounds)

//output is written to v1, v2 and v3 are temporary variables, v4 is the previous key, shuff_const and aes_const are round/aes specific constants
#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4, aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)

#define EXPAND192_STEP(idx,aes_const)                                       \
    EXPAND_ASSIST(x0,x1,x2,x3,85,aes_const);                                \
    x3 = _mm_xor_si128(x3,_mm_slli_si128 (x3, 4));                          \
    x3 = _mm_xor_si128(x3,_mm_shuffle_epi32(x0, 255));                      \
    kp[idx] = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(tmp),        \
                                              _mm_castsi128_ps(x0), 68));   \
    kp[idx+1] = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(x0),       \
                                                _mm_castsi128_ps(x3), 78)); \
    EXPAND_ASSIST(x0,x1,x2,x3,85,(aes_const*2));                            \
    x3 = _mm_xor_si128(x3,_mm_slli_si128 (x3, 4));                          \
    x3 = _mm_xor_si128(x3,_mm_shuffle_epi32(x0, 255));                      \
    kp[idx+2] = x0; tmp = x3





void AES_128_Key_Expansion(const unsigned char *userkey, AES_KEY* aesKey);
void AES_192_Key_Expansion(const unsigned char *userkey, AES_KEY* aesKey);
void AES_256_Key_Expansion(const unsigned char *userkey, AES_KEY* aesKey);
void AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *aesKey);
	
void AES_encryptC(block *in, block *out, AES_KEY *aesKey);
void AES_ecb_encrypt(block *blk, AES_KEY *aesKey);

void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *aesKey);
void AES_ecb_encrypt_blks_4(block *blk, AES_KEY *aesKey);
void AES_ecb_encrypt_blks_4_in_out(block *in, block *out, AES_KEY *aesKey);
void AES_ecb_encrypt_blks_4_in_out_ind_keys(block *in, block *out,  AES_KEY **aesKey, block** sched);
void AES_ecb_encrypt_blks_4_in_out_par_ks(block *in, block *out,  const unsigned char* userkey);
void AES256_ecb_encrypt_blks_4_in_out_par_ks(block *in, block *out,  const unsigned char* userkey);

void AES_ecb_encrypt_blks_2_in_out(block *in, block *out, AES_KEY *aesKey);
void AES_ecb_encrypt_chunk_in_out(block *in, block *out, unsigned nblks, AES_KEY *aesKey);

#endif
#endif
