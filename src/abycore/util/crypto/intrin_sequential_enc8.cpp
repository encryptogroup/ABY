/*
 * Copied and modified from Shay Gueron's intrin_sequential_ks4_enc8.cpp
 *
/********************************************************************/
/* Copyright(c) 2014, Intel Corp.                                   */
/* Developers and authors: Shay Gueron (1) (2)                      */
/* (1) University of Haifa, Israel                                  */
/* (2) Intel, Israel                                                */
/* IPG, Architecture, Israel Development Center, Haifa, Israel      */
/********************************************************************/

#include "intrin_sequential_enc8.h"

#ifdef USE_PIPELINED_AES_NI


#define KS_BLOCK(t, reg, reg2) {globAux=_mm_slli_epi64(reg, 32);\
								reg=_mm_xor_si128(globAux, reg);\
								globAux=_mm_shuffle_epi8(reg, con3);\
								reg=_mm_xor_si128(globAux, reg);\
								reg=_mm_xor_si128(reg2, reg);\
								}

#define KS_round(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	x2 =_mm_shuffle_epi8(keyB, mask); \
	keyB_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(1, keyB, keyB_aux);\
	x2 =_mm_shuffle_epi8(keyC, mask); \
	keyC_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(2, keyC, keyC_aux);\
	x2 =_mm_shuffle_epi8(keyD, mask); \
	keyD_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(3, keyD, keyD_aux);\
	con=_mm_slli_epi32(con, 1);\
	_mm_storeu_si128((__m128i *)(keyptr[0].KEY+i*16), keyA);\
	_mm_storeu_si128((__m128i *)(keyptr[1].KEY+i*16), keyB);	\
	_mm_storeu_si128((__m128i *)(keyptr[2].KEY+i*16), keyC);	\
	_mm_storeu_si128((__m128i *)(keyptr[3].KEY+i*16), keyD);	\
	}

#define KS_round_last(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyB, mask); \
	keyB_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyC, mask); \
	keyC_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyD, mask); \
	keyD_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	KS_BLOCK(1, keyB, keyB_aux);\
	KS_BLOCK(2, keyC, keyC_aux);\
	KS_BLOCK(3, keyD, keyD_aux);\
	_mm_storeu_si128((__m128i *)(keyptr[0].KEY+i*16), keyA);\
	_mm_storeu_si128((__m128i *)(keyptr[1].KEY+i*16), keyB);	\
	_mm_storeu_si128((__m128i *)(keyptr[2].KEY+i*16), keyC);	\
	_mm_storeu_si128((__m128i *)(keyptr[3].KEY+i*16), keyD);	\
	}

#define READ_KEYS(i) {keyA = _mm_loadu_si128((__m128i const*)(keyptr[0].KEY+i*16));\
	keyB = _mm_loadu_si128((__m128i const*)(keyptr[1].KEY+i*16));\
	keyC = _mm_loadu_si128((__m128i const*)(keyptr[2].KEY+i*16));\
	keyD = _mm_loadu_si128((__m128i const*)(keyptr[3].KEY+i*16));\
	keyE = _mm_loadu_si128((__m128i const*)(keyptr[4].KEY+i*16));\
	keyF = _mm_loadu_si128((__m128i const*)(keyptr[5].KEY+i*16));\
	keyG = _mm_loadu_si128((__m128i const*)(keyptr[6].KEY+i*16));\
	keyH = _mm_loadu_si128((__m128i const*)(keyptr[7].KEY+i*16));\
	}

#define ENC_round(i) {block1=_mm_aesenc_si128(block1, (*(__m128i const*)(keyptr[0].KEY+i*16))); \
	block2=_mm_aesenc_si128(block2, (*(__m128i const*)(keyptr[1].KEY+i*16))); \
	block3=_mm_aesenc_si128(block3, (*(__m128i const*)(keyptr[2].KEY+i*16))); \
	block4=_mm_aesenc_si128(block4, (*(__m128i const*)(keyptr[3].KEY+i*16))); \
	block5=_mm_aesenc_si128(block5, (*(__m128i const*)(keyptr[4].KEY+i*16))); \
	block6=_mm_aesenc_si128(block6, (*(__m128i const*)(keyptr[5].KEY+i*16))); \
	block7=_mm_aesenc_si128(block7, (*(__m128i const*)(keyptr[6].KEY+i*16))); \
	block8=_mm_aesenc_si128(block8, (*(__m128i const*)(keyptr[7].KEY+i*16))); \
}

#define ENC_round_last(i) {block1=_mm_aesenclast_si128(block1, (*(__m128i const*)(keyptr[0].KEY+i*16))); \
	block2=_mm_aesenclast_si128(block2, (*(__m128i const*)(keyptr[1].KEY+i*16))); \
	block3=_mm_aesenclast_si128(block3, (*(__m128i const*)(keyptr[2].KEY+i*16))); \
	block4=_mm_aesenclast_si128(block4, (*(__m128i const*)(keyptr[3].KEY+i*16))); \
	block5=_mm_aesenclast_si128(block5, (*(__m128i const*)(keyptr[4].KEY+i*16))); \
	block6=_mm_aesenclast_si128(block6, (*(__m128i const*)(keyptr[5].KEY+i*16))); \
	block7=_mm_aesenclast_si128(block7, (*(__m128i const*)(keyptr[6].KEY+i*16))); \
	block8=_mm_aesenclast_si128(block8, (*(__m128i const*)(keyptr[7].KEY+i*16))); \
}




#define KS1_BLOCK(t, reg, reg2) {globAux=_mm_slli_epi64(reg, 32);\
								reg=_mm_xor_si128(globAux, reg);\
								globAux=_mm_shuffle_epi8(reg, con3);\
								reg=_mm_xor_si128(globAux, reg);\
								reg=_mm_xor_si128(reg2, reg);\
								}

#define KS1_round(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS1_BLOCK(0, keyA, keyA_aux);\
	con=_mm_slli_epi32(con, 1);\
	_mm_storeu_si128((__m128i *)(keyptr[0].KEY+i*16), keyA);\
	}

#define KS1_round_last(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS1_BLOCK(0, keyA, keyA_aux);\
	_mm_storeu_si128((__m128i *)(keyptr[0].KEY+i*16), keyA);\
	}

#define READ_KEYS1(i) {keyA = _mm_loadu_si128((__m128i const*)(keyptr[0].KEY+i*16));\
	}

#define ENC1_round(i) {block1=_mm_aesenc_si128(block1, (*(__m128i const*)(keyptr[0].KEY+i*16))); \
}

#define ENC1_round_last(i) {block1=_mm_aesenclast_si128(block1, (*(__m128i const*)(keyptr[0].KEY+i*16))); \
}





//generates nkeys round keys from the bytes stored in key_bytes
void intrin_sequential_ks4(ROUND_KEYS* ks, unsigned char* key_bytes, int nkeys) {
	ROUND_KEYS *keyptr=(ROUND_KEYS *)ks;
	register __m128i keyA, keyB, keyC, keyD, con, mask, x2, keyA_aux, keyB_aux, keyC_aux, keyD_aux, globAux;
	int i;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	int lim = (nkeys/4)*4;

	for (i=0;i<lim;i+=4){
		keyptr[0].nr=10;
		keyptr[1].nr=10;
		keyptr[2].nr=10;
		keyptr[3].nr=10;

		keyA = _mm_loadu_si128((__m128i const*)(key_bytes));
		keyB = _mm_loadu_si128((__m128i const*)(key_bytes+16));
		keyC = _mm_loadu_si128((__m128i const*)(key_bytes+32));
		keyD = _mm_loadu_si128((__m128i const*)(key_bytes+48));

		_mm_storeu_si128((__m128i *)keyptr[0].KEY, keyA);
		_mm_storeu_si128((__m128i *)keyptr[1].KEY, keyB);
		_mm_storeu_si128((__m128i *)keyptr[2].KEY, keyC);
		_mm_storeu_si128((__m128i *)keyptr[3].KEY, keyD);

		con = _mm_loadu_si128((__m128i const*)_con1);
		mask = _mm_loadu_si128((__m128i const*)_mask);

		KS_round(1)
		KS_round(2)
		KS_round(3)
		KS_round(4)
		KS_round(5)
		KS_round(6)
		KS_round(7)
		KS_round(8)
		con = _mm_loadu_si128((__m128i const*)_con2);

		KS_round(9)
		KS_round_last(10)

		keyptr+=4;
		key_bytes+=64;
	}

	for(; i<nkeys; i++) {
		keyptr[0].nr=10;

		keyA = _mm_loadu_si128((__m128i const*)(key_bytes));

		_mm_storeu_si128((__m128i *)keyptr[0].KEY, keyA);

		con = _mm_loadu_si128((__m128i const*)_con1);
		mask = _mm_loadu_si128((__m128i const*)_mask);

		KS1_round(1)
		KS1_round(2)
		KS1_round(3)
		KS1_round(4)
		KS1_round(5)
		KS1_round(6)
		KS1_round(7)
		KS1_round(8)
		con = _mm_loadu_si128((__m128i const*)_con2);

		KS1_round(9)
		KS1_round_last(10)

		keyptr++;
		key_bytes+=16;
	}
}

void intrin_sequential_enc8(const unsigned char* PT, unsigned char* CT, int n_aesiters, int nkeys, ROUND_KEYS* ks){

	ROUND_KEYS *keyptr=(ROUND_KEYS *)ks;
    register __m128i keyA, keyB, keyC, keyD, keyE, keyF, keyG, keyH, con, mask, x2, keyA_aux, keyB_aux, keyC_aux, keyD_aux, globAux;
    unsigned char *ptptr, ctptr;
	int i, j, ptoffset, ctoffset;

	ctoffset = n_aesiters * 16;

	for (i=0;i<nkeys;i+=8){

		for(j=0;j<n_aesiters; j++) {
			register __m128i block1 = _mm_loadu_si128((__m128i const*)(0*16+PT));
			register __m128i block2 = _mm_loadu_si128((__m128i const*)(1*16+PT));
			register __m128i block3 = _mm_loadu_si128((__m128i const*)(2*16+PT));
			register __m128i block4 = _mm_loadu_si128((__m128i const*)(3*16+PT));
			register __m128i block5 = _mm_loadu_si128((__m128i const*)(4*16+PT));
			register __m128i block6 = _mm_loadu_si128((__m128i const*)(5*16+PT));
			register __m128i block7 = _mm_loadu_si128((__m128i const*)(6*16+PT));
			register __m128i block8 = _mm_loadu_si128((__m128i const*)(7*16+PT));

			READ_KEYS(0)

			block1 = _mm_xor_si128(keyA, block1);
			block2 = _mm_xor_si128(keyB, block2);
			block3 = _mm_xor_si128(keyC, block3);
			block4 = _mm_xor_si128(keyD, block4);
			block5 = _mm_xor_si128(keyE, block5);
			block6 = _mm_xor_si128(keyF, block6);
			block7 = _mm_xor_si128(keyG, block7);
			block8 = _mm_xor_si128(keyH, block8);

			ENC_round(1)
			ENC_round(2)
			ENC_round(3)
			ENC_round(4)
			ENC_round(5)
			ENC_round(6)
			ENC_round(7)
			ENC_round(8)
			ENC_round(9)
			ENC_round_last(10)

			_mm_storeu_si128((__m128i *)(CT+0*16), block1);
			_mm_storeu_si128((__m128i *)(CT+1*16), block2);
			_mm_storeu_si128((__m128i *)(CT+2*16), block3);
			_mm_storeu_si128((__m128i *)(CT+3*16), block4);
			_mm_storeu_si128((__m128i *)(CT+4*16), block5);
			_mm_storeu_si128((__m128i *)(CT+5*16), block6);
			_mm_storeu_si128((__m128i *)(CT+6*16), block7);
			_mm_storeu_si128((__m128i *)(CT+7*16), block8);

			PT+=128;
			CT+=128;

		}
		keyptr+=8;
	}
}



void intrin_sequential_gen_rnd8(unsigned char* ctr_buf, const unsigned long long ctr, unsigned char* CT,
		int n_aesiters, int nkeys, ROUND_KEYS* ks){

	ROUND_KEYS *keyptr=(ROUND_KEYS *)ks;
    register __m128i keyA, keyB, keyC, keyD, keyE, keyF, keyG, keyH, con, mask, x2, keyA_aux, keyB_aux, keyC_aux, keyD_aux, globAux;
    unsigned char *ctptr;
	int i, j, ctoffset;
	unsigned long long* tmpctr = (unsigned long long*) ctr_buf;

	ctoffset = n_aesiters * 16;

	register __m128i inblock, block1, block2, block3, block4, block5, block6, block7, block8;

	int lim = (nkeys/8)*8;

	for (i=0;i<lim;i+=8){
		ctptr=CT + i*ctoffset;
		(*tmpctr) = ctr;
		for(j=0;j<n_aesiters; j++) {
			(*tmpctr)++;
			inblock = _mm_loadu_si128((__m128i const*)(ctr_buf));

			READ_KEYS(0)

			block1 = _mm_xor_si128(keyA, inblock);
			block2 = _mm_xor_si128(keyB, inblock);
			block3 = _mm_xor_si128(keyC, inblock);
			block4 = _mm_xor_si128(keyD, inblock);
			block5 = _mm_xor_si128(keyE, inblock);
			block6 = _mm_xor_si128(keyF, inblock);
			block7 = _mm_xor_si128(keyG, inblock);
			block8 = _mm_xor_si128(keyH, inblock);

			ENC_round(1)
			ENC_round(2)
			ENC_round(3)
			ENC_round(4)
			ENC_round(5)
			ENC_round(6)
			ENC_round(7)
			ENC_round(8)
			ENC_round(9)
			ENC_round_last(10)

			_mm_storeu_si128((__m128i *)(ctptr+0*ctoffset), block1);
			_mm_storeu_si128((__m128i *)(ctptr+1*ctoffset), block2);
			_mm_storeu_si128((__m128i *)(ctptr+2*ctoffset), block3);
			_mm_storeu_si128((__m128i *)(ctptr+3*ctoffset), block4);
			_mm_storeu_si128((__m128i *)(ctptr+4*ctoffset), block5);
			_mm_storeu_si128((__m128i *)(ctptr+5*ctoffset), block6);
			_mm_storeu_si128((__m128i *)(ctptr+6*ctoffset), block7);
			_mm_storeu_si128((__m128i *)(ctptr+7*ctoffset), block8);

			ctptr+=16;
		}
		keyptr+=8;
	}


	for (;i<nkeys;i++){
		ctptr=CT + i*ctoffset;
		(*tmpctr) = ctr;
		for(j=0;j<n_aesiters; j++) {
			(*tmpctr)++;
			inblock = _mm_loadu_si128((__m128i const*)(ctr_buf));

			READ_KEYS1(0)

			block1 = _mm_xor_si128(keyA, inblock);

			ENC1_round(1)
			ENC1_round(2)
			ENC1_round(3)
			ENC1_round(4)
			ENC1_round(5)
			ENC1_round(6)
			ENC1_round(7)
			ENC1_round(8)
			ENC1_round(9)
			ENC1_round_last(10)

			_mm_storeu_si128((__m128i *)(ctptr), block1);

			ctptr+=16;
		}
		keyptr++;
	}
}
#endif

