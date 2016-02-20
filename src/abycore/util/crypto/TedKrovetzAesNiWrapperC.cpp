#include "TedKrovetzAesNiWrapperC.h"
#ifdef USE_PIPELINED_AES_NI

#ifdef _WIN32
#include "StdAfx.h"
#endif

void AES_128_Key_Expansion(const unsigned char *userkey, AES_KEY *aesKey)
{
    block x0,x1,x2;
    //block *kp = (block *)&aesKey;
	aesKey->rd_key[0] = x0 = _mm_loadu_si128((block*)userkey);
    x2 = _mm_setzero_si128();
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);   aesKey->rd_key[1] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);   aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);   aesKey->rd_key[3] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);   aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);  aesKey->rd_key[5] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);  aesKey->rd_key[7] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 128); aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);  aesKey->rd_key[9] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);  aesKey->rd_key[10] = x0;
}



void AES_192_Key_Expansion(const unsigned char *userkey, AES_KEY *aesKey)
{
    __m128i x0,x1,x2,x3,tmp,*kp = (block *)&aesKey;
    kp[0] = x0 = _mm_loadu_si128((block*)userkey);
    tmp = x3 = _mm_loadu_si128((block*)(userkey+16));
    x2 = _mm_setzero_si128();
    EXPAND192_STEP(1,1);
    EXPAND192_STEP(4,4);
    EXPAND192_STEP(7,16);
    EXPAND192_STEP(10,64);
}

void AES_256_Key_Expansion(const unsigned char *userkey, AES_KEY *aesKey)
{
	__m128i x0, x1, x2, x3;/* , *kp = (block *)&aesKey;*/
	aesKey->rd_key[0] = x0 = _mm_loadu_si128((block*)userkey);
	aesKey->rd_key[1] = x3 = _mm_loadu_si128((block*)(userkey + 16));
    x2 = _mm_setzero_si128();
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 1);  aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 1);  aesKey->rd_key[3] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 2);  aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 2);  aesKey->rd_key[5] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 4);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 4);  aesKey->rd_key[7] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 8);  aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 8);  aesKey->rd_key[9] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 16); aesKey->rd_key[10] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 16); aesKey->rd_key[11] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 32); aesKey->rd_key[12] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 32); aesKey->rd_key[13] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 64); aesKey->rd_key[14] = x0;
}

void AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *aesKey)
{
    if (bits == 128) {
		AES_128_Key_Expansion(userKey, aesKey);
    } else if (bits == 192) {
		AES_192_Key_Expansion(userKey, aesKey);
    } else if (bits == 256) {
		AES_256_Key_Expansion(userKey, aesKey);
    }

	aesKey->rounds = 6 + bits / 32;
   
}

void AES_encryptC(block *in, block *out,  AES_KEY *aesKey)
{
	int j, rnds = ROUNDS(aesKey);
	const __m128i *sched = ((__m128i *)(aesKey->rd_key));
	__m128i tmp = _mm_load_si128((__m128i*)in);
	tmp = _mm_xor_si128(tmp, sched[0]);
	for (j = 1; j<rnds; j++)  tmp = _mm_aesenc_si128(tmp, sched[j]);
	tmp = _mm_aesenclast_si128(tmp, sched[j]);
	_mm_store_si128((__m128i*)out, tmp);
}


void AES_ecb_encrypt(block *blk,  AES_KEY *aesKey) {
	unsigned j, rnds = ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));

	*blk = _mm_xor_si128(*blk, sched[0]);
	for (j = 1; j<rnds; ++j)
		*blk = _mm_aesenc_si128(*blk, sched[j]);
	*blk = _mm_aesenclast_si128(*blk, sched[j]);
}

void AES_ecb_encrypt_blks(block *blks, unsigned nblks,  AES_KEY *aesKey) {
    unsigned i,j,rnds=ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_xor_si128(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm_aesenc_si128(blks[i], sched[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_aesenclast_si128(blks[i], sched[j]);
}

void AES_ecb_encrypt_blks_4(block *blks,  AES_KEY *aesKey) {
	unsigned j, rnds = ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));
	blks[0] = _mm_xor_si128(blks[0], sched[0]);
	blks[1] = _mm_xor_si128(blks[1], sched[0]);
	blks[2] = _mm_xor_si128(blks[2], sched[0]);
	blks[3] = _mm_xor_si128(blks[3], sched[0]);

	for (j = 1; j < rnds; ++j){
		blks[0] = _mm_aesenc_si128(blks[0], sched[j]);
		blks[1] = _mm_aesenc_si128(blks[1], sched[j]);
		blks[2] = _mm_aesenc_si128(blks[2], sched[j]);
		blks[3] = _mm_aesenc_si128(blks[3], sched[j]);
	}
	blks[0] = _mm_aesenclast_si128(blks[0], sched[j]);
	blks[1] = _mm_aesenclast_si128(blks[1], sched[j]);
	blks[2] = _mm_aesenclast_si128(blks[2], sched[j]);
	blks[3] = _mm_aesenclast_si128(blks[3], sched[j]);
}


void AES_ecb_encrypt_blks_2_in_out(block *in, block *out, AES_KEY *aesKey) {

	unsigned j, rnds = ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));

	out[0] = _mm_xor_si128(in[0], sched[0]);
	out[1] = _mm_xor_si128(in[1], sched[0]);
	
	for (j = 1; j < rnds; ++j){
		out[0] = _mm_aesenc_si128(out[0], sched[j]);
		out[1] = _mm_aesenc_si128(out[1], sched[j]);
		
	}
	out[0] = _mm_aesenclast_si128(out[0], sched[j]);
	out[1] = _mm_aesenclast_si128(out[1], sched[j]);
}

void AES_ecb_encrypt_blks_4_in_out(block *in, block *out,  AES_KEY *aesKey) {
	unsigned j, rnds = ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));
	//block temp[4];

	out[0] = _mm_xor_si128(in[0], sched[0]);
	out[1] = _mm_xor_si128(in[1], sched[0]);
	out[2] = _mm_xor_si128(in[2], sched[0]);
	out[3] = _mm_xor_si128(in[3], sched[0]);

	for (j = 1; j < rnds; ++j){
		out[0] = _mm_aesenc_si128(out[0], sched[j]);
		out[1] = _mm_aesenc_si128(out[1], sched[j]);
		out[2] = _mm_aesenc_si128(out[2], sched[j]);
		out[3] = _mm_aesenc_si128(out[3], sched[j]);
	}
	out[0] = _mm_aesenclast_si128(out[0], sched[j]);
	out[1] = _mm_aesenclast_si128(out[1], sched[j]);
	out[2] = _mm_aesenclast_si128(out[2], sched[j]);
	out[3] = _mm_aesenclast_si128(out[3], sched[j]);
}

void AES_ecb_encrypt_blks_4_in_out_ind_keys(block *in, block *out,  AES_KEY **aesKey, block** sched) {
	unsigned j, rnds = ROUNDS(aesKey[0]);
	sched[0] = ((block *)(aesKey[0][0].rd_key));
	sched[1] = ((block *)(aesKey[0][1].rd_key));
	sched[2] = ((block *)(aesKey[0][2].rd_key));
	sched[3] = ((block *)(aesKey[0][3].rd_key));
	//block temp[4];

	out[0] = _mm_xor_si128(in[0], sched[0][0]);
	out[1] = _mm_xor_si128(in[1], sched[1][0]);
	out[2] = _mm_xor_si128(in[2], sched[2][0]);
	out[3] = _mm_xor_si128(in[3], sched[3][0]);

	for (j = 1; j < rnds; ++j){
		out[0] = _mm_aesenc_si128(out[0], sched[0][j]);
		out[1] = _mm_aesenc_si128(out[1], sched[1][j]);
		out[2] = _mm_aesenc_si128(out[2], sched[2][j]);
		out[3] = _mm_aesenc_si128(out[3], sched[3][j]);
	}
	out[0] = _mm_aesenclast_si128(out[0], sched[0][j]);
	out[1] = _mm_aesenclast_si128(out[1], sched[1][j]);
	out[2] = _mm_aesenclast_si128(out[2], sched[2][j]);
	out[3] = _mm_aesenclast_si128(out[3], sched[3][j]);
}


void AES_ecb_encrypt_blks_4_in_out_par_ks(block *in, block *out,  const unsigned char* userkey) {
	unsigned int j, rnds = 10;

    block k0, k1, k2, k3, ktmp, k0tmp, k1tmp, k2tmp, k3tmp;
	/*aesKey->rd_key[0] = x0 = _mm_loadu_si128((block*)userkey);
    x2 = _mm_setzero_si128();
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);   aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);   aesKey->rd_key[3] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);   aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);  aesKey->rd_key[5] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);  aesKey->rd_key[7] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 128); aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);  aesKey->rd_key[9] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);  aesKey->rd_key[10] = x0;*/

	/*sched[0] = ((block *)(aesKey[0]->rd_key));
	sched[1] = ((block *)(aesKey[1]->rd_key));
	sched[2] = ((block *)(aesKey[2]->rd_key));
	sched[3] = ((block *)(aesKey[3]->rd_key));*/


    k0 = _mm_loadu_si128((block*)userkey);
	out[0] = _mm_xor_si128(in[0], k0);
    k1 = _mm_loadu_si128((block*)(userkey+16));
	out[1] = _mm_xor_si128(in[1], k1);
    k2 = _mm_loadu_si128((block*)(userkey+32));
	out[2] = _mm_xor_si128(in[2], k2);
    k3 = _mm_loadu_si128((block*)(userkey+48));
	out[3] = _mm_xor_si128(in[3], k3);

	k0tmp = _mm_setzero_si128();
	k1tmp = _mm_setzero_si128();
	k2tmp = _mm_setzero_si128();
	k3tmp = _mm_setzero_si128();

	//First Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 1);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 1);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 1);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 1);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Second Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 2);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 2);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 2);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 2);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Third Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 4);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 4);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 4);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 4);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Fourth Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 8);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 8);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 8);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 8);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Fifth Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 16);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 16);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 16);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 16);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Sixth Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 32);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 32);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 32);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 32);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Seventh Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 64);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 64);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 64);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 64);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Eight Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 128);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 128);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 128);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 128);
	out[3] = _mm_aesenc_si128(out[3], k3);


	//Ninth Round
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 27);
	out[0] = _mm_aesenc_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 27);
	out[1] = _mm_aesenc_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 27);
	out[2] = _mm_aesenc_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 27);
	out[3] = _mm_aesenc_si128(out[3], k3);

	//Tenth Roundkey
	EXPAND_ASSIST(k0, ktmp, k0tmp, k0, 255, 54);
	out[0] = _mm_aesenclast_si128(out[0], k0);
	EXPAND_ASSIST(k1, ktmp, k1tmp, k1, 255, 54);
	out[1] = _mm_aesenclast_si128(out[1], k1);
	EXPAND_ASSIST(k2, ktmp, k2tmp, k2, 255, 54);
	out[2] = _mm_aesenclast_si128(out[2], k2);
	EXPAND_ASSIST(k3, ktmp, k3tmp, k3, 255, 54);
	out[3] = _mm_aesenclast_si128(out[3], k3);
}

void AES256_ecb_encrypt_blks_4_in_out_par_ks(block *in, block *out,  const unsigned char* userkey) {
	unsigned int j, rnds = 14;

	//four keys for even and odd-numbered rounds as well as temporary keys
    block k0e, k1e, k2e, k3e, k0o, k1o, k2o, k3o, ktmp, k0tmp, k1tmp, k2tmp, k3tmp;

    /*	__m128i x0, x1, x2, x3;
	aesKey->rd_key[0] = x0 = _mm_loadu_si128((block*)userkey);
	aesKey->rd_key[1] = x3 = _mm_loadu_si128((block*)(userkey + 16));
    x2 = _mm_setzero_si128();
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 1);  aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 1);  aesKey->rd_key[3] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 2);  aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 2);  aesKey->rd_key[5] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 4);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 4);  aesKey->rd_key[7] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 8);  aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 8);  aesKey->rd_key[9] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 16); aesKey->rd_key[10] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 16); aesKey->rd_key[11] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 32); aesKey->rd_key[12] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 32); aesKey->rd_key[13] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 64); aesKey->rd_key[14] = x0;*/

    //Zero-th Round
    k0e = _mm_loadu_si128((block*)userkey);
	out[0] = _mm_xor_si128(in[0], k0e);
    k1e = _mm_loadu_si128((block*)(userkey+32));
	out[1] = _mm_xor_si128(in[1], k1e);
    k2e = _mm_loadu_si128((block*)(userkey+64));
	out[2] = _mm_xor_si128(in[2], k2e);
    k3e = _mm_loadu_si128((block*)(userkey+96));
	out[3] = _mm_xor_si128(in[3], k3e);

	k0tmp = _mm_setzero_si128();
	k1tmp = _mm_setzero_si128();
	k2tmp = _mm_setzero_si128();
	k3tmp = _mm_setzero_si128();

    //First Round
    k0o = _mm_loadu_si128((block*)(userkey+16));
    out[0] = _mm_aesenc_si128(out[0], k0o);
    k1o = _mm_loadu_si128((block*)(userkey+48));
    out[1] = _mm_aesenc_si128(out[1], k1o);
    k2o = _mm_loadu_si128((block*)(userkey+80));
    out[2] = _mm_aesenc_si128(out[2], k2o);
    k3o = _mm_loadu_si128((block*)(userkey+112));
    out[3] = _mm_aesenc_si128(out[3], k3o);

	//Second Round; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 1);  aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 1);
	out[0] = _mm_aesenc_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 1);
	out[1] = _mm_aesenc_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 1);
	out[2] = _mm_aesenc_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 1);
	out[3] = _mm_aesenc_si128(out[3], k3e);

	//Third Round; odd round: result is written in kio
	//EXPAND_ASSIST(x3, x1, x2, x0, 170, 1);  aesKey->rd_key[3] = x3;
	EXPAND_ASSIST(k0o, ktmp, k0tmp, k0e, 170, 1);
	out[0] = _mm_aesenc_si128(out[0], k0o);
	EXPAND_ASSIST(k1o, ktmp, k1tmp, k1e, 170, 1);
	out[1] = _mm_aesenc_si128(out[1], k1o);
	EXPAND_ASSIST(k2o, ktmp, k2tmp, k2e, 170, 1);
	out[2] = _mm_aesenc_si128(out[2], k2o);
	EXPAND_ASSIST(k3o, ktmp, k3tmp, k3e, 170, 1);
	out[3] = _mm_aesenc_si128(out[3], k3o);

	//Fourth Round; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 2);  aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 2);
	out[0] = _mm_aesenc_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 2);
	out[1] = _mm_aesenc_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 2);
	out[2] = _mm_aesenc_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 2);
	out[3] = _mm_aesenc_si128(out[3], k3e);

	//Fifth Round; odd round: result is written in kio
	//EXPAND_ASSIST(x3, x1, x2, x0, 170, 2);  aesKey->rd_key[5] = x3;
	EXPAND_ASSIST(k0o, ktmp, k0tmp, k0e, 170, 2);
	out[0] = _mm_aesenc_si128(out[0], k0o);
	EXPAND_ASSIST(k1o, ktmp, k1tmp, k1e, 170, 2);
	out[1] = _mm_aesenc_si128(out[1], k1o);
	EXPAND_ASSIST(k2o, ktmp, k2tmp, k2e, 170, 2);
	out[2] = _mm_aesenc_si128(out[2], k2o);
	EXPAND_ASSIST(k3o, ktmp, k3tmp, k3e, 170, 2);
	out[3] = _mm_aesenc_si128(out[3], k3o);

	//Sixth Round; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 4);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 4);
	out[0] = _mm_aesenc_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 4);
	out[1] = _mm_aesenc_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 4);
	out[2] = _mm_aesenc_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 4);
	out[3] = _mm_aesenc_si128(out[3], k3e);

	//Seventh Round: result is written in kio
	//EXPAND_ASSIST(x3, x1, x2, x0, 170, 4);  aesKey->rd_key[7] = x3;
	EXPAND_ASSIST(k0o, ktmp, k0tmp, k0e, 170, 4);
	out[0] = _mm_aesenc_si128(out[0], k0o);
	EXPAND_ASSIST(k1o, ktmp, k1tmp, k1e, 170, 4);
	out[1] = _mm_aesenc_si128(out[1], k1o);
	EXPAND_ASSIST(k2o, ktmp, k2tmp, k2e, 170, 4);
	out[2] = _mm_aesenc_si128(out[2], k2o);
	EXPAND_ASSIST(k3o, ktmp, k3tmp, k3e, 170, 4);
	out[3] = _mm_aesenc_si128(out[3], k3o);

	//Eigth Round; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 8);  aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 8);
	out[0] = _mm_aesenc_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 8);
	out[1] = _mm_aesenc_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 8);
	out[2] = _mm_aesenc_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 8);
	out[3] = _mm_aesenc_si128(out[3], k3e);

	//Ninth Round: odd result is written in kio
	//EXPAND_ASSIST(x3, x1, x2, x0, 170, 8);  aesKey->rd_key[9] = x3;
	EXPAND_ASSIST(k0o, ktmp, k0tmp, k0e, 170, 8);
	out[0] = _mm_aesenc_si128(out[0], k0o);
	EXPAND_ASSIST(k1o, ktmp, k1tmp, k1e, 170, 8);
	out[1] = _mm_aesenc_si128(out[1], k1o);
	EXPAND_ASSIST(k2o, ktmp, k2tmp, k2e, 170, 8);
	out[2] = _mm_aesenc_si128(out[2], k2o);
	EXPAND_ASSIST(k3o, ktmp, k3tmp, k3e, 170, 8);
	out[3] = _mm_aesenc_si128(out[3], k3o);

	//Tenth Round; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 16); aesKey->rd_key[10] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 16);
	out[0] = _mm_aesenc_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 16);
	out[1] = _mm_aesenc_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 16);
	out[2] = _mm_aesenc_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 16);
	out[3] = _mm_aesenc_si128(out[3], k3e);

	//Eleventh Roundkey: odd result is written in kio
	//EXPAND_ASSIST(x3, x1, x2, x0, 170, 16); aesKey->rd_key[11] = x3;
	EXPAND_ASSIST(k0o, ktmp, k0tmp, k0e, 170, 16);
	out[0] = _mm_aesenc_si128(out[0], k0o);
	EXPAND_ASSIST(k1o, ktmp, k1tmp, k1e, 170, 16);
	out[1] = _mm_aesenc_si128(out[1], k1o);
	EXPAND_ASSIST(k2o, ktmp, k2tmp, k2e, 170, 16);
	out[2] = _mm_aesenc_si128(out[2], k2o);
	EXPAND_ASSIST(k3o, ktmp, k3tmp, k3e, 170, 16);
	out[3] = _mm_aesenc_si128(out[3], k3o);

	//Twelvth Roundkey; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 32); aesKey->rd_key[12] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 32);
	out[0] = _mm_aesenc_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 32);
	out[1] = _mm_aesenc_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 32);
	out[2] = _mm_aesenc_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 32);
	out[3] = _mm_aesenc_si128(out[3], k3e);

	//Thirtheenth Roundkey: odd result is written in kio
	//EXPAND_ASSIST(x3, x1, x2, x0, 170, 32); aesKey->rd_key[13] = x3;
	EXPAND_ASSIST(k0o, ktmp, k0tmp, k0e, 170, 32);
	out[0] = _mm_aesenc_si128(out[0], k0o);
	EXPAND_ASSIST(k1o, ktmp, k1tmp, k1e, 170, 32);
	out[1] = _mm_aesenc_si128(out[1], k1o);
	EXPAND_ASSIST(k2o, ktmp, k2tmp, k2e, 170, 32);
	out[2] = _mm_aesenc_si128(out[2], k2o);
	EXPAND_ASSIST(k3o, ktmp, k3tmp, k3e, 170, 32);
	out[3] = _mm_aesenc_si128(out[3], k3o);

	//Fourteenth Roundkey; even round: result is written in kie
	//EXPAND_ASSIST(x0, x1, x2, x3, 255, 64); aesKey->rd_key[14] = x0;
	EXPAND_ASSIST(k0e, ktmp, k0tmp, k0o, 255, 64);
	out[0] = _mm_aesenclast_si128(out[0], k0e);
	EXPAND_ASSIST(k1e, ktmp, k1tmp, k1o, 255, 64);
	out[1] = _mm_aesenclast_si128(out[1], k1e);
	EXPAND_ASSIST(k2e, ktmp, k2tmp, k2o, 255, 64);
	out[2] = _mm_aesenclast_si128(out[2], k2e);
	EXPAND_ASSIST(k3e, ktmp, k3tmp, k3o, 255, 64);
	out[3] = _mm_aesenclast_si128(out[3], k3e);
}


void AES_ecb_encrypt_chunk_in_out(block *in, block *out, unsigned nblks, AES_KEY *aesKey) {

	int numberOfLoops = nblks / 8;
	int blocksPipeLined = numberOfLoops * 8;
	int remainingEncrypts = nblks - blocksPipeLined;

	unsigned j, rnds = ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));

	for (int i = 0; i < numberOfLoops; i++){

		out[0 + i * 8] = _mm_xor_si128(in[0 + i * 8], sched[0]);
		out[1 + i * 8] = _mm_xor_si128(in[1 + i * 8], sched[0]);
		out[2 + i * 8] = _mm_xor_si128(in[2 + i * 8], sched[0]);
		out[3 + i * 8] = _mm_xor_si128(in[3 + i * 8], sched[0]);
		out[4 + i * 8] = _mm_xor_si128(in[4 + i * 8], sched[0]);
		out[5 + i * 8] = _mm_xor_si128(in[5 + i * 8], sched[0]);
		out[6 + i * 8] = _mm_xor_si128(in[6 + i * 8], sched[0]);
		out[7 + i * 8] = _mm_xor_si128(in[7 + i * 8], sched[0]);

		for (j = 1; j < rnds; ++j){
			out[0 + i * 8] = _mm_aesenc_si128(out[0 + i * 8], sched[j]);
			out[1 + i * 8] = _mm_aesenc_si128(out[1 + i * 8], sched[j]);
			out[2 + i * 8] = _mm_aesenc_si128(out[2 + i * 8], sched[j]);
			out[3 + i * 8] = _mm_aesenc_si128(out[3 + i * 8], sched[j]);
			out[4 + i * 8] = _mm_aesenc_si128(out[4 + i * 8], sched[j]);
			out[5 + i * 8] = _mm_aesenc_si128(out[5 + i * 8], sched[j]);
			out[6 + i * 8] = _mm_aesenc_si128(out[6 + i * 8], sched[j]);
			out[7 + i * 8] = _mm_aesenc_si128(out[7 + i * 8], sched[j]);
		}
		out[0 + i * 8] = _mm_aesenclast_si128(out[0 + i * 8], sched[j]);
		out[1 + i * 8] = _mm_aesenclast_si128(out[1 + i * 8], sched[j]);
		out[2 + i * 8] = _mm_aesenclast_si128(out[2 + i * 8], sched[j]);
		out[3 + i * 8] = _mm_aesenclast_si128(out[3 + i * 8], sched[j]);
		out[4 + i * 8] = _mm_aesenclast_si128(out[4 + i * 8], sched[j]);
		out[5 + i * 8] = _mm_aesenclast_si128(out[5 + i * 8], sched[j]);
		out[6 + i * 8] = _mm_aesenclast_si128(out[6 + i * 8], sched[j]);
		out[7 + i * 8] = _mm_aesenclast_si128(out[7 + i * 8], sched[j]);
	}

	for (int i = blocksPipeLined; i < blocksPipeLined + remainingEncrypts; ++i){
		out[i] = _mm_xor_si128(in[i], sched[0]);
		for (j = 1; j < rnds; ++j)
		{
			out[i] = _mm_aesenc_si128(out[i], sched[j]);
		}
		out[i] = _mm_aesenclast_si128(out[i], sched[j]);
	}
	
}
#endif
