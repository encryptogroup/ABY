/**
 \file 		djnparty.h
 \author 	daniel.demmler@ec-spride.de
 \copyright __________________
 \brief		Implementation of DJNParty class
 */

#ifndef __DJNPARTY_H__
#define __DJNPARTY_H__

#include <gmp.h>
#include <vector>
#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/djn.h"
#include "../util/powmod.h"

using namespace std;

class DJNParty {
public:
	DJNParty(UINT DJNbits, UINT sharelen);
	DJNParty(UINT DJNbits, UINT sharelen, CSocket sock);
	~DJNParty();

	void keyExchange(CSocket sock);
	void preCompBench(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, UINT numMTs, CSocket sock);

	void setSharelLength(UINT sharelen);

	void keyGen();

private:
	USHORT m_nNumMTThreads;
	USHORT m_nShareLength;
	UINT m_nDJNbits;
	UINT m_nBuflen;

	// Crypto and GMP PRNG
	djn_pubkey_t *m_localpub, *m_remotepub;
	djn_prvkey_t *m_prv;
	gmp_randstate_t m_randstate;

	void benchPreCompPacking1(CSocket sock, BYTE * buf, UINT packlen, UINT numshares, mpz_t * a, mpz_t * b, mpz_t * c, mpz_t * a1, mpz_t * b1, mpz_t * c1, mpz_t r, mpz_t x,
			mpz_t y, mpz_t z);

	void sendmpz_t(mpz_t t, CSocket sock, BYTE * buf);
	void receivempz_t(mpz_t t, CSocket sock, BYTE * buf);

	void sendmpz_t(mpz_t t, CSocket sock);
	void receivempz_t(mpz_t t, CSocket sock);

	void printBuf(BYTE* b, UINT l);

};

#endif //__DJN_PARTY_H__
