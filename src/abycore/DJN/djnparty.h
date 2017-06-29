/**
 \file 		djnparty.h
 \author 	daniel.demmler@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of DJNParty class
*/

#ifndef __DJNPARTY_H__
#define __DJNPARTY_H__

#include <gmp.h>
#include <vector>
#include "../ENCRYPTO_utils/typedefs.h"
#include "../ENCRYPTO_utils/socket.h"
#include "../ENCRYPTO_utils/crypto/djn.h"
#include "../ENCRYPTO_utils/powmod.h"
#include "../ENCRYPTO_utils/channel.h"

using namespace std;

class DJNParty {
public:
	DJNParty(UINT DJNbits, UINT sharelen);
	DJNParty(UINT DJNbits, UINT sharelen, channel* chan);
	~DJNParty();

	void keyExchange(channel* chan);
	void preCompBench(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, UINT numMTs, channel* chan);

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

	void benchPreCompPacking1(channel* chan, BYTE * buf, UINT packlen, UINT numshares, mpz_t * a, mpz_t * b, mpz_t * c, mpz_t * a1, mpz_t * b1, mpz_t * c1, mpz_t r, mpz_t x,
			mpz_t y, mpz_t z);

	void sendmpz_t(mpz_t t, channel* chan, BYTE * buf);
	void receivempz_t(mpz_t t, channel* chan, BYTE * buf);

	void sendmpz_t(mpz_t t, channel* chan);
	void receivempz_t(mpz_t t, channel* chan);

	void printBuf(BYTE* b, UINT l);

};

#endif //__DJN_PARTY_H__
