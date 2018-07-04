/**
 \file 		dgkparty.h
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
 \brief		DGKParty
*/

#ifndef __DGKPARTY_H__
#define __DGKPARTY_H__

#include <gmp.h>
#include <vector>
#include "../ENCRYPTO_utils/typedefs.h"
#include "../ENCRYPTO_utils/socket.h"
#include "../ENCRYPTO_utils/crypto/dgk.h"
#include "../ENCRYPTO_utils/powmod.h"
#include "../ENCRYPTO_utils/channel.h"

class DGKParty {
public:
	DGKParty(UINT DGKbits, UINT sharelen, UINT readkey);
	DGKParty(UINT DGKbits, UINT sharelen, channel* chan, UINT readkey);
	~DGKParty();

	void keyExchange(channel* chan);

	void preCompBench(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, UINT numMTs, channel* chan);

	void readKey();

	void generateKey();

	void loadNewKey(UINT DGKbits, UINT sharelen);

private:
	USHORT m_nNumMTThreads;
	USHORT m_nShareLength;
	UINT m_nDGKbits;
	UINT m_nBuflen;

	// Crypto and GMP PRNG
	dgk_pubkey_t *m_localpub, *m_remotepub;
	dgk_prvkey_t *m_prv;

	void benchPreCompPacking1(channel* chan, BYTE * buf, UINT packlen, UINT numshares, mpz_t * a, mpz_t * b, mpz_t * c, mpz_t * a1, mpz_t * b1, mpz_t * c1, mpz_t r, mpz_t x,
			mpz_t y, mpz_t z);

	void sendmpz_t(mpz_t t, channel* chan, BYTE * buf);
	void receivempz_t(mpz_t t, channel* chan, BYTE * buf);

	void sendmpz_t(mpz_t t, channel* chan);
	void receivempz_t(mpz_t t, channel* chan);

	void printBuf(BYTE* b, UINT l);

};

#endif //__DGK_PARTY_H__
