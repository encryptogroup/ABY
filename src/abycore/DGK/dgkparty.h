/**
 \file 		dgkparty.h
 \author 	daniel.demmler@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		DGKParty
*/

#ifndef __DGKPARTY_H__
#define __DGKPARTY_H__

#define DGK_CHECKMT 0
#define DGK_DEBUG 0
#define DGK_BENCH 0
#define DGK_NETDEBUG 0
#define DGK_WINDOWSIZE 65536 //maximum size of a network packet in Byte

#include <gmp.h>
#include <vector>
#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/crypto/dgk.h>
#include <ENCRYPTO_utils/powmod.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/utils.h>
#if DGK_DEBUG || DGK_BENCH
#include <iostream>
#endif

class DGKParty {
public:
	DGKParty(uint32_t DGKModulusBits, uint32_t shareBitLength, uint32_t readkey);
	DGKParty(uint32_t DGKModulusBits, uint32_t shareBitLength, channel* chan, uint32_t readkey);
	~DGKParty();

	void keyExchange(channel* chan);

	void computeArithmeticMTs(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, uint32_t numMTs, channel* chan);

	void readKey();

	void generateKey();

	void loadNewKey(uint32_t DGKModulusBits, uint32_t shareBitLength);

private:
	uint16_t m_nNumMTThreads;
	uint16_t m_nShareBitLength;
	uint32_t m_nDGKModulusBits;
	uint32_t m_nBuflen;

	// Crypto and GMP PRNG
	dgk_pubkey_t *m_localpub, *m_remotepub;
	dgk_prvkey_t *m_prv;

	void benchPreCompPacking1(channel* chan, BYTE * buf, uint32_t packlen, uint32_t numshares, mpz_t * a, mpz_t * b, mpz_t * c, mpz_t * a1, mpz_t * b1, mpz_t * c1, mpz_t r, mpz_t x,
			mpz_t y, mpz_t z);

	void sendmpz_t(mpz_t t, channel* chan, BYTE * buf);
	void receivempz_t(mpz_t t, channel* chan, BYTE * buf);

	void sendmpz_t(mpz_t t, channel* chan);
	void receivempz_t(mpz_t t, channel* chan);

	void printBuf(BYTE* b, uint32_t l);
};

#endif //__DGK_PARTY_H__
