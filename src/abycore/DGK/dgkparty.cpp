/**
 \file 		dgkparty.cpp
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
 \brief		DGKParty implementation
 */

#include "dgkparty.h"

/**
 * initializes a DGK_Party with the asymmetric security parameter and the sharelength and exchanges public keys.
 * @param mode - 0 = generate new key; 1 = read key
 */
DGKParty::DGKParty(uint32_t DGKModulusBits, uint32_t shareBitLength, channel* chan, uint32_t readkey) {

	m_nShareBitLength = shareBitLength;
	m_nDGKModulusBits = DGKModulusBits;
	m_nBuflen = DGKModulusBits / 8 + 1; //size of one ciphertext to send via network. DGK uses n bits == n/8 bytes

#if DGK_DEBUG
	std::cout << "Created party with " << DGKModulusBits << " key bits and " << shareBitLength << " bit shares" << std::endl;
#endif

	if (readkey) {
		readKey();
	} else {
		generateKey();
	}

	keyExchange(chan);
}

/**
 * initializes a DGK_Party with the asymmetric security parameter and the sharelength.
 * @param mode - 0 = generate new key; 1 = read key
 * Public keys must be exchanged manually when using this constructor!
 */
DGKParty::DGKParty(uint32_t DGKModulusBits, uint32_t shareBitLength, uint32_t readkey) {

	m_nShareBitLength = shareBitLength;
	m_nDGKModulusBits = DGKModulusBits;
	m_nBuflen = DGKModulusBits / 8 + 1; //size of one ciphertext to send via network. DGK uses n bits == n/8 bytes

#if DGK_DEBUG
	std::cout << "Created party with " << DGKModulusBits << " key bits and " << shareBitLength << " bit shares" << std::endl;
#endif

	if (readkey) {
		readKey();
	} else {
		generateKey();
	}
}

void DGKParty::readKey() {
#if DGK_DEBUG
	std::cout << "Reading DGK key…" << std::endl;
#endif
	dgk_readkey(m_nDGKModulusBits, m_nShareBitLength, &m_localpub, &m_prv);
#if DGK_DEBUG
	std::cout << "key read." << std::endl;
#endif
}

void DGKParty::generateKey() {
#if DGK_DEBUG
	std::cout << "Generating DKG key…" << std::endl;
#endif
	dgk_keygen(m_nDGKModulusBits, m_nShareBitLength, &m_localpub, &m_prv);
#if DGK_DEBUG
	std::cout << "key generated." << std::endl;
#endif
}

/**
 * deletes party and frees keys
 */
DGKParty::~DGKParty() {
#if DGK_DEBUG
	std::cout << "Deleting DGKParty…" << std::endl;
#endif
	dgk_freeprvkey(m_prv);
	dgk_freepubkey(m_localpub);
	dgk_freepubkey(m_remotepub);
}

/**
 * inputs: pre-allocates byte buffers for aMT calculation.
 * numMTs is the total number of MTs
 */
void DGKParty::computeArithmeticMTs(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, uint32_t numMTs, channel* chan) {
	struct timespec start, end;

	numMTs = ceil_divide(numMTs, 2); // We can be both sender and receiver at the same time.

	uint32_t shareBytes = m_nShareBitLength / 8;
	uint32_t offset = 0;

#if DGK_DEBUG
	std::cout << "DGKModulusBits: " << m_nDGKModulusBits << " shareBitLength: " << m_nShareBitLength << std::endl;
#endif

	mpz_t r, x, y, z;
	mpz_inits(r, x, y, z, NULL);

	// shares for server part
	mpz_t a[numMTs];
	mpz_t b[numMTs];
	mpz_t c[numMTs];

	// shares for client part
	mpz_t a1[numMTs];
	mpz_t b1[numMTs];
	mpz_t c1[numMTs];

	for (uint32_t i = 0; i < numMTs; i++) {
		mpz_inits(a[i], b[i], c[i], a1[i], b1[i], c1[i], NULL);
	}

	//allocate buffers for mpz_t ciphertext #numMTs with m_nBuflen
	BYTE * abuf = (BYTE*) calloc(numMTs * m_nBuflen, 1);
	BYTE * bbuf = (BYTE*) calloc(numMTs * m_nBuflen, 1);
	BYTE * zbuf = (BYTE*) calloc(numMTs * m_nBuflen, 1);

	clock_gettime(CLOCK_MONOTONIC, &start);

	// read server a,b shares and encrypt them into buffer
	for (uint32_t i = 0; i < numMTs; i++) {
		mpz_import(x, 1, 1, shareBytes, 0, 0, bA + i * shareBytes);
		mpz_import(y, 1, 1, shareBytes, 0, 0, bB + i * shareBytes);

		dgk_encrypt_crt(r, m_localpub, m_prv, x);
		mpz_export(abuf + i * m_nBuflen, NULL, -1, 1, 1, 0, r);
		dgk_encrypt_crt(z, m_localpub, m_prv, y);
		mpz_export(bbuf + i * m_nBuflen, NULL, -1, 1, 1, 0, z);

	}

	// send & receive encrypted values
	int window = DGK_WINDOWSIZE;
	int tosend = m_nBuflen * numMTs;
	offset = 0;

	while (tosend > 0) {

		window = std::min(window, tosend);

		chan->send(abuf + offset, window);
		chan->blocking_receive(abuf + offset, window);

		chan->send(bbuf + offset, window);
		chan->blocking_receive(bbuf + offset, window);

		tosend -= window;
		offset += window;
	}

	// ----------------#############   ###############-----------------------
	// pack ALL the packets

	offset = 0;

	//read shares from client byte arrays
	for (uint32_t j = 0; j < numMTs; j++) {
		mpz_import(a1[j], 1, 1, shareBytes, 0, 0, bA1 + offset);
		mpz_import(b1[j], 1, 1, shareBytes, 0, 0, bB1 + offset);

		mpz_import(x, m_nBuflen, -1, 1, 1, 0, abuf + j * m_nBuflen);
		mpz_import(y, m_nBuflen, -1, 1, 1, 0, bbuf + j * m_nBuflen);

		dbpowmod(c1[j], x, b1[j], y, a1[j], m_remotepub->n);

		// pick random r for masking
		aby_prng(x, 2 * m_nShareBitLength + 1);

		dgk_encrypt_fb(y, m_remotepub, x);

		// "add" encrypted r and add to buffer
		mpz_mul(z, c1[j], y);
		mpz_mod(z, z, m_remotepub->n);
		mpz_export(zbuf + j * m_nBuflen, NULL, -1, 1, 1, 0, z); // TODO maybe reuse abuf, but make sure it's cleaned properly

		mpz_mul(c1[j], a1[j], b1[j]); //c = a * b
		mpz_sub(c1[j], c1[j], x); // c = c - x
		mpz_mod_2exp(c1[j], c1[j], m_nShareBitLength); // c = c mod 2^shareLength

		mpz_export(bC1 + offset, NULL, 1, shareBytes, 0, 0, c1[j]);

		offset += shareBytes;
	}

// ----------------#############   ###############-----------------------
// all packets packed. exchange these packets

	window = DGK_WINDOWSIZE;
	tosend = m_nBuflen * numMTs;
	offset = 0;

	while (tosend > 0) {
		window = std::min(window, tosend);

		chan->send(zbuf + offset, window);
		chan->blocking_receive(zbuf + offset, window);

		tosend -= window;
		offset += window;
	}

//calculate server c shares

	offset = 0;

	for (uint32_t i = 0; i < numMTs; i++) {

		mpz_import(r, m_nBuflen, -1, 1, 1, 0, zbuf + i * m_nBuflen);
		dgk_decrypt(r, m_localpub, m_prv, r);

		mpz_import(a[i], 1, 1, shareBytes, 0, 0, bA + offset);
		mpz_import(b[i], 1, 1, shareBytes, 0, 0, bB + offset);

		mpz_mod_2exp(c[i], r, m_nShareBitLength); // c = x mod 2^shareLength == read the share from least significant bits
		mpz_addmul(c[i], a[i], b[i]); //c = a*b + c
		mpz_mod_2exp(c[i], c[i], m_nShareBitLength); // c = c mod 2^shareLength
		mpz_export(bC + offset, NULL, 1, shareBytes, 0, 0, c[i]);
		offset += shareBytes;

	}

#if DGK_CHECKMT
	//TODO: This overwrites generated MTs and should be put in a separate function.
	std::cout << "Checking MT validity with values from other party:" << std::endl;

	mpz_t ai, bi, ci, ai1, bi1, ci1, ta, tb;
	mpz_inits(ai, bi, ci, ai1, bi1, ci1, ta, tb, NULL);

	chan->send(bA, numMTs * shareBytes);
	chan->blocking_receive(bA, numMTs * shareBytes);
	chan->send(bB, numMTs * shareBytes);
	chan->blocking_receive(bB, numMTs * shareBytes);
	chan->send(bC, numMTs * shareBytes);
	chan->blocking_receive(bC, numMTs * shareBytes);

	for (uint32_t i = 0; i < numMTs; i++) {

		mpz_import(ai, 1, 1, shareBytes, 0, 0, bA + i * shareBytes);
		mpz_import(bi, 1, 1, shareBytes, 0, 0, bB + i * shareBytes);
		mpz_import(ci, 1, 1, shareBytes, 0, 0, bC + i * shareBytes);

		mpz_import(ai1, 1, 1, shareBytes, 0, 0, bA1 + i * shareBytes);
		mpz_import(bi1, 1, 1, shareBytes, 0, 0, bB1 + i * shareBytes);
		mpz_import(ci1, 1, 1, shareBytes, 0, 0, bC1 + i * shareBytes);

		mpz_add(ta, ai, ai1);
		mpz_add(tb, bi, bi1);
		mpz_mul(ta, ta, tb);
		mpz_add(tb, ci, ci1);
		mpz_mod_2exp(ta, ta, m_nShareBitLength);
		mpz_mod_2exp(tb, tb, m_nShareBitLength);

		if (mpz_cmp(ta, tb) == 0) {
			std::cout << "MT is fine - i:" << i << "| " << ai << " " << bi << " " << ci << " . " << ai1 << " " << bi1 << " " << ci1 << std::endl;
		} else {
			std::cout << "Error in MT - i:" << i << "| " << ai << " " << bi << " " << ci << " . " << ai1 << " " << bi1 << " " << ci1 << std::endl;
		}
		//cout << (mpz_cmp(c1[i], a1[i]) == 0 ? "MT is fine." : "Error in MT!") << std::endl;
	}
	mpz_clears(ai, bi, ci, ai1, bi1, ci1, ta, tb, NULL);
#endif

	clock_gettime(CLOCK_MONOTONIC, &end);

#if DGK_BENCH
	printf("generating 2x %u MTs took %f\n", numMTs, getMillies(start, end));
#endif

//clean up after ourselves
	for (uint32_t i = 0; i < numMTs; i++) {
		mpz_clears(a[i], b[i], c[i], a1[i], b1[i], c1[i], NULL);
	}

	mpz_clears(r, x, y, z, NULL);

	free(abuf);
	free(bbuf);
	free(zbuf);
}

/**
 * exchanges private keys with other party via sock, pre-calculates fixed-base representation of remote pub-key
 */
void DGKParty::keyExchange(channel* chan) {

//send public key
	sendmpz_t(m_localpub->n, chan);
	sendmpz_t(m_localpub->g, chan);
	sendmpz_t(m_localpub->h, chan);

//receive and complete public key
	mpz_t n, g, h;
	mpz_inits(n, g, h, NULL);
	receivempz_t(n, chan); //n
	receivempz_t(g, chan); //g
	receivempz_t(h, chan); //h

	dgk_complete_pubkey(m_nDGKModulusBits, m_nShareBitLength, &m_remotepub, n, g, h);

	// pre calculate table for fixed-base exponentiation for client
	fbpowmod_init_g(m_remotepub->g, m_remotepub->n, 2 * m_nShareBitLength + 2);
	fbpowmod_init_h(m_remotepub->h, m_remotepub->n, 400); // 2.5 * t = 2.5 * 160 = 400 bit

	//free a and b
	mpz_clears(n, g, h, NULL);

#if DGK_DEBUG
	std::cout << "KX done. Local pubkey: " << m_localpub->n << " remote pubkey: " << m_remotepub->n << std::endl;
#endif
}

/**
 * send one mpz_t to sock
 */
void DGKParty::sendmpz_t(mpz_t t, channel* chan, BYTE * buf) {

//clear upper bytes of the buffer, so tailing bytes are zero
	for (uint32_t i = mpz_sizeinbase(t, 256); i < m_nBuflen; i++) {
		*(buf + i) = 0;
	}

#if DGK_NETDEBUG
	std::cout << mpz_sizeinbase(t, 256) << " vs. " << m_nBuflen << std::endl;
#endif

	mpz_export(buf, NULL, -1, 1, 1, 0, t);

//send bytes of t
	chan->send(buf, (uint64_t) m_nBuflen);

#if DGK_NETDEBUG
	std::cout << std::endl << "SEND" << std::endl;
	for (uint32_t i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(buf + i));
	}

	std::cout << std::endl << "sent: " << t << " with len: " << m_nBuflen << " should have been " << mpz_sizeinbase(t, 256) << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DGKParty::receivempz_t(mpz_t t, channel* chan, BYTE * buf) {
	chan->blocking_receive(buf, (uint64_t) m_nBuflen);
	mpz_import(t, m_nBuflen, -1, 1, 1, 0, buf);

#if DGK_NETDEBUG
	std::cout << std::endl << "RECEIVE" << std::endl;
	for (uint32_t i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(buf + i));
	}

	std::cout << "received: " << t << " with len: " << m_nBuflen << std::endl;
#endif
}

/**
 * send one mpz_t to sock, allocates buffer
 */
void DGKParty::sendmpz_t(mpz_t t, channel* chan) {
	unsigned int bytelen = mpz_sizeinbase(t, 256);
	BYTE* arr = (BYTE*) malloc(bytelen);
	mpz_export(arr, NULL, 1, 1, 1, 0, t);

//send byte length
	chan->send((BYTE*) &bytelen, sizeof(bytelen));

//send bytes of t
	chan->send(arr, (uint64_t) bytelen);

	free(arr);
#if DGK_NETDEBUG
	std::cout << "sent: " << t << " with len: " << bytelen << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DGKParty::receivempz_t(mpz_t t, channel* chan) {
	unsigned int bytelen;

//reiceive byte length
	chan->blocking_receive((BYTE*) &bytelen, sizeof(bytelen));
	BYTE* arr = (BYTE*) malloc(bytelen);

//receive bytes of t
	chan->blocking_receive(arr, (uint64_t) bytelen);
	mpz_import(t, bytelen, 1, 1, 1, 0, arr);

	free(arr);
#if DGK_NETDEBUG
	std::cout << "received: " << t << " with len: " << bytelen << std::endl;
#endif
}

#if DEBUG
void DGKParty::printBuf(BYTE* b, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("%02x.", *(b + i));
	}
	std::cout << std::endl;
}
#endif

/**
 * reads a new key from disk (to be used when parameters change)
 */
void DGKParty::loadNewKey(uint32_t DGKModulusBits, uint32_t shareBitLength) {
	m_nDGKModulusBits = DGKModulusBits;
	m_nShareBitLength = shareBitLength;
	dgk_readkey(m_nDGKModulusBits, m_nShareBitLength, &m_localpub, &m_prv);
}
