/**
 \file 		djnparty.cpp
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

#include "djnparty.h"
#include "../ENCRYPTO_utils/timer.h"
#include "../ENCRYPTO_utils/utils.h"

#define CHECKMT 0
#define DJN_DEBUG 0
#define NETDEBUG 0
#define NETDEBUG2 0
#define WINDOWSIZE 65536//maximum size of a network packet in Byte

/**
 * initializes a DJN_Party with the asymmetric security parameter and the sharelength.
 * Generates DJN key.
 * Key Exchange must be done manually after calling this constructor!
 */
DJNParty::DJNParty(UINT DJNbits, UINT sharelen, channel* chan) {

	m_nShareLength = sharelen;
	m_nDJNbits = DJNbits;
	m_nBuflen = DJNbits / 4 + 1;

#if DJN_DEBUG
	std::cout << "(sock) Created party with " << DJNbits << " bits and" << m_nBuflen << std::endl;
#endif

	keyGen();
	keyExchange(chan);
}

DJNParty::DJNParty(UINT DJNbits, UINT sharelen) {

	m_nShareLength = sharelen;
	m_nDJNbits = DJNbits;
	m_nBuflen = DJNbits / 4 + 1;

#if DJN_DEBUG
	std::cout << "(nosock) Created party with " << DJNbits << " bits and" << m_nBuflen << std::endl;
#endif

	keyGen();
}

void DJNParty::keyGen() {
#if DJN_DEBUG
	std::cout << "KG" << std::endl;
#endif
	djn_keygen(m_nDJNbits, &m_localpub, &m_prv);
}

void DJNParty::setSharelLength(UINT sharelen) {
	m_nShareLength = sharelen;
}

/**
 * deletes party and frees keys and randstate
 */
DJNParty::~DJNParty() {
#if DJN_DEBUG
	std::cout << "Deleting DJNParty...";
#endif
	djn_freeprvkey(m_prv);
	djn_freepubkey(m_localpub);
	djn_freepubkey(m_remotepub);

}

/**
 * inputs pre-allocates byte buffers for aMT calculation.
 * numMTs must be the total number of MTs and divisible by 2
 */
void DJNParty::preCompBench(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, UINT numMTs, channel* chan) {
	struct timespec start, end;

	numMTs = numMTs / 2; // We can be both sender and receiver at the same time.

	UINT maxShareLen = 2 * m_nShareLength + 41; // length of one share in the packet, sigma = 40
	UINT packshares = m_nDJNbits / maxShareLen; // number of shares in one packet
	UINT numpacks = (numMTs + packshares - 1) / packshares; // total number of packets to send in order to generate numMTs = CEIL(numMTs/2*numshares)

	UINT shareBytes = m_nShareLength / 8;
	UINT offset = 0;
	UINT limit = packshares; // upper bound for a package shares, used to handle non-full last packages / alignment

#if DJN_DEBUG
	std::cout << "djnbits: " << m_nDJNbits << " sharelen: " << m_nShareLength << " packlen: " << maxShareLen << " numshares: " << packshares << " numpacks: " << numpacks << std::endl;
#endif

	mpz_t r, x, y, z;
	mpz_inits(r, x, y, z, NULL);

	// shares for server part
	mpz_t a[packshares];
	mpz_t b[packshares];
	mpz_t c[packshares];

	// shares for client part
	mpz_t a1[packshares];
	mpz_t b1[packshares];
	mpz_t c1[packshares];

	for (UINT i = 0; i < packshares; i++) {
		mpz_inits(a[i], b[i], c[i], a1[i], b1[i], c1[i], NULL);
	}

	//allocate buffers for mpz_t ciphertext #numMTs with m_nBuflen
	BYTE * abuf = (BYTE*) calloc(numMTs * m_nBuflen, 1);
	BYTE * bbuf = (BYTE*) calloc(numMTs * m_nBuflen, 1);
	BYTE * zbuf = (BYTE*) calloc(numpacks * m_nBuflen, 1);

	clock_gettime(CLOCK_MONOTONIC, &start);

	// read server a,b shares and encrypt them into buffer
	for (UINT i = 0; i < numMTs; i++) {
		mpz_import(x, 1, 1, shareBytes, 0, 0, bA + i * shareBytes);
		mpz_import(y, 1, 1, shareBytes, 0, 0, bB + i * shareBytes);

		djn_encrypt_crt(r, m_localpub, m_prv, x);
		mpz_export(abuf + i * m_nBuflen, NULL, -1, 1, 1, 0, r);
		djn_encrypt_crt(z, m_localpub, m_prv, y);
		mpz_export(bbuf + i * m_nBuflen, NULL, -1, 1, 1, 0, z);

	}

	// send & receive encrypted values
	int window = WINDOWSIZE;
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
	for (UINT i = 0; i < numpacks; i++) {

		if (i == numpacks - 1) {
			limit = numMTs % packshares; // if last package, only fill buffers to requested size and discard remaining shares
		}

		//read shares from client byte arrays
		for (UINT j = 0; j < limit; j++) {
			mpz_import(a1[j], 1, 1, shareBytes, 0, 0, bA1 + offset);
			mpz_import(b1[j], 1, 1, shareBytes, 0, 0, bB1 + offset);

			mpz_import(x, m_nBuflen, -1, 1, 1, 0, abuf + (j + i * packshares) * m_nBuflen);
			mpz_import(y, m_nBuflen, -1, 1, 1, 0, bbuf + (j + i * packshares) * m_nBuflen);

			dbpowmod(c1[j], x, b1[j], y, a1[j], m_remotepub->n_squared); //double base exponentiation
			offset += shareBytes;
		}

		// horner packing of shares into 1 ciphertext
		mpz_set(z, c1[limit - 1]);
		mpz_set_ui(y, 0);
		mpz_setbit(y, maxShareLen); // y = 2^shareLength, for shifting ciphertext

		for (int j = limit - 2; j >= 0; j--) {
			mpz_powm(z, z, y, m_remotepub->n_squared);
			mpz_mul(z, z, c1[j]);
			mpz_mod(z, z, m_remotepub->n_squared);
		}

		// pick random r for masking
		aby_prng(x, mpz_sizeinbase(m_remotepub->n, 2) + 128);
		mpz_mod(x, x, m_remotepub->n);

		djn_encrypt_fb(y, m_remotepub, x);

		// "add" encrypted r and add to buffer
		mpz_mul(z, z, y);
		mpz_mod(z, z, m_remotepub->n_squared);

		mpz_export(zbuf + i * m_nBuflen, NULL, -1, 1, 1, 0, z); // TODO maybe reuse abuf, but make sure it's cleaned properly

		offset -= shareBytes * limit;

		// calculate c shares for client part
		for (UINT j = 0; j < limit; j++) {
			mpz_mod_2exp(y, x, m_nShareLength); // y = r mod 2^shareLength == read the share from least significant bits
			mpz_div_2exp(x, x, maxShareLen); // r = r >> maxShareLen

			mpz_mul(c1[j], a1[j], b1[j]); //c = a * b
			mpz_sub(c1[j], c1[j], y); // c = c - y

			mpz_mod_2exp(c1[j], c1[j], m_nShareLength); // c = c mod 2^shareLength
			mpz_export(bC1 + offset, NULL, 1, shareBytes, 0, 0, c1[j]);

			offset += shareBytes;
		}
	}

	// ----------------#############   ###############-----------------------
	// all packets packed. exchange these packets

	window = WINDOWSIZE;
	tosend = m_nBuflen * numpacks;
	offset = 0;

	while (tosend > 0) {
		window = std::min(window, tosend);

		chan->send(zbuf + offset, window);
		chan->blocking_receive(zbuf + offset, window);

		tosend -= window;
		offset += window;
	}

	//unpack and calculate server c shares
	limit = packshares;
	offset = 0;

	for (UINT i = 0; i < numpacks; i++) {

		if (i == numpacks - 1) {
			limit = numMTs % packshares; // if last package, only fill buffers to requested size and discard remaining shares
		}

		mpz_import(r, m_nBuflen, -1, 1, 1, 0, zbuf + i * m_nBuflen);

		djn_decrypt(r, m_localpub, m_prv, r);

		for (UINT j = 0; j < limit; j++) {
			mpz_import(a[j], 1, 1, shareBytes, 0, 0, bA + offset);
			mpz_import(b[j], 1, 1, shareBytes, 0, 0, bB + offset);

			mpz_mod_2exp(c[j], r, m_nShareLength); // c = x mod 2^shareLength == read the share from least significant bits
			mpz_div_2exp(r, r, maxShareLen); // x = x >> maxShareLen
			mpz_addmul(c[j], a[j], b[j]); //c = a*b + c
			mpz_mod_2exp(c[j], c[j], m_nShareLength); // c = c mod 2^shareLength
			mpz_export(bC + offset, NULL, 1, shareBytes, 0, 0, c[j]);
			offset += shareBytes;
		}
	}

#if CHECKMT
	std::cout << "Checking MT validity with values from other party:" << std::endl;

	mpz_t ai, bi, ci, ai1, bi1, ci1, ta, tb;
	mpz_inits(ai, bi, ci, ai1, bi1, ci1, ta, tb, NULL);

	chan->send(bA, numMTs * shareBytes);
	chan->blocking_receive(bA, numMTs * shareBytes);
	chan->send(bB, numMTs * shareBytes);
	chan->blocking_receive(bB, numMTs * shareBytes);
	chan->send(bC, numMTs * shareBytes);
	chan->blocking_receive(bC, numMTs * shareBytes);

	for (UINT i = 0; i < numMTs; i++) {

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
		mpz_mod_2exp(ta, ta, m_nShareLength);
		mpz_mod_2exp(tb, tb, m_nShareLength);

		if (mpz_cmp(ta, tb) == 0) {
			std::cout << "MT is fine - i:" << i << "| " << ai << " " << bi << " " << ci << " . " << ai1 << " " << bi1 << " " << ci1 << std::endl;
		} else {
			std::cout << "Error in MT - i:" << i << "| " << ai << " " << bi << " " << ci << " . " << ai1 << " " << bi1 << " " << ci1 << std::endl;
		}

		//std::cout << (mpz_cmp(c1[i], a1[i]) == 0 ? "MT is fine." : "Error in MT!") << std::endl;
	}
	mpz_clears(ai, bi, ci, ai1, bi1, ci1, ta, tb, NULL);
#endif

	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("generating 2x %u MTs took %f\n", numMTs, getMillies(start, end));

//clean up after ourselves
	for (UINT i = 0; i < packshares; i++) {
		mpz_clears(a[i], b[i], c[i], a1[i], b1[i], c1[i], NULL);
	}

	mpz_clears(r, x, y, z, NULL);

	free(abuf);
	free(bbuf);
	free(zbuf);
}

/**
 * Interleaved sending and receiving. Server and client role at the same time for load balancing.
 * a,b,c are server shares. a1,b1,c1 are client shares.
 * All mpz_t values must be pre-initialized.
 */
void DJNParty::benchPreCompPacking1(channel* chan, BYTE * buf, UINT packlen, UINT numshares, mpz_t * a, mpz_t * b, mpz_t * c, mpz_t * a1, mpz_t * b1, mpz_t * c1, mpz_t r, mpz_t x,
		mpz_t y, mpz_t z) {
#if DJN_DEBUG
	std::cout << "packlen: " << packlen << " numshares: " << numshares << std::endl;
#endif

	for (UINT i = 0; i < numshares; i++) {
		djn_encrypt_crt(r, m_localpub, m_prv, a[i]);
		mpz_export(buf + 2 * i * m_nBuflen, NULL, -1, 1, 1, 0, r);
		djn_encrypt_crt(r, m_localpub, m_prv, b[i]);
		mpz_export(buf + (2 * i + 1) * m_nBuflen, NULL, -1, 1, 1, 0, r);
	}

	chan->send(buf, (uint64_t) m_nBuflen * numshares * 2);

#if NETDEBUG
	std::cout << " SEND " << std::endl;
	for (UINT xx=0; xx < m_nBuflen * numshares * 2; xx++) {
		printf("%02x.", *(buf + xx));
	}
#endif

	chan->blocking_receive(buf, (uint64_t) m_nBuflen * numshares * 2);

#if NETDEBUG
	std::cout << " RECV " << std::endl;
	for (UINT xx=0; xx < m_nBuflen * numshares * 2; xx++) {
		printf("%02x.", *(buf + xx));
	}
#endif

	for (UINT i = 0; i < numshares; i++) {
		mpz_import(x, m_nBuflen, -1, 1, 1, 0, buf + 2 * i * m_nBuflen);
		mpz_import(y, m_nBuflen, -1, 1, 1, 0, buf + (2 * i + 1) * m_nBuflen);

		dbpowmod(c1[i], x, b1[i], y, a1[i], m_remotepub->n_squared); //double base exponentiation
	}

// horner packing of shares into 1 ciphertext
	mpz_set(z, c1[numshares - 1]);
	mpz_set_ui(y, 0);
	mpz_setbit(y, packlen); // y = 2^shareLength, for shifting ciphertext

	for (int i = numshares - 2; i >= 0; i--) {
		mpz_powm(z, z, y, m_remotepub->n_squared);
		mpz_mul(z, z, c1[i]);
		mpz_mod(z, z, m_remotepub->n_squared);
	}

// pick random r for masking
	aby_prng(x, mpz_sizeinbase(m_remotepub->n, 2) + 128);
	mpz_mod(x, x, m_remotepub->n);
	djn_encrypt_fb(y, m_remotepub, x);

// "add" encrypted r and send
	mpz_mul(z, z, y);
	mpz_mod(z, z, m_remotepub->n_squared);

// calculate c shares for client part
	for (UINT i = 0; i < numshares; i++) {
		mpz_mod_2exp(y, x, m_nShareLength); // y = r mod 2^shareLength == read the share from least significant bits
		mpz_div_2exp(x, x, packlen); // r = r >> packlen

		mpz_mul(c1[i], a1[i], b1[i]); //c = a * b
		mpz_sub(c1[i], c1[i], y); // c = c - y

		mpz_mod_2exp(c1[i], c1[i], m_nShareLength); // c = c mod 2^shareLength
	}
}

/**
 * exchanges private keys with other party via sock, pre-calculates fixed-base representation of remote pub-key
 */
void DJNParty::keyExchange(channel* chan) {

//send public key
	sendmpz_t(m_localpub->n, chan);
	sendmpz_t(m_localpub->h, chan);

//receive and complete public key
	mpz_t a, b;
	mpz_inits(a, b, NULL);
	receivempz_t(a, chan); //n
	receivempz_t(b, chan); //h
	djn_complete_pubkey(m_nDJNbits, &m_remotepub, a, b);

// pre calculate table for fixed-base exponentiation for client
	fbpowmod_init_g(m_remotepub->h_s, m_remotepub->n_squared, 2 * m_nDJNbits);

//free a and b
	mpz_clears(a, b, NULL);

#if DJN_DEBUG
	std::cout << "KX done. This pubkey: " << m_localpub->n << " remotekey: " << m_remotepub->n << std::endl;
#endif
}

/**
 * send one mpz_t to sock
 */
void DJNParty::sendmpz_t(mpz_t t, channel* chan, BYTE * buf) {

//clear upper bytes of the buffer, so tailing bytes are zero
	for (int i = mpz_sizeinbase(t, 256); i < m_nBuflen; i++) {
		*(buf + i) = 0;
	}

#if NETDEBUG2
	std::cout << mpz_sizeinbase(t, 256) << " vs. " << m_nBuflen << std::endl;
#endif

	mpz_export(buf, NULL, -1, 1, 1, 0, t);

	//send Bytes of t
	chan->send(buf, (uint64_t) m_nBuflen);

#if NETDEBUG
	std::cout << std::endl << "SEND" << std::endl;
	for (int i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(m_sendbuf + i));
	}

	std::cout << std::endl << "sent: " << t << " with len: " << m_nBuflen << " should have been " << mpz_sizeinbase(t, 256) << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DJNParty::receivempz_t(mpz_t t, channel* chan, BYTE * buf) {
	chan->blocking_receive(buf, (uint64_t) m_nBuflen);
	mpz_import(t, m_nBuflen, -1, 1, 1, 0, buf);

#if NETDEBUG
	std::cout << std::endl << "RECEIVE" << std::endl;
	for (int i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(m_recbuf + i));
	}

	std::cout << "received: " << t << " with len: " << m_nBuflen << std::endl;
#endif
}

/**
 * send one mpz_t to sock, allocates buffer
 */
void DJNParty::sendmpz_t(mpz_t t, channel* chan) {
	unsigned int bytelen = mpz_sizeinbase(t, 256);
	BYTE* arr = (BYTE*) malloc(bytelen);
	mpz_export(arr, NULL, 1, 1, 1, 0, t);

//send byte length
	chan->send((BYTE*) &bytelen, sizeof(bytelen));

//send bytes of t
	chan->send(arr, (uint64_t) bytelen);

	free(arr);
#if NETDEBUG
	std::cout << "sent: " << t << " with len: " << bytelen << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DJNParty::receivempz_t(mpz_t t, channel* chan) {
	unsigned int bytelen;

//reiceive byte length
	chan->blocking_receive((BYTE*) &bytelen, sizeof(bytelen));
	BYTE* arr = (BYTE*) malloc(bytelen);

//receive bytes of t
	chan->blocking_receive(arr, (uint64_t) bytelen);
	mpz_import(t, bytelen, 1, 1, 1, 0, arr);

	free(arr);
#if NETDEBUG
	std::cout << "received: " << t << " with len: " << bytelen << std::endl;
#endif
}

#if DJN_DEBUG
void DJNParty::printBuf(BYTE* b, UINT len) {
	for (UINT i = 0; i < len; i++) {
		printf("%02x.", *(b + i));
	}
	std::cout << std::endl;
}
#endif
