/**
 \file 		naor-pinkas.cpp
 \author 	michael.zohner@ec-spride.de
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
 \brief		naor-pinkas implementation.
 */

#include "naor-pinkas.h"

void NaorPinkas::Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector& choices, CSocket& socket, uint8_t* ret) {

	fe* PK0 = m_cPKCrypto->get_fe();
	fe** PK_sigma = (fe**) malloc(sizeof(fe*) * nOTs);
	fe** pDec = (fe**) malloc(sizeof(fe*) * nOTs);
	fe** pC = (fe**) malloc(sizeof(fe*) * nSndVals);
	fe* g = m_cPKCrypto->get_generator();

	num** pK = (num**) malloc(sizeof(num*) * nOTs);

	uint8_t* retPtr;
	uint32_t u, k, choice, hash_bytes, fe_bytes;
	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();

	brickexp *bg, *bc;
	bg = m_cPKCrypto->get_brick(g);

	uint8_t* pBuf = (uint8_t*) malloc(sizeof(uint8_t) * nOTs * fe_bytes);
	uint32_t nBufSize = nSndVals * fe_bytes;

	//calculate the generator of the group
	for (k = 0; k < nOTs; k++) {
		PK_sigma[k] = m_cPKCrypto->get_fe();
		pK[k] = m_cPKCrypto->get_rnd_num();

		bg->pow(PK_sigma[k], pK[k]);
	}

	socket.Receive(pBuf, nBufSize);
	uint8_t* pBufIdx = pBuf;

	for (u = 0; u < nSndVals; u++) {
		pC[u] = m_cPKCrypto->get_fe();
		pC[u]->import_from_bytes(pBufIdx);
		pBufIdx += fe_bytes;
	}

	bc = m_cPKCrypto->get_brick(pC[0]);

	//====================================================
	// N-P receiver: send pk0
	pBufIdx = pBuf;
	for (k = 0; k < nOTs; k++) {
		choice = choices.GetBit((int32_t) k);
		if (choice != 0) {
			PK0->set_div(pC[choice], PK_sigma[k]);
		} else {
			PK0->set(PK_sigma[k]);
		}
		PK0->export_to_bytes(pBufIdx);
		pBufIdx += fe_bytes;
	}

	socket.Send(pBuf, nOTs * m_cPKCrypto->fe_byte_size());

	free(pBuf);
	pBuf = (uint8_t*) malloc(sizeof(uint8_t) * fe_bytes);
	retPtr = ret;

	for (k = 0; k < nOTs; k++) {
		pDec[k] = m_cPKCrypto->get_fe();
		bc->pow(pDec[k], pK[k]);
		pDec[k]->export_to_bytes(pBuf);

		hashReturn(retPtr, hash_bytes, pBuf, fe_bytes, k);
		retPtr += hash_bytes;
	}

	delete bc;
	delete bg;

	delete[] pBuf;
	//TODO delete all field elements and numbers
	free(PK_sigma);
	free(pDec);
	free(pC);
	free(pK);
}

void NaorPinkas::Sender(uint32_t nSndVals, uint32_t nOTs, CSocket& socket, uint8_t* ret) {
	num *alpha, *PKr, *tmp;
	fe **pCr, **pC, *fetmp, *PK0r, *g, **pPK0;
	uint8_t* pBuf, *pBufIdx;
	uint32_t hash_bytes, fe_bytes, nBufSize, u, k;

	hash_bytes = m_cCrypto->get_hash_bytes();
	fe_bytes = m_cPKCrypto->fe_byte_size();

	alpha = m_cPKCrypto->get_rnd_num();
	PKr = m_cPKCrypto->get_num();

	pCr = (fe**) malloc(sizeof(fe*) * nSndVals);
	pC = (fe**) malloc(sizeof(fe*) * nSndVals);

	fetmp = m_cPKCrypto->get_fe();
	PK0r = m_cPKCrypto->get_fe();
	pC[0] = m_cPKCrypto->get_fe();
	g = m_cPKCrypto->get_generator();

	//random C1
	pC[0]->set_pow(g, alpha);

	//random C(i+1)
	for (u = 1; u < nSndVals; u++) {
		pC[u] = m_cPKCrypto->get_fe();
		tmp = m_cPKCrypto->get_rnd_num();
		pC[u]->set_pow(g, tmp);
	}

	//====================================================
	// Export the generated C_1-C_nSndVals to a uint8_t vector and send them to the receiver
	nBufSize = nSndVals * fe_bytes;
	pBuf = (uint8_t*) malloc(nBufSize);
	pBufIdx = pBuf;
	for (u = 0; u < nSndVals; u++) {
		pC[u]->export_to_bytes(pBufIdx);
		pBufIdx += fe_bytes;
	}
	socket.Send(pBuf, nBufSize);

	//====================================================
	// compute C^R
	for (u = 1; u < nSndVals; u++) {
		pCr[u] = m_cPKCrypto->get_fe();
		pCr[u]->set_pow(pC[u], alpha);
	}
	//====================================================

	free(pBuf);
	// N-P sender: receive pk0
	nBufSize = fe_bytes * nOTs;
	pBuf = (uint8_t*) malloc(nBufSize);
	socket.Receive(pBuf, nBufSize);

	pBufIdx = pBuf;

	pPK0 = (fe**) malloc(sizeof(fe*) * nOTs);
	for (k = 0; k < nOTs; k++) {
		pPK0[k] = m_cPKCrypto->get_fe();
		pPK0[k]->import_from_bytes(pBufIdx);
		pBufIdx += fe_bytes;
	}

	//====================================================
	// Write all nOTs * nSndVals possible values to ret
	free(pBuf);
	pBuf = (uint8_t*) malloc(sizeof(uint8_t) * fe_bytes * nSndVals);
	uint8_t* retPtr = ret;
	fetmp = m_cPKCrypto->get_fe();

	for (k = 0; k < nOTs; k++) {
		pBufIdx = pBuf;
		for (u = 0; u < nSndVals; u++) {

			if (u == 0) {
				// pk0^r
				PK0r->set_pow(pPK0[k], alpha);
				PK0r->export_to_bytes(pBufIdx);

			} else {
				// pk^r
				fetmp->set_div(pCr[u], PK0r);
				fetmp->export_to_bytes(pBufIdx);
			}
			hashReturn(retPtr, hash_bytes, pBufIdx, fe_bytes, k);
			pBufIdx += fe_bytes;
			retPtr += hash_bytes;
		}

	}

	free(pBuf);
	free(pCr);
	free(pC);
}
