/**
 \file 		yaosharing.cpp
 \author	michael.zohner@ec-spride.de
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
 \brief		Yao Sharing class implementation.
 */

#include "yaosharing.h"
#include <iostream>
#include <iomanip>


void YaoSharing::Init() {
	/* init the class for correctly sized Yao key operations*/
	InitYaoKey(&m_pKeyOps, m_cCrypto->get_seclvl().symbits);

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, m_eContext);

	m_bZeroBuf = (BYTE*) calloc(m_nSecParamBytes, sizeof(BYTE));
	m_bTempKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);

	m_nGarbledTableCtr = 0;

#ifdef FIXED_KEY_GARBLING
	m_bResKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);
	m_kGarble = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	m_cCrypto->init_aes_key(m_kGarble, (uint8_t*) m_vFixedKeyAESSeed);
#endif

	m_nSecParamIters = ceil_divide(m_nSecParamBytes, sizeof(UGATE_T));
}

YaoSharing::~YaoSharing() {
	delete m_pKeyOps;
	delete m_cBoolCircuit;
	free(m_bZeroBuf);
	free(m_bTempKeyBuf);
#ifdef FIXED_KEY_GARBLING
	free(m_bResKeyBuf);
	m_cCrypto->clean_aes_key(m_kGarble);
	free(m_kGarble);
#endif
}

BOOL YaoSharing::EncryptWire(BYTE* c, BYTE* p, uint32_t id)
{
#ifdef FIXED_KEY_GARBLING
	memset(m_bTempKeyBuf, 0, AES_BYTES);
	memcpy(m_bTempKeyBuf, (BYTE*) (&id), sizeof(uint32_t));
	m_pKeyOps->XOR_DOUBLE_B(m_bTempKeyBuf, m_bTempKeyBuf, p);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, p);
	m_cCrypto->encrypt(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf, AES_BYTES);

	m_pKeyOps->XOR(c, m_bResKeyBuf, m_bTempKeyBuf);


#else

	HASH_CTX sha;
	BYTE buf[SHA1_BYTES];
	MPC_HASH_INIT(&sha);
	MPC_HASH_UPDATE(&sha, l, ceil_divide(m_sSecLvl.symbits, 8));
	MPC_HASH_UPDATE(&sha, r, ceil_divide(m_sSecLvl.symbits, 8));
	MPC_HASH_UPDATE(&sha, (BYTE*) &id, sizeof(uint32_t));
	MPC_HASH_FINAL(&sha, buf);

	m_pKeyOps->XOR(c, p, buf);

#endif


#ifdef DEBUGYAO
	std::cout << std::endl << " encrypting : ";
	PrintKey(p);
	std::cout << " to : ";
	PrintKey(c);
#endif

	return true;
}

void YaoSharing::PrintKey(BYTE* key) {
	for (uint32_t i = 0; i < m_nSecParamBytes; i++) {
		std::cout << std::setw(2) << std::setfill('0') << (std::hex) << (uint32_t) key[i];
	}
	std::cout << (std::dec);
}

void YaoSharing::PrintPerformanceStatistics() {
	std::cout <<  get_sharing_name(m_eContext) << ": ANDs: " << m_nANDGates << " ; Depth: " << GetMaxCommunicationRounds() << std::endl;
}
