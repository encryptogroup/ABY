/**
 \file 		yaosharing.cpp
 \author	michael.zohner@ec-spride.de
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
 \brief		Yao Sharing class implementation.
 */

#include "yaosharing.h"
#include <cstring>
#include <iostream>
#include <iomanip>


void YaoSharing::Init() {
	/* init the class for correctly sized Yao key operations*/
	InitYaoKey(&m_pKeyOps, m_cCrypto->get_seclvl().symbits);

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, m_eContext, m_cCircuitFileDir);

	m_bZeroBuf = (BYTE*) calloc(m_nSecParamBytes, sizeof(BYTE));
	m_bTempKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);

	m_nGarbledTableCtr = 0;

	m_bResKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);
	m_kGarble = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	m_cCrypto->init_aes_key(m_kGarble, (uint8_t*) m_vFixedKeyAESSeed);

	m_nSecParamIters = ceil_divide(m_nSecParamBytes, sizeof(UGATE_T));
}

YaoSharing::~YaoSharing() {
	delete m_pKeyOps;
	delete m_cBoolCircuit;
	free(m_bZeroBuf);
	free(m_bTempKeyBuf);
	free(m_bResKeyBuf);
	m_cCrypto->clean_aes_key(m_kGarble);
	free(m_kGarble);
}

BOOL YaoSharing::EncryptWire(BYTE* c, BYTE* p, uint32_t id)
{
	memset(m_bTempKeyBuf, 0, AES_BYTES);
	memcpy(m_bTempKeyBuf, (BYTE*) (&id), sizeof(uint32_t));
	m_pKeyOps->XOR_DOUBLE_B(m_bTempKeyBuf, m_bTempKeyBuf, p);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, p);
	m_cCrypto->encrypt(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf, AES_BYTES);

	m_pKeyOps->XOR(c, m_bResKeyBuf, m_bTempKeyBuf);


#ifdef DEBUGYAO
	std::cout << std::endl << " encrypting : ";
	PrintKey(p);
	std::cout << " to : ";
	PrintKey(c);
#endif

	return true;
}

BOOL YaoSharing::EncryptWireGRR3(BYTE* c, BYTE* p, BYTE* l, BYTE* r, uint32_t id)
{
	//cout << "Start with c = " << (unsigned long) c << ", p = " << (unsigned long) p << endl;
	memset(m_bTempKeyBuf, 0, AES_BYTES);
	memcpy(m_bTempKeyBuf, (BYTE*) (&id), sizeof(uint32_t));
	//cout << "XOR left" << endl;
	m_pKeyOps->XOR_DOUBLE_B(m_bTempKeyBuf, m_bTempKeyBuf, l);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, l);//todo, this is a circular leftshift of l by one and an XOR
	//cout << "XOR right " << endl;
	m_pKeyOps->XOR_QUAD_B(m_bTempKeyBuf, m_bTempKeyBuf, r);
	//m_pKeyOps->XOR(m_bTempKeyBuf, m_bTempKeyBuf, r);//todo, this is a circular leftshift of r by two and an XOR

	//MPC_AES_ENCRYPT(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf);
	m_cCrypto->encrypt(m_kGarble, m_bResKeyBuf, m_bTempKeyBuf, AES_BYTES);

	//cout << "XOR reskeybuf" << endl;
	m_pKeyOps->XOR(m_bResKeyBuf, m_bResKeyBuf, m_bTempKeyBuf);
	//cout << "Final XOR with c = " << (unsigned long) c << ", p = " << (unsigned long) p << endl;
	m_pKeyOps->XOR(c, m_bResKeyBuf, p);


#ifdef DEBUGYAO
	cout << endl << " encrypting : ";
	PrintKey(p);
	cout << " using: ";
	PrintKey(l);
	cout << " and : ";
	PrintKey(r);
	cout << " to : ";
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
