/**
 \file 		yaosharing.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	________________
 \brief		Yao Sharing class implementation.
 */

#include "yaosharing.h"

void YaoSharing::Init() {
	/* init the class for correctly sized Yao key operations*/
	InitYaoKey(&m_pKeyOps, m_cCrypto->get_seclvl().symbits);

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, S_YAO);

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
	cout << endl << " encrypting : ";
	PrintKey(p);
	cout << " to : ";
	PrintKey(c);
#endif

	return true;
}

void YaoSharing::PrintKey(BYTE* key) {
	for (uint32_t i = 0; i < m_nSecParamBytes; i++) {
		cout << setw(2) << setfill('0') << (hex) << (uint32_t) key[i];
	}
	cout << (dec);
}

void YaoSharing::PrintPerformanceStatistics() {
	cout << "Yao Sharing: ANDs: " << m_nANDGates << " ; Depth: " << GetMaxCommunicationRounds() << endl;
}
