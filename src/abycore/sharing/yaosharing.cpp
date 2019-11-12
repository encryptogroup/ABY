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
#include <iomanip>
#include <openssl/sha.h>


void YaoSharing::Init() {
	/* init the class for correctly sized Yao key operations*/
	InitYaoKey(&m_pKeyOps, m_cCrypto->get_seclvl().symbits);

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, m_eContext);

	m_bZeroBuf = (BYTE*) calloc(m_nSecParamBytes, sizeof(BYTE));
	m_bTempKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);

	m_nGarbledTableCtr = 0;

	m_bResKeyBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);
	m_kGarble = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	m_cCrypto->init_aes_key(m_kGarble, (uint8_t*) m_vFixedKeyAESSeed);

	m_nSecParamIters = ceil_divide(m_nSecParamBytes, sizeof(UGATE_T));

#ifdef KM11_GARBLING
	m_nDJNBytes = ceil_divide(m_cCrypto->get_seclvl().ifcbits, 8);
	m_nWireKeyBytes = m_nSecParamBytes; // the length of the randomly chosen wirekeys (e.g. 16 Bytes)
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	m_nCiphertextSize = 2 * m_nDJNBytes + 1; // encrypted plaintext might be twice as large as m_nDJNBytes
	assert(m_nWireKeyBytes < m_nDJNBytes); // m_nDJNBytes must be greater than m_nSecParamBytes (requirement of djn_encrypt)
	mpz_init(m_zWireKeyMaxValue);
	mpz_ui_pow_ui(m_zWireKeyMaxValue, 2, 128);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	m_cPKCrypto = m_cCrypto->gen_field(ECC_FIELD);
	m_nCiphertextSize = m_cPKCrypto->fe_byte_size();
#endif
#endif
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

#define AES_BLOCK_SIZE 32

// symmectric encrytion function (AES encrytion using key as the seed for the AES key)
void YaoSharing::sEnc(BYTE* c, BYTE* p, uint32_t p_len, BYTE* key, uint32_t key_len)
{
	//std::cout << "sEnc(p_len = "<<p_len<<")" << '\n';
	int nrounds = 5; // rounds of key material hashing
	unsigned char evp_key[32], evp_iv[32];

	int i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), NULL, key, key_len, nrounds, evp_key, evp_iv);
	assert(i == 16); // key size should be 128 bits (16 bytes)

	EVP_CIPHER_CTX* enc_ctx;
	enc_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(enc_ctx);
	EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, evp_key, evp_iv);

	BYTE* tmpSymEncBuf = (BYTE*) malloc(p_len + m_nSymEncPaddingBytes);
	memcpy(tmpSymEncBuf, p, p_len);
	memset(tmpSymEncBuf + p_len, 0, m_nSymEncPaddingBytes);
	int c_len;
	EVP_EncryptUpdate(enc_ctx, c, &c_len, tmpSymEncBuf, p_len + m_nSymEncPaddingBytes);
	assert(c_len == p_len + m_nSymEncPaddingBytes);
	EVP_CIPHER_CTX_free(enc_ctx);
	free(tmpSymEncBuf);
}

bool YaoSharing::sDec(BYTE* p, BYTE* c, uint32_t c_len, BYTE* key, uint32_t key_len)
{
	//std::cout << "sDec(c_len = "<<c_len<<")" << '\n';

	int nrounds = 5; // rounds of key material hashing
	unsigned char evp_key[32], evp_iv[32];

	int i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), NULL, key, key_len, nrounds, evp_key, evp_iv);
	assert(i == 16); // key size should be 128 bits (16 bytes)

	EVP_CIPHER_CTX* dec_ctx;
	dec_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(dec_ctx);
	EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cbc(), NULL, evp_key, evp_iv);

	int p_len;
	EVP_DecryptUpdate(dec_ctx, p, &p_len, c, c_len);
	//std::cout << "c_len: " << c_len << ", p_len: " << p_len << ", m_nSymEncPaddingBytes: " << m_nSymEncPaddingBytes << '\n';

	//assert(p_len == c_len - m_nSymEncPaddingBytes);
	EVP_CIPHER_CTX_free(dec_ctx);

	return (memcmp(p + c_len - m_nSymEncPaddingBytes, zerobuffer, m_nSymEncPaddingBytes) == 0);
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
