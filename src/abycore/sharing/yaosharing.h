/**
 \file 		yaosharing.h
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
 \brief		Yao Sharing class.
 */

#ifndef __YAOSHARING_H__
#define __YAOSHARING_H__

#include "sharing.h"
#include "../ABY_utils/yaokey.h"
#include "../circuit/booleancircuits.h"
#include <ENCRYPTO_utils/constants.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include "seal/seal.h"
#include <ENCRYPTO_utils/crypto/ecc-pk-crypto.h>
#include <ENCRYPTO_utils/crypto/pk-crypto.h>


class XORMasking;

typedef struct {
	uint32_t gateid;
	UGATE_T* inval;
} input_gate_val_t;

typedef struct {
	uint32_t gateid;
	uint32_t pos;
} a2y_gate_pos_t;


// enable KM11 garbling (private function evaluation. Please note: In ABY, the
// client holds the circuit and the server acts as the garbler)
#define KM11_GARBLING

// choose between DJN/Paillier, RLWE-based (BFV) or ECC-based (EC ElGamal) encryption
#define KM11_CRYPTOSYSTEM_DJN 1
#define KM11_CRYPTOSYSTEM_BFV 2
#define KM11_CRYPTOSYSTEM_ECC 3
#define KM11_CRYPTOSYSTEM KM11_CRYPTOSYSTEM_DJN

// enable improved variant of KM11
// (see section 3.2 "A More Efficient Variant" in KM11 paper)
// With this optimization turned on, the wire key representing the value '1' is
// derived from the wire key representing '0' using the global random shift r.
// BFV and ECC cryptosystems only implement the improved variant of KM11.
#define KM11_IMPROVED

// enable precomputation (encryption) of blinding value b (this cannot be
// disabled for BFV and ECC cryptosystems)
#define KM11_PRECOMPUTEB

// enable pipelined sending of the encrypted garbled gates
#define KM11_PIPELINING

// garbled tables with only two entries are not compatible with the KM11
// protocol since the wiring of the circuit has to be hidden
#ifdef KM11_GARBLING
#define KEYS_PER_GATE_IN_TABLE 4
#else
#define KEYS_PER_GATE_IN_TABLE 2
#endif

/**
 \def 	KEYS_PER_UNIV_GATE_IN_TABLE
 \brief	____________________
 */
#define KEYS_PER_UNIV_GATE_IN_TABLE 3

/**
 Yao Sharing class. <Detailed Description please.>
 */
class YaoSharing: public Sharing {

public:

	/** Constructor for the class. */
	YaoSharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt) :
			Sharing(context, role, sharebitlen, circuit, crypt) {
		Init();
	}
	;
	/** Destructor for the class. */
	virtual ~YaoSharing();

	// METHODS FROM SUPER CLASS SHARING...
	virtual void Reset() = 0;
	virtual void PrepareSetupPhase(ABYSetup* setup) = 0;
	virtual void PerformSetupPhase(ABYSetup* setup) = 0;
	virtual void FinishSetupPhase(ABYSetup* setup) = 0;
	virtual void EvaluateLocalOperations(uint32_t gateid) = 0;

	virtual void FinishCircuitLayer() = 0;

	virtual void PrepareOnlinePhase() = 0;

	void PreComputationPhase() {
		return;
	}

	virtual void InstantiateGate(GATE* gate) = 0;

	virtual void GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& bytesize) = 0;
	virtual void GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) = 0;

	virtual uint32_t AssignInput(CBitVector& input) = 0;
	virtual uint32_t GetOutput(CBitVector& out) = 0;

	uint32_t GetMaxCommunicationRounds() {
		return m_cBoolCircuit->GetMaxDepth();
	}
	;
	uint32_t GetNumNonLinearOperations() {
		return m_nANDGates;
	}
	;

	Circuit* GetCircuitBuildRoutine() {
		return m_cBoolCircuit;
	}
	;

	void PrintPerformanceStatistics();
	//SUPER CLASS METHODS END HERE...

	/**
	 Evaluating SIMD Gate.
	 \param 	gateid 	Identifier of the gate to be evaluated.
	 */
	void EvaluateSIMDGate(uint32_t gateid);

protected:
	YaoKey *m_pKeyOps; /**< A variable that points to inline functions for key xor.*/
	uint32_t m_nANDGates; /**< AND Gates_____________*/
	uint32_t m_nXORGates; /**< XOR Gates_____________*/
	uint32_t m_nConstantGates; /**< Constant Gates_____________*/
	uint32_t m_nInputGates; /**< Constant Gates_____________*/
	uint32_t m_nUNIVGates; /**< Universal Gates_____________*/

	uint32_t m_nDJNBytes;
	uint32_t m_nWireKeyBytes;
	uint32_t m_nCiphertextSize;

	XORMasking *fMaskFct; /**< Mask ____________*/
	std::vector<GATE*> m_vANDGates; /**< Vector of AND Gates. */

	std::vector<GATE*> m_vOutputShareGates; /**< Vector of output share gates. */

	uint32_t m_nInputShareSndSize; /**< Input share send size. */
	uint32_t m_nOutputShareSndSize; /**< Output share send size. */

	uint32_t m_nInputShareRcvSize; /**< Input share receiver size. */
	uint32_t m_nOutputShareRcvSize; /**< Output share receiver size. */

	uint32_t m_nClientInputBits; /**< Client Input Bits. */
	CBitVector m_vClientInputKeys; /**< Client Input Keys. */

	uint32_t m_nConversionInputBits; /**< Conversion Input Bits. */
	//CBitVector			m_vConversionInputKeys;

	uint32_t m_nServerInputBits; /**< Server Input Bits. */
	CBitVector m_vServerInputKeys; /**< Server Input Keys. */

	CBitVector m_vGarbledCircuit; /**< Garbled Circuit Vector.*/
	uint64_t m_nGarbledTableCtr; /**< Garbled Table Counter. */

	CBitVector m_vUniversalGateTable; /**< Table for the universal gates.*/
	uint64_t m_nUniversalGateTableCtr; /**< Universal Gate Table Counter. */

	BYTE* m_bZeroBuf; /**< Zero Buffer. */
	BYTE* m_bTempKeyBuf; /**< Temporary Key Buffer. */

	BooleanCircuit* m_cBoolCircuit; /**< Boolean circuit */

	uint32_t m_nSecParamIters; /**< Secure_____________*/

	uint64_t m_nANDWindowCtr; /**< Counts #AND gates for pipelined exec */
	uint64_t m_nRemANDGates; /**< Remaining AND gates to be processed for pipelined exec */

	BYTE* m_bResKeyBuf; /**< _________________________*/
	AES_KEY_CTX* m_kGarble; /**< _________________________*/

	const size_t m_nBFVpolyModulusDegree = 2048;
	seal::SmallModulus m_nBFVplainModulus = seal::SmallModulus(2);
	std::vector<seal::SmallModulus> m_nBFVCoeffModulus = {seal::SmallModulus(12289), seal::SmallModulus(1099511590913)};
	const int m_nBFVpublicKeyLenExported = 65609;//32841;//8265;//65609;
	const uint64_t m_nBFVciphertextBufLen = 1024*8;//8265;//16457;
	const int m_nBFVgaloiskeysBufLen = 136376;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	const int m_nSymEncPaddingBytes = 16;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	const int m_nSymEncPaddingBytes = 11;
#endif

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	pk_crypto* m_cPKCrypto;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	mpz_t m_zWireKeyMaxValue;
#endif

	/** Initiator function. This method is invoked from the constructor of the class.*/
	void Init();

	void encodeBufAsPlaintext(seal::Plaintext* plaintext, BYTE* buf, uint32_t buf_len) {
		assert(plaintext->coeff_count() <= buf_len);
		assert(buf_len % 32 == 0);
		plaintext->set_zero();

		size_t integer_count = buf_len/32; // size of buf in 32bit integers
		size_t coeff_index = 0;

		for (size_t i = 0; i < integer_count; i++) {
			uint32_t bitmask = 1;
			uint32_t tmpBufVal;
			memcpy(&tmpBufVal, buf + i * 4, 4);
			for (size_t j = 0; j < 32; j++) {
				if ((tmpBufVal & bitmask) != 0) {
					(*plaintext)[coeff_index] = 1;
				}
				bitmask <<= 1;
				coeff_index++;
			}
		}
	}

	void decodePlaintextAsBuf(BYTE* buf, seal::Plaintext* plaintext, size_t offset = 0) {
		assert(plaintext->coeff_count() <= 2048);

		size_t coeff_index = 0;
		size_t max_index;
		uint32_t tmpBufVal;
		for (size_t i = 0; i < 8; i++) {
			tmpBufVal = 0;
			max_index = 32;
			// coeff_count might be less than 32, 64, 96, ... bit
			if (offset + 32 * i + 32 > plaintext->coeff_count()) {
				if (offset + 32 * i >= plaintext->coeff_count()) {
					// all coefficients have already been copied -> do nothing
					max_index = 0;
				} else {
					// copy remaining coefficients (less than 32)
					max_index = plaintext->coeff_count() - 32 * i - offset;
				}
			}
			for (size_t j = 0; j < max_index; j++) {
				tmpBufVal += (*plaintext)[coeff_index + offset] << j;
				coeff_index++;
			}
			memcpy(buf + i * 4, &tmpBufVal, 4);
		}
	}

	void exportCiphertextToBuf(BYTE* buf, seal::Ciphertext* ciphertext) {
		size_t ciphertextCount = ciphertext->uint64_count();
		assert(m_nBFVciphertextBufLen == ciphertextCount * 2);

		for (size_t i = 0; i < ciphertextCount; i++) {
			uint16_t element = (*ciphertext)[i];
			((uint16_t *)buf)[i] = element;
		}
	}

	void importCiphertextFromBuf(seal::Ciphertext* ciphertext, BYTE* buf) {
		size_t ciphertextCount = ciphertext->uint64_count();
		BYTE* ciphertextData = (BYTE*) ciphertext->data();
		assert(ciphertext->uint64_count() != 0);
		for (size_t i = 0; i < ciphertextCount; i++) {
			memcpy(ciphertextData + i * 8, buf + i * 2, 2);
		}
	}

	/**
	 symmectric encrytion function (AES using key as the seed for the AES key)
	 \param  c 		the ciphertext
	 \param  p 		the plaintext
	 \param  key	the seed for the AES key (will be hashed by sEnc)
	 \param  bytes	the length of p, c and key in bytes
	 */
	void sEnc(BYTE* c, BYTE* p, uint32_t p_len, BYTE* key, uint32_t key_len);

	/**
	 symmectric decrytion function (AES using key as the seed for the AES key)
	 \param  p 			the plaintext
	 \param  c 			the ciphertext
	 \param  key		the seed for the AES key (will be hashed by sEnc)
	 \param  bytes	the length of p, c and key in bytes
	 */
	bool sDec(BYTE* p, BYTE* c, uint32_t c_len, BYTE* key, uint32_t key_len);

	const BYTE zerobuffer[16]{0};

	/**
	 Encrypt Wire Function <DETAILED DESCRIPTION>
	 \param  c 		output mask
	 \param  p 		input key
	 \param  id 		unique id
	 */
	BOOL EncryptWire(BYTE* c, BYTE* p, uint32_t id);

	/**
	 Encrypt Wire Function for GRR-3 used for universal gates
	 \param  c 		output garbled row
	 \param  p 		input key to be garbled
	 \param  l 		input key on left wire
	 \param  r 		input key on right wire
	 \param  id 	unique id
	 */
	BOOL EncryptWireGRR3(BYTE* c, BYTE* p, BYTE* l, BYTE* r, uint32_t id);

	/** Print the key. */
	void PrintKey(BYTE* key);
};

#endif /* __YAOSHARING_H__ */
