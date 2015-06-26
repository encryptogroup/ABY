/**
 \file 		ot-extension.h
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
 \brief		Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "../util/crypto/crypto.h"
#include "maskingfunction.h"

//#define DEBUG
#define FIXED_KEY_AES_HASHING
//#define AES_OWF
//#define DEBUG_MALICIOUS
//#define VERIFY_OT
//#define OT_HASH_DEBUG
//#define OTTiming
//#define HIGH_SPEED_ROT_LT

const BYTE G_OT = 0x01;
const BYTE C_OT = 0x02;
const BYTE R_OT = 0x03;

#define NUMOTBLOCKS 4096

typedef struct OTBlock_t {
	int blockid;
	int processedOTs;
	BYTE* snd_buf;
	OTBlock_t* next;
} OTBlock;

#ifdef FIXED_KEY_AES_HASHING
static const uint8_t fixed_key_aes_seed[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
#endif

static void InitAESKey(AES_KEY_CTX* ctx, BYTE* keybytes, uint32_t numkeys, crypto* crypt) {
	BYTE* pBufIdx = keybytes;
	uint32_t aes_key_bytes = crypt->get_aes_key_bytes();
	for (uint32_t i = 0; i < numkeys; i++) {
		crypt->init_aes_key(ctx + i, pBufIdx);
		pBufIdx += aes_key_bytes;
	}
}

#define OWF_BYTES AES_BYTES

class OTExtSnd {
	/*
	 * OT sender part
	 * Input: 
	 * ret: returns the resulting bit representations. Has to initialized to a byte size of: nOTs * nSndVals * state.field_size
	 * 
	 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
	 * Output: was the execution successful?
	 */
public:
	OTExtSnd(uint32_t nSndVals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes, CBitVector& x0, CBitVector& x1, BYTE type,
			int nbaseOTs = -1, int nchecks = -1, int nbaseseeds = -1) {
		Init(nSndVals, crypt, sock, U, keybytes, nbaseOTs, nchecks, nbaseseeds);
		m_nOTs = nOTs;
		m_vValues[0] = x0;
		m_vValues[1] = x1;
		m_nBitLength = bitlength;
		m_bProtocol = type;
	}
	;

	OTExtSnd(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes, int nbaseOTs = -1, int nchecks = -1, int nbaseseeds = -1) {
		Init(nSndVals, crypt, sock, U, keybytes, nbaseOTs, nchecks, nbaseseeds);
	}
	;

	void Init(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes, int nbaseOTs, int nchecks, int nbaseseeds) {
		m_nSndVals = nSndVals;
		m_vSockets = sock;
		m_nCounter = 0;
		m_cCrypt = crypt;
		m_nSymSecParam = m_cCrypt->get_seclvl().symbits;
		m_nBaseOTs = m_nSymSecParam;

		if (nbaseOTs != -1)
			m_nBaseOTs = nbaseOTs;

		int keyseeds = m_nBaseOTs;
		if (nbaseseeds != -1)
			keyseeds = nbaseseeds;

		m_vU.Create(keyseeds);
		m_vU.Copy(U.GetArr(), 0, ceil_divide(keyseeds, 8));
		for (int i = keyseeds; i < PadToMultiple(keyseeds, 8); i++)
			m_vU.SetBit(i, 0);

		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * nSndVals);
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * keyseeds);
		m_lSendLock = new CLock;

		InitAESKey(m_vKeySeeds, keybytes, keyseeds, m_cCrypt);

#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypt->init_aes_key(m_kCRFKey, (uint8_t*) fixed_key_aes_seed);
#endif
	}
	;

	~OTExtSnd() {
		//free(m_vKeySeeds);
	}
	;
	BOOL send(uint32_t numOTs, uint32_t bitlength, CBitVector& s0, CBitVector& s1, BYTE type, uint32_t numThreads, MaskingFunction* maskfct);
	BOOL send(uint32_t numThreads);

	BOOL OTSenderRoutine(uint32_t id, uint32_t myNumOTs);

	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t blocksize, BYTE* ctr);
	void ProcessAndEnqueue(CBitVector* snd_buf, uint32_t id, uint32_t progress, uint32_t processedOTs);
	void SendBlocks(uint32_t numThreads);
	void MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs);
	BOOL verifyOT(uint32_t myNumOTs);

protected:
	BYTE m_bProtocol;
	uint32_t m_nSndVals;
	uint32_t m_nOTs;
	uint32_t m_nBitLength;
	uint32_t m_nCounter;
	uint32_t m_nBlocks;
	uint32_t m_nSymSecParam;
	uint32_t m_nBaseOTs;

	crypto* m_cCrypt;

	CSocket* m_vSockets;
	CBitVector m_vU;
	CBitVector* m_vValues;
	MaskingFunction* m_fMaskFct;
	AES_KEY_CTX* m_vKeySeeds;
	OTBlock* m_sBlockHead;
	OTBlock* m_sBlockTail;
	CLock* m_lSendLock;
	BYTE* m_vSeed;

#ifdef FIXED_KEY_AES_HASHING
	AES_KEY_CTX* m_kCRFKey;
#endif

	class OTSenderThread: public CThread {
	public:
		OTSenderThread(uint32_t id, uint32_t nOTs, OTExtSnd* ext) {
			senderID = id;
			numOTs = nOTs;
			callback = ext;
			success = false;
		}
		;
		~OTSenderThread() {
		}
		;
		void ThreadMain() {
			success = callback->OTSenderRoutine(senderID, numOTs);
		}
		;
	private:
		uint32_t senderID;
		uint32_t numOTs;
		OTExtSnd* callback;
		BOOL success;
	};

};

class OTExtRec {
	/*
	 * OT receiver part
	 * Input: 
	 * nSndVals: perform a 1-out-of-nSndVals OT
	 * nOTs: the number of OTs that shall be performed
	 * choices: a vector containing nBaseOTs choices in the domain 0-(SndVals-1) 
	 * ret: returns the resulting bit representations, Has to initialized to a byte size of: nOTs * state.field_size
	 * 
	 * Output: was the execution successful?
	 */
public:
	OTExtRec(uint32_t nSndVals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock, BYTE* keybytes, CBitVector& choices, CBitVector& ret, BYTE protocol,
			int nbaseOTs = -1, int nbaseseeds = -1) {
		Init(nSndVals, crypt, sock, keybytes, nbaseOTs, nbaseseeds);
		m_nOTs = nOTs;
		m_nChoices = choices;
		m_nRet = ret;
		m_nBitLength = bitlength;
		m_eOTFlav = protocol;
	}
	;
	OTExtRec(uint32_t nSndVals, crypto* crypt, CSocket* sock, BYTE* keybytes, int nbaseOTs = -1, int nbaseseeds = -1) {
		Init(nSndVals, crypt, sock, keybytes, nbaseOTs, nbaseseeds);
	}
	;

	void Init(uint32_t nSndVals, crypto* crypt, CSocket* sock, BYTE* keybytes, int nbaseOTs, int nbaseseeds) {
		m_nSndVals = nSndVals;
		m_vSockets = sock;
		m_cCrypt = crypt;
		m_nSymSecParam = m_cCrypt->get_seclvl().symbits;
		m_nBaseOTs = m_nSymSecParam;
		if (nbaseOTs != -1)
			m_nBaseOTs = nbaseOTs;
		int keyseeds = m_nBaseOTs;
		if (nbaseseeds != -1)
			keyseeds = nbaseseeds;

		m_nCounter = 0;
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * keyseeds * nSndVals);
		InitAESKey(m_vKeySeedMtx, keybytes, keyseeds * nSndVals, m_cCrypt);

#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypt->init_aes_key(m_kCRFKey, (uint8_t*) fixed_key_aes_seed);
#endif
	}

	~OTExtRec() {
		//free(m_vKeySeedMtx);
	}
	;

	BOOL receive(uint32_t numOTs, uint32_t bitlength, CBitVector& choices, CBitVector& ret, BYTE type, uint32_t numThreads, MaskingFunction* maskfct);

	BOOL receive(uint32_t numThreads);
	BOOL OTReceiverRoutine(uint32_t id, uint32_t myNumOTs);
	void ReceiveAndProcess(uint32_t numThreads);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint32_t numblocks, uint32_t ctr, BYTE* ctr_buf);
	void HashValues(CBitVector& T, CBitVector& seedbuf, uint32_t ctr, uint32_t lim);
	BOOL verifyOT(uint32_t myNumOTs);

protected:
	BYTE m_eOTFlav;
	uint32_t m_nSndVals;
	uint32_t m_nOTs;
	uint32_t m_nBitLength;
	uint32_t m_nCounter;
	uint32_t m_nSymSecParam;
	uint32_t m_nBaseOTs;

	crypto* m_cCrypt;

	CSocket* m_vSockets;
	CBitVector m_nChoices;
	CBitVector m_nRet;
	CBitVector m_vTempOTMasks;
	MaskingFunction* m_fMaskFct;
	AES_KEY_CTX* m_vKeySeedMtx;

#ifdef FIXED_KEY_AES_HASHING
	AES_KEY_CTX* m_kCRFKey;
#endif

	class OTReceiverThread: public CThread {
	public:
		OTReceiverThread(uint32_t id, uint32_t nOTs, OTExtRec* ext) {
			receiverID = id;
			numOTs = nOTs;
			callback = ext;
			success = false;
		}
		;
		~OTReceiverThread() {
		}
		;
		void ThreadMain() {
			success = callback->OTReceiverRoutine(receiverID, numOTs);
		}
		;
	private:
		uint32_t receiverID;
		uint32_t numOTs;
		OTExtRec* callback;
		BOOL success;
	};

};

#ifdef FIXED_KEY_AES_HASHING
inline void FixedKeyHashing(AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, uint64_t id, uint32_t bytessecparam, crypto* crypt) {
#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) tmpbuf)[0] = id ^ ((uint64_t*) inbuf)[0];
	((uint64_t*) tmpbuf)[1] = ((uint64_t*) inbuf)[1];
#else
	memset(tmpbuf, 0, AES_BYTES);
	memcpy(tmpbuf, (BYTE*) (&id), sizeof(int));

	for (int i = 0; i < bytessecparam; i++) {
		tmpbuf[i] = tmpbuf[i] ^ inbuf[i];
	}
#endif

	crypt->encrypt(aeskey, outbuf, tmpbuf, AES_BYTES);

#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) outbuf)[0] ^= ((uint64_t*) inbuf)[0];
	((uint64_t*) outbuf)[1] ^= ((uint64_t*) inbuf)[1];
#else
	for (int i = 0; i < bytessecparam; i++) {
		outbuf[i] = outbuf[i] ^ inbuf[i];
	}
#endif
}
#endif

#endif /* __OT_EXTENSION_H_ */
