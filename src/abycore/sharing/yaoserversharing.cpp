/**
 \file 		yaoserversharing.cpp
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
 \brief		Yao Server Sharing class implementation.
 */

#include "yaoserversharing.h"
#include "../aby/abysetup.h"
#include <cstdlib>
#include <ENCRYPTO_utils/utils.h>
#include <limits.h>

void YaoServerSharing::InitServer() {

	//Allocate memory that is needed when generating the garbled tables
	for(uint32_t i = 0; i < 2; i++) {
		m_bLMaskBuf[i] = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
		m_bRMaskBuf[i] = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
		m_bOKeyBuf[i] = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
	}
	m_bLKeyBuf = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
	m_bTmpBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);

	m_vOutputDestionations = nullptr;

	m_nUniversalGateTableCtr = 0;
	m_nGarbledTableCtr = 0L;
	m_nGarbledTableSndCtr = 0L;

	m_nClientInputKexIdx = 0;
	m_nClientInputKeyCtr = 0;

	m_nOutputShareSndSize = 0;
	m_nOutputShareRcvCtr = 0;

	m_nPermBitCtr = 0;

#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	fMaskFct = new XORMasking(m_nCiphertextSize * 8);
#else
	fMaskFct = new XORMasking(m_cCrypto->get_seclvl().symbits);
#endif

	InitNewLayer();
}

YaoServerSharing::~YaoServerSharing() {
		Reset();
		for(size_t i = 0; i < 2; i++) {
			free(m_bLMaskBuf[i]);
			free(m_bRMaskBuf[i]);
			free(m_bOKeyBuf[i]);
		}
		free(m_bLKeyBuf);
		free(m_bTmpBuf);
#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
		free(m_bWireKeys);
#endif
		free(m_bEncWireKeys);
		free(m_bEncGG);
		free(m_bGTKeys);
		free(m_bTmpGTEntry);
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		free(m_bPublickey);
#endif
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
		mpz_clear(m_zR);
		mpz_clear(m_zTmpWirekey);
		mpz_clear(m_zWireKeyMaxValue);
#endif
#endif
		delete fMaskFct;
}

//Pre-set values for new layer
void YaoServerSharing::InitNewLayer() {
	m_nServerKeyCtr = 0;
	m_nClientInBitCtr = 0;
}

/* Send a new task for pre-computing the OTs in the setup phase */
void YaoServerSharing::PrepareSetupPhase(ABYSetup* setup) {
	BYTE* buf;
	uint64_t gt_size;
	uint64_t univ_size;
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	uint32_t symbits = m_nCiphertextSize * 8; // EC ElGamal plaintexts (and ciphertexts) are of the same size
#else
	uint32_t symbits = m_cCrypto->get_seclvl().symbits;
#endif
	m_nANDGates = m_cBoolCircuit->GetNumANDGates();
	m_nXORGates = m_cBoolCircuit->GetNumXORGates();
	m_nInputGates = m_cBoolCircuit->GetNumInputGates();
	m_nConstantGates = m_cBoolCircuit->GetNumConstantGates();
	m_nUNIVGates = m_cBoolCircuit->GetNumUNIVGates();

#ifdef KM11_GARBLING
	// KM11 uses 4 keys per garbled table
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	assert(symbits == 37 * 8);
	gt_size = ((uint64_t) m_nANDGates + m_nXORGates) * KEYS_PER_GATE_IN_TABLE * (m_nCiphertextSize + m_nSymEncPaddingBytes);
#else
	assert(symbits == m_nWireKeyBytes * 8);
	gt_size = ((uint64_t) m_nANDGates + m_nXORGates) * KEYS_PER_GATE_IN_TABLE * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes);
#endif
#else
	gt_size = ((uint64_t) m_nANDGates) * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
#endif
	univ_size = ((uint64_t) m_nUNIVGates) * KEYS_PER_UNIV_GATE_IN_TABLE * m_nSecParamBytes;

	/* If no gates were built, return */
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

#ifdef KM11_GARBLING
	m_nNumberOfKeypairs = m_cBoolCircuit->GetNumInputGates() + m_nANDGates + m_nXORGates + m_nConstantGates;
	assert(m_nNumberOfKeypairs != 0);
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	// for BFV, we store the two wire keys for each gate in the m_bWireKeys buffer
	m_bWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * 2 * m_nWireKeyBytes);
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * m_nBFVciphertextBufLen);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) / 8 * m_nBFVciphertextBufLen);
	assert(m_bWireKeys != NULL);
	assert(m_bEncWireKeys != NULL);
	assert(m_bEncGG != NULL);
	m_bTmpWirekeys = (BYTE*) malloc(m_nWireKeyBytes * 2);
  m_bGTKeys = (BYTE*) malloc(m_nWireKeyBytes * 8);
	m_bTmpGTEntry = (BYTE*) malloc(sizeof(BYTE) * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes));
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	m_bPublickey = (BYTE*) malloc(2 * (m_nDJNBytes + 1));
	// for the improved version, we store only one wire key per gate and compute
	// the second one on-the-fly using AddGlobalRandomShift()
#ifdef KM11_IMPROVED
	m_bWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * m_nWireKeyBytes);
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * m_nCiphertextSize);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) * 2 * m_nCiphertextSize);
	mpz_init(m_zTmpWirekey);
#else // KM11_IMPROVED
	// for the unoptimized version, we store the two wire keys for each gate in the m_bWireKeys buffer
	m_bWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * 2 * m_nWireKeyBytes);
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
#endif // KM11_IMPROVED
	m_bTmpWirekeys = (BYTE*) malloc(m_nWireKeyBytes * 2);
  m_bGTKeys = (BYTE*) malloc(m_nWireKeyBytes * 8);
	m_bTmpGTEntry = (BYTE*) malloc(sizeof(BYTE) * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes));
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	m_bPublickey = (BYTE*) malloc(m_nCiphertextSize);
	// for ECC the wire keys and the encrypted wire keys are field elements (points) in the ECC field
	m_vWireKeys.resize(m_nNumberOfKeypairs);
	// ECC ciphertexts consist of two ECC field elements (K, C) per wire key
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
  m_bGTKeys = (BYTE*) malloc(m_nCiphertextSize * 8);
	m_bTmpGTEntry = (BYTE*) malloc(sizeof(BYTE) * (m_nCiphertextSize + m_nSymEncPaddingBytes));
	m_bTmpWirekeys = (BYTE*) malloc(m_nCiphertextSize * 2);
#endif // KM11_CRYPTOSYSTEM

	/* Preset the number of input bits for client and server */
	m_nServerInputBits = m_cBoolCircuit->GetNumInputBitsForParty(SERVER) + m_nConstantGates;
#else // #ifdef KM11_GARBLING
	/* Preset the number of input bits for client and server */
	m_nServerInputBits = m_cBoolCircuit->GetNumInputBitsForParty(SERVER);
#endif

	m_nClientInputBits = m_cBoolCircuit->GetNumInputBitsForParty(CLIENT);
	m_nConversionInputBits = m_cBoolCircuit->GetNumB2YGates() + m_cBoolCircuit->GetNumA2YGates() + m_cBoolCircuit->GetNumYSwitchGates();

	//m_vPreSetInputGates = (input_gate_val_t*) calloc(m_nServerInputBits, sizeof(input_gate_val_t));

	buf = (BYTE*) malloc(gt_size);
	m_vGarbledCircuit.AttachBuf(buf, gt_size);

	if (m_nUNIVGates > 0) {
		std::cout << "Allocating memory for universal gates..." << '\n';
		m_vUniversalGateTable.Create(0);
		buf = (BYTE*) malloc(univ_size);
		m_vUniversalGateTable.AttachBuf(buf, univ_size);
	}

	m_vR.Create(symbits, m_cCrypto);

#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
	mpz_init(m_zR);
	mpz_import(m_zR, 1, -1, m_nWireKeyBytes, -1, 0, m_vR.GetArr());
#endif
#else
	m_vR.SetBit(symbits - 1, 1);
#endif

#ifdef DEBUGYAOSERVER
	std::cout << "Secret key generated: ";
	PrintKey(m_vR.GetArr());
	std::cout << std::endl;
#endif

#ifdef KM11_GARBLING
	struct timespec start, end;
	uint64_t delta;

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	seal::EncryptionParameters parms(seal::scheme_type::BFV);
	parms.set_poly_modulus_degree(m_nBFVpolyModulusDegree);
	parms.set_plain_modulus(m_nBFVplainModulus);
	parms.set_coeff_modulus(m_nBFVCoeffModulus);
	m_nWirekeySEALcontext = seal::SEALContext::Create(parms);

	seal::KeyGenerator keygen(m_nWirekeySEALcontext);
	m_nWirekeySEALpublicKey = keygen.public_key();
	m_nWirekeySEALsecretKey = keygen.secret_key();
	m_nSEALdecryptor = new seal::Decryptor(m_nWirekeySEALcontext, m_nWirekeySEALsecretKey);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	djn_keygen(m_nDJNBytes * 8, &m_nDJNPubkey, &m_nDJNPrvkey);

	// export public key
	size_t count0 = 0, count1 = 0;
	mpz_export(m_bPublickey + 0 * (m_nDJNBytes + 1), &count0, -1, m_nDJNBytes + 1, -1, 0, m_nDJNPubkey->n);
	mpz_export(m_bPublickey + 1 * (m_nDJNBytes + 1), &count1, -1, m_nDJNBytes + 1, -1, 0, m_nDJNPubkey->h);
	assert(count0 == 1 && count1 == 1);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "\n[timeDJNkey] djn_keygen took " << delta << " microseconds.\n" << std::endl;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	// compute public key A = aP
	fe* P = m_cPKCrypto->get_generator();
	m_nECCGeneratorBrick = m_cPKCrypto->get_brick(P);
	m_nECCPrvkey = m_cPKCrypto->get_rnd_num();
	m_nECCPubkey = m_cPKCrypto->get_fe();
	m_nECCGeneratorBrick->pow(m_nECCPubkey, m_nECCPrvkey); // m_nECCPubkey = m_nECCPrvkey * P
	m_nECCPubkeyBrick = m_cPKCrypto->get_brick(m_nECCPubkey);
	m_nECCPubkey->export_to_bytes(m_bPublickey);
	m_zR = m_cPKCrypto->get_rnd_fe();
#endif // KM11_CRYPTOSYSTEM
#endif // KM11_GARBLING

	m_vROTMasks.resize(2);
	m_vROTMasks[0].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);
	m_vROTMasks[1].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);

	CreateRandomWireKeys(m_vServerInputKeys, m_nServerInputBits + m_cBoolCircuit->GetNumA2YGates());
	CreateRandomWireKeys(m_vClientInputKeys, m_nClientInputBits + m_nConversionInputBits);
	//CreateRandomWireKeys(m_vConversionInputKeys, m_nConversionInputBits);


#ifdef DEBUGYAOSERVER
	std::cout << "Server input keys: ";
	m_vServerInputKeys.PrintHex();
	std::cout << "Client input keys: ";
	m_vClientInputKeys.PrintHex();
#endif

	m_vPermBits.Create(m_nServerInputBits + m_nConversionInputBits, m_cCrypto);

	m_vServerKeySndBuf.Create((m_nServerInputBits + m_cBoolCircuit->GetNumA2YGates()) * symbits);

	m_vClientKeySndBuf.resize(2);
	m_vClientKeySndBuf[0].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);
	m_vClientKeySndBuf[1].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);

	m_vOutputShareSndBuf.Create(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));

	m_vOutputDestionations = (e_role*) malloc(
			sizeof(e_role) * (m_cBoolCircuit->GetOutputGatesForParty(CLIENT).size()
					+ m_cBoolCircuit->GetOutputGatesForParty(SERVER).size()));
	m_nOutputDestionationsCtr = 0;
	//std::deque<uint32_t> out = m_cBoolCircuit->GetOutputGatesForParty(CLIENT);

	IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
	task->bitlen = symbits;
	task->snd_flavor = Snd_R_OT;
	task->rec_flavor = Rec_OT;
	task->numOTs = m_nClientInputBits + m_nConversionInputBits;
	task->mskfct = fMaskFct;
	task->delete_mskfct = FALSE; // is deleted in destructor
	task->pval.sndval.X0 = &(m_vROTMasks[0]);
	task->pval.sndval.X1 = &(m_vROTMasks[1]);

	setup->AddOTTask(task, m_eContext == S_YAO? 0 : 1);
}

/*  send the garbled table */
void YaoServerSharing::PerformSetupPhase(ABYSetup* setup) {
	/* If no gates were built, return */
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	struct timespec start, end;
	uint64_t delta;

#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
  // export public key to buffer
  std::ostringstream BFVpublickeyOStringStream;
  m_nWirekeySEALpublicKey.save(BFVpublickeyOStringStream);
  std::string BFVpublickeyString = BFVpublickeyOStringStream.str();
  std::cout << "[SEND] BFV public key: " << BFVpublickeyString.length() << '\n';
  assert(BFVpublickeyString.length() == m_nBFVpublicKeyLenExported);
  setup->AddSendTask((unsigned char*) BFVpublickeyString.c_str(), m_nBFVpublicKeyLenExported);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	std::cout << "[SEND] DJN public key: " << (2 * (m_nDJNBytes + 1)) << std::endl;
	setup->AddSendTask(m_bPublickey, 2 * (m_nDJNBytes + 1));
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	std::cout << "[SEND] ECC public key: " << m_nCiphertextSize << std::endl;
	setup->AddSendTask(m_bPublickey, m_nCiphertextSize);
#endif

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	CreateEncryptedWireKeys();
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[time encWK] creating the encWKs took _____ " << delta << " _____ microseconds." << std::endl;

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	std::cout << "start: " << start.tv_sec << " " << start.tv_nsec << '\n';

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	// BFV without packing
	std::cout << "[SEND] m_bEncWireKeys:\t\t" << m_nNumberOfKeypairs * m_nBFVciphertextBufLen << " bytes // " << m_nNumberOfKeypairs * m_nBFVciphertextBufLen*1.0/1024/1024 << " MB" << std::endl;
	setup->AddSendTask(m_bEncWireKeys, m_nNumberOfKeypairs * m_nBFVciphertextBufLen);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	// Paillier improved KM11 protocol
	std::cout << "[SEND] m_bEncWireKeys:\t\t" << m_nNumberOfKeypairs * m_nCiphertextSize << " bytes // " << m_nNumberOfKeypairs * m_nCiphertextSize*1.0/1024/1024 << " MB" << std::endl;
	setup->AddSendTask(m_bEncWireKeys, m_nNumberOfKeypairs * m_nCiphertextSize);
#else // KM11_IMPROVED
	// Paillier standard KM11 protocol
	std::cout << "[SEND] m_bEncWireKeys:\t\t" << m_nNumberOfKeypairs * 2 * m_nCiphertextSize << std::endl;
	setup->AddSendTask(m_bEncWireKeys, m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
#endif // KM11_IMPROVED
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	std::cout << "[SEND] m_bEncWireKeys:\t\t" << m_nNumberOfKeypairs * 2 * m_nCiphertextSize << std::endl;
	setup->AddSendTask(m_bEncWireKeys, m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
#endif // KM11_CRYPTOSYSTEM

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[time encWK] [IDLE] sending the encWKs took " << delta << " microseconds." << std::endl;
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);

	// receive encrypted garbled gates (encGG)
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	std::cout << "[RECEIVE] m_bEncGG:\t\t" << (m_nANDGates + m_nXORGates) / 8 * m_nBFVciphertextBufLen << '\n';
#ifndef KM11_PIPELINING
	setup->AddReceiveTask(m_bEncGG, (m_nANDGates + m_nXORGates) / 8 * m_nBFVciphertextBufLen);
#endif
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	std::cout << "[RECEIVE] m_bEncGG:\t\t" << (m_nXORGates + m_nANDGates) * 2 * m_nCiphertextSize << '\n';
	setup->AddReceiveTask(m_bEncGG, (m_nXORGates + m_nANDGates) * 2 * m_nCiphertextSize);
#else // KM11_IMPROVED
	std::cout << "[RECEIVE] m_bEncGG:\t\t" << (m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize << '\n';
	setup->AddReceiveTask(m_bEncGG, (m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
#endif // KM11_IMPROVED
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	std::cout << "[RECEIVE] m_bEncGG:\t\t" << (m_nANDGates + m_nXORGates) * 4 * m_nCiphertextSize << '\n';
#ifndef KM11_PIPELINING
	std::cout << "error: only pipelining is implemented" << '\n';
	setup->AddReceiveTask(m_bEncGG, (m_nANDGates + m_nXORGates) * 4 * m_nCiphertextSize);
#endif
#endif // KM11_CRYPTOSYSTEM
	setup->WaitForTransmissionEnd();

#ifndef KM11_PIPELINING
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[time encGG] [IDLE] receiving the encGGs took " << delta << " microseconds." << std::endl;
#endif

	// send wire keys for constant and output gates
	GATE* gate;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	BYTE* wirekeyShiftedSndBuf = (BYTE*) malloc(sizeof(BYTE) * m_nWireKeyBytes * (m_nConstantGates + 2 * m_cBoolCircuit->GetNumOutputGates()));
#endif
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	BYTE* wirekeyShiftedSndBuf = (BYTE*) malloc(sizeof(BYTE) * m_nCiphertextSize * (m_nConstantGates + 2 * m_cBoolCircuit->GetNumOutputGates()));
#endif
	uint32_t wirekeyShiftedSndCtr = 0;
	for (int gateid = 0; gateid < m_cBoolCircuit->GetNumGates(); gateid++) {
		gate = &(m_vGates[gateid]);
		if (gate->type == G_CONSTANT) {
			UGATE_T constval = gate->gs.constval;
			std::cout << "CONST " << gateid << ", value: " << constval << ", nvals: " << gate->nvals << " ";
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
			if (constval == 0) {
				setup->AddSendTask(m_bWireKeys + gateid * m_nWireKeyBytes, m_nWireKeyBytes);
			} else {
				AddGlobalRandomShift(wirekeyShiftedSndBuf + wirekeyShiftedSndCtr * m_nWireKeyBytes, m_bWireKeys + gateid * m_nWireKeyBytes);
				setup->AddSendTask(wirekeyShiftedSndBuf + wirekeyShiftedSndCtr * m_nWireKeyBytes, m_nWireKeyBytes);
				wirekeyShiftedSndCtr++;
			}
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
			setup->AddSendTask(m_bWireKeys + (2 * gateid + constval) * m_nWireKeyBytes, m_nWireKeyBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
			std::cout << "constant gates are not supported for ECC" << '\n';
			exit(1);
#endif
		} else if (gate->type == G_OUT) {
			uint32_t parentid = gate->ingates.inputs.parent;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
			memcpy(wirekeyShiftedSndBuf + wirekeyShiftedSndCtr * m_nWireKeyBytes,
						 m_bWireKeys + parentid * m_nWireKeyBytes, m_nWireKeyBytes);
			AddGlobalRandomShift(wirekeyShiftedSndBuf + (wirekeyShiftedSndCtr + 1) * m_nWireKeyBytes,
													 m_bWireKeys + parentid * m_nWireKeyBytes);
			setup->AddSendTask(wirekeyShiftedSndBuf + wirekeyShiftedSndCtr * m_nWireKeyBytes, 2 * m_nWireKeyBytes);
			wirekeyShiftedSndCtr += 2;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
			setup->AddSendTask(m_bWireKeys + (2 * parentid) * m_nWireKeyBytes, 2 * m_nWireKeyBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
			m_vWireKeys[parentid]->export_to_bytes(wirekeyShiftedSndBuf + wirekeyShiftedSndCtr * m_nCiphertextSize);
			fe* s1 = m_cPKCrypto->get_fe();
			s1->set_mul(m_vWireKeys[parentid], m_zR);
			s1->export_to_bytes(wirekeyShiftedSndBuf + (wirekeyShiftedSndCtr + 1) * m_nCiphertextSize);
			setup->AddSendTask(wirekeyShiftedSndBuf + wirekeyShiftedSndCtr * m_nCiphertextSize, 2 * m_nCiphertextSize);
			wirekeyShiftedSndCtr += 2;
#endif
		}
	}
	setup->WaitForTransmissionEnd();

#ifdef KM11_IMPROVED
	free(wirekeyShiftedSndBuf);
#endif
#endif

	CreateAndSendGarbledCircuit(setup);
}

void YaoServerSharing::FinishSetupPhase(ABYSetup* setup) {
	/* If no gates were built, return */

	m_nOutputDestionationsCtr = 0;
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	setup->WaitForTransmissionEnd();

	//Reset input gates since they were instantiated before
	//TODO: Change execution
	std::deque<uint32_t> insrvgates = m_cBoolCircuit->GetInputGatesForParty(SERVER);
	for (uint32_t i = 0; i < insrvgates.size(); i++) {
		m_vGates[insrvgates[i]].gs.ishare.src = SERVER;
	}

	//Set pre-initialized input values that were instantiated before the setup phase
	for (uint32_t i = 0; i < m_vPreSetInputGates.size(); i++) {
		m_vGates[m_vPreSetInputGates[i].gateid].gs.ishare.inval = m_vPreSetInputGates[i].inval;
	}
	m_vPreSetInputGates.clear();

	//Set pre-initialized input values that were instantiated before the setup phase
	for (uint32_t i = 0; i < m_vPreSetA2YPositions.size(); i++) {
		m_vGates[m_vPreSetA2YPositions[i].gateid].gs.pos = m_vPreSetA2YPositions[i].pos;
	}
	m_vPreSetA2YPositions.clear();

	std::deque<uint32_t> incligates = m_cBoolCircuit->GetInputGatesForParty(CLIENT);
	for (uint32_t i = 0; i < incligates.size(); i++) {
		m_vGates[incligates[i]].gs.ishare.src = CLIENT;
	}



#ifdef DEBUGYAOSERVER
	std::cout << "Resulting X0 from OT: ";
	m_vROTMasks[0].PrintHex();
	std::cout << "Resulting X1 from OT: ";
	m_vROTMasks[1].PrintHex();
#endif
}
void YaoServerSharing::EvaluateLocalOperations(uint32_t depth) {
	//only evalute the PRINT_VAL operation for debugging, all other work was pre-computed
	std::deque<uint32_t> localqueue = m_cBoolCircuit->GetLocalQueueOnLvl(depth);
	GATE* gate;
	for (uint32_t i = 0; i < localqueue.size(); i++) {
		gate = &(m_vGates[localqueue[i]]);
		if(gate->type == G_PRINT_VAL) {
			EvaluatePrintValGate(localqueue[i], C_BOOLEAN);
		} else if(gate->type == G_ASSERT) {
			EvaluateAssertGate(localqueue[i], C_BOOLEAN);
		} else {
			//do nothing
		}
	}
}

void YaoServerSharing::EvaluateInteractiveOperations(uint32_t depth) {
	std::deque<uint32_t> interactivequeue = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);
	GATE *gate, *parent;

	for (uint32_t i = 0; i < interactivequeue.size(); i++) {
		gate = &(m_vGates[interactivequeue[i]]);
#ifdef DEBUGYAOSERVER
		std::cout << "Evaluating gate with id = " << interactivequeue[i] << ", and type = "<< get_gate_type_name(gate->type) << ", and depth = " << gate->depth << std::endl;
#endif
#ifdef KM11_GARBLING
		assert(gate->type == G_IN || gate->type == G_OUT);
#endif
		switch (gate->type) {
		case G_IN:
			if (gate->gs.ishare.src == SERVER) {
				SendServerInputKey(interactivequeue[i]);
			} else {
				SendClientInputKey(interactivequeue[i]);
			}
			break;
		case G_OUT:
			if (m_vOutputDestionations[m_nOutputDestionationsCtr] == SERVER ||
					m_vOutputDestionations[m_nOutputDestionationsCtr] == ALL) {
				m_vServerOutputGates.push_back(gate);
				m_nOutputShareRcvCtr += gate->nvals;
			}
			m_nOutputDestionationsCtr++;
			//else do nothing since the client has already been given the output
			break;
		case G_CONV:
			parent = &(m_vGates[gate->ingates.inputs.parents[0]]);
			if (parent->context == S_ARITH) {
				SendConversionValues(interactivequeue[i]);
			} else if(parent->context == S_BOOL || parent->context == S_YAO || parent->context == S_YAO_REV) {
				EvaluateConversionGate(interactivequeue[i]);
			}
			break;
		case G_CALLBACK:
			EvaluateCallbackGate(interactivequeue[i]);
			break;
		default:
			std::cerr << "Interactive Operation not recognized: " << (uint32_t) gate->type << " (" << get_gate_type_name(gate->type) << "), stopping execution" << std::endl;
			std::exit(EXIT_FAILURE);
		}

	}
}

void YaoServerSharing::SendConversionValues(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	GATE* parent = &(m_vGates[gate->ingates.inputs.parents[0]]);

	uint32_t pos = gate->gs.pos;
	uint32_t id = pos >> 1;

#ifdef DEBUGYAOSERVER
	std::cout << "Evaluating A2Y with gateid = " << gateid << ", parent = " <<
			gate->ingates.inputs.parents[0] << ", pos = " << pos;
#endif
	assert(parent->instantiated);

	//Convert server's share
	if ((pos & 0x01) == 0) {
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(gate->nvals, GATE_T_BITS), sizeof(UGATE_T));
		for(uint32_t i = 0; i < gate->nvals; i++) {
			//gate->gs.ishare.inval[0] = (parent->gs.aval[id / GATE_T_BITS] >> (id % GATE_T_BITS)) & 0x01;
			gate->gs.ishare.inval[i/GATE_T_BITS] |= ((parent->gs.aval[(id+(i*parent->sharebitlen)) / GATE_T_BITS] >>
					((id+i*parent->sharebitlen) % GATE_T_BITS)) & 0x01) << (i% GATE_T_BITS);
		}
#ifdef DEBUGYAOSERVER
		std::cout << " (server share) with value " << (uint32_t) gate->gs.ishare.inval[0] << " (" << id / GATE_T_BITS << ", " << (id%GATE_T_BITS) <<
		", " << parent->gs.aval[0] <<") " << gate->ingates.inputs.parents[0] << ", " << (uint64_t) parent->gs.aval << std::endl;
#endif
		SendServerInputKey(gateid);
	} else { //Convert client's share
#ifdef DEBUGYAOSERVER
	std::cout << " (client share) " << std::endl;
#endif
		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);
	}
}

void YaoServerSharing::SendServerInputKey(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);

#ifdef KM11_GARBLING
	assert(gate->nvals == 1);
	BOOL inval = *gate->gs.ishare.inval;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
	// copy wirekey to send buffer
	if (inval == 0) {
		// if value is '0', just copy the wirekey to the send buffer
		memcpy(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes,
					 m_bWireKeys + gateid * m_nSecParamBytes,
					 m_nSecParamBytes);
	} else { // inval == 1
		// if value is '1', add R to wirekey to derive the wirekey representing '1' from the wirekey representing '0'
		AddGlobalRandomShift(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes,
												 m_bWireKeys + gateid * m_nWireKeyBytes);
	}
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
#ifdef DEBUGYAOSERVER
	std::cout << "Sending key for gate " << gateid << " (value = " << inval << ")";
	printb("", m_bWireKeys + (2 * gateid + inval) * m_nSecParamBytes, m_nSecParamBytes);
#endif
	// copy wirekey to send buffer
	memcpy(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes,
				 m_bWireKeys + (2 * gateid + inval) * m_nSecParamBytes, m_nSecParamBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	if (inval == 0) {
		m_vWireKeys[gateid]->export_to_bytes(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nCiphertextSize);
	} else {
		fe* s1 = m_cPKCrypto->get_fe();
		s1->set_mul(m_vWireKeys[gateid], m_zR);
		s1->export_to_bytes(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nCiphertextSize);
	}
#endif
	m_nServerKeyCtr++;
	m_nPermBitCtr++;
#else
	UGATE_T* input = gate->gs.ishare.inval;

	for (uint32_t i = 0; i < gate->nvals; i++, m_nServerKeyCtr++, m_nPermBitCtr++) {
		if (!!((input[i / GATE_T_BITS] >> (i % GATE_T_BITS)) & 0x01) ^ m_vPermBits.GetBit(m_nPermBitCtr)) {
			// send serverInputKey XOR vR
			m_pKeyOps->XOR(m_bTempKeyBuf, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_vR.GetArr());
			memcpy(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes, m_bTempKeyBuf, m_nSecParamBytes);
		} else {
			// input bit at position is 0 -> send 0 key
			// send serverInputKey
			memcpy(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_nSecParamBytes);
		}
	}
	free(input);
#endif
}

void YaoServerSharing::SendClientInputKey(uint32_t gateid) {
	//push back and wait for bit of client
	GATE* gate = &(m_vGates[gateid]);
	m_nClientInBitCtr += gate->nvals;
	m_vClientInputGate.push_back(gateid);
}

void YaoServerSharing::PrepareOnlinePhase() {
	//Do nothing right now, figure out which parts come here
	m_nClientInBitCtr = 0;
	m_nPermBitCtr = 0;
}

void YaoServerSharing::CreateAndSendGarbledCircuit(ABYSetup* setup) {
	//Go over all gates and garble them
	uint32_t maxdepth = m_cBoolCircuit->GetMaxDepth();
	if (maxdepth == 0)
		return;

#ifdef KM11_GARBLING
	uint32_t numGates = m_cBoolCircuit->GetNumGates();

	m_nEncGGRcvCtr = 0;
	m_nEncGGRcvPtr = m_bEncGG;

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	seal::Ciphertext encGG = seal::Ciphertext();
	encGG.resize(m_nWirekeySEALcontext, 2);

	seal::Plaintext encGG_plain;

	struct timespec start, end;
	uint64_t delta;

#ifdef KM11_PIPELINING
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	setup->AddReceiveTask(m_nEncGGRcvPtr, 1 * m_nBFVciphertextBufLen);
#endif

	for (uint32_t i = 0; i < numGates; i++) {
		GATE* gate = &(m_vGates[i]);
		assert(gate->type == G_LIN || gate->type == G_NON_LIN || gate->type == G_IN || gate->type == G_OUT); //gate->type == G_CONSTANT);
		if(gate->type == G_IN) {
			EvaluateInputGate(i);
		} else if (gate->type == G_OUT) {
			EvaluateOutputGate(gate);
		} else if (gate->type == G_LIN || gate->type == G_NON_LIN) {
			if (i % 8 == 0) {
#ifdef KM11_PIPELINING
					setup->WaitForTransmissionEnd();
					if (m_nEncGGRcvCtr == 0) {
						clock_gettime(CLOCK_MONOTONIC_RAW, &end);
						delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
						std::cout << "[time] waiting for the first encGG took _____ " << delta << " _____ microseconds.\n" << std::endl;
					}
					if(m_nEncGGRcvCtr + 1 < (m_nANDGates + m_nXORGates) / 8) {
						setup->AddReceiveTask(m_nEncGGRcvPtr + m_nBFVciphertextBufLen, 1 * m_nBFVciphertextBufLen);
					}
#endif
				// decrypt encGG
				importCiphertextFromBuf(&encGG, m_nEncGGRcvPtr);
				m_nEncGGRcvCtr++;
				m_nEncGGRcvPtr += m_nBFVciphertextBufLen;

				m_nSEALdecryptor->decrypt(encGG, encGG_plain);

				// m_bGTKeys: [L0, R0, L0, R1, L1, R0, L1, R1]
				//            [ 0   1   2   3   4   5   6   7]
				// L0, R0
				decodePlaintextAsBuf(m_bGTKeys + 0 * m_nWireKeyBytes, &encGG_plain);
			} else { // i % 8 != 0
				// L0, R0
				decodePlaintextAsBuf(m_bGTKeys + 0 * m_nWireKeyBytes, &encGG_plain, (i % 8) * 256);
			}
			// L0
			memcpy(m_bGTKeys + 2 * m_nWireKeyBytes, m_bGTKeys + 0 * m_nWireKeyBytes, m_nWireKeyBytes);
			// R0
			memcpy(m_bGTKeys + 5 * m_nWireKeyBytes, m_bGTKeys + 1 * m_nWireKeyBytes, m_nWireKeyBytes);
			// L1
			m_pKeyOps->XOR(m_bGTKeys + 4 * m_nWireKeyBytes, m_bGTKeys + 0 * m_nWireKeyBytes, m_vR.GetArr());
			memcpy(m_bGTKeys + 6 * m_nWireKeyBytes, m_bGTKeys + 4 * m_nWireKeyBytes, m_nWireKeyBytes);
			// R1
			m_pKeyOps->XOR(m_bGTKeys + 3 * m_nWireKeyBytes, m_bGTKeys + 1 * m_nWireKeyBytes, m_vR.GetArr());
			memcpy(m_bGTKeys + 7 * m_nWireKeyBytes, m_bGTKeys + 3 * m_nWireKeyBytes, m_nWireKeyBytes);

			EvaluateKM11Gate(i, setup);
		} else {
			std::cout << "Gate type not supported by KM11" << '\n';
			exit(1);
		}

	}
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
#if defined(KM11_PIPELINING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	// pipelining is not implemented for DJN
	setup->AddReceiveTask(m_nEncGGRcvPtr, 4 * m_nCiphertextSize);
#endif

	for (uint32_t i = 0; i < numGates; i++) {
		GATE* gate = &(m_vGates[i]);
		assert(gate->type == G_LIN || gate->type == G_NON_LIN || gate->type == G_IN || gate->type == G_OUT);
		if(gate->type == G_IN) {
			EvaluateInputGate(i);
		} else if (gate->type == G_OUT) {
			EvaluateOutputGate(gate);
		} else if (gate->type == G_LIN || gate->type == G_NON_LIN) {
			EvaluateKM11Gate(i, setup);
		} else {
			std::cout << "Gate type not supported by KM11" << '\n';
			exit(1);
		}
	}
#endif // KM11_CRYPTOSYSTEM
#else // KM11_GARBLING
	for (uint32_t i = 0; i < maxdepth; i++) {
		std::deque<uint32_t> localqueue = m_cBoolCircuit->GetLocalQueueOnLvl(i);
		PrecomputeGC(localqueue, setup);
		std::deque<uint32_t> interactivequeue = m_cBoolCircuit->GetInteractiveQueueOnLvl(i);
		PrecomputeGC(interactivequeue, setup);
	}
#endif
	//Store the shares of the clients output gates
	CollectClientOutputShares();

	//Send the garbled circuit and the output mapping to the client
	if (m_nGarbledTableSndCtr < m_nGarbledTableCtr) {
#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
		std::cout << "[SEND] m_vGarbledCircuit:\t" << m_nGarbledTableCtr * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE << '\n';
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE, (m_nGarbledTableCtr - m_nGarbledTableSndCtr) * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		std::cout << "[SEND] m_vGarbledCircuit:\t" << m_nGarbledTableCtr * (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE << '\n';
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE, (m_nGarbledTableCtr - m_nGarbledTableSndCtr) * (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE);
#endif
#else // KM11_GARBLING
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE,
				(m_nGarbledTableCtr - m_nGarbledTableSndCtr) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
#endif
		m_nGarbledTableSndCtr = m_nGarbledTableCtr;
	}


	if (m_nUNIVGates > 0)
		setup->AddSendTask(m_vUniversalGateTable.GetArr(), m_nUNIVGates * m_nSecParamBytes * KEYS_PER_UNIV_GATE_IN_TABLE);
	if (m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT) > 0) {
		setup->AddSendTask(m_vOutputShareSndBuf.GetArr(), ceil_divide(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT), 8));
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Sending Garbled Circuit...";
	//m_vGarbledCircuit.PrintHex();
	std::cout << "Sending my output shares: ";
	m_vOutputShareSndBuf.Print(0, m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));
#endif

}

void YaoServerSharing::PrecomputeGC(std::deque<uint32_t>& queue, ABYSetup* setup) {
	for (uint32_t i = 0; i < queue.size(); i++) {
		GATE* gate = &(m_vGates[queue[i]]);
#ifdef DEBUGYAOSERVER
		std::cout << "Evaluating gate with id = " << queue[i] << ", and type = "<< get_gate_type_name(gate->type) << "(" << gate->type << "), depth = " << gate->depth
		<< ", nvals = " << gate->nvals << ", sharebitlen = " << gate->sharebitlen << std::endl;
#endif
		assert(gate->nvals > 0 && gate->sharebitlen == 1);

#ifdef KM11_GARBLING
		assert(gate->type == G_LIN || gate->type == G_NON_LIN || gate->type == G_IN || gate->type == G_OUT ||
					 gate->type == G_CONSTANT);
#endif

		if (gate->type == G_LIN) {
#ifdef KM11_GARBLING
			EvaluateKM11Gate(queue[i], setup);
#else
			EvaluateXORGate(gate);
#endif
		} else if (gate->type == G_NON_LIN) {
#ifdef KM11_GARBLING
			EvaluateKM11Gate(queue[i], setup);
#else
			EvaluateANDGate(gate, setup);
#endif
		} else if (gate->type == G_IN) {
			EvaluateInputGate(queue[i]);
		} else if (gate->type == G_OUT) {
#ifdef DEBUGYAOSERVER
			std::cout << "Obtained output gate with key = ";
			uint32_t parentid = gate->ingates.inputs.parent;
			PrintKey(m_vGates[parentid].gs.yinput.outKey);
			std::cout << " and pi = " << (uint32_t) m_vGates[parentid].gs.yinput.pi[0] << std::endl;
#endif
			EvaluateOutputGate(gate);
		} else if (gate->type == G_CONV) {
#ifdef DEBUGYAOSERVER
			std::cout << "Ealuating conversion gate" << std::endl;
#endif
			EvaluateConversionGate(queue[i]);
		} else if (gate->type == G_CONSTANT) {
			//assign 0 and 1 gates
			UGATE_T constval = gate->gs.constval;
			InstantiateGate(gate);
#ifdef KM11_GARBLING
			std::cout << "constant" << constval << " - " << gate->nvals << '\n';
			assert(gate->nvals == 1);
			assert(constval == 0 || constval == 1);
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
			if (constval == 0) {
				// if value is '0', just copy the wirekey
				memcpy(gate->gs.yinput.outKey, m_bWireKeys + queue[i] * m_nSecParamBytes, m_nSecParamBytes);
			}
			if (constval == 1) {
				// if value is '1', add R to the wirekey to derive the wirekey representing '1' from the wirekey representing '0'
				AddGlobalRandomShift(gate->gs.yinput.outKey, m_bWireKeys + queue[i] * m_nSecParamBytes);
			}
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
			// assign the corresponding wire key from the wire key buffer
			memcpy(gate->gs.yinput.outKey, m_bWireKeys + (2 * queue[i] + constval) * m_nSecParamBytes, m_nSecParamBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
			if (constval == 0) {
				m_vWireKeys[queue[i]]->export_to_bytes(gate->gs.yinput.outKey);
			} else {
				fe* s1 = m_cPKCrypto->get_fe();
				s1->set_mul(m_vWireKeys[queue[i]], m_zR);
				s1->export_to_bytes(gate->gs.yinput.outKey);
			}
#endif
#else
			memset(gate->gs.yinput.outKey, 0, m_nSecParamBytes * gate->nvals);
			for(uint32_t i = 0; i < gate->nvals; i++) {
				gate->gs.yinput.pi[i] = (constval>>i) & 0x01;
			}
#endif
#ifdef DEBUGYAOSERVER
			std::cout << "Assigned key to constant gate " << queue[i] << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") : ";
			PrintKey(gate->gs.yinput.outKey);
			std::cout << std::endl;
#endif
		} else if (IsSIMDGate(gate->type)) {
			EvaluateSIMDGate(queue[i]);
		} else if (gate->type == G_INV) {
			EvaluateInversionGate(gate);
		} else if (gate->type == G_CALLBACK) {
			EvaluateCallbackGate(queue[i]);
		} else if (gate->type == G_UNIV) {
			EvaluateUniversalGate(gate);
		} else if (gate->type == G_SHARED_OUT) {
			GATE* parent = &(m_vGates[gate->ingates.inputs.parent]);
			InstantiateGate(gate);
			memcpy(gate->gs.yinput.outKey, parent->gs.yinput.outKey, gate->nvals * m_nSecParamBytes);
			memcpy(gate->gs.yinput.pi, parent->gs.yinput.pi, gate->nvals);
			UsedGate(gate->ingates.inputs.parent);
			// TODO this currently copies both keys and bits and getclearvalue will probably fail.
			//std::cerr << "SharedOutGate is not properly tested for Yao!" << std::endl;
		} else if(gate->type == G_SHARED_IN) {
			//Do nothing
		} else if(gate->type == G_PRINT_VAL) {
			//Do nothing since inputs are not known yet and hence no debugging can occur
		} else if(gate->type == G_ASSERT) {
			//Do nothing since inputs are not known yet and hence no debugging can occur
		} else {
			std::cerr << "Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

void YaoServerSharing::EvaluateInversionGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;
	InstantiateGate(gate);
	assert((gate - m_vGates.data()) > parentid);
	memcpy(gate->gs.yinput.outKey, m_vGates[parentid].gs.yinput.outKey, m_nSecParamBytes * gate->nvals);
	for (uint32_t i = 0; i < gate->nvals; i++) {
		gate->gs.yinput.pi[i] = m_vGates[parentid].gs.yinput.pi[i] ^ 0x01;

		assert(gate->gs.yinput.pi[i] < 2 && m_vGates[parentid].gs.yinput.pi[i] < 2);

	}
	UsedGate(parentid);
}

void YaoServerSharing::EvaluateInputGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	if (gate->gs.ishare.src == SERVER) {

		if(gate->instantiated) {
			input_gate_val_t ingatevals;
			ingatevals.gateid = gateid;
			ingatevals.inval = gate->gs.ishare.inval;
			m_vPreSetInputGates.push_back(ingatevals);
		}
		InstantiateGate(gate);

		memcpy(gate->gs.yinput.outKey, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
			m_nPermBitCtr++;
		}
	} else {
		InstantiateGate(gate);

		memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		memset(gate->gs.yinput.pi, 0, gate->nvals);
		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Assigned key to input gate " << gateid << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") : ";
	PrintKey(gate->gs.yinput.outKey);
	std::cout << std::endl;
#endif
}

/* Treat conversion gates as a combination of server and client inputs - set permutation bit
 * and perform an oblivious transfer
 */
void YaoServerSharing::EvaluateConversionGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	GATE* parent = &(m_vGates[gate->ingates.inputs.parents[0]]);
	uint32_t pos = gate->gs.pos;
	InstantiateGate(gate);

	if (parent->context == S_BOOL) {
		memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
			m_nPermBitCtr++;
		}

		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);
	} else if(parent->context == S_YAO || parent->context == S_YAO_REV) {//TODO: merge with S_BOOL routine
		//std::cout << "Performing transform roles protocol!" << std::endl;
		memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
			m_nPermBitCtr++;
		}

		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);

		//std::cout << "done" << std::endl;
	} else if (parent->context == S_ARITH) {
#ifdef DEBUGYAOSERVER
		std::cout << "Evaluating arithmetic conversion gate with gateid = " << gateid << " and pos = " << pos;
#endif
		//Convert server's share
		a2y_gate_pos_t a2ygate;
		a2ygate.gateid = gateid;
		a2ygate.pos = pos;
		m_vPreSetA2YPositions.push_back(a2ygate);
		if((pos & 0x01) == 0) {
#ifdef DEBUGYAOSERVER
			std::cout << " converting server share" << std::endl;
#endif
			memcpy(gate->gs.yinput.outKey, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
			for (uint32_t i = 0; i < gate->nvals; i++) {
				gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
				m_nPermBitCtr++;
			}
		} else { //Convert client's share
#ifdef DEBUGYAOSERVER
		std::cout << " converting client share" << std::endl;
#endif
			memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
			memset(gate->gs.yinput.pi, 0, gate->nvals);
			//gate->gs.yinput.pi[0] = 0;
			m_nClientInBitCtr += gate->nvals;
			m_vClientInputGate.push_back(gateid);
		}
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Assigned key to conversion gate " << gateid << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") : ";
	PrintKey(gate->gs.yinput.outKey);
	std::cout << std::endl;
#endif
	// not calling UsedGate(gate->ingates.inputs.parents[0]) here:
	// is called in YaoServerSharing::FinishCircuitLayer()
}

#ifdef KM11_GARBLING
// decrypts the encrypted garbled gate and creates the garbled table for the gate
void YaoServerSharing::EvaluateKM11Gate(uint32_t gateid, ABYSetup* setup) {
	GATE* gate = &(m_vGates[gateid]);
	struct timespec start, end;
	uint32_t delta;

	// decrypt the encrypted garbled gate (encGG) to obtain the keys required to
	// create the garbled table
	// (KM11 approach to hide the wiring of the gates)

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	mpz_t encGG_j0, encGG_k0; // encGG_j{0,1} represent the values for the left wire, encGGj{0,1} for the right wire
	mpz_inits(encGG_j0, encGG_k0, NULL);
	mpz_import(encGG_j0, 1, -1, m_nCiphertextSize, -1, 0, m_nEncGGRcvPtr + 0 * m_nCiphertextSize);
	mpz_import(encGG_k0, 1, -1, m_nCiphertextSize, -1, 0, m_nEncGGRcvPtr + 1 * m_nCiphertextSize);
	m_nEncGGRcvPtr += 2 * m_nCiphertextSize;

	// encGG_j0_dec corresponds to L_i^0 in the KM11 paper
	// encGG_k0_dec corresponds to R_i^0 in the KM11 paper
	mpz_t encGG_j0_dec, encGG_k0_dec;
	mpz_inits(encGG_j0_dec, encGG_k0_dec, NULL);
	// dgk_decrypt(encGG_k0_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_k0);
	// dgk_decrypt(encGG_j0_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_j0);
	djn_decrypt(encGG_j0_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_j0);
	djn_decrypt(encGG_k0_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_k0);
	mpz_clears(encGG_j0, encGG_k0, NULL);

	mpz_mod(encGG_j0_dec, encGG_j0_dec, m_zWireKeyMaxValue);
	mpz_mod(encGG_k0_dec, encGG_k0_dec, m_zWireKeyMaxValue);

	// export mpz variables to buffer
	// m_bGTKeys: [L0, R0, L0, R1, L1, R0, L1, R1]
	//            [ 0   1   2   3   4   5   6   7]
	size_t count0, count2;
  // L0
	mpz_export(m_bGTKeys + 0 * m_nWireKeyBytes, &count0, -1, m_nWireKeyBytes, -1, 0, encGG_j0_dec);
	memcpy(m_bGTKeys + 2 * m_nWireKeyBytes, m_bGTKeys + 0 * m_nWireKeyBytes, m_nWireKeyBytes);
	// R0
	mpz_export(m_bGTKeys + 1 * m_nWireKeyBytes, &count2, -1, m_nWireKeyBytes, -1, 0, encGG_k0_dec);
	memcpy(m_bGTKeys + 5 * m_nWireKeyBytes, m_bGTKeys + 1 * m_nWireKeyBytes, m_nWireKeyBytes);

	assert(count0 == 1 && count2 == 1);
	mpz_clears(encGG_j0_dec, encGG_k0_dec, NULL);

	// L1
	AddGlobalRandomShift(m_bGTKeys + 4 * m_nWireKeyBytes, m_bGTKeys + 0 * m_nWireKeyBytes);
	memcpy(m_bGTKeys + 6 * m_nWireKeyBytes, m_bGTKeys + 4 * m_nWireKeyBytes, m_nWireKeyBytes);
	// R1
	AddGlobalRandomShift(m_bGTKeys + 3 * m_nWireKeyBytes, m_bGTKeys + 1 * m_nWireKeyBytes);
	memcpy(m_bGTKeys + 7 * m_nWireKeyBytes, m_bGTKeys + 3 * m_nWireKeyBytes, m_nWireKeyBytes);

	// export s0, s1
	memcpy(m_bTmpWirekeys, m_bWireKeys + gateid * m_nWireKeyBytes, m_nWireKeyBytes);
	AddGlobalRandomShift(m_bTmpWirekeys + m_nWireKeyBytes, m_bWireKeys + gateid * m_nWireKeyBytes);
#else // KM11_IMPROVED
	mpz_t encGG_j0, encGG_j1, encGG_k0, encGG_k1; // encGG_j{0,1} represent the values for the left wire, encGGj{0,1} for the right wire
	mpz_inits(encGG_j0, encGG_j1, encGG_k0, encGG_k1, NULL);
	mpz_import(encGG_j0, 1, -1, m_nCiphertextSize, -1, 0, m_nEncGGRcvPtr + 0 * m_nCiphertextSize);
	mpz_import(encGG_j1, 1, -1, m_nCiphertextSize, -1, 0, m_nEncGGRcvPtr + 1 * m_nCiphertextSize);
	mpz_import(encGG_k0, 1, -1, m_nCiphertextSize, -1, 0, m_nEncGGRcvPtr + 2 * m_nCiphertextSize);
	mpz_import(encGG_k1, 1, -1, m_nCiphertextSize, -1, 0, m_nEncGGRcvPtr + 3 * m_nCiphertextSize);
	m_nEncGGRcvPtr += 4 * m_nCiphertextSize;

	// encGG_j0_dec corresponds to L_i^0 in the KM11 paper
	// encGG_j1_dec corresponds to L_i^1 in the KM11 paper
	// encGG_k0_dec corresponds to R_i^0 in the KM11 paper
	// encGG_k1_dec corresponds to R_i^1 in the KM11 paper
	mpz_t encGG_j0_dec, encGG_j1_dec, encGG_k0_dec, encGG_k1_dec;
	mpz_inits(encGG_j0_dec, encGG_j1_dec, encGG_k0_dec, encGG_k1_dec, NULL);
	djn_decrypt(encGG_j0_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_j0);
	djn_decrypt(encGG_j1_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_j1);
	djn_decrypt(encGG_k0_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_k0);
	djn_decrypt(encGG_k1_dec, m_nDJNPubkey, m_nDJNPrvkey, encGG_k1);
	mpz_clears(encGG_j0, encGG_j1, encGG_k0, encGG_k1, NULL);

	mpz_mod(encGG_j0_dec, encGG_j0_dec, m_zWireKeyMaxValue);
	mpz_mod(encGG_j1_dec, encGG_j1_dec, m_zWireKeyMaxValue);
	mpz_mod(encGG_k0_dec, encGG_k0_dec, m_zWireKeyMaxValue);
	mpz_mod(encGG_k1_dec, encGG_k1_dec, m_zWireKeyMaxValue);

	// export mpz variables to buffer
	// m_bGTKeys: [L0, R0, L0, R1, L1, R0, L1, R1]
	//            [ 0   1   2   3   4   5   6   7]
	size_t count0 = 0, count1 = 0, count2 = 0, count3 = 0;
	// L0
	mpz_export(m_bGTKeys + 0 * m_nWireKeyBytes, &count0, -1, m_nWireKeyBytes, -1, 0, encGG_j0_dec);
	memcpy(m_bGTKeys + 2 * m_nWireKeyBytes, m_bGTKeys + 0 * m_nWireKeyBytes, m_nWireKeyBytes);
	// L1
	mpz_export(m_bGTKeys + 4 * m_nWireKeyBytes, &count1, -1, m_nWireKeyBytes, -1, 0, encGG_j1_dec);
	memcpy(m_bGTKeys + 6 * m_nWireKeyBytes, m_bGTKeys + 4 * m_nWireKeyBytes, m_nWireKeyBytes);
	// R0
	mpz_export(m_bGTKeys + 1 * m_nWireKeyBytes, &count2, -1, m_nWireKeyBytes, -1, 0, encGG_k0_dec);
	memcpy(m_bGTKeys + 5 * m_nWireKeyBytes, m_bGTKeys + 1 * m_nWireKeyBytes, m_nWireKeyBytes);
	// R1
	mpz_export(m_bGTKeys + 3 * m_nWireKeyBytes, &count3, -1, m_nWireKeyBytes, -1, 0, encGG_k1_dec);
	memcpy(m_bGTKeys + 7 * m_nWireKeyBytes, m_bGTKeys + 3 * m_nWireKeyBytes, m_nWireKeyBytes);
	assert(count0 == 1 && count1 == 1 && count2 == 1 && count3 == 1);
	mpz_clears(encGG_j0_dec, encGG_j1_dec, encGG_k0_dec, encGG_k1_dec, NULL);

	// export s0, s1
	memcpy(m_bTmpWirekeys, m_bWireKeys + (2 * gateid) * m_nWireKeyBytes, m_nWireKeyBytes);
	memcpy(m_bTmpWirekeys + m_nWireKeyBytes, m_bWireKeys + (2 * gateid + 1) * m_nWireKeyBytes, m_nWireKeyBytes);
#endif // KM11_IMPROVED
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	// export s0, s1
	memcpy(m_bTmpWirekeys, m_bWireKeys + (2 * gateid) * m_nWireKeyBytes, m_nWireKeyBytes);
	memcpy(m_bTmpWirekeys + m_nWireKeyBytes, m_bWireKeys + (2 * gateid + 1) * m_nWireKeyBytes, m_nWireKeyBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
#ifdef KM11_PIPELINING
	setup->WaitForTransmissionEnd();
	if(m_nEncGGRcvCtr + 1 < (m_nANDGates + m_nXORGates)) {
		setup->AddReceiveTask(m_nEncGGRcvPtr + 4 * m_nCiphertextSize, 4 * m_nCiphertextSize);
		m_nEncGGRcvCtr++;
	}
#endif

	// decrypt encGG
	// m_bGTKeys: [L0, R0, L0, R1, L1, R0, L1, R1]
	//            [ 0   1   2   3   4   5   6   7]
	fe* aK = m_cPKCrypto->get_fe();
	fe* blindedWireKey = m_cPKCrypto->get_fe();

	// decrypt L0, L1
	aK->import_from_bytes(m_nEncGGRcvPtr + 0 * m_nCiphertextSize); // import K
	aK->set_pow(aK, m_nECCPrvkey); // K = a * K
	blindedWireKey->import_from_bytes(m_nEncGGRcvPtr + 1 * m_nCiphertextSize); // import C

	// L0 = C - a * K (L0 = Dec(Enc(s0 + b)))
	blindedWireKey->set_div(blindedWireKey, aK); // L0 = C - S = C - aK
	blindedWireKey->export_to_bytes(m_bGTKeys);
	memcpy(m_bGTKeys + 2 * m_nCiphertextSize, m_bGTKeys, m_nCiphertextSize);

	blindedWireKey->set_mul(blindedWireKey, m_zR); // L1 = L0 + r
	blindedWireKey->export_to_bytes(m_bGTKeys + 4 * m_nCiphertextSize);
	memcpy(m_bGTKeys + 6 * m_nCiphertextSize, m_bGTKeys + 4 * m_nCiphertextSize, m_nCiphertextSize);


	// decrypt R0, R1
	aK->import_from_bytes(m_nEncGGRcvPtr + 2 * m_nCiphertextSize);
	aK->set_pow(aK, m_nECCPrvkey); // K = a * K
	blindedWireKey->import_from_bytes(m_nEncGGRcvPtr + 3 * m_nCiphertextSize);

	// L0 = C - a * K (L0 = Dec(Enc(s0 + b)))
	blindedWireKey->set_div(blindedWireKey, aK);
	blindedWireKey->export_to_bytes(m_bGTKeys + 1 * m_nCiphertextSize);
	memcpy(m_bGTKeys + 5 * m_nCiphertextSize, m_bGTKeys + 1 * m_nCiphertextSize, m_nCiphertextSize);

	blindedWireKey->set_mul(blindedWireKey, m_zR);
	blindedWireKey->export_to_bytes(m_bGTKeys + 3 * m_nCiphertextSize);
	memcpy(m_bGTKeys + 7 * m_nCiphertextSize, m_bGTKeys + 3 * m_nCiphertextSize, m_nCiphertextSize);


	m_nEncGGRcvPtr += 4 * m_nCiphertextSize;

	delete aK;
	delete blindedWireKey;

	// export wirekeys s0, s1
	m_vWireKeys[gateid]->export_to_bytes(m_bTmpWirekeys);
	fe* s1 = m_cPKCrypto->get_fe();
	s1->set_mul(m_vWireKeys[gateid], m_zR);
	s1->export_to_bytes(m_bTmpWirekeys + m_nCiphertextSize);
#endif // KM11_CRYPTOSYSTEM

	// create garbled table to hide the wirekey pair for this gate (either s0 or s1)
	// (formalized as "encYAO" from KM11)
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	uint32_t const GTEntrySize = m_nWireKeyBytes;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	uint32_t const GTEntrySize = m_nCiphertextSize;
#endif

	uint8_t* table = m_vGarbledCircuit.GetArr() + m_nGarbledTableCtr * KEYS_PER_GATE_IN_TABLE * (GTEntrySize + m_nSymEncPaddingBytes);

	// The server should not have any knowledge about gate type (only use NAND gates).
	// We use this conditional statement here to be able to evaluate circuits built
	// out of XOR /and/ AND gates.
	uint8_t val1, val2, val3;
	if (gate->type == G_LIN) { // XOR
		val1 = 1; val2 = 1; val3 = 0;
	} else if (gate->type == G_NON_LIN) { // AND
		val1 = 0; val2 = 0; val3 = 1;
	}

	// encrypt the 4 garbled table entries
	sEnc(table + 0 * (GTEntrySize + m_nSymEncPaddingBytes), m_bTmpWirekeys +    0 * GTEntrySize, GTEntrySize,
			 m_bGTKeys + 0 * GTEntrySize, 2 * GTEntrySize);
	sEnc(table + 1 * (GTEntrySize + m_nSymEncPaddingBytes), m_bTmpWirekeys + val1 * GTEntrySize, GTEntrySize,
			 m_bGTKeys + 2 * GTEntrySize, 2 * GTEntrySize);
	sEnc(table + 2 * (GTEntrySize + m_nSymEncPaddingBytes), m_bTmpWirekeys + val2 * GTEntrySize, GTEntrySize,
			 m_bGTKeys + 4 * GTEntrySize, 2 * GTEntrySize);
	sEnc(table + 3 * (GTEntrySize + m_nSymEncPaddingBytes), m_bTmpWirekeys + val3 * GTEntrySize, GTEntrySize,
			 m_bGTKeys + 6 * GTEntrySize, 2 * GTEntrySize);

	m_nGarbledTableCtr++;

	// send (part of) the garbled table if enough gates have been garbled
	if((m_nGarbledTableCtr - m_nGarbledTableSndCtr) >= GARBLED_TABLE_WINDOW) {
#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		std::cout << "AddSendTask(m_vGarbledCircuit, " << (m_nGarbledTableCtr - m_nGarbledTableSndCtr) * (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE << ")" << '\n';
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE, (m_nGarbledTableCtr - m_nGarbledTableSndCtr) * (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE);
#else
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE, (m_nGarbledTableCtr - m_nGarbledTableSndCtr) * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE);
#endif
#else // KM11_GARBLING
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE,
				(m_nGarbledTableCtr - m_nGarbledTableSndCtr) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
#endif
		m_nGarbledTableSndCtr = m_nGarbledTableCtr;
	}

	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;
	UsedGate(idleft);
	UsedGate(idright);
	InstantiateGate(gate);
}
#endif // KM11_GARBLING

//TODO: optimize for uint64_t pointers
void YaoServerSharing::EvaluateXORGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;

	BYTE* lpi = m_vGates[idleft].gs.yinput.pi;
	BYTE* rpi = m_vGates[idright].gs.yinput.pi;

	BYTE* lkey = m_vGates[idleft].gs.yinput.outKey;
	BYTE* rkey = m_vGates[idright].gs.yinput.outKey;
	InstantiateGate(gate);

	BYTE* gpi = gate->gs.yinput.pi;
	BYTE* gkey = gate->gs.yinput.outKey;

#ifdef GATE_INST_FLAG
	assert(m_vGates[idleft].instantiated);
	assert(m_vGates[idright].instantiated);
#endif
	for (uint32_t g = 0; g < gate->nvals; g++, gpi++, lpi++, rpi++, lkey += m_nSecParamBytes, rkey += m_nSecParamBytes, gkey += m_nSecParamBytes) {
		*gpi = *lpi ^ *rpi;
		m_pKeyOps->XOR(gkey, lkey, rkey);
		assert(*gpi < 2);
	}

#ifdef DEBUGYAOSERVER
	PrintKey(gate->gs.yinput.outKey);
	std::cout << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") = ";
	PrintKey(m_vGates[idleft].gs.yinput.outKey);
	std::cout << " (" << (uint32_t) m_vGates[idleft].gs.yinput.pi[0] << ")(" << idleft << ") ^ ";
	PrintKey(m_vGates[idright].gs.yinput.outKey);
	std::cout << " (" << (uint32_t) m_vGates[idright].gs.yinput.pi[0] << ")(" << idright << ")" << std::endl;
#endif

	assert(m_vGates[idleft].gs.yinput.pi[0] < 2 && m_vGates[idright].gs.yinput.pi[0] < 2);
	UsedGate(idleft);
	UsedGate(idright);
}

//Evaluate an AND gate
void YaoServerSharing::EvaluateANDGate(GATE* gate, ABYSetup* setup) {
	uint32_t idleft = gate->ingates.inputs.twin.left;//gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right;//gate->gs.ginput.right;

	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	InstantiateGate(gate);

	for(uint32_t g = 0; g < gate->nvals; g++) {
		CreateGarbledTable(gate, g, gleft, gright);
		m_nGarbledTableCtr++;
		assert(gate->gs.yinput.pi[g] < 2);

	}

	if((m_nGarbledTableCtr - m_nGarbledTableSndCtr) >= GARBLED_TABLE_WINDOW) {
#ifdef KM11_GARBLING
		std::cout << "this should not have happened" << '\n';
		exit(1);
#else
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE,
				(m_nGarbledTableCtr - m_nGarbledTableSndCtr) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
#endif
		m_nGarbledTableSndCtr = m_nGarbledTableCtr;
	}

	UsedGate(idleft);
	UsedGate(idright);
}

#ifdef KM11_GARBLING
/* create one encrypted keypair for each wire to be sent to the client who
	 will then use them to create the encrypted garbled gates (encGG) */
void YaoServerSharing::CreateEncryptedWireKeys(){
	struct timespec start, mid, mid2, end;
	uint64_t delta_a;
	uint64_t delta;

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	//seal::BatchEncoder bfvWirekeyEncoder(m_nWirekeySEALcontext);
	seal::Encryptor bfvWirekeyEncryptor(m_nWirekeySEALcontext, m_nWirekeySEALpublicKey);
	seal::Plaintext plaintextWirekey;
	plaintextWirekey.resize(128);
	seal::Ciphertext ciphertextWirekey;
	mpz_t s0;
	mpz_init(s0);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	mpz_t s0, s0_encrypted;
	mpz_inits(s0, s0_encrypted, NULL);
#ifndef KM11_IMPROVED
	mpz_t s1, s1_encrypted;
	mpz_inits(s1, s1_encrypted, NULL);
#endif
	// pre-compute fixed base table (used by djn_encrypt_fb)
	fbpowmod_init_g(m_nDJNPubkey->h_s, m_nDJNPubkey->n_squared, 2 * m_nDJNBytes * 8);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	fe* tmpFE = m_cPKCrypto->get_fe();
	fe* s0_enc;
	ecc_num* k = (ecc_num*) m_cPKCrypto->get_num();
	uint32_t field_size = ((ecc_field*)m_cPKCrypto)->get_size();
#endif

	size_t count;
	uint64_t bufPos = 0;
	BYTE* buf = m_bEncWireKeys;

	for (uint64_t i = 0; i < m_nNumberOfKeypairs; i++) {
		//std::cout << "i " << i << '\n';
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
		assert(m_nWireKeyBytes == 16);

		// create s0
		aby_prng(s0, m_nWireKeyBytes * 8);
		//mpz_set_si(s0, 1+i);

		// export s0
		mpz_export(m_bWireKeys + (2 * i + 0) * m_nWireKeyBytes, &count, -1, m_nWireKeyBytes, -1, 0, s0);
		assert(count == 1);

		// export s1 = s0 XOR m_vR
		m_pKeyOps->XOR(m_bWireKeys + (2 * i + 1) * m_nWireKeyBytes, m_bWireKeys + (2 * i + 0) * m_nWireKeyBytes, m_vR.GetArr());

		// encrypt s0
#ifdef DEBUGYAOSERVER
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

		encodeBufAsPlaintext(&plaintextWirekey, m_bWireKeys + (2 * i + 0) * m_nWireKeyBytes, 128);

#ifdef DEBUGYAOSERVER
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "CreateEncryptedWireKeys encode: " << delta << '\n';
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

		bfvWirekeyEncryptor.encrypt(plaintextWirekey, ciphertextWirekey);

#ifdef DEBUGYAOSERVER
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "CreateEncryptedWireKeys encrypt: " << delta << '\n';

		// check noise budget
		std::cout << "    + noise budget in freshly encrypted ciphertextWirekey: "
		<< m_nSEALdecryptor->invariant_noise_budget(ciphertextWirekey) << " bits" << std::endl;
		assert(m_nSEALdecryptor->invariant_noise_budget(ciphertextWirekey) != 0);

		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

		exportCiphertextToBuf(buf, &ciphertextWirekey);
		buf += m_nBFVciphertextBufLen;

#ifdef DEBUGYAOSERVER
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "CreateEncryptedWireKeys export: " << delta << '\n';
#endif


#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
		aby_prng(s0, m_nWireKeyBytes * 8);
		mpz_export(m_bWireKeys + i * m_nWireKeyBytes, &count, -1, m_nWireKeyBytes, -1, 0, s0);
		assert(count == 1);

		// encrypt s0/s1 and write results to m_bEncWireKeys
		djn_encrypt_fb(s0_encrypted, m_nDJNPubkey, s0);
		//djn_encrypt_crt(s0_encrypted, m_nDJNPubkey, m_nDJNPrvkey, s0);
		// dgk_encrypt_crt(s0_encrypted, dgk_pubkey, dgk_prvkey, s0);

		mpz_export(m_bEncWireKeys + i * m_nCiphertextSize, &count, -1, m_nCiphertextSize, -1, 0, s0_encrypted);
		assert(count == 1);
#else // KM11_IMPROVED
		aby_prng(s0, m_nWireKeyBytes * 8);
		aby_prng(s1, m_nWireKeyBytes * 8);

		size_t count0, count1;
		mpz_export(m_bWireKeys + (2 * i + 0) * m_nWireKeyBytes, &count0, -1, m_nWireKeyBytes, -1, 0, s0);
		mpz_export(m_bWireKeys + (2 * i + 1) * m_nWireKeyBytes, &count1, -1, m_nWireKeyBytes, -1, 0, s1);
		assert(count0 == 1 && count1 == 1);

		// encrypt s0/s1 and write results to m_bEncWireKeys
		djn_encrypt_fb(s0_encrypted, m_nDJNPubkey, s0);
		djn_encrypt_fb(s1_encrypted, m_nDJNPubkey, s1);
		//djn_encrypt_crt(s0_encrypted, m_nDJNPubkey, m_nDJNPrvkey, s0);
		//djn_encrypt_crt(s1_encrypted, m_nDJNPubkey, m_nDJNPrvkey, s1);
		clock_gettime(CLOCK_MONOTONIC_RAW, &mid2);

		mpz_export(m_bEncWireKeys + (2 * i + 0) * m_nCiphertextSize, &count0, -1, m_nCiphertextSize, -1, 0, s0_encrypted);
		mpz_export(m_bEncWireKeys + (2 * i + 1) * m_nCiphertextSize, &count1, -1, m_nCiphertextSize, -1, 0, s1_encrypted);
		assert(count0 == 1 && count1 == 1);
#endif // KM11_IMPROVED
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		// generate ciphertext (K, C) = (k * P, k * aP + M)
		k->set_rnd(field_size);
		m_nECCGeneratorBrick->pow(tmpFE, k); // tmpFE = k * P
		tmpFE->export_to_bytes(buf);
		buf += m_nCiphertextSize;
		m_nECCPubkeyBrick->pow(tmpFE, k); // tmpFE = k * aP

		k->set_rnd(field_size);
		m_vWireKeys[i] = m_cPKCrypto->get_fe(); // s0
		m_nECCGeneratorBrick->pow(m_vWireKeys[i], k); // s0 = k * P
		s0_enc = m_cPKCrypto->get_fe();
		s0_enc->set_mul(tmpFE, m_vWireKeys[i]); // tmpFE = k * aP + M
		s0_enc->export_to_bytes(buf);
		buf += m_nCiphertextSize;
#endif // KM11_CRYPTOSYSTEM

		clock_gettime(CLOCK_MONOTONIC_RAW, &mid);

#ifdef DEBUGYAOSERVER
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
		// some basic tests
		mpz_t s0_encrypted_2, s1_encrypted_2;
		mpz_inits(s0_encrypted_2, s1_encrypted_2, NULL);
#ifdef KM11_IMPROVED
		mpz_import(s0_encrypted_2, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + i * m_nCiphertextSize);
		assert(mpz_cmp(s0_encrypted, s0_encrypted_2) == 0);
#else
		mpz_import(s0_encrypted_2, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + (2 * i + 0) * m_nCiphertextSize);
		mpz_import(s1_encrypted_2, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + (2 * i + 1) * m_nCiphertextSize);
		assert(mpz_cmp(s0_encrypted, s0_encrypted_2) == 0);
		assert(mpz_cmp(s1_encrypted, s1_encrypted_2) == 0);
#endif

		// more tests
		mpz_t res0, res1;
		mpz_init(res0);
		mpz_init(res1);
		djn_decrypt(res0, m_nDJNPubkey, m_nDJNPrvkey, s0_encrypted);
		assert(mpz_cmp(res0, s0) == 0);
#ifndef KM11_IMPROVED
		djn_decrypt(res1, m_nDJNPubkey, m_nDJNPrvkey, s1_encrypted);
		assert(mpz_cmp(res1, s1) == 0);
#endif
		mpz_clears(res0, res1, NULL);
#endif // KM11_CRYPTOSYSTEM
#endif // DEBUGYAOSERVER
	}

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	mpz_clears(s0, s0_encrypted, NULL);
#ifndef KM11_IMPROVED
	mpz_clears(s1, s1_encrypted, NULL);
#endif
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	mpz_clear(s0);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	delete tmpFE;
	delete s0_enc;
	delete k;
#endif
}

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
void YaoServerSharing::AddGlobalRandomShift(BYTE* keyout, BYTE* keyin) {
	mpz_import(m_zTmpWirekey, 1, -1, m_nWireKeyBytes, -1, 0, keyin);

	mpz_add(m_zTmpWirekey, m_zTmpWirekey, m_zR);
	mpz_mod(m_zTmpWirekey, m_zTmpWirekey, m_zWireKeyMaxValue);
	size_t count;
	mpz_export(keyout, &count, -1, m_nWireKeyBytes, -1, 0, m_zTmpWirekey);
	assert(count == 1);
}
#endif // KM11_CRYPTOSYSTEM
#endif // KM11_GARBLING

void YaoServerSharing::CreateGarbledTable(GATE* ggate, uint32_t pos, GATE* gleft, GATE* gright){
	uint8_t *table, *lkey, *rkey, *outwire_key;
	uint8_t lpbit = gleft->gs.yinput.pi[pos];
	uint8_t rpbit = gright->gs.yinput.pi[pos];
	uint8_t lsbit, rsbit;

	assert(lpbit < 2 && rpbit < 2);

	table = m_vGarbledCircuit.GetArr() + m_nGarbledTableCtr * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
	outwire_key = ggate->gs.yinput.outKey + pos * m_nSecParamBytes;

	lkey = gleft->gs.yinput.outKey + pos * m_nSecParamBytes;
	rkey = gright->gs.yinput.outKey + pos * m_nSecParamBytes;

	lsbit = (lkey[m_nSecParamBytes-1] & 0x01);
	rsbit = (rkey[m_nSecParamBytes-1] & 0x01);

	if(lpbit) {
		m_pKeyOps->XOR(m_bLKeyBuf, lkey, m_vR.GetArr());
	} else {
		memcpy(m_bLKeyBuf, lkey, m_nSecParamBytes);
	}

	//Encryptions of wire A
	EncryptWire(m_bLMaskBuf[lpbit], lkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr);
	m_pKeyOps->XOR(m_bTmpBuf, lkey, m_vR.GetArr());
	EncryptWire(m_bLMaskBuf[!lpbit], m_bTmpBuf, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr);

	//Encryptions of wire B
	EncryptWire(m_bRMaskBuf[rpbit], rkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr+1);
	m_pKeyOps->XOR(m_bTmpBuf, rkey, m_vR.GetArr());
	EncryptWire(m_bRMaskBuf[!rpbit], m_bTmpBuf, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr+1);

	//Compute two table entries, T_G is the first cipher-text, T_E the second cipher-text
	//Compute T_G = Enc(W_a^0) XOR Enc(W_a^1) XOR p_b*R

	m_pKeyOps->XOR(table, m_bLMaskBuf[0], m_bLMaskBuf[1]);
	if(rpbit)
		m_pKeyOps->XOR(table, table, m_vR.GetArr());

	if(lpbit)
		m_pKeyOps->XOR(outwire_key, m_bLMaskBuf[1], m_bRMaskBuf[0]);
	else
		m_pKeyOps->XOR(outwire_key, m_bLMaskBuf[0], m_bRMaskBuf[0]);

	if((lsbit) & (rsbit))
		m_pKeyOps->XOR(outwire_key, outwire_key, m_vR.GetArr());


	//Compute W^0 = W_G^0 XOR W_E^0 = Enc(W_a^0) XOR Enc(W_b^0) XOR p_a*T_G XOR p_b * (T_E XOR W_a^0)

	//Compute T_E = Enc(W_b^0) XOR Enc(W_b^1) XOR W_a^0
	m_pKeyOps->XOR(table + m_nSecParamBytes, m_bRMaskBuf[0], m_bRMaskBuf[1]);
	m_pKeyOps->XOR(table + m_nSecParamBytes, table + m_nSecParamBytes, m_bLKeyBuf);

	//Compute the resulting key for the output wire
	if(rpbit) {
		//std::cout << "Server Xoring right_table" << std::endl;
		m_pKeyOps->XOR(outwire_key, outwire_key, table + m_nSecParamBytes);
		m_pKeyOps->XOR(outwire_key, outwire_key, m_bLKeyBuf);
	}

	//Set permutation bit
	if((outwire_key[m_nSecParamBytes-1] & 0x01)) {
		m_pKeyOps->XOR(outwire_key, outwire_key, m_vR.GetArr());
		ggate->gs.yinput.pi[pos] = !(outwire_key[m_nSecParamBytes-1] & 0x01) ^ ((lpbit) & (rpbit));
	} else {
		ggate->gs.yinput.pi[pos] = (outwire_key[m_nSecParamBytes-1] & 0x01) ^ ((lpbit) & (rpbit));
	}

#ifdef DEBUGYAOSERVER
		std::cout << " encr : ";
		PrintKey(lkey);
		std::cout << " (" << (uint32_t) gleft->gs.yinput.pi[pos] << ") and : ";
		PrintKey(rkey);
		std::cout << " (" << (uint32_t) gright->gs.yinput.pi[pos] << ") to : ";
		PrintKey(outwire_key);
		std::cout << " (" << (uint32_t) ggate->gs.yinput.pi[pos] << ")" << std::endl;
		std::cout << "A_0: ";
		PrintKey(m_bLMaskBuf[0]);
		std::cout << "; A_1: ";
		PrintKey(m_bLMaskBuf[1]);
		std::cout << std::endl << "B_0: ";
		PrintKey(m_bRMaskBuf[0]);
		std::cout << "; B_1: ";
		PrintKey(m_bRMaskBuf[1]);

		std::cout << std::endl << "Table A: ";
		PrintKey(table);
		std::cout << "; Table B: ";
		PrintKey(table+m_nSecParamBytes);
		std::cout << std::endl;

#endif
}

//Evaluate a Universal Gate
void YaoServerSharing::EvaluateUniversalGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;

	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);
	uint32_t ttable = gate->gs.ttable;

	InstantiateGate(gate);

	for(uint32_t g = 0; g < gate->nvals; g++) {
		GarbleUniversalGate(gate, g, gleft, gright, ttable);
		m_nUniversalGateTableCtr++;
		//gate->gs.yinput.pi[g] = 0;
		assert(gate->gs.yinput.pi[g] < 2);
	}
	UsedGate(idleft);
	UsedGate(idright);
}

//Garble a universal gate via the GRR-3 optimization
void YaoServerSharing::GarbleUniversalGate(GATE* ggate, uint32_t pos, GATE* gleft, GATE* gright, uint32_t ttable) {
	BYTE* univ_table = m_vUniversalGateTable.GetArr() + m_nUniversalGateTableCtr * KEYS_PER_UNIV_GATE_IN_TABLE * m_nSecParamBytes;
	uint32_t ttid = (gleft->gs.yinput.pi[pos] << 1) + gright->gs.yinput.pi[pos];

	assert(gright->instantiated && gleft->instantiated);

	memcpy(m_bLMaskBuf[0], gleft->gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes);
	m_pKeyOps->XOR(m_bLMaskBuf[1], m_bLMaskBuf[0], m_vR.GetArr());

	memcpy(m_bRMaskBuf[0], gright->gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes);
	m_pKeyOps->XOR(m_bRMaskBuf[1], m_bRMaskBuf[0], m_vR.GetArr());

	BYTE* outkey[2];
	outkey[0] = ggate->gs.yinput.outKey + pos * m_nSecParamBytes;
	outkey[1] = m_bOKeyBuf[0];

	assert(((uint64_t*) m_bZeroBuf)[0] == 0);
	//GRR: Encryption with both original keys of a zero-string becomes the key on the output wire of the gate
	EncryptWireGRR3(outkey[0], m_bZeroBuf, m_bLMaskBuf[0], m_bRMaskBuf[0], 0);

	//Sort the values according to the permutation bit and precompute the second wire key
	BYTE kbit = outkey[0][m_nSecParamBytes-1] & 0x01;
	ggate->gs.yinput.pi[pos] = ((ttable>>ttid)&0x01) ^ kbit;//((kbit^1) & (ttid == 3)) | (kbit & (ttid != 3));

#ifdef DEBUGYAOSERVER
		std::cout << " encrypting : ";
		PrintKey(m_bZeroBuf);
		std::cout << " using: ";
		PrintKey(m_bLMaskBuf[0]);
		std::cout << " (" << (uint32_t) gleft->gs.yinput.pi[pos] << ") and : ";
		PrintKey(m_bRMaskBuf[0]);
		std::cout << " (" << (uint32_t) gright->gs.yinput.pi[pos] << ") to : ";
		PrintKey(m_bOKeyBuf[0]);
		std::cout << std::endl;
#endif
	memcpy(outkey[kbit], outkey[0], m_nSecParamBytes);
	m_pKeyOps->XOR(outkey[kbit^1], outkey[kbit], m_vR.GetArr());

	for(uint32_t i = 1, keyid; i < 4; i++, univ_table+=m_nSecParamBytes) {
		keyid = ((ttable>>(ttid^i))&0x01) ^ ggate->gs.yinput.pi[pos];
		assert(keyid < 2);
		//std::cout << "Encrypting into outkey = " << outkey << ", " << (unsigned long) m_bOKeyBuf[0] << ", " <<  (unsigned long) m_bOKeyBuf[1] <<
		//		", truthtable = " << (unsigned uint32_t) g_TruthTable[id^i] << ", mypermbit = " << (unsigned uint32_t) ggate->gs.yinput.pi[pos] << ", id = " << id << std::endl;
		EncryptWireGRR3(univ_table, outkey[keyid], m_bLMaskBuf[i>>1], m_bRMaskBuf[i&0x01], i);
#ifdef DEBUGYAOSERVER
		std::cout << " encrypting : ";
		//PrintKey(m_bOKeyBuf[outkey]);
		std::cout << " using: ";
		PrintKey(m_bLMaskBuf[i>>1]);
		std::cout << " (" << (uint32_t) gleft->gs.yinput.pi[pos] << ") and : ";
		PrintKey(m_bRMaskBuf[i&0x01]);
		std::cout << " (" << (uint32_t) gright->gs.yinput.pi[pos] << ") to : ";
		PrintKey(univ_table);
		std::cout << std::endl;
#endif
	}
}

//Collect the permutation bits on the clients output gates and prepare them to be sent off
void YaoServerSharing::CollectClientOutputShares() {
	std::deque<uint32_t> out = m_cBoolCircuit->GetOutputGatesForParty(CLIENT);
	while (out.size() > 0) {
		for (uint32_t j = 0; j < m_vGates[out.front()].nvals; j++, m_nOutputShareSndSize++) {
			m_vOutputShareSndBuf.SetBit(m_nOutputShareSndSize, !!((m_vGates[out.front()].gs.val[j / GATE_T_BITS]) & ((UGATE_T) 1 << (j % GATE_T_BITS))));
		}
		out.pop_front();
	}
}

void YaoServerSharing::EvaluateOutputGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;

	//push the output back since it will be deleted but is needed in the online phase
	//std::cout << "Before " << std::endl;
	m_vOutputDestionations[m_nOutputDestionationsCtr++] = gate->gs.oshare.dst;

	//std::cout << "After" << std::endl;
	//InstantiateGate(gate);

	gate->gs.val = (UGATE_T*) calloc(ceil_divide(gate->nvals, GATE_T_BITS), sizeof(UGATE_T));
	gate->instantiated = true;
	for (uint32_t i = 0; i < gate->nvals; i++) {
		gate->gs.val[i / GATE_T_BITS] |= (((UGATE_T) m_vGates[parentid].gs.yinput.pi[i]) << (i % GATE_T_BITS));
	}

#ifdef DEBUGYAOSERVER
	std::cout << "Stored output share " << gate->gs.val[0] << std::endl;
#endif
	UsedGate(parentid);
}

void YaoServerSharing::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
	//Input keys of server
	if (m_nServerKeyCtr > 0) {
		sendbuf.push_back(m_vServerKeySndBuf.GetArr());
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		sndbytes.push_back(m_nServerKeyCtr * m_nCiphertextSize);
#else
#ifdef DEBUGYAOSERVER
		std::cout << "want to send servers input keys which are of size " << m_nServerKeyCtr * m_nSecParamBytes << " bytes" << std::endl;
		std::cout << "Server input keys = ";
		m_vServerKeySndBuf.PrintHex();
		std::cout << std::endl;
#endif
		sndbytes.push_back(m_nServerKeyCtr * m_nSecParamBytes);
#endif
	}
	//Input keys of client
	if (m_nClientInputKeyCtr > 0) {
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		uint32_t keySize = m_nCiphertextSize;
#else
		uint32_t keySize = m_nSecParamBytes;
#endif
#ifdef DEBUGYAOSERVER
		std::cout << "want to send client input keys which are of size 2 * " << m_nClientInputKeyCtr * keySize << " bytes" << std::endl;
		std::cout << "Client input keys[0] = ";
		m_vClientKeySndBuf[0].PrintHex();
		std::cout << "Client input keys[1] = ";
		m_vClientKeySndBuf[1].PrintHex();
#endif
		sendbuf.push_back(m_vClientKeySndBuf[0].GetArr());
		sndbytes.push_back(m_nClientInputKeyCtr * keySize);
		sendbuf.push_back(m_vClientKeySndBuf[1].GetArr());
		sndbytes.push_back(m_nClientInputKeyCtr * keySize);
		m_nClientInputKeyCtr = 0;
	}
}

void YaoServerSharing::FinishCircuitLayer() {
	//Use OT bits from the client to determine the send bits that are supposed to go out next round
	if (m_nClientInBitCtr > 0) {
		for (uint32_t i = 0, linbitctr = 0; i < m_vClientInputGate.size() && linbitctr < m_nClientInBitCtr; i++) {
			uint32_t gateid = m_vClientInputGate[i];
			if (m_vGates[gateid].type == G_IN) {
				for (uint32_t k = 0; k < m_vGates[gateid].nvals; k++, linbitctr++, m_nClientInputKexIdx++, m_nClientInputKeyCtr++) {
#ifdef KM11_GARBLING
					assert(m_vGates[gateid].nvals == 1);
#endif
					uint8_t clientROTbit = m_vClientROTRcvBuf.GetBitNoMask(linbitctr);

					// assign values to m_vClientKeySndBuf[0] and and m_vClientKeySndBuf[1]
					/* if clientROTbit == 0:
							 m_vClientKeySndBuf[0] = (mask resulting from OT) XOR (client input key representing "0")
							 m_vClientKeySndBuf[1] = (mask resulting from OT) XOR (client input key representing "1")
						 if clientROTbit == 1:
							 m_vClientKeySndBuf[0] = (mask resulting from OT) XOR (client input key representing "1")
							 m_vClientKeySndBuf[1] = (mask resulting from OT) XOR (client input key representing "0")
					*/
#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN && defined(KM11_IMPROVED)
					// optimized variant of KM11

					// (client input key representing "1") = (client input key representing "0" + m_vR)
					AddGlobalRandomShift(m_bTempKeyBuf, m_bWireKeys + gateid * m_nWireKeyBytes);

					m_pKeyOps->XOR(m_vClientKeySndBuf[clientROTbit].GetArr() + linbitctr * m_nSecParamBytes,
												 m_vROTMasks[clientROTbit].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, // mask resulting from OT
												 m_bWireKeys + gateid * m_nWireKeyBytes); // client input key representing "0"

					m_pKeyOps->XOR(m_vClientKeySndBuf[1-clientROTbit].GetArr() + linbitctr * m_nSecParamBytes,
												 m_vROTMasks[1-clientROTbit].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, // mask resulting from OT
												 m_bTempKeyBuf); // client input key representing "1"
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
					// KM11 without optimizations
					m_pKeyOps->XOR(m_vClientKeySndBuf[clientROTbit].GetArr() + linbitctr * m_nSecParamBytes,
												 m_vROTMasks[clientROTbit].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, // mask resulting from OT
												 m_bWireKeys + (2 * gateid + 0) * m_nSecParamBytes); // client input key representing "0"

					m_pKeyOps->XOR(m_vClientKeySndBuf[1-clientROTbit].GetArr() + linbitctr * m_nSecParamBytes,
												 m_vROTMasks[1-clientROTbit].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, // mask resulting from OT
												 m_bWireKeys + (2 * gateid + 1) * m_nSecParamBytes); // client input key representing "1"
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
					m_vWireKeys[gateid]->export_to_bytes(m_bTmpWirekeys);

					m_pKeyOps->XOR37(m_vClientKeySndBuf[clientROTbit].GetArr() + linbitctr * m_nCiphertextSize,
													 m_vROTMasks[clientROTbit].GetArr() + m_nClientInputKexIdx * m_nCiphertextSize, // mask resulting from OT
													 m_bTmpWirekeys); // client input key representing "0"

					fe* s1 = m_cPKCrypto->get_fe();
					s1->set_mul(m_vWireKeys[gateid], m_zR);
					s1->export_to_bytes(m_bTmpWirekeys);

					m_pKeyOps->XOR37(m_vClientKeySndBuf[1-clientROTbit].GetArr() + linbitctr * m_nCiphertextSize,
													 m_vROTMasks[1-clientROTbit].GetArr() + m_nClientInputKexIdx * m_nCiphertextSize, // mask resulting from OT
													 m_bTmpWirekeys); // client input key representing "1"
#endif
#else
					// no KM11 at all

					// (client input key representing "1") = (client input key representing "0") XOR (m_vR)
					m_pKeyOps->XOR(m_bTempKeyBuf, m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, m_vR.GetArr());

					m_pKeyOps->XOR(m_vClientKeySndBuf[clientROTbit].GetArr() + linbitctr * m_nSecParamBytes,
												 m_vROTMasks[clientROTbit].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, // mask resulting from OT
												 m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); // client input key representing "0"

					m_pKeyOps->XOR(m_vClientKeySndBuf[1-clientROTbit].GetArr() + linbitctr * m_nSecParamBytes,
												 m_vROTMasks[1-clientROTbit].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, // mask resulting from OT
												 m_bTempKeyBuf); // client input key representing "1"

#ifdef DEBUGYAOSERVER
					std::cout << "T0: ";
					PrintKey(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes);
					std::cout << " = ";
					PrintKey(m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
					std::cout << " ^ ";
					PrintKey((clientROTbit == 0) ? m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes : m_bTempKeyBuf);
					std::cout << std::endl;
					std::cout << "T1: ";
					PrintKey(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes);
					std::cout << " = ";
					PrintKey(m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
					std::cout << " ^ ";
					PrintKey((clientROTbit == 0) ? m_bTempKeyBuf : m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
					std::cout << std::endl;
#endif
#endif
				}
			} else { //Evaluate conversion gates
				uint32_t input = m_vGates[gateid].ingates.inputs.parents[0];

				for (uint32_t k = 0; k < m_vGates[gateid].nvals; k++, linbitctr++, m_nClientInputKexIdx++, m_nClientInputKeyCtr++) {
					m_pKeyOps->XOR(m_bTempKeyBuf, m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, m_vR.GetArr());
					uint32_t permval = 0;
					if (m_vGates[input].context == S_BOOL) {
						uint32_t val = (m_vGates[input].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01;
						permval = val ^ m_vGates[gateid].gs.yinput.pi[k];
					} else  if (m_vGates[input].context == S_YAO || m_vGates[input].context == S_YAO_REV) {//switch roles gate
						//std::cout << "copying keys from input " << input << " at position " << k << std::endl;
						assert(m_vGates[input].instantiated);
						uint32_t val = m_vGates[input].gs.yval[((k+1) * m_nSecParamBytes)-1] & 0x01; //get client permutation bit
						//std::cout << "Server conv share = " << val << std::endl;
						permval = val ^ m_vGates[gateid].gs.yinput.pi[k];
						//std::cout << "done copying keys" << std::endl;
					}
#ifdef DEBUGYAOSERVER
					std::cout << "Processing keys for gate " << gateid << ", perm-bit = " << (uint32_t) m_vGates[gateid].gs.yinput.pi[k] <<
					", client-cor: " << (uint32_t) m_vClientROTRcvBuf.GetBitNoMask(linbitctr) << std::endl;

					PrintKey(m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
					std::cout << std::endl;
#endif
					if ((m_vClientROTRcvBuf.GetBitNoMask(linbitctr) ^ permval) == 1) {
						m_pKeyOps->XOR(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_bTempKeyBuf); //One - key
						m_pKeyOps->XOR(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); //Zero - key
					} else {
						//masks remain the same
						m_pKeyOps->XOR(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); //Zero - key
						m_pKeyOps->XOR(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_bTempKeyBuf); //One - key
					}
				}
				UsedGate(input);
			}
		}
	}

	m_vClientInputGate.clear();
	m_nClientInBitCtr = 0;

	if (m_nOutputShareRcvCtr > 0) {
		AssignOutputShares();
	}

	//Recheck if this is working
	InitNewLayer();
}
;

void YaoServerSharing::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//receive bit from random-OT
	if (m_nClientInBitCtr > 0) {
#ifdef DEBUGYAOSERVER
		std::cout << "want to receive clients OT-bits which are of size " << m_nClientInBitCtr << " bits" << std::endl;
#endif
		m_vClientROTRcvBuf.Create(m_nClientInBitCtr);
		rcvbuf.push_back(m_vClientROTRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nClientInBitCtr, 8));
	}

	if (m_nOutputShareRcvCtr > 0) {
#ifdef DEBUGYAOSERVER
		std::cout << "want to receive server output bits which are of size " << m_nOutputShareRcvCtr << " bits" << std::endl;
#endif
		m_vOutputShareRcvBuf.Create(m_nOutputShareRcvCtr);
		rcvbuf.push_back(m_vOutputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nOutputShareRcvCtr, 8));
	}
}

void YaoServerSharing::AssignOutputShares() {
	GATE* gate;
	for (uint32_t i = 0, offset = 0; i < m_vServerOutputGates.size(); i++) {
		gate = m_vServerOutputGates[i];
#ifdef DEBUGYAOSERVER
		std::cout << "Server Output: " << (uint32_t) (m_vOutputShareRcvBuf.GetBit(offset) ^ gate->gs.val[0] ) << " = "<< (uint32_t) m_vOutputShareRcvBuf.GetBit(offset) << " ^ " << (uint32_t) gate->gs.val[0] << std::endl;
#endif
		//InstantiateGate(gate);
		for (uint32_t j = 0; j < gate->nvals; j++, offset++) {
			gate->gs.val[j / GATE_T_BITS] = (gate->gs.val[j / GATE_T_BITS] ^ (((UGATE_T) m_vOutputShareRcvBuf.GetBit(offset))) << (j % GATE_T_BITS));
		}
	}
	m_nOutputShareRcvCtr = 0;
	m_vServerOutputGates.clear();

}

void YaoServerSharing::CreateRandomWireKeys(CBitVector& vec, uint32_t numkeys) {
	//Create the random keys
	vec.Create(numkeys * m_cCrypto->get_seclvl().symbits, m_cCrypto);
	for (uint32_t i = 0; i < numkeys; i++) {
		vec.ANDByte((i + 1) * m_nSecParamBytes - 1, 0xFE);
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Created wire keys: with num = " << numkeys << std::endl;
	vec.PrintHex();
	std::cout << "m_vR = ";
	m_vR.PrintHex();
#endif
}

void YaoServerSharing::InstantiateGate(GATE* gate) {
	gate->gs.yinput.outKey = (BYTE*) malloc(sizeof(UGATE_T) * m_nSecParamIters * gate->nvals);
	gate->gs.yinput.pi = (BYTE*) malloc(sizeof(BYTE) * gate->nvals);
	if (gate->gs.yinput.outKey == NULL) {
		std::cerr << "Memory allocation not successful at Yao gate instantiation" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	gate->instantiated = true;
}

void YaoServerSharing::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	if (gate->type == G_COMBINE) {
		uint32_t* inptr = gate->ingates.inputs.parents; //gate->gs.cinput;
		uint32_t nparents = gate->ingates.ningates;
		uint32_t parent_nvals;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		BYTE* piptr = gate->gs.yinput.pi;
		for(uint32_t g = 0; g < nparents; g++) {
			parent_nvals = m_vGates[inptr[g]].nvals;
			memcpy(keyptr, m_vGates[inptr[g]].gs.yinput.outKey, m_nSecParamBytes * parent_nvals);
			keyptr += m_nSecParamBytes * parent_nvals;

			memcpy(piptr, m_vGates[inptr[g]].gs.yinput.pi, parent_nvals);
			piptr += parent_nvals;

			UsedGate(inptr[g]);
		}
		free(inptr);
	} else if (gate->type == G_SPLIT) {
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idleft = gate->ingates.inputs.parent; //gate->gs.sinput.input;
		InstantiateGate(gate);
		memcpy(gate->gs.yinput.outKey, m_vGates[idleft].gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		memcpy(gate->gs.yinput.pi, m_vGates[idleft].gs.yinput.pi + pos, gate->nvals);
		UsedGate(idleft);
	} else if (gate->type == G_REPEAT) {
		uint32_t idleft = gate->ingates.inputs.parent; //gate->gs.rinput;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idleft].gs.yinput.outKey, m_nSecParamBytes);
			gate->gs.yinput.pi[g] = m_vGates[idleft].gs.yinput.pi[0];
			assert(gate->gs.yinput.pi[g] < 2);
		}
		UsedGate(idleft);
	} else if (gate->type == G_COMBINEPOS) {
		uint32_t* combinepos = gate->ingates.inputs.parents; //gate->gs.combinepos.input;
		uint32_t pos = gate->gs.combinepos.pos;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			uint32_t idleft = combinepos[g];
			memcpy(keyptr, m_vGates[idleft].gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes);
			gate->gs.yinput.pi[g] = m_vGates[idleft].gs.yinput.pi[pos];
			assert(gate->gs.yinput.pi[g] < 2);
			UsedGate(idleft);
		}
		free(combinepos);
	} else if (gate->type == G_SUBSET) {
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;

		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idparent].gs.yinput.outKey + positions[g] * m_nSecParamBytes, m_nSecParamBytes);
			gate->gs.yinput.pi[g] = m_vGates[idparent].gs.yinput.pi[positions[g]];
			assert(gate->gs.yinput.pi[g] < 2);
		}
		UsedGate(idparent);
		if(del_pos)
			free(positions);
	}
}

uint32_t YaoServerSharing::AssignInput(CBitVector& inputvals) {
	std::cout << "potentially unused code" << '\n'; exit(0);
	std::deque<uint32_t> myingates = m_cBoolCircuit->GetInputGatesForParty(m_eRole);
	inputvals.Create(m_cBoolCircuit->GetNumInputBitsForParty(m_eRole), m_cCrypto);

	GATE* gate;
	uint32_t inbits = 0;
	for (uint32_t i = 0, inbitstart = 0, bitstocopy, len, lim; i < myingates.size(); i++) {
		gate = &(m_vGates[myingates[i]]);
		if (!gate->instantiated) {
			bitstocopy = gate->nvals * gate->sharebitlen;
			inbits += bitstocopy;
			lim = ceil_divide(bitstocopy, GATE_T_BITS);

			UGATE_T* inval = (UGATE_T*) calloc(lim, sizeof(UGATE_T));

			for (uint32_t j = 0; j < lim; j++, bitstocopy -= GATE_T_BITS) {
				len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
				inval[j] = inputvals.Get<UGATE_T>(inbitstart, len);
				inbitstart += len;
			}
			gate->gs.ishare.inval = inval;
		}
	}
	return inbits;
}

uint32_t YaoServerSharing::GetOutput(CBitVector& out) {
	std::deque<uint32_t> myoutgates = m_cBoolCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits);

	GATE* gate;
	for (uint32_t i = 0, outbitstart = 0, lim; i < myoutgates.size(); i++) {
		gate = &(m_vGates[myoutgates[i]]);
		lim = gate->nvals * gate->sharebitlen;

		for (uint32_t j = 0; j < lim; j++, outbitstart++) {
			out.SetBitNoMask(outbitstart, (gate->gs.val[j / GATE_T_BITS] >> (j % GATE_T_BITS)) & 0x01);
		}
	}
	return outbits;
}

void YaoServerSharing::Reset() {
	m_vR.delCBitVector();
	m_vPermBits.delCBitVector();

	for (uint32_t i = 0; i < m_vROTMasks.size(); i++)
		m_vROTMasks[i].delCBitVector();

	m_nClientInputKexIdx = 0;

	m_vServerKeySndBuf.delCBitVector();
	for (uint32_t i = 0; i < m_vClientKeySndBuf.size(); i++)
		m_vClientKeySndBuf[i].delCBitVector();

	m_vClientROTRcvBuf.delCBitVector();

	m_vOutputShareSndBuf.delCBitVector();
	m_vOutputShareRcvBuf.delCBitVector();

	m_nOutputShareRcvCtr = 0;

	m_nPermBitCtr = 0;
	m_nServerInBitCtr = 0;

	m_nServerKeyCtr = 0;
	m_nClientInBitCtr = 0;

	m_vClientInputGate.clear();
	m_vANDGates.clear();
	m_vOutputShareGates.clear();
	m_vServerOutputGates.clear();

	free(m_vOutputDestionations);
	m_vOutputDestionations = nullptr;
	m_nOutputDestionationsCtr = 0;

	m_nANDGates = 0;
	m_nXORGates = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_nConversionInputBits = 0;

	m_nClientInputBits = 0;
	m_vClientInputKeys.delCBitVector();

	m_nServerInputBits = 0;
	m_vServerInputKeys.delCBitVector();

	m_vGarbledCircuit.delCBitVector();
	m_nGarbledTableCtr = 0;
	m_nGarbledTableSndCtr = 0L;

	m_vUniversalGateTable.delCBitVector();
	m_nUniversalGateTableCtr = 0;

	m_cBoolCircuit->Reset();
}
