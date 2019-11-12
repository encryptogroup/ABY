/**
 \file 		yaoclientsharing.cpp
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
 \brief		Yao Client Sharing class implementation.
 */
#include "yaoclientsharing.h"
#include "../aby/abysetup.h"
#include <cstdlib>

void YaoClientSharing::InitClient() {

	m_nChoiceBitCtr = 0;
	m_vROTCtr = 0;

	m_nClientSndOTCtr = 0;
	m_nClientRcvKeyCtr = 0;
	m_nServerInBitCtr = 0;
	m_nClientOutputShareCtr = 0;
	m_nServerOutputShareCtr = 0;
	m_nClientOUTBitCtr = 0;

	m_nKeyInputRcvIdx = 0;

	m_vClientKeyRcvBuf.resize(2);

#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	fMaskFct = new XORMasking(m_nCiphertextSize * 8);
#else
	fMaskFct = new XORMasking(m_cCrypto->get_seclvl().symbits);
#endif

	m_vTmpEncBuf = (uint8_t**) malloc(sizeof(uint8_t*) * KEYS_PER_GATE_IN_TABLE);
	for(uint32_t i = 0; i < KEYS_PER_GATE_IN_TABLE; i++)
		m_vTmpEncBuf[i] = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES);

}

YaoClientSharing::~YaoClientSharing() {
		Reset();
		for(size_t i = 0; i < KEYS_PER_GATE_IN_TABLE; i++) {
			free(m_vTmpEncBuf[i]);
		}
		free(m_vTmpEncBuf);
#ifdef KM11_GARBLING
		free(m_bTmpGTEntry);
#endif
		delete fMaskFct;
}

//Pre-set values for new layer
void YaoClientSharing::InitNewLayer() {
	m_nServerInBitCtr = 0;
	m_vServerInputGates.clear();

	m_nServerOutputShareCtr = 0;

}

/* Send a new task for pre-computing the OTs in the setup phase */
void YaoClientSharing::PrepareSetupPhase(ABYSetup* setup) {
	BYTE* buf;
	uint64_t gt_size;
	uint64_t univ_size;
	m_nANDGates = m_cBoolCircuit->GetNumANDGates();
	m_nXORGates = m_cBoolCircuit->GetNumXORGates();
	m_nConstantGates = m_cBoolCircuit->GetNumConstantGates();
	m_nInputGates = m_cBoolCircuit->GetNumInputGates();
	m_nUNIVGates = m_cBoolCircuit->GetNumUNIVGates();

#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	gt_size = ((uint64_t) m_nANDGates + m_nXORGates) * KEYS_PER_GATE_IN_TABLE * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	gt_size = ((uint64_t) m_nANDGates + m_nXORGates) * KEYS_PER_GATE_IN_TABLE * (m_nCiphertextSize + m_nSymEncPaddingBytes);
#endif // KM11_CRYPTOSYSTEM
#else // KM11_GARBLING
	gt_size = ((uint64_t) m_nANDGates) * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
#endif
	univ_size = ((uint64_t) m_nUNIVGates) * KEYS_PER_UNIV_GATE_IN_TABLE * m_nSecParamBytes;

	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

#ifdef KM11_GARBLING
	m_nNumberOfKeypairs = m_cBoolCircuit->GetNumInputGates() + m_nANDGates + m_nXORGates + m_nConstantGates;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * m_nBFVciphertextBufLen);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) / 8 * m_nBFVciphertextBufLen);
	m_bBlindingValues = (BYTE*) malloc((m_nANDGates + m_nXORGates) * 2 * m_nWireKeyBytes);
	m_vEncBlindingValues.resize((m_nXORGates + m_nANDGates)/8);
	// plaintext wire key pairs of (constant and) output gates to determine circuit output
	m_bOutputWireKeys = (BYTE*) malloc((m_nConstantGates + 2 * m_cBoolCircuit->GetNumOutputGates()) * m_nWireKeyBytes);
	m_nOutputWireKeysCtr = 0;
	m_bTmpGTKey = (BYTE*) malloc(m_nWireKeyBytes * 2);
	m_bTmpGTEntry = (BYTE*) malloc(sizeof(BYTE) * (m_nSecParamBytes + m_nSymEncPaddingBytes));
	assert(m_bTmpGTEntry != NULL);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * m_nCiphertextSize);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) * 2 * m_nCiphertextSize);
#else
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
#endif
	// plaintext wire key pairs of (constant and) output gates to determine circuit output
	m_bOutputWireKeys = (BYTE*) malloc((m_nConstantGates + 2 * m_cBoolCircuit->GetNumOutputGates()) * m_nWireKeyBytes);
	m_nOutputWireKeysCtr = 0;
	m_bTmpGTKey = (BYTE*) malloc(m_nWireKeyBytes * 2);
	m_bTmpGTEntry = (BYTE*) malloc(sizeof(BYTE) * (m_nSecParamBytes + m_nSymEncPaddingBytes));
	assert(m_bTmpGTEntry != NULL);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	m_bEncWireKeys = (BYTE*) malloc(m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
	m_bEncGG = (BYTE*) malloc((m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
	m_vBlindingValues.resize(m_cBoolCircuit->GetNumGates() * 2);
	m_vEncBlindingValues.resize((m_nXORGates + m_nANDGates) * 4);
	m_bTmpGTKey = (BYTE*) malloc(m_nCiphertextSize * 2);
	m_bTmpGTEntry = (BYTE*) malloc(m_nCiphertextSize + m_nSymEncPaddingBytes);
	// plaintext wire key pairs of (constant and) output gates to determine circuit output
	m_bOutputWireKeys = (BYTE*) malloc((m_nConstantGates + 2 * m_cBoolCircuit->GetNumOutputGates()) * m_nCiphertextSize);
	m_nOutputWireKeysCtr = 0;
	assert(m_bTmpGTEntry != NULL);
#endif // KM11_CRYPTOSYSTEM
#endif

	//TODO figure out which parts of the init can be moved to prepareonlinephase
	/* Preset the number of input bits for client and server */
	m_nServerInputBits = m_cBoolCircuit->GetNumInputBitsForParty(SERVER);
	m_nClientInputBits = m_cBoolCircuit->GetNumInputBitsForParty(CLIENT);
	m_nConversionInputBits = m_cBoolCircuit->GetNumB2YGates() + m_cBoolCircuit->GetNumA2YGates() + m_cBoolCircuit->GetNumYSwitchGates();

	buf = (BYTE*) malloc(gt_size);
	m_vGarbledCircuit.AttachBuf(buf, gt_size);

	m_vUniversalGateTable.Create(0);
	buf = (BYTE*) malloc(univ_size);
	m_vUniversalGateTable.AttachBuf(buf, univ_size);

	m_nUniversalGateTableCtr = 0;

#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	// init BFV parameters
	seal::EncryptionParameters parms(seal::scheme_type::BFV);
	parms.set_poly_modulus_degree(m_nBFVpolyModulusDegree);
	parms.set_coeff_modulus(m_nBFVCoeffModulus);
	parms.set_plain_modulus(m_nBFVplainModulus);
	m_nWirekeySEALcontext = seal::SEALContext::Create(parms);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	fe* P = m_cPKCrypto->get_generator();
	m_nECCGeneratorBrick = m_cPKCrypto->get_brick(P);
#endif
#endif

	m_vOutputShareRcvBuf.Create((uint32_t) m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));
	m_vOutputShareSndBuf.Create((uint32_t) m_cBoolCircuit->GetNumOutputBitsForParty(SERVER));
	m_vROTSndBuf.Create((uint32_t) m_cBoolCircuit->GetNumInputBitsForParty(CLIENT) + m_nConversionInputBits);

#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	m_vROTMasks.Create((m_nClientInputBits + m_nConversionInputBits) * m_nCiphertextSize * 8);
#else
	m_vROTMasks.Create((m_nClientInputBits + m_nConversionInputBits) * m_cCrypto->get_seclvl().symbits); //TODO: do a bit more R-OTs to get the offset right
#endif

	m_vChoiceBits.Create(m_nClientInputBits + m_nConversionInputBits, m_cCrypto);

#ifdef DEBUGYAOCLIENT
	std::cout << "OT Choice bits: " << std::endl;
	m_vChoiceBits.Print(0, m_nClientInputBits + m_nConversionInputBits);
#endif
	/* Use the standard XORMasking function */

	/* Define the new OT tasks that will be done when the setup phase is performed*/
	IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	task->bitlen = m_nCiphertextSize * 8;
#else
	task->bitlen = m_cCrypto->get_seclvl().symbits;
#endif
	task->snd_flavor = Snd_R_OT;
	task->rec_flavor = Rec_OT;
	task->numOTs = m_nClientInputBits + m_nConversionInputBits;
	task->mskfct = fMaskFct;
	task->delete_mskfct = FALSE; // is deleted in destructor
	task->pval.rcvval.C = &(m_vChoiceBits);
	task->pval.rcvval.R = &(m_vROTMasks);

	setup->AddOTTask(task, m_eContext == S_YAO? 0 : 1);
}

/* If played as server send the garbled table, if played as client receive the garbled table */
void YaoClientSharing::PerformSetupPhase(ABYSetup* setup) {
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	uint64_t delta;
	struct timespec start, end;

#ifdef KM11_GARBLING
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	CreateBlindingValues();
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[time] Creation of blinding values took " << delta << " microseconds.\n" << std::endl;
#endif // KM11_GARBLING

#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	// receive BFV public key
	BYTE* BFVpublickeyBuf = (BYTE*) malloc(m_nBFVpublicKeyLenExported);
	std::cout << "setup->AddReceiveTask(BFVpublickeyBuf, " << m_nBFVpublicKeyLenExported << ");" << '\n';
	setup->AddReceiveTask(BFVpublickeyBuf, m_nBFVpublicKeyLenExported);
	setup->WaitForTransmissionEnd();

	std::string BFVpublickeyStr((const char*) BFVpublickeyBuf, m_nBFVpublicKeyLenExported);
	std::istringstream BFVpublickeyIStringStream(BFVpublickeyStr);
	m_nWirekeySEALpublicKey = seal::PublicKey();
	m_nWirekeySEALpublicKey.load(m_nWirekeySEALcontext, BFVpublickeyIStringStream);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	// receive DJN public key
	BYTE* publickeyBuf = (BYTE*) malloc(2 * (m_nDJNBytes + 1));
	std::cout << "AddReceiveTask(publickeyBuf, " << (2 * (m_nDJNBytes + 1)) << ")" << std::endl;
	setup->AddReceiveTask(publickeyBuf, 2 * (m_nDJNBytes + 1));
	setup->WaitForTransmissionEnd();

	// import DJN public key received from the server
	mpz_t n, h;
	mpz_inits(n, h, NULL);
	mpz_import(n, 1, -1, m_nDJNBytes + 1, -1, 0, publickeyBuf + 0 * (m_nDJNBytes + 1));
	mpz_import(h, 1, -1, m_nDJNBytes + 1, -1, 0, publickeyBuf + 1 * (m_nDJNBytes + 1));
	djn_complete_pubkey(m_nDJNBytes * 8, &m_nDJNPubkey, n, h);
	mpz_clears(n, h, NULL);
	free(publickeyBuf);

	// pre-compute fixed base table (used by djn_encrypt_fb)
	fbpowmod_init_g(m_nDJNPubkey->h_s, m_nDJNPubkey->n_squared, 2 * m_nDJNBytes * 8);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	// receive ECC public key
	BYTE* publickeyBuf = (BYTE*) malloc(m_nCiphertextSize);
	std::cout << "AddReceiveTask(publickeyBuf, " << m_nCiphertextSize << ")" << std::endl;
	setup->AddReceiveTask(publickeyBuf, m_nCiphertextSize);
	setup->WaitForTransmissionEnd();
	m_nECCPubkey = m_cPKCrypto->get_fe();
	m_nECCPubkey->import_from_bytes(publickeyBuf);
	m_nECCPubkeyBrick = m_cPKCrypto->get_brick(m_nECCPubkey);
	free(publickeyBuf);
#endif // KM11_CRYPTOSYSTEM

	// precompute blinding vectors b
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	PrecomputeBlindingValues();
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[timePrecomB] Precomputation of parameter b took " << delta << " microseconds.\n" << std::endl;

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	// receive encrypted wirepairs
	std::cout << "AddReceiveTask(m_bEncWireKeys)" << std::endl;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	setup->AddReceiveTask(m_bEncWireKeys, ((uint64_t)m_nNumberOfKeypairs) * m_nBFVciphertextBufLen);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	setup->AddReceiveTask(m_bEncWireKeys, m_nNumberOfKeypairs * m_nCiphertextSize);
#else
	setup->AddReceiveTask(m_bEncWireKeys, m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
#endif
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	setup->AddReceiveTask(m_bEncWireKeys, m_nNumberOfKeypairs * 2 * m_nCiphertextSize);
#endif // KM11_CRYPTOSYSTEM
	setup->WaitForTransmissionEnd();
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[timeEncWK] receiving the encrypted wirekeys took " << delta << " microseconds.\n" << std::endl;

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	CreateEncGarbledGates(setup);
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[timeEncGG] creating the the encrypted garbled gates took _____ " << delta << " _____ microseconds.\n" << std::endl;

	// send encrypted garbled gates
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
#ifndef KM11_PIPELINING
	std::cout << "AddSendTask(m_bEncGG, " << (m_nANDGates + m_nXORGates) / 8 * m_nBFVciphertextBufLen << ");" << std::endl;
	setup->AddSendTask(m_bEncGG, (m_nANDGates + m_nXORGates) / 8 * m_nBFVciphertextBufLen);
#endif
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
	std::cout << "AddSendTask(m_bEncGG, " << (m_nXORGates + m_nANDGates) * 2 * m_nCiphertextSize << ");" << std::endl;
	setup->AddSendTask(m_bEncGG, (m_nXORGates + m_nANDGates) * 2 * m_nCiphertextSize);
#else // KM11_IMPROVED
	std::cout << "AddSendTask(m_bEncGG, " << (m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize << ");" << std::endl;
	setup->AddSendTask(m_bEncGG, (m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
#endif // KM11_IMPROVED
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
#ifndef KM11_PIPELINING
	std::cout << "AddSendTask(m_bEncGG, " << (m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize << ");" << std::endl;
	setup->AddSendTask(m_bEncGG, (m_nXORGates + m_nANDGates) * 4 * m_nCiphertextSize);
#endif
#endif // KM11_CRYPTOSYSTEM

	// receive wire keys for constant and output gates
	GATE* gate;
	for (int gateid = 0; gateid < m_cBoolCircuit->GetNumGates(); gateid++) {
		gate = &(m_vGates[gateid]);
		if (gate->type == G_CONSTANT) {
			setup->AddReceiveTask(m_bOutputWireKeys + m_nOutputWireKeysCtr * m_nWireKeyBytes, m_nWireKeyBytes);
			m_nOutputWireKeysCtr++;
		} else if (gate->type == G_OUT) {
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
			setup->AddReceiveTask(m_bOutputWireKeys + m_nOutputWireKeysCtr * m_nCiphertextSize, 2 * m_nCiphertextSize);
#else
			setup->AddReceiveTask(m_bOutputWireKeys + m_nOutputWireKeysCtr * m_nWireKeyBytes, 2 * m_nWireKeyBytes);
#endif
			m_nOutputWireKeysCtr += 2;
		}
	}
	m_nOutputWireKeysCtr = 0;
	setup->WaitForTransmissionEnd();
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	std::cout << "[Time] sending the encGG & receiving the keys for the output gates took " << delta << " microseconds." << std::endl;
#endif // #ifdef KM11_GARBLING

	ReceiveGarbledCircuitAndOutputShares(setup);
}

void YaoClientSharing::PrepareOnlinePhase() {
	InitNewLayer();
}

void YaoClientSharing::ReceiveGarbledCircuitAndOutputShares(ABYSetup* setup) {
#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	uint64_t gt_size = ((uint64_t) m_nANDGates + m_nXORGates) * KEYS_PER_GATE_IN_TABLE * (m_nSecParamBytes + 2 * m_nSymEncPaddingBytes);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	uint64_t gt_size = ((uint64_t) m_nANDGates + m_nXORGates) * KEYS_PER_GATE_IN_TABLE * (m_nCiphertextSize + m_nSymEncPaddingBytes);
#endif
#else
	uint64_t gt_size = ((uint64_t) m_nANDGates) * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
#endif
	if (gt_size > 0)
		setup->AddReceiveTask(m_vGarbledCircuit.GetArr(), gt_size);
	if (m_nUNIVGates > 0)
		setup->AddReceiveTask(m_vUniversalGateTable.GetArr(), ((uint64_t) m_nUNIVGates) * m_nSecParamBytes * KEYS_PER_UNIV_GATE_IN_TABLE);
	if (m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT) > 0)
		setup->AddReceiveTask(m_vOutputShareRcvBuf.GetArr(), ceil_divide(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT), 8));

}

void YaoClientSharing::FinishSetupPhase(ABYSetup* setup) {
	setup->WaitForTransmissionEnd();
	/*std::cout << "Garbled Table Cl: " << std::endl;
	m_vGarbledCircuit.PrintHex(0, ((uint64_t) m_nANDGates) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);

	std::cout << "Outshares C: " << std::endl;
	m_vOutputShareRcvBuf.PrintHex(ceil_divide(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT), 8));*/
#ifdef DEBUGYAOCLIENT
	std::cout << "Received Garbled Circuit.";
	//m_vGarbledCircuit.PrintHex();
	std::cout << "Received my output shares: ";
	m_vOutputShareRcvBuf.Print(0, m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));

	if(m_cBoolCircuit->GetMaxDepth() == 0)
	return;
	std::cout << "Choice bits in OT: ";
	m_vChoiceBits.Print(0, m_nClientInputBits);
	std::cout << "Resulting R from OT: ";
	m_vROTMasks.PrintHex();
#endif
}
void YaoClientSharing::EvaluateLocalOperations(uint32_t depth) {

	std::deque<uint32_t> localops = m_cBoolCircuit->GetLocalQueueOnLvl(depth);

	//std::cout << "In total I have " <<  localops.size() << " local operations to evaluate on this level " << std::endl;
	for (uint32_t i = 0; i < localops.size(); i++) {
		GATE* gate = &(m_vGates[localops[i]]);
#ifdef DEBUGYAOCLIENT
		std::cout << "Evaluating gate " << localops[i] << " with context = " << gate->context << std::endl;
#endif
		if (gate->type == G_LIN) {
#ifdef KM11_GARBLING
			EvaluateKM11Gate(localops[i]);
#else
			EvaluateXORGate(gate);
#endif
		} else if (gate->type == G_NON_LIN) {
#ifdef KM11_GARBLING
			EvaluateKM11Gate(localops[i]);
#else
			EvaluateANDGate(gate);
#endif
		} else if (gate->type == G_CONSTANT) {
			InstantiateGate(gate);
			UGATE_T constval = gate->gs.constval;
			std::cout << "UGATE_T constval = gate->gs.constval: " << constval << '\n';
#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
			memcpy(gate->gs.yval, m_bOutputWireKeys + m_nOutputWireKeysCtr * m_nCiphertextSize, m_nWireKeyBytes);
#else
			memcpy(gate->gs.yval, m_bOutputWireKeys + m_nOutputWireKeysCtr * m_nWireKeyBytes, m_nWireKeyBytes);
#endif
			m_nOutputWireKeysCtr++;
#else
			memset(gate->gs.yval, 0, m_nSecParamBytes * gate->nvals);
#endif
		} else if (IsSIMDGate(gate->type)) {
			//std::cout << "Evaluating SIMD gate" << std::endl;
			EvaluateSIMDGate(localops[i]);
		} else if (gate->type == G_INV) {
			//only copy values, SERVER did the inversion
			uint32_t parentid = gate->ingates.inputs.parent; // gate->gs.invinput;
			InstantiateGate(gate);
			memcpy(gate->gs.yval, m_vGates[parentid].gs.yval, m_nSecParamBytes * gate->nvals);
			UsedGate(parentid);
		} else if (gate->type == G_SHARED_OUT) {
			GATE* parent = &(m_vGates[gate->ingates.inputs.parent]);
			InstantiateGate(gate);
			memcpy(gate->gs.yval, parent->gs.yval, gate->nvals * m_nSecParamBytes);
			UsedGate(gate->ingates.inputs.parent);
			// TODO this currently copies both keys and bits and getclearvalue will probably fail.
			//std::cerr << "SharedOutGate is not properly tested for Yao!" << std::endl;
		} else if(gate->type == G_SHARED_IN) {
			//Do nothing
		} else if(gate->type == G_CALLBACK) {
			EvaluateCallbackGate(localops[i]);
		} else if(gate->type == G_PRINT_VAL) {
			EvaluatePrintValGate(localops[i], C_BOOLEAN);
		} else if(gate->type == G_ASSERT) {
			EvaluateAssertGate(localops[i], C_BOOLEAN);
		} else if (gate->type == G_UNIV) {
			//std::cout << "Client: Evaluating Universal Circuit gate" << std::endl;
			EvaluateUNIVGate(gate);
		} else {
			std::cerr << "YaoClientSharing: Non-interactive operation not recognized: " <<
					(uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

void YaoClientSharing::EvaluateInteractiveOperations(uint32_t depth) {
	std::deque<uint32_t> interactiveops = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);

	//std::cout << "In total I have " <<  localops.size() << " local operations to evaluate on this level " << std::endl;
	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = &(m_vGates[interactiveops[i]]);
#ifdef DEBUGYAOCLIENT
		std::cout << "Evaluating interactive operation in Yao client sharing with type = " << get_gate_type_name(gate->type) << std::endl;
#endif
		if (gate->type == G_IN) {
			if (gate->gs.ishare.src == SERVER) {
				ReceiveServerKeys(interactiveops[i]);
				//Receive servers input shares;
			} else {
				ReceiveClientKeys(interactiveops[i]);
				//Receive servers input shares;
			}
		} else if (gate->type == G_OUT) {
#ifdef DEBUGYAOCLIENT
			std::cout << "Obtained output gate (" << interactiveops[i] << ") with key = ";
			PrintKey(m_vGates[gate->ingates.inputs.parent].gs.yval);
			std::cout << std::endl;
#endif
			if (gate->gs.oshare.dst == SERVER) {
				EvaluateServerOutputGate(gate);
			} else if (gate->gs.oshare.dst == ALL) {
				//std::cout << "Output gate for both of us, sending server output for gateid: " << interactiveops[i] << std::endl;
				EvaluateServerOutputGate(gate);
				//std::cout << "Setting my output gate" << std::endl;
				EvaluateClientOutputGate(interactiveops[i]);
				//std::cout << "finished setting my output" <<std::endl;
			} else {
				//ouput reconstruction
				EvaluateClientOutputGate(interactiveops[i]);
			}
		} else if (gate->type == G_CONV) {
			EvaluateConversionGate(interactiveops[i]);
		} else if(gate->type == G_CALLBACK) {
			EvaluateCallbackGate(interactiveops[i]);
		} else {
			std::cerr << "YaoClientSharing: Interactive operation not recognized: " << (uint32_t) gate->type << "(" <<
					get_gate_type_name(gate->type) << ")" << std::endl;
		}
	}
}

#ifdef KM11_GARBLING
void YaoClientSharing::CreateBlindingValues() {
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	size_t count0;
	mpz_t b;
	mpz_init(b);
	for(int i = 0; i < (m_nANDGates + m_nXORGates); i++) {
		aby_prng(b, 2 * m_nWireKeyBytes * 8);
		mpz_export(m_bBlindingValues + i * 2 * m_nWireKeyBytes, &count0, -1, 2 * m_nWireKeyBytes, -1, 0, b);
		assert(count0 == 1);
	}
	mpz_clear(b);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifndef KM11_IMPROVED
	mpz_t a1, a2;
	mpz_inits(a1, a2, NULL);
#endif
	mpz_t b1, b2;
	mpz_inits(b1, b2, NULL);
	size_t count0, count1;
	for(int i = 0; i < m_cBoolCircuit->GetNumGates(); i++) {
		GATE* gate = &(m_vGates[i]);
		aby_prng(b1, m_nWireKeyBytes * 8);
		aby_prng(b2, m_nWireKeyBytes * 8);
		gate->gs.yinput.b1 = (BYTE*) malloc(m_nWireKeyBytes);
		gate->gs.yinput.b2 = (BYTE*) malloc(m_nWireKeyBytes);
		mpz_export(gate->gs.yinput.b1, &count0, -1, m_nWireKeyBytes, -1, 0, b1);
		mpz_export(gate->gs.yinput.b2, &count1, -1, m_nWireKeyBytes, -1, 0, b2);
		assert(count0 == 1 && count1 == 1);
#ifndef KM11_IMPROVED
		aby_prng(a1, m_nWireKeyBytes * 8);
		aby_prng(a2, m_nWireKeyBytes * 8);
		gate->gs.yinput.a1 = (BYTE*) malloc(m_nWireKeyBytes);
		gate->gs.yinput.a2 = (BYTE*) malloc(m_nWireKeyBytes);
		mpz_export(gate->gs.yinput.a1, &count0, -1, m_nWireKeyBytes, -1, 0, a1);
		mpz_export(gate->gs.yinput.a2, &count1, -1, m_nWireKeyBytes, -1, 0, a2);
		assert(count0 == 1 && count1 == 1);
#endif
	}
#ifndef KM11_IMPROVED
	mpz_clears(a1, a2, NULL);
#endif
	mpz_clears(b1, b2, NULL);
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	for(int i = 0; i < m_cBoolCircuit->GetNumGates(); i++) {
		num* b1 = m_cPKCrypto->get_rnd_num();
		num* b2 = m_cPKCrypto->get_rnd_num();

		m_vBlindingValues[2 * i] = m_cPKCrypto->get_fe();
		m_nECCGeneratorBrick->pow(m_vBlindingValues[2 * i], b1);
		m_vBlindingValues[2 * i + 1] = m_cPKCrypto->get_fe();
		m_nECCGeneratorBrick->pow(m_vBlindingValues[2 * i + 1], b2);
	}
#endif // KM11_CRYPTOSYSTEM
}

void YaoClientSharing::PrecomputeBlindingValues() {
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	seal::Encryptor bfvWirekeyEncryptor(m_nWirekeySEALcontext, m_nWirekeySEALpublicKey);
	seal::Plaintext b_plain;
	b_plain.resize(2048);

	for(int i = 0; i < (m_nXORGates + m_nANDGates); i+=8) {
		m_vEncBlindingValues[i/8] = seal::Ciphertext();

		encodeBufAsPlaintext(&b_plain, m_bBlindingValues + i * 2 * m_nWireKeyBytes, 2048);
		bfvWirekeyEncryptor.encrypt(b_plain, m_vEncBlindingValues[i/8]);
	}
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_PRECOMPUTEB
	mpz_t b1, b2;
	mpz_inits(b1, b2, NULL);
	GATE* gate;

	for(int i = 0; i < m_cBoolCircuit->GetNumGates(); i++) {
		gate = &(m_vGates[i]);
		mpz_import(b1, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.b1);
		mpz_import(b2, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.b2);

		// prepare parameter b for homomorphic addition: Dec(Enc(s) * Enc(b)) = s + b
		djn_encrypt_fb(b1, m_nDJNPubkey, b1);
		djn_encrypt_fb(b2, m_nDJNPubkey, b2);

		gate->gs.yinput.b1_enc = (BYTE*) malloc(m_nCiphertextSize);
		gate->gs.yinput.b2_enc = (BYTE*) malloc(m_nCiphertextSize);

		size_t count1, count2;
		mpz_export(gate->gs.yinput.b1_enc, &count1, -1, m_nCiphertextSize, -1, 0, b1);
		mpz_export(gate->gs.yinput.b2_enc, &count2, -1, m_nCiphertextSize, -1, 0, b2);
		assert(count1 == 1 && count2 == 1);
	}
	mpz_clears(b1, b2, NULL);

#endif // KM11_PRECOMPUTEB
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	// precompute blinding values

	fe* kaP = m_cPKCrypto->get_fe();
	ecc_num* k = (ecc_num*) m_cPKCrypto->get_num();
	uint32_t field_size = ((ecc_field*)m_cPKCrypto)->get_size();

	for(int i = 0; i < (m_nXORGates + m_nANDGates); i++) {
		// encrypt 1st blinding value for gate i
		k->set_rnd(field_size);
		m_vEncBlindingValues[4 * i] = m_cPKCrypto->get_fe();
		m_nECCGeneratorBrick->pow(m_vEncBlindingValues[4 * i], k); // K = kP = k * P

		m_nECCPubkeyBrick->pow(kaP, k); // kaP = k * aP
		m_vEncBlindingValues[4 * i + 1] = m_cPKCrypto->get_fe();
		m_vEncBlindingValues[4 * i + 1]->set_mul(kaP, m_vBlindingValues[2 * i]); // C = kaP + M

		// encrypt 2nd blinding value for gate i
		k->set_rnd(field_size);
		m_vEncBlindingValues[4 * i + 2] = m_cPKCrypto->get_fe();
		m_nECCGeneratorBrick->pow(m_vEncBlindingValues[4 * i + 2], k); // K = kP = k * P

		m_nECCPubkeyBrick->pow(kaP, k); // kaP = k * aP
		m_vEncBlindingValues[4 * i + 3] = m_cPKCrypto->get_fe();
		m_vEncBlindingValues[4 * i + 3]->set_mul(kaP, m_vBlindingValues[2 * i + 1]); // C = kaP + M
	}
	delete kaP;
	delete k;
#endif // KM11_CRYPTOSYSTEM
}

void YaoClientSharing::CreateEncGarbledGates(ABYSetup* setup) {
	uint32_t maxdepth = m_cBoolCircuit->GetMaxDepth();
	if (maxdepth == 0) {
		std::cout << "maxdepth == 0" << std::endl;
		return;
	}

	GATE *gate;
	uint32_t idleft, idright;
	uint32_t maxgateid = m_nANDGates + m_nXORGates + m_nInputGates;
	BYTE* encGGptr = m_bEncGG;

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
#ifdef DEBUGYAOCLIENT
	struct timespec start, end; uint64_t delta;
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

	seal::Evaluator bfvWirekeyEvaluator(m_nWirekeySEALcontext);
	seal::Plaintext b_plain;
	seal::Ciphertext encGG = seal::Ciphertext();
	seal::Ciphertext s_enc = seal::Ciphertext();
	seal::Ciphertext b_enc = seal::Ciphertext();
	encGG.resize(m_nWirekeySEALcontext, 2);
	s_enc.resize(m_nWirekeySEALcontext, 2);
	b_enc.resize(m_nWirekeySEALcontext, 2);

	seal::Plaintext shift;
	uint32_t shift_bits; // shift by shift_bits bits

#ifdef DEBUGYAOCLIENT
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "[time] initialisations: " << delta << " microseconds." << std::endl;
#endif

	//uint32_t numGates = m_cBoolCircuit->GetNumGates();
	assert((m_nANDGates + m_nXORGates) % 8 == 0);
	uint32_t ciphertextsProduced = 0;
	uint32_t ciphertextsSent = 0;
	const uint32_t ciphertextSendThreshold = 1;

	seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool();

	for (size_t gateid = m_nInputGates; gateid < maxgateid; gateid++) {
		gate = &(m_vGates[gateid]);
		idleft = gate->ingates.inputs.twin.left;
		idright = gate->ingates.inputs.twin.right;

		assert(gate->nvals == 1); // KM11 sharing is only implemented for gate->nvals == 1

		// get the (encrypted) wirekeys from the two input wires of this gate (idleft,
		// idright) and blind them using the blinding values for the current gate (ai, bi)
		// in order to form the encrypted garbled gate (encGG) (not to be confused
		// with the encryted garbled table sent by the server later in the protocol)

		// sj0 / sj1 represent the left gate, sk0 / sk1 represent the right gate
#ifdef DEBUGYAOCLIENT
		std::cout << "idleft: " << idleft << ", idright: " << idright << '\n';
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

		// import sj0_enc
		if (gateid % 8 == 0) {
			importCiphertextFromBuf(&encGG, m_bEncWireKeys + idleft * m_nBFVciphertextBufLen);
			shift_bits = 128;
		} else {
			importCiphertextFromBuf(&s_enc, m_bEncWireKeys + idleft * m_nBFVciphertextBufLen);
			// combine the two wire keys into one ciphertext for the encrypted garbled gate
			// multiply by 2**shift_bits (equivalent to bit shift by shift_bits bit)
			shift.resize(shift_bits + 1);
			shift.set_zero();
			shift[shift_bits] = 1;
			bfvWirekeyEvaluator.multiply_plain_inplace(s_enc, shift);
			shift_bits += 128;

			// add sj0 to encGG
			bfvWirekeyEvaluator.add_inplace(encGG, s_enc);
		}

#ifdef DEBUGYAOCLIENT
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "[time] 2x import " << delta << " microseconds." << std::endl;
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

#ifdef DEBUGYAOCLIENT
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "[time] 1x multiply_plain_inplace " << delta << " microseconds." << std::endl;
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

		// import sk0_enc
		importCiphertextFromBuf(&s_enc, m_bEncWireKeys + idright * m_nBFVciphertextBufLen);

		// combine the two wire keys into one ciphertext for the encrypted garbled gate
		// multiply by 2**shift_bits (equivalent to bit shift by shift_bits bit)
		shift.resize(shift_bits + 1);
		shift.set_zero();
		shift[shift_bits] = 1;
		bfvWirekeyEvaluator.multiply_plain_inplace(s_enc, shift);
		shift_bits += 128;

		// add sj0 to encGG
		bfvWirekeyEvaluator.add_inplace(encGG, s_enc);

#ifdef DEBUGYAOCLIENT
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "[time] 2x add_inplace " << delta << " microseconds." << std::endl;
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

		if (gateid % 8 == 7) {
			// homomorphic addition of the blinding values
			bfvWirekeyEvaluator.add_inplace(encGG, m_vEncBlindingValues[(gateid-m_nInputGates-7)/8]);

			seal::parms_id_type parms_id = encGG.parms_id();
			std::shared_ptr<const seal::SEALContext::ContextData> context_data_ = m_nWirekeySEALcontext->get_context_data(parms_id);
			add_extra_noise(encGG, context_data_, 4, pool); // after this step, the invariant noise budget
			// 																							// should be sigma (=40) bits less than it was before
			// bfvWirekeyEvaluator.mod_switch_to_next_inplace(encGG);

#ifdef DEBUGYAOCLIENT
			clock_gettime(CLOCK_MONOTONIC_RAW, &end);
			delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
			std::cout << "[time] 1x add_plain_inplace (blinding values): " << delta << " microseconds." << std::endl;
			clock_gettime(CLOCK_MONOTONIC_RAW, &start);
#endif

			// write the ciphertext containing 8 encrypted garbled gates to the m_bEncGG buffer
			exportCiphertextToBuf(encGGptr, &encGG);
			ciphertextsProduced++;

#ifdef KM11_PIPELINING
			setup->AddSendTask(encGGptr, m_nBFVciphertextBufLen);
#endif
			encGGptr += m_nBFVciphertextBufLen;
		}

#ifdef DEBUGYAOCLIENT
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		delta = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		std::cout << "[time] 2x export " << delta << " microseconds." << std::endl;
#endif
	}
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifdef KM11_IMPROVED
		mpz_t sj0_enc, sk0_enc; // the encrypted wirekeypairs
		mpz_inits(sj0_enc, sk0_enc, NULL);
		mpz_t encGG_j0, encGG_k0;
		mpz_inits(encGG_j0, encGG_k0, NULL);
#else
		mpz_t sj0_enc, sj1_enc, sk0_enc, sk1_enc; // the encrypted wirekeypairs
		mpz_inits(sj0_enc, sj1_enc, sk0_enc, sk1_enc, NULL);
		mpz_t aj, ak; // a_i, a_i' from KM11
		mpz_inits(aj, ak, NULL);
		mpz_t aj_times_sj0_enc, aj_times_sj1_enc, ak_times_sk0_enc, ak_times_sk1_enc, encGG_j0, encGG_j1, encGG_k0, encGG_k1;
		mpz_inits(aj_times_sj0_enc, aj_times_sj1_enc, ak_times_sk0_enc, ak_times_sk1_enc, encGG_j0, encGG_j1, encGG_k0, encGG_k1, NULL);
#endif
		mpz_t bj_enc, bk_enc; // Enc(b_i), Enc(b_i') from KM11
		mpz_inits(bj_enc, bk_enc, NULL);

#ifndef KM11_PRECOMPUTEB
		mpz_t bj, bk; // b_i, b_i' from KM11
		mpz_inits(bj, bk, NULL);
#endif

	for (size_t gateid = m_nInputGates; gateid < maxgateid; gateid++) {
		gate = &(m_vGates[gateid]);
		idleft = gate->ingates.inputs.twin.left;
		idright = gate->ingates.inputs.twin.right;
		assert(gate->nvals == 1); // KM11 sharing is only implemented for gate->nvals == 1

		struct timespec start, end;
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		// get the (encrypted) wirekeys from the two input wires of this gate (idleft,
		// idright) and blind them using the blinding values for the current gate (ai, bi)
		// in order to form the encrypted garbled gate (encGG) (not to be confused
		// with the encryted garbled table sent by the server later in the protocol)

		// sj0 / sj1 represent the left gate, sk0 / sk1 represent the right gate
#ifdef DEBUGYAOCLIENT
		std::cout << "idleft: " << idleft << ", idright: " << idright << '\n';
#endif

#ifdef KM11_IMPROVED
		// import sj0_enc, sk0_enc
		mpz_import(sj0_enc, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + idleft * m_nCiphertextSize);
		mpz_import(sk0_enc, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + idright * m_nCiphertextSize);
#else
		// import sj0_enc, sj1_enc, sk0_enc, sk1_enc
		mpz_import(sj0_enc, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + (2 * idleft + 0) * m_nCiphertextSize);
		mpz_import(sj1_enc, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + (2 * idleft + 1) * m_nCiphertextSize);
		mpz_import(sk0_enc, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + (2 * idright + 0) * m_nCiphertextSize);
		mpz_import(sk1_enc, 1, -1, m_nCiphertextSize, -1, 0, m_bEncWireKeys + (2 * idright + 1) * m_nCiphertextSize);

		// import aj, ak
		mpz_import(aj, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.a1);
		mpz_import(ak, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.a2);
#endif

#ifdef KM11_PRECOMPUTEB
		// directly import bj_enc, bk_enc
		mpz_import(bj_enc, 1, -1, m_nCiphertextSize, -1, 0, gate->gs.yinput.b1_enc);
		mpz_import(bk_enc, 1, -1, m_nCiphertextSize, -1, 0, gate->gs.yinput.b2_enc);
#else // KM11_PRECOMPUTEB
		// import bj, bk and encrypt them
		mpz_import(bj, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.b1);
		mpz_import(bk, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.b2);
		djn_encrypt_fb(bj_enc, m_nDJNPubkey, bj);
		djn_encrypt_fb(bk_enc, m_nDJNPubkey, bk);
#endif // KM11_PRECOMPUTEB

#ifdef KM11_IMPROVED
		// homomorphic addition (Dec(Enc(s) * Enc(b)) == s + b)
		mpz_mul(encGG_j0, sj0_enc, bj_enc);
		mpz_mul(encGG_k0, sk0_enc, bk_enc);
		mpz_mod(encGG_j0, encGG_j0, m_nDJNPubkey->n_squared);
		mpz_mod(encGG_k0, encGG_k0, m_nDJNPubkey->n_squared);

		size_t count0, count2;
		mpz_export(encGGptr + 0 * m_nCiphertextSize, &count0, -1, m_nCiphertextSize, -1, 0, encGG_j0);
		mpz_export(encGGptr + 1 * m_nCiphertextSize, &count2, -1, m_nCiphertextSize, -1, 0, encGG_k0);
		assert(count0 == 1 && count2 == 1);
		encGGptr += 2 * m_nCiphertextSize;
#else
		// homomorphic multiplication: Dec(Enc(s) ^ a) == s * a
		mpz_powm(aj_times_sj0_enc, sj0_enc, aj, m_nDJNPubkey->n_squared);
		mpz_powm(aj_times_sj1_enc, sj1_enc, aj, m_nDJNPubkey->n_squared);
		mpz_powm(ak_times_sk0_enc, sk0_enc, ak, m_nDJNPubkey->n_squared);
		mpz_powm(ak_times_sk1_enc, sk1_enc, ak, m_nDJNPubkey->n_squared);

		// homomorphic addition (Dec(Enc(s) * Enc(b)) == s + b)
		mpz_mul(encGG_j0, aj_times_sj0_enc, bj_enc);
		mpz_mul(encGG_j1, aj_times_sj1_enc, bj_enc);
		mpz_mul(encGG_k0, ak_times_sk0_enc, bk_enc);
		mpz_mul(encGG_k1, ak_times_sk1_enc, bk_enc);
		mpz_mod(encGG_j0, encGG_j0, m_nDJNPubkey->n_squared);
		mpz_mod(encGG_j1, encGG_j1, m_nDJNPubkey->n_squared);
		mpz_mod(encGG_k0, encGG_k0, m_nDJNPubkey->n_squared);
		mpz_mod(encGG_k1, encGG_k1, m_nDJNPubkey->n_squared);

		size_t count0, count1, count2, count3;
		mpz_export(encGGptr + 0 * m_nCiphertextSize, &count0, -1, m_nCiphertextSize, -1, 0, encGG_j0);
		mpz_export(encGGptr + 1 * m_nCiphertextSize, &count1, -1, m_nCiphertextSize, -1, 0, encGG_j1);
		mpz_export(encGGptr + 2 * m_nCiphertextSize, &count2, -1, m_nCiphertextSize, -1, 0, encGG_k0);
		mpz_export(encGGptr + 3 * m_nCiphertextSize, &count3, -1, m_nCiphertextSize, -1, 0, encGG_k1);
		assert(count0 == 1 && count1 == 1 && count2 == 1 && count3 == 1);
		encGGptr += 4 * m_nCiphertextSize;
#endif // KM11_IMPROVED
	}

#ifndef KM11_PRECOMPUTEB
	mpz_clears(bj, bk, NULL);
#endif
#ifdef KM11_IMPROVED
	mpz_clears(sj0_enc, sk0_enc,
						 bj_enc, bk_enc,
						 encGG_j0, encGG_k0,
						 NULL);
#else
	mpz_clears(sj0_enc, sj1_enc, sk0_enc, sk1_enc,
						 aj, bj_enc, ak, bk_enc,
						 aj_times_sj0_enc, aj_times_sj1_enc, ak_times_sk0_enc, ak_times_sk1_enc,
						 encGG_j0, encGG_j1, encGG_k0, encGG_k1, NULL);
#endif

#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	fe* s_enc = m_cPKCrypto->get_fe();

	for (size_t gateid = m_nInputGates; gateid < maxgateid; gateid++) {
		gate = &(m_vGates[gateid]);
		idleft = gate->ingates.inputs.twin.left;
		idright = gate->ingates.inputs.twin.right;
		assert(gate->nvals == 1); // KM11 sharing is only implemented for gate->nvals == 1

		// blind the 1st component of ciphertext for the left wire key
		s_enc->import_from_bytes(m_bEncWireKeys + (2 * idleft) * m_nCiphertextSize);
		s_enc->set_mul(s_enc, m_vEncBlindingValues[4 * (gateid - m_nInputGates)]);
		s_enc->export_to_bytes(encGGptr);

		// blind the 2nd component of ciphertext for the left wire key
		s_enc->import_from_bytes(m_bEncWireKeys + (2 * idleft + 1) * m_nCiphertextSize);
		s_enc->set_mul(s_enc, m_vEncBlindingValues[4 * (gateid - m_nInputGates) + 1]);
		s_enc->export_to_bytes(encGGptr + m_nCiphertextSize);

		// blind the 1st component of ciphertext for the right wire key
		s_enc->import_from_bytes(m_bEncWireKeys + (2 * idright) * m_nCiphertextSize);
		s_enc->set_mul(s_enc, m_vEncBlindingValues[4 * (gateid - m_nInputGates) + 2]);
		s_enc->export_to_bytes(encGGptr + 2 * m_nCiphertextSize);

		// blind the 2nd component of ciphertext for the right wire key
		s_enc->import_from_bytes(m_bEncWireKeys + (2 * idright + 1) * m_nCiphertextSize);
		s_enc->set_mul(s_enc, m_vEncBlindingValues[4 * (gateid - m_nInputGates) + 3]);
		s_enc->export_to_bytes(encGGptr + 3 * m_nCiphertextSize);

#ifdef KM11_PIPELINING
		setup->AddSendTask(encGGptr, 4 * m_nCiphertextSize);
#endif
		encGGptr += 4 * m_nCiphertextSize;
	}
#endif // KM11_CRYPTOSYSTEM
}

void YaoClientSharing::EvaluateKM11Gate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	InstantiateGate(gate);
	assert(gate->nvals == 1); // KM11 sharing is only implemented for gate->nvals == 1

	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;

	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	uint8_t* lkey = gleft->gs.yval;
	uint8_t* rkey = gright->gs.yval;
	uint8_t* outKey = gate->gs.yval;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	uint8_t* table = m_vGarbledCircuit.GetArr() + (m_nSecParamBytes + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE * m_nGarbledTableCtr;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	uint8_t* table = m_vGarbledCircuit.GetArr() + (m_nCiphertextSize + m_nSymEncPaddingBytes) * KEYS_PER_GATE_IN_TABLE * m_nGarbledTableCtr;
#endif

	assert(lkey != NULL);
	assert(rkey != NULL);

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	memcpy(m_bTmpGTKey, gleft->gs.yval, m_nWireKeyBytes);
	memcpy(m_bTmpGTKey + m_nWireKeyBytes, gright->gs.yval, m_nWireKeyBytes);

	// Li = sj + bi
	m_pKeyOps->XOR(m_bTmpGTKey, m_bTmpGTKey,
								 m_bBlindingValues + (2 * (gateid - m_nInputGates)) * m_nWireKeyBytes);
	// Ri = sk + bi'
	m_pKeyOps->XOR(m_bTmpGTKey + m_nWireKeyBytes, m_bTmpGTKey + m_nWireKeyBytes,
								 m_bBlindingValues + (2 * (gateid - m_nInputGates) + 1) * m_nWireKeyBytes);

#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
#ifndef KM11_IMPROVED
	mpz_t aj, ak;
	mpz_inits(aj, ak, NULL);
	mpz_import(aj, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.a1);
	mpz_import(ak, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.a2);
#endif
	mpz_t sj, sk, bj, bk, Li, Ri;
	mpz_inits(sj, sk, bj, bk, Li, Ri, NULL);
	mpz_import(sj, 1, -1, m_nWireKeyBytes, -1, 0, gleft->gs.yval);
	mpz_import(sk, 1, -1, m_nWireKeyBytes, -1, 0, gright->gs.yval);
	mpz_import(bj, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.b1);
	mpz_import(bk, 1, -1, m_nWireKeyBytes, -1, 0, gate->gs.yinput.b2);

#ifdef DEBUGYAOCLIENT
	std::cout << "idleft: " << idleft << " - idright: " << idright << '\n';
	gmp_printf("sj: %Zx\t%Zd\n", sj, sj);
	gmp_printf("sk: %Zx\t%Zd\n", sk, sk);
#endif

#ifdef KM11_IMPROVED
	// Li = sj + bj
	mpz_add(Li, sj, bj);
	mpz_mod(Li, Li, m_zWireKeyMaxValue);

	// Ri = sk + bk
	mpz_add(Ri, sk, bk);
	mpz_mod(Ri, Ri, m_zWireKeyMaxValue);
#else
	// Li = aj * sj + bj
	mpz_mul(Li, aj, sj);
	mpz_add(Li, Li, bj);
	mpz_mod(Li, Li, m_zWireKeyMaxValue);

	// Ri = ak * sk + bk
	mpz_mul(Ri, ak, sk);
	mpz_add(Ri, Ri, bk);
	mpz_mod(Ri, Ri, m_zWireKeyMaxValue);

	mpz_clears(aj, ak, NULL);
#endif
	size_t count;
	mpz_export(m_bTmpGTKey, &count, -1, m_nWireKeyBytes, -1, 0, Li);
	assert(count == 1);
	mpz_export(m_bTmpGTKey + m_nWireKeyBytes, &count, -1, m_nWireKeyBytes, -1, 0, Ri);
	assert(count == 1);

#ifdef DEBUGYAOCLIENT
	gmp_printf("Li: %Zx\t%Zd\n", Li, Li);
	gmp_printf("Ri: %Zx\t%Zd\n", Ri, Ri);
#endif
	mpz_clears(sj, sk, bj, bk, Li, Ri, NULL);

#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	fe* sj = m_cPKCrypto->get_fe();
	fe* sk = m_cPKCrypto->get_fe();
	sj->import_from_bytes(gleft->gs.yval);
	sk->import_from_bytes(gright->gs.yval);
	sj->set_mul(sj, m_vBlindingValues[2 * (gateid - m_nInputGates)]);
	sk->set_mul(sk, m_vBlindingValues[2 * (gateid - m_nInputGates) + 1]);
	sj->export_to_bytes(m_bTmpGTKey);
	sk->export_to_bytes(m_bTmpGTKey + m_nCiphertextSize);
#endif // KM11_CRYPTOSYSTEM

	bool valid;
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN || KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	uint32_t const GTEntrySize = m_nWireKeyBytes;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	uint32_t const GTEntrySize = m_nCiphertextSize;
#endif
	for(int i = 0; i < 4; i++) {
		valid = sDec(m_bTmpGTEntry, table + i * (GTEntrySize + m_nSymEncPaddingBytes), GTEntrySize + m_nSymEncPaddingBytes, m_bTmpGTKey, 2 * GTEntrySize);

		// check if m_bTmpGTEntry is a valid decryption
		if(valid == 1) {
			memcpy(outKey, m_bTmpGTEntry, GTEntrySize);
			break;
		}

		if (i == 3) {
			std::cout << "Could not decrypt garbled table for gate " << gateid << '\n';
			exit(1);
		}
	}

	m_nGarbledTableCtr++;

	UsedGate(idleft);
	UsedGate(idright);
}
#endif // KM11_GARBLING

void YaoClientSharing::EvaluateXORGate(GATE* gate) {
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;

	InstantiateGate(gate);
	//TODO: optimize for uint64_t pointers, there might be some problems here, code is untested
	/*for(uint32_t i = 0; i < m_nSecParamBytes * nvals; i++) {
	 gate->gs.yval[i] = m_vGates[idleft].gs.yval[i] ^ m_vGates[idright].gs.yval[i];
	 }*/
	//std::cout << "doing " << m_nSecParamIters << "iters on " << nvals << " vals " << std::endl;
	for (uint32_t i = 0; i < m_nSecParamIters * nvals; i++) {
		((UGATE_T*) gate->gs.yval)[i] = ((UGATE_T*) m_vGates[idleft].gs.yval)[i] ^ ((UGATE_T*) m_vGates[idright].gs.yval)[i];
	}
	//std::cout << "Keyval (" << 0 << ")= " << (gate->gs.yval[m_nSecParamBytes-1] & 0x01)  << std::endl;
	//std::cout << (gate->gs.yval[m_nSecParamBytes-1] & 0x01);
#ifdef DEBUGYAOCLIENT
	PrintKey(gate->gs.yval);
	std::cout << " = ";
	PrintKey(m_vGates[idleft].gs.yval);
	std::cout << " (" << idleft << ") ^ ";
	PrintKey(m_vGates[idright].gs.yval);
	std::cout << " (" << idright << ")" << std::endl;
#endif

	UsedGate(idleft);
	UsedGate(idright);
}

void YaoClientSharing::EvaluateANDGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;
	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	//evaluate garbled table
	InstantiateGate(gate);
	for (uint32_t g = 0; g < gate->nvals; g++) {
		EvaluateGarbledTable(gate, g, gleft, gright);
		m_nGarbledTableCtr++;

		//Pipelined receive - TODO: outsource in own thread
		/*if(andctr >= GARBLED_TABLE_WINDOW) {
		 gtsize = std::min(remandgates, GARBLED_TABLE_WINDOW);
		 sock.Receive(m_vGarbledTables.GetArr(), gtsize * KEYS_PER_GATE_IN_TABLE * BYTES_SSP);
		 remandgates -= gtsize;
		 andctr=0;
		 }*/

	}
	UsedGate(idleft);
	UsedGate(idright);
}

BOOL YaoClientSharing::EvaluateGarbledTable(GATE* gate, uint32_t pos, GATE* gleft, GATE* gright)
{

	uint8_t *lkey, *rkey, *okey, *gtptr;
	uint8_t lpbit, rpbit;

	okey = gate->gs.yval + pos * m_nSecParamBytes;
	lkey = gleft->gs.yval + pos * m_nSecParamBytes;
	rkey = gright->gs.yval + pos * m_nSecParamBytes;
	gtptr = m_vGarbledCircuit.GetArr() + m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE * m_nGarbledTableCtr;

	lpbit = lkey[m_nSecParamBytes-1] & 0x01;
	rpbit = rkey[m_nSecParamBytes-1] & 0x01;

	assert(lpbit < 2 && rpbit < 2);

	EncryptWire(m_vTmpEncBuf[0], lkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr);
	EncryptWire(m_vTmpEncBuf[1], rkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr+1);

	m_pKeyOps->XOR(okey, m_vTmpEncBuf[0], m_vTmpEncBuf[1]);//gc_xor(okey, encbuf[0], encbuf[1]);

	if(lpbit) {
		m_pKeyOps->XOR(okey, okey, gtptr);//gc_xor(okey, okey, gtptr);
	}
	if(rpbit) {
		m_pKeyOps->XOR(okey, okey, gtptr+m_nSecParamBytes);//gc_xor(okey, okey, gtptr+BYTES_SSP);
		m_pKeyOps->XOR(okey, okey, lkey);//gc_xor(okey, okey, gtptr+BYTES_SSP);
	}

#ifdef DEBUGYAOCLIENT
		std::cout << " using: ";
		PrintKey(lkey);
		std::cout << " (" << (uint32_t) lpbit << ") and : ";
		PrintKey(rkey);
		std::cout << " (" << (uint32_t) rpbit << ") to : ";
		PrintKey(okey);
		std::cout << " (" << (uint32_t) (okey[m_nSecParamBytes-1] & 0x01) << ")" << std::endl;
		std::cout << "A: ";
		PrintKey(m_vTmpEncBuf[0]);
		std::cout << "; B: ";
		PrintKey(m_vTmpEncBuf[1]);
		std::cout << std::endl;
		std::cout << "Table A: ";
		PrintKey(gtptr);
		std::cout << "; Table B: ";
		PrintKey(gtptr+m_nSecParamBytes);
		std::cout << std::endl;
#endif

	return true;
}

void YaoClientSharing::EvaluateUNIVGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;
	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	//evaluate univeral gate table
	InstantiateGate(gate);
	for (uint32_t g = 0; g < gate->nvals; g++) {
		EvaluateUniversalGate(gate, g, gleft, gright);
		m_nUniversalGateTableCtr++;
	}
	UsedGate(idleft);
	UsedGate(idright);
}


BOOL YaoClientSharing::EvaluateUniversalGate(GATE* gate, uint32_t pos, GATE* gleft, GATE* gright)
{
	BYTE *lkey, *rkey, *okey;
	uint32_t id;
	lkey = gleft->gs.yval + pos * m_nSecParamBytes;
	rkey = gright->gs.yval + pos * m_nSecParamBytes;
	okey = gate->gs.yval + pos * m_nSecParamBytes;

	id = (lkey[m_nSecParamBytes-1] & 0x01)<<1;
	id += (rkey[m_nSecParamBytes-1] & 0x01);

	//encrypt_wire((BYTE*)gate->gs.val, m_vGarbledTables.GetArr() + BYTES_SSP * (4 * andctr + id), pleft, pright, id, m_kGarble, key_buf);
	if(id == 0) {
		EncryptWireGRR3(okey, m_bZeroBuf, lkey, rkey, id);
#ifdef DEBUGYAOCLIENT
		std::cout << " decrypted : ";
		PrintKey(m_bZeroBuf);
#endif
	} else {
#ifdef DEBUGYAOCLIENT
		std::cout << " decrypted : ";
		PrintKey(m_vUniversalGateTable.GetArr() + m_nSecParamBytes * (KEYS_PER_UNIV_GATE_IN_TABLE * m_nUniversalGateTableCtr + id-1));
#endif
		EncryptWireGRR3(okey, m_vUniversalGateTable.GetArr() + m_nSecParamBytes * (KEYS_PER_UNIV_GATE_IN_TABLE * m_nUniversalGateTableCtr + id-1), lkey, rkey, id);
	}

#ifdef DEBUGYAOCLIENT
		std::cout << " using: ";
		PrintKey(lkey);
		std::cout << " and : ";
		PrintKey(rkey);
		std::cout << " to : ";
		PrintKey(okey);
		std::cout << std::endl;
#endif

	return true;
}

/* Evaluate the gate and use the servers output permutation bits to compute the output */
void YaoClientSharing::EvaluateClientOutputGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t parentid = gate->ingates.inputs.parent; //gate->gs.oshare.parentgate;
	InstantiateGate(gate);

#ifdef KM11_GARBLING
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	uint32_t keySize = m_nCiphertextSize;
#else
	uint32_t keySize = m_nWireKeyBytes;
#endif
	if(memcmp(m_vGates[parentid].gs.yinput.outKey, m_bOutputWireKeys + m_nOutputWireKeysCtr * keySize, keySize) == 0) {
		*gate->gs.val = 0;
	} else if(memcmp(m_vGates[parentid].gs.yinput.outKey, m_bOutputWireKeys + (m_nOutputWireKeysCtr + 1) * keySize, keySize) == 0) {
		*gate->gs.val = 1;
	} else {
		std::cout << "\n\n\nOUTKEY IS INVALID!" << '\n';
		exit(1);
	}
	m_nOutputWireKeysCtr += 2;
#else
#ifdef DEBUGYAOCLIENT
	uint32_t in;
	std::cout << "ClientOutput: ";
#endif
	for (uint32_t i = 0; i < gate->nvals; i++) {
#ifdef DEBUGYAOCLIENT
		in = (m_vGates[parentid].gs.yval[(i + 1) * m_nSecParamBytes - 1] & 0x01);
#endif
		gate->gs.val[i / GATE_T_BITS] ^= ((((UGATE_T) m_vGates[parentid].gs.yval[(i + 1) * m_nSecParamBytes - 1] & 0x01)
				^ ((UGATE_T) m_vOutputShareRcvBuf.GetBit(m_nClientOUTBitCtr))) << (i % GATE_T_BITS));
#ifdef DEBUGYAOCLIENT
		std::cout << (uint32_t) gate->gs.val[i/GATE_T_BITS] << " = " << in << " ^ " << (uint32_t) m_vOutputShareRcvBuf.GetBit(m_nClientOUTBitCtr) << std::endl;
#endif
		m_nClientOUTBitCtr++;
	}
#endif

	UsedGate(parentid);
}

/* Copy the output shares for the server and send them later on */
void YaoClientSharing::EvaluateServerOutputGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;	//gate->gs.oshare.parentgate;

	for (uint32_t i = 0; i < gate->nvals; i++, m_nServerOutputShareCtr++) {
		m_vOutputShareSndBuf.SetBit(m_nServerOutputShareCtr, m_vGates[parentid].gs.yval[((i + 1) * m_nSecParamBytes) - 1] & 0x01);
#ifdef DEBUGYAOCLIENT
		std::cout << "Setting ServerOutputShare to " << ((uint32_t) m_vGates[parentid].gs.yval[((i+1)*m_nSecParamBytes) - 1] & 0x01) << std::endl;
#endif
	}

	//TODO: is the gate is an output gate for both parties, uncommenting this will crash the program. FIX!
	//UsedGate(parentid);
}

/* Store the input bits of my gates to send the correlation with the R-OTs later on */
void YaoClientSharing::ReceiveClientKeys(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	UGATE_T* input = gate->gs.ishare.inval;
	m_vROTSndBuf.SetBits((BYTE*) input, (int) m_nClientSndOTCtr, gate->nvals);
	m_nClientSndOTCtr += gate->nvals;
	m_vClientSendCorrectionGates.push_back(gateid);
}

/* Add the servers input keys to the queue to receive them later on */
void YaoClientSharing::ReceiveServerKeys(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);

	m_vServerInputGates.push_back(gateid);
	m_nServerInBitCtr += gate->nvals;
}

void YaoClientSharing::EvaluateConversionGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	GATE* parent = &(m_vGates[gate->ingates.inputs.parents[0]]);
	assert(parent->instantiated);
	UGATE_T* val = parent->gs.val;

	if (parent->context == S_ARITH && (gate->gs.pos & 0x01) == 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "Server conversion gate with pos = " << gate->gs.pos << std::endl;
#endif
		m_vServerInputGates.push_back(gateid);
		m_nServerInBitCtr += gate->nvals;
	} else {
#ifdef DEBUGYAOCLIENT
		std::cout << "Client conversion gate with pos = " << gate->gs.pos << std::endl;
#endif
		if (parent->context == S_ARITH) {
			uint64_t id;
			uint8_t *tval;
			tval = (uint8_t*) calloc(ceil_divide(parent->nvals, 8), sizeof(uint8_t));
			id = gate->gs.pos >> 1;
			for(uint32_t i = 0; i < parent->nvals; i++) {
				tval[i/8] |= ((val[(id+i*parent->sharebitlen) / GATE_T_BITS] >>
						((id+i*parent->sharebitlen) % GATE_T_BITS)) & 0x01) << (i%8);
			}
			m_vROTSndBuf.SetBits((BYTE*) tval, (int) m_nClientSndOTCtr, gate->nvals);
			free(tval);
#ifdef DEBUGYAOCLIENT
			std::cout << "value of conversion gate: " << tval << std::endl;
#endif
		} else if (parent->context == S_BOOL){
			m_vROTSndBuf.SetBits((BYTE*) val, (int) m_nClientSndOTCtr, gate->nvals);
#ifdef DEBUGYAOCLIENT
			std::cout << "value of conversion gate: " << val[0] << std::endl;
#endif
		} else if(parent->context == S_YAO || parent->context == S_YAO_REV) {
			for(uint32_t i = 0; i < parent->nvals; i++) {
				m_vROTSndBuf.SetBits(parent->gs.yinput.pi+i, (int) m_nClientSndOTCtr+i, 1);
				//std::cout << "Client conv share = " << (uint32_t) parent->gs.yinput.pi[i] << std::endl;
			}
		}
		else{
			std::cerr << "Error: unkown parent context: " << parent->context << std::endl;
		}
		m_nClientSndOTCtr += gate->nvals;
		m_vClientSendCorrectionGates.push_back(gateid);
	}
}

//TODO bits in ROTMasks are not going to be aligned later on, recheck
void YaoClientSharing::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
	//Send the correlation bits with the random OTs
	if (m_nClientSndOTCtr > 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "want to send client OT-bits which are of size " << m_nClientSndOTCtr << " bits" << std::endl;
#endif
		m_vROTSndBuf.XORBitsPosOffset(m_vChoiceBits.GetArr(), m_nChoiceBitCtr, 0, m_nClientSndOTCtr);
#ifdef DEBUGYAOCLIENT
		std::cout << "Sending corrections: ";
		m_vROTSndBuf.Print(0, m_nClientSndOTCtr);
		std::cout << " = value ^ ";
		m_vChoiceBits.Print(m_nChoiceBitCtr, m_nChoiceBitCtr + m_nClientSndOTCtr);
#endif
		sendbuf.push_back(m_vROTSndBuf.GetArr());
		sndbytes.push_back(ceil_divide(m_nClientSndOTCtr, 8));
		m_nChoiceBitCtr += m_nClientSndOTCtr;
	}

	if (m_nServerOutputShareCtr > 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "want to send server output shares which are of size " << m_nServerOutputShareCtr << " bits" << std::endl;
#endif
		sendbuf.push_back(m_vOutputShareSndBuf.GetArr());
		sndbytes.push_back(ceil_divide(m_nServerOutputShareCtr, 8));
	}

#ifdef DEBUGYAO
	if(m_nInputShareSndSize > 0) {
		std::cout << "Sending " << m_nInputShareSndSize << " Input shares : ";
		m_vInputShareSndBuf.Print(0, m_nInputShareSndSize);
	}
	if(m_nOutputShareSndSize > 0) {
		std::cout << "Sending " << m_nOutputShareSndSize << " Output shares : ";
		m_vOutputShareSndBuf.Print(0, m_nOutputShareSndSize);
	}
#endif
}

/* Register the values that are to be received in this iteration */
void YaoClientSharing::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//Receive servers keys
	if (m_nServerInBitCtr > 0) {
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		m_vServerInputKeys.Create(m_nServerInBitCtr * m_nCiphertextSize * 8);
		rcvbuf.push_back(m_vServerInputKeys.GetArr());
		rcvbytes.push_back(m_nServerInBitCtr * m_nCiphertextSize);
#else
#ifdef DEBUGYAOCLIENT
		std::cout << "want to receive servers input keys which are of size " << (m_nServerInBitCtr * m_nSecParamBytes) << " bytes" << std::endl;
#endif
		m_vServerInputKeys.Create(m_nServerInBitCtr * m_cCrypto->get_seclvl().symbits);
		rcvbuf.push_back(m_vServerInputKeys.GetArr());
		rcvbytes.push_back(m_nServerInBitCtr * m_nSecParamBytes);
#endif
	}

	if (m_nClientRcvKeyCtr > 0) {
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		m_vClientKeyRcvBuf[0].Create(m_nClientRcvKeyCtr * m_nCiphertextSize * 8);
		rcvbuf.push_back(m_vClientKeyRcvBuf[0].GetArr());
		rcvbytes.push_back(m_nClientRcvKeyCtr * m_nCiphertextSize);

		m_vClientKeyRcvBuf[1].Create(m_nClientRcvKeyCtr * m_nCiphertextSize * 8);
		rcvbuf.push_back(m_vClientKeyRcvBuf[1].GetArr());
		rcvbytes.push_back(m_nClientRcvKeyCtr * m_nCiphertextSize);
#else
#ifdef DEBUGYAOCLIENT
		std::cout << "want to receive client input keys which are of size 2* " << m_nClientRcvKeyCtr * m_nSecParamBytes << " bytes" << std::endl;
#endif
		m_vClientKeyRcvBuf[0].Create(m_nClientRcvKeyCtr * m_cCrypto->get_seclvl().symbits);
		rcvbuf.push_back(m_vClientKeyRcvBuf[0].GetArr());
		rcvbytes.push_back(m_nClientRcvKeyCtr * m_nSecParamBytes);

		m_vClientKeyRcvBuf[1].Create(m_nClientRcvKeyCtr * m_cCrypto->get_seclvl().symbits);
		rcvbuf.push_back(m_vClientKeyRcvBuf[1].GetArr());
		rcvbytes.push_back(m_nClientRcvKeyCtr * m_nSecParamBytes);
#endif
	}
}

void YaoClientSharing::FinishCircuitLayer() {
	//Assign the servers input keys that were received this round
	if (m_nServerInBitCtr > 0) {
		AssignServerInputKeys();
	}

	//Assign the clients input keys that were received this round
	if (m_nClientRcvKeyCtr > 0) {
		AssignClientInputKeys();
	}

	//Assign the clients input keys to the gates
	if (m_nClientSndOTCtr > 0) {
		m_nClientRcvKeyCtr = m_nClientSndOTCtr;
		m_nClientSndOTCtr = 0;
		//TODO optimize
		for (uint32_t i = 0; i < m_vClientSendCorrectionGates.size(); i++) {
			m_vClientRcvInputKeyGates.push_back(m_vClientSendCorrectionGates[i]);
		}
		m_vClientSendCorrectionGates.clear();
	}

	InitNewLayer();
}
;

/* Assign the received server input keys to the pushed back gates in this round */
void YaoClientSharing::AssignServerInputKeys() {
	GATE* gate;
	for (uint32_t i = 0, offset = 0; i < m_vServerInputGates.size(); i++) {
		gate = &(m_vGates[m_vServerInputGates[i]]);
		InstantiateGate(gate);
		//Assign the keys to the gate
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
		memcpy(gate->gs.yval, m_vServerInputKeys.GetArr() + offset, m_nCiphertextSize * gate->nvals);
		offset += (m_nCiphertextSize * gate->nvals);
#else
		memcpy(gate->gs.yval, m_vServerInputKeys.GetArr() + offset, m_nSecParamBytes * gate->nvals);
		offset += (m_nSecParamBytes * gate->nvals);
#endif
#ifdef DEBUGYAOCLIENT
#ifdef KM11_GARBLING
		assert(gate->nvals == 1);
#endif
		std::cout << "assigned server input key to gate " << m_vServerInputGates[i] << ": ";
		PrintKey(gate->gs.yval);
		std::cout << std::endl;
#endif
	}
	m_vServerInputGates.clear();

	m_nServerInBitCtr = 0;
}

/* Assign the received server input keys to the pushed back gates in this round */
void YaoClientSharing::AssignClientInputKeys() {
	GATE* gate;
	for (uint32_t i = 0, offset = 0; i < m_vClientRcvInputKeyGates.size(); i++) {
		gate = &(m_vGates[m_vClientRcvInputKeyGates[i]]);
		//input = ;

		InstantiateGate(gate);
		//Assign the keys to the gate, TODO XOR with R-OT masks
		for (uint32_t j = 0; j < gate->nvals; j++, m_nKeyInputRcvIdx++, offset++) {
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
			m_pKeyOps->XOR37(gate->gs.yval + j * m_nCiphertextSize,
					m_vClientKeyRcvBuf[m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx)].GetArr() + offset * m_nCiphertextSize,
					m_vROTMasks.GetArr() + m_nKeyInputRcvIdx * m_nCiphertextSize);
#else
			m_pKeyOps->XOR(gate->gs.yval + j * m_nSecParamBytes,
					m_vClientKeyRcvBuf[m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx)].GetArr() + offset * m_nSecParamBytes,
					m_vROTMasks.GetArr() + m_nKeyInputRcvIdx * m_nSecParamBytes);
#ifdef DEBUGYAOCLIENT
			std::cout << "assigned client input key to gate " << m_vClientRcvInputKeyGates[i] << ": ";
			PrintKey(gate->gs.yval);
			std::cout << " (" << (uint32_t) m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx) << ") = ";
			PrintKey( m_vClientKeyRcvBuf[m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx)].GetArr() + offset * m_nSecParamBytes);
			std::cout << " ^ ";
			PrintKey(m_vROTMasks.GetArr() + (m_nKeyInputRcvIdx) * m_nSecParamBytes);
			std::cout << std::endl;
#endif
#endif
		}
		if (gate->type == G_IN) {
			free(gate->gs.ishare.inval);
		} else {
		//if (gate->type == G_CONV) {
			//G_CONV
			free(gate->ingates.inputs.parents);
		}
	}
	m_vClientRcvInputKeyGates.clear();

	m_nClientRcvKeyCtr = 0;
}

void YaoClientSharing::InstantiateGate(GATE* gate) {
	gate->instantiated = true;
#if defined(KM11_GARBLING) && KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	gate->gs.yval = (BYTE*) calloc(m_nCiphertextSize, sizeof(BYTE));
#else
	gate->gs.yval = (BYTE*) calloc(m_nSecParamIters * gate->nvals, sizeof(UGATE_T));
#endif
}

void YaoClientSharing::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	if (gate->type == G_COMBINE) {
		uint32_t* inptr = gate->ingates.inputs.parents; //gate->gs.cinput;
		uint32_t nparents = gate->ingates.ningates;
		uint32_t parent_nvals;

		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < nparents; g++) {
			parent_nvals = m_vGates[inptr[g]].nvals;
			memcpy(keyptr, m_vGates[inptr[g]].gs.yval, m_nSecParamBytes * parent_nvals);
			keyptr += m_nSecParamBytes * parent_nvals;
			UsedGate(inptr[g]);
		}
		free(inptr);
	} else if (gate->type == G_SPLIT) {
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idleft = gate->ingates.inputs.parent; // gate->gs.sinput.input;
		InstantiateGate(gate);
		memcpy(gate->gs.yval, m_vGates[idleft].gs.yval + pos * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		UsedGate(idleft);
	} else if (gate->type == G_REPEAT) {
		uint32_t idleft = gate->ingates.inputs.parent; //gate->gs.rinput;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idleft].gs.yval, m_nSecParamBytes);
		}
		UsedGate(idleft);
	} else if (gate->type == G_COMBINEPOS) {
		uint32_t* combinepos = gate->ingates.inputs.parents; //gate->gs.combinepos.input;
		uint32_t pos = gate->gs.combinepos.pos;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			uint32_t idleft = combinepos[g];
			memcpy(keyptr, m_vGates[idleft].gs.yval + pos * m_nSecParamBytes, m_nSecParamBytes);
			UsedGate(idleft);
		}
		free(combinepos);
#ifdef ZDEBUG
		std::cout << "), size = " << size << ", and val = " << gate->gs.val[0]<< std::endl;
#endif
#ifdef DEBUGCLIENT
		std::cout << ", res: " << ((unsigned uint32_t) gate->gs.yval[BYTES_SSP-1] & 0x01) << " = " << ((unsigned uint32_t) gleft->gs.yval[BYTES_SSP-1] & 0x01) << " and " << ((unsigned uint32_t) gright->gs.yval[BYTES_SSP-1] & 0x01);
#endif
	} else if (gate->type == G_SUBSET) {
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;

		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idparent].gs.yval + positions[g] * m_nSecParamBytes, m_nSecParamBytes);
		}
		UsedGate(idparent);
		if(del_pos)
			free(positions);
	}
}

uint32_t YaoClientSharing::AssignInput(CBitVector& inputvals) {
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

uint32_t YaoClientSharing::GetOutput(CBitVector& out) {
	std::deque<uint32_t> myoutgates = m_cBoolCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits);

	GATE* gate;
	for (uint32_t i = 0, outbitstart = 0, lim; i < myoutgates.size(); i++) {
		gate = &(m_vGates[myoutgates[i]]);
		lim = gate->nvals * gate->sharebitlen;
		std::cout << "outgate no " << i << " : " << myoutgates[i] << " with nvals = " << gate->nvals << " and sharebitlen = " << gate->sharebitlen << std::endl;

		for (uint32_t j = 0; j < lim; j++, outbitstart++) {
			out.SetBitNoMask(outbitstart, (gate->gs.val[j / GATE_T_BITS] >> (j % GATE_T_BITS)) & 0x01);
		}
	}
	return outbits;
}

void YaoClientSharing::Reset() {
	m_vROTMasks.delCBitVector();
	m_nChoiceBitCtr = 0;
	m_vChoiceBits.delCBitVector();

	m_nServerInBitCtr = 0;
	m_nClientSndOTCtr = 0;
	m_nClientRcvKeyCtr = 0;
	m_nClientOutputShareCtr = 0;
	m_nServerOutputShareCtr = 0;

	m_nClientOUTBitCtr = 0;

	m_nKeyInputRcvIdx = 0;

	for (uint32_t i = 0; i < m_vClientKeyRcvBuf.size(); i++)
		m_vClientKeyRcvBuf[i].delCBitVector();

	m_nGarbledCircuitRcvCtr = 0;

	m_vOutputShareRcvBuf.delCBitVector();
	m_vOutputShareSndBuf.delCBitVector();

	m_vClientSendCorrectionGates.clear();
	m_vServerInputGates.clear();
	m_vANDGates.clear();
	m_vOutputShareGates.clear();

	m_vROTSndBuf.delCBitVector();
	m_vROTCtr = 0;

	m_nANDGates = 0;
	m_nXORGates = 0;

	m_nConversionInputBits = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_nClientInputBits = 0;
	m_vClientInputKeys.delCBitVector();

	m_nServerInputBits = 0;
	m_vServerInputKeys.delCBitVector();

	m_vGarbledCircuit.delCBitVector();
	m_nGarbledTableCtr = 0;

	m_vUniversalGateTable.delCBitVector();
	m_nUniversalGateTableCtr = 0;

#ifdef KM11_GARBLING
	m_nOutputWireKeysCtr = 0;
#endif

	m_cBoolCircuit->Reset();
}

void add_poly_coeffs_uniform(uint64_t *poly, uint32_t noise_len,
		std::shared_ptr<seal::UniformRandomGenerator> random,
		std::shared_ptr<const seal::SEALContext::ContextData> &context_data)
{
		auto &parms = context_data->parms();
		auto &coeff_modulus = parms.coeff_modulus();
		size_t coeff_count = parms.poly_modulus_degree();
		size_t coeff_mod_count = coeff_modulus.size();
		uint32_t final_offset = (noise_len) % 32;

		seal::RandomToStandardAdapter engine(random);
		for (size_t i = 0; i < coeff_count; i++)
		{
				uint64_t noise = 0;
				for(int k = 0; k < (noise_len)/32; k++)
						noise = (noise << 32) | engine();
				noise = (noise << final_offset) | (engine() & ((1 << final_offset) - 1));
				for (size_t j = 0; j < coeff_mod_count; j++)
				{
						poly[i + (j * coeff_count)] = noise % coeff_modulus[j].value();
				}
		}
}

void add_extra_noise(seal::Ciphertext &destination, std::shared_ptr<const seal::SEALContext::ContextData> &context_data,
		 uint32_t noise_len, seal::MemoryPoolHandle pool)
{
		//auto &context_data = *(encryptor.context_)->context_data();
		auto &parms = context_data->parms();
		auto &coeff_modulus = parms.coeff_modulus();
		size_t coeff_count = parms.poly_modulus_degree();
		size_t coeff_mod_count = coeff_modulus.size();

		// Generate u
		auto u(seal::util::allocate_poly(coeff_count, coeff_mod_count, pool));
		std::shared_ptr<seal::UniformRandomGenerator> random(parms.random_generator()->create());

		// Generate e_0, add this value into destination[0].
		add_poly_coeffs_uniform(u.get(), noise_len, random, context_data);
		for (size_t i = 0; i < coeff_mod_count; i++)
		{
				seal::util::add_poly_poly_coeffmod(u.get() + (i * coeff_count),
						destination.data() + (i * coeff_count), coeff_count,
						coeff_modulus[i], destination.data() + (i * coeff_count));
		}
		// Generate e_1, add this value into destination[1].
		add_poly_coeffs_uniform(u.get(), noise_len, random, context_data);
		for (size_t i = 0; i < coeff_mod_count; i++)
		{
				seal::util::add_poly_poly_coeffmod(u.get() + (i * coeff_count),
						destination.data(1) + (i * coeff_count), coeff_count,
						coeff_modulus[i], destination.data(1) + (i * coeff_count));
		}
}
