/**
 \file 		yaoserversharing.h
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
 \brief		Yao Server Sharing class.
 */

#ifndef __YAOSERVERSHARING_H__
#define __YAOSERVERSHARING_H__

#include "sharing.h"
#include <algorithm>
#include <deque>
#include <vector>
#include "yaosharing.h"
#include "seal/seal.h"
#include <ENCRYPTO_utils/crypto/djn.h>
#include <ENCRYPTO_utils/crypto/ecc-pk-crypto.h>
#include <ENCRYPTO_utils/crypto/pk-crypto.h>

//#define DEBUGYAOSERVER
/**
 Yao Server Sharing class.
 */
class YaoServerSharing: public YaoSharing {

public:
	/**
	 Constructor of the class.
	 */
	YaoServerSharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt) :
			YaoSharing(context, role, sharebitlen, circuit, crypt) {
		InitServer();
	}
	;
	/**
	 Destructor of the class.
	 */
	~YaoServerSharing();

	//MEMBER FUNCTIONS FROM SUPER CLASS YAO SHARING
	void Reset();
	void PrepareSetupPhase(ABYSetup* setup);
	void PerformSetupPhase(ABYSetup* setup);
	void FinishSetupPhase(ABYSetup* setup);
	void EvaluateLocalOperations(uint32_t level);
	void EvaluateInteractiveOperations(uint32_t level);
	void SendConversionValues(uint32_t gateid);

	void FinishCircuitLayer();

	void PrepareOnlinePhase();

	void InstantiateGate(GATE* gate);

	void GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& bytesize);
	void GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes);

	uint32_t AssignInput(CBitVector& input);
	uint32_t GetOutput(CBitVector& out);

	const char* sharing_type() {
		return "Yao server";
	}
	;
	//ENDS HERE..

private:
	//Global constant key
	CBitVector m_vR; /**< _____________*/
	//Permutation bits for the servers input keys
	CBitVector m_vPermBits; /**< _____________*/
	//Random values from output of ot extension
	std::vector<CBitVector> m_vROTMasks; /**< Masks_______________*/
	uint32_t m_nClientInputKexIdx; /**< Client __________*/
	uint32_t m_nClientInputKeyCtr; /**< Client __________*/

#ifdef KM11_GARBLING
	uint64_t m_nNumberOfKeypairs; /**< the number of gates for which wire keys are generated (KM11 protocol) */
	uint8_t* m_bEncWireKeys; /**< the encrypted wire keys sent to the client (KM11 protocol) */
	uint8_t* m_bEncGG; /**< the encryted garbled gates receibed from the client (KM11 protocol) */
	uint8_t* m_bGTKeys; /**< buffer used while generating the garbled tables */
	uint8_t* m_bTmpGTEntry; /**< buffer used while generating the garbled tables */
	uint8_t* m_bTmpWirekeys; /**< buffer for two wire keys */
	uint32_t m_nEncGGRcvCtr; /**< counter used when receiving the encrypted garbled gates */
	uint8_t* m_nEncGGRcvPtr; /**< pointer used when receiving the encrypted garbled gates */

#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	uint8_t* m_bWireKeys; /**< the unencrypted wire keys created by the server */
	uint8_t* m_bPublickey; /**< the exported DJN/ECC public key */
	djn_pubkey_t *m_nDJNPubkey; /**< the DJN public key */
	djn_prvkey_t *m_nDJNPrvkey; /**< the DJN secret key */
	mpz_t m_zR; /**< mpz representation of the global random shift r (see section "3.2 A More Efficient Variant" of KM11) */
	mpz_t m_zTmpWirekey; /**< temporary mpz value for a wire key */
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_BFV
	uint8_t* m_bWireKeys; /**< the unencrypted wire keys created by the server (KM11 protocol) */
	std::shared_ptr<seal::SEALContext> m_nWirekeySEALcontext;
	seal::PublicKey m_nWirekeySEALpublicKey;
	seal::SecretKey m_nWirekeySEALsecretKey;
	seal::GaloisKeys m_nSEALgaloisKeys;
	seal::Decryptor* m_nSEALdecryptor;
#elif KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_ECC
	std::vector<fe*> m_vWireKeys; /**< the unencrypted wire keys created by the server (KM11 protocol) */
	uint8_t* m_bPublickey; /**< the exported DJN/ECC public key (KM11 protocol) */
	fe* m_nECCPubkey; /**< EC ElGamal public key */
	num* m_nECCPrvkey; /**< EC ElGamal private key */
	brickexp* m_nECCPubkeyBrick; /**< public key brick to speedup scalar multiplications with the public key */
	brickexp* m_nECCGeneratorBrick; /**< generator point brick to speedup scalar mult. with the generator point */
	fe* m_zR; /**< ECC representation of the global random shift r (see section "3.2 A More Efficient Variant" of KM11) */
#endif // KM11_CRYPTOSYSTEM
#endif // KM11_GARBLING

	uint64_t m_nGarbledTableSndCtr; /**< _____________*/

	CBitVector m_vServerKeySndBuf; /**< Server Key Sender Buffer*/
	std::vector<CBitVector> m_vClientKeySndBuf; /**< Client Key Sender Buffer*/
	CBitVector m_vClientROTRcvBuf; /**< Client ______________*/

	//std::vector<CBitVector> m_vClientConversionKeySndBuf;
	//CBitVector			m_vClientCOnversionROTRcvBuf;

	CBitVector m_vOutputShareSndBuf; /**< Output Share Sender Buffer.*/
	CBitVector m_vOutputShareRcvBuf; /**< Output Share Receiver Buffer.*/

	std::vector<GATE*> m_vServerOutputGates; /**< Server Output Gates*/

	uint32_t m_nOutputShareRcvCtr; /**< Output Share Receiver Counter*/

	uint64_t m_nPermBitCtr; /**< _____________*/
	uint64_t m_nServerInBitCtr; /**< _____________*/

	uint32_t m_nServerKeyCtr; /**< _____________*/
	uint32_t m_nClientInBitCtr; /**< _____________*/

	uint8_t* m_bLMaskBuf[2]; /**< _____________*/
	uint8_t* m_bRMaskBuf[2]; /**< _____________*/
	uint8_t* m_bLKeyBuf; /**< _____________*/
	uint8_t* m_bOKeyBuf[2]; /**< _____________*/
	uint8_t* m_bTmpBuf;
	//CBitVector

	std::vector<uint32_t> m_vClientInputGate; /**< _____________*/
	std::deque<input_gate_val_t> m_vPreSetInputGates;/**< _____________*/
	std::deque<a2y_gate_pos_t> m_vPreSetA2YPositions;/**< _____________*/
	e_role* m_vOutputDestionations; /** <  _____________*/
	uint32_t m_nOutputDestionationsCtr;


	//std::deque<uint32_t> 			m_vClientInputGate;

	/**Initialising the server. */
	void InitServer();
	/**Initialising a new layer.*/
	void InitNewLayer();

	/**
	 Creating Random wire keys.
	 \param	vec 		Bit vector.
	 \param 	numkeys		number of keys.
	 */
	void CreateRandomWireKeys(CBitVector& vec, uint32_t numkeys);
#ifdef KM11_GARBLING
	/**
	 Create the encrypted wire keys for each wire that will be sent to the
	 client (KM11)
	**/
	void CreateEncryptedWireKeys();
#if KM11_CRYPTOSYSTEM == KM11_CRYPTOSYSTEM_DJN
	/**
	 Add global random shift r to a wire key buffer (KM11, only used for DJN
	 homomorphic encryption)
	 \param keyout	buffer to which the shifted wire key will be written
	 \param keyin		buffer holding the wire key to be shifted
	**/
	void AddGlobalRandomShift(BYTE* keyout, BYTE* keyin);
#endif
#endif // KM11_GARBLING
	/**
	 Creating and sending Garbled Circuit.
	 \param 	setup 	ABYSetup Object.
	 */
	void CreateAndSendGarbledCircuit(ABYSetup* setup);
	/**
	 Receiving the garbled circuit object.
	 */
	void ReceiveGarbledCircuit();
	/**
	 Method for evaluating a Input gate for the inputted
	 gate id.
	 \param gateid	Gate Identifier
	 */
	void EvaluateInputGate(uint32_t gateid);
#ifdef KM11_GARBLING
	/**
	 Method for evaluating a KM11 gate (all gate types) for the given gateid.
	 Decrypts the received encrypted garbled gate and creates the garbled table
	 for the gate to be sent to the client.
	 \param gate		Gate Identifier
	 \param setup 	ABYSetup Object
	 */
	void EvaluateKM11Gate(uint32_t gateid, ABYSetup* setup);
#endif // KM11_GARBLING
	/**
	 Method for evaluating XOR gate for the inputted
	 gate object.
	 \param gate		Gate Object
	 */
	void EvaluateXORGate(GATE* gate);
	/**
	 Method for evaluating AND gate for the inputted
	 gate object.
	 \param gate		Gate Object
	 */
	void EvaluateANDGate(GATE* gate, ABYSetup* setup);
	/**
	 Method for evaluating a Universal gate for the inputted
	 gate object.
	 \param gate		Gate Object
	 */
	void EvaluateUniversalGate(GATE* gate);
	/**
	 Method for evaluating SIMD gate for the inputted
	 gateid.
	 \param gateid		Gate identifier
	 */
	void EvaluateSIMDGate(uint32_t gateid);
	/**
	 Method for evaluating Inversion gate for the inputted
	 gate object.
	 \param gate		Gate Object
	 */
	void EvaluateInversionGate(GATE* gate);
	/**
	 Method for evaluating conversion gate for the inputted
	 gateid.
	 \param gateid		Gate Identifier
	 */
	void EvaluateConversionGate(uint32_t gateid);
	/**
	 Method for garbling a universal gate.
	 \param ggate	gate Object.
	 \param pos 		Position of the object in the queue.
	 \param gleft	left gate in the queue.
	 \param gright	right gate in the queue.
	 \param ttable	the 4-bit truth table of the form x_0x_1x_2x_3
	 */
	void GarbleUniversalGate(GATE* ggate, uint32_t pos, GATE* gleft, GATE* gright, uint32_t ttable);
	/**
	 Method for creating garbled table.
	 \param ggate	gate Object.
	 \param pos 		Position of the object in the queue.
	 \param gleft	left gate in the queue.
	 \param gright	right gate in the queue.
	 */
	void CreateGarbledTable(GATE* ggate, uint32_t pos, GATE* gleft, GATE* gright);
	/**
	 PrecomputeGC______________
	 \param queue 	Dequeue Object.
	 \param setup	Is needed to perform pipelined sending of the circuit
	 */
	void PrecomputeGC(std::deque<uint32_t>& queue, ABYSetup* setup);

	//void EvaluateClientOutputGate(GATE* gate);
	void CollectClientOutputShares();
	/**
	 Method for evaluating Output gate for the inputted
	 gate object.
	 \param gate		Gate Object
	 */
	void EvaluateOutputGate(GATE* gate);

	/**
	 Send Server Keys from the given gateid.
	 \param	gateid 	Gate Identifier
	 */
	void SendServerInputKey(uint32_t gateid);
	/**
	 Send Client Keys from the given gateid.
	 \param	gateid 	Gate Identifier
	 */
	void SendClientInputKey(uint32_t gateid);
	/**
	 Method for assigning Output shares.
	 */
	void AssignOutputShares();
};

#endif /* __YAOSERVERSHARING_H__ */
