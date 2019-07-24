/**
 \file 		yaoclientsharing.h
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
 \brief		Yao Client Sharing class.
 */
#ifndef __YAOCLIENTSHARING_H__
#define __YAOCLIENTSHARING_H__

#include "sharing.h"
#include <algorithm>
#include "yaosharing.h"

//#define DEBUGYAOCLIENT

/**
 Yao Client Sharing class.
 */
class YaoClientSharing: public YaoSharing {

public:
	/** Constructor of the class.*/
	YaoClientSharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt, const std::string& circdir = ABY_CIRCUIT_DIR) :
			YaoSharing(context, role, sharebitlen, circuit, crypt, circdir) {
		InitClient();
	}
	;
	/** Destructor of the class.*/
	~YaoClientSharing();

	//MEMBER FUNCTIONS FROM SUPER CLASS YAO SHARING
	void Reset();
	void PrepareSetupPhase(ABYSetup* setup);
	void PerformSetupPhase(ABYSetup* setup);
	void FinishSetupPhase(ABYSetup* setup);
	void EvaluateLocalOperations(uint32_t gateid);
	void EvaluateInteractiveOperations(uint32_t gateid);
	void EvaluateConversionGate(uint32_t gateid);

	void FinishCircuitLayer();

	void PrepareOnlinePhase();

	void InstantiateGate(GATE* gate);

	void GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& bytesize);
	void GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes);

	uint32_t AssignInput(CBitVector& input);
	uint32_t GetOutput(CBitVector& out);

	const char* sharing_type() {
		return "Yao client";
	}
	;
	//ENDS HERE..

private:

	CBitVector m_vROTMasks; /**< Masks_______________*/
	uint32_t m_nChoiceBitCtr; /**< Choice bits counter.*/
	CBitVector m_vChoiceBits; /**< random choice bits of the client in the OTs*/
	uint32_t m_nKeyInputRcvIdx; /**< Key Input Receiver Index.*/

	uint64_t m_nServerInBitCtr; /**< Server Input Bit Counter.*/
	uint32_t m_nClientSndOTCtr; /**< Client Send OT Counter*/
	uint32_t m_nClientRcvKeyCtr; /**< Client Receiver Key Counter*/
	uint32_t m_nClientOutputShareCtr;/**< Client Output Share Counter*/
	uint32_t m_nServerOutputShareCtr;/**< Server Output Share Counter*/

	uint64_t m_nClientOUTBitCtr; /**< Client Output Bit Counter.*/

	CBitVector m_vServerKeyRcvBuf; /**< Server Key Receiver Buffer*/
	std::vector<CBitVector> m_vClientKeyRcvBuf; /**< Client Key Receiver Buffer*/

	uint32_t m_nGarbledCircuitRcvCtr;/**< Garbled Circuit Receiver Counter*/

	CBitVector m_vOutputShareRcvBuf;/**< Output Share Receiver Buffer.*/
	CBitVector m_vOutputShareSndBuf;/**< Output Share Sender Buffer*/

	std::vector<uint32_t> m_vClientSendCorrectionGates; /**< Client send correction gates.*/
	std::vector<uint32_t> m_vClientRcvInputKeyGates; /**< Client receives input key gates.*/

	std::vector<uint32_t> m_vServerInputGates; /**< Server Input gates.*/

	CBitVector m_vROTSndBuf;/**< __________________*/
	uint32_t m_vROTCtr;/**< __________________*/

	uint8_t**			m_vTmpEncBuf;

	/**
	 Receive Server Keys from the given gateid.
	 \param	gateid 	Gate Identifier
	 */
	void ReceiveServerKeys(uint32_t gateid);
	/**
	 Receive Client Keys from the given gateid.
	 \param	gateid 	Gate Identifier
	 */
	void ReceiveClientKeys(uint32_t gateid);

	/**
	 Method for assigning server input keys.
	 */
	void AssignServerInputKeys();
	/**
	 Method for assigning client input keys.
	 */
	void AssignClientInputKeys();

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
	void EvaluateANDGate(GATE* gate);
	/**
	 Method for evaluating garbled table.
	 \param gate	gate Object.
	 \param pos 		Position of the object in the queue.
	 \param gleft	left gate in the queue.
	 \param gright	right gate in the queue.
	 */
	BOOL EvaluateGarbledTable(GATE* gate, uint32_t pos, GATE* gleft, GATE* gright);
	/**
	 Method for evaluating UNIV gate for the inputted
	 gate object.
	 \param gate		Gate Object
	 */
	void EvaluateUNIVGate(GATE* gate);
	/**
	 Method for evaluating universal gates.
	 \param gate	gate Object.
	 \param pos 		Position of the object in the queue.
	 \param gleft	left gate in the queue.
	 \param gright	right gate in the queue.
	 */
	BOOL EvaluateUniversalGate(GATE* gate, uint32_t pos, GATE* gleft, GATE* gright);
	/**
	 Method for server output Gate for the inputted Gate.
	 \param gate		Gate Object
	 */
	void EvaluateServerOutputGate(GATE* gate);
	/**
	 Method for evaluating SIMD gate for the inputted
	 gate identifier.
	 \param gateid		Gate Identifier
	 */
	void EvaluateSIMDGate(uint32_t gateid);

	/**
	 Method for initiating the client.
	 */
	void InitClient();
	/**
	 Method for initiating a new layer.
	 */
	void InitNewLayer();

	/**
	 Method for evaluating a client output gate for the inputted
	 gate id.
	 \param gateid	Gate Identifier
	 */
	void EvaluateClientOutputGate(uint32_t gateid);

	/**
	 Method for receive Garbled Circuit And Output shares
	 \param setup 	ABYSetup Object.
	 */
	void ReceiveGarbledCircuitAndOutputShares(ABYSetup* setup);
};

#endif /* __YAOCLIENTSHARING_H__ */
