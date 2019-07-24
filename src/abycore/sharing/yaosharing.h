/**
 \file 		yaosharing.h
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
 \brief		Yao Sharing class.
 */

#ifndef __YAOSHARING_H__
#define __YAOSHARING_H__

#include "sharing.h"
#include "../ABY_utils/yaokey.h"
#include "../circuit/booleancircuits.h"
#include <ENCRYPTO_utils/constants.h>
#include <ENCRYPTO_utils/crypto/crypto.h>


class XORMasking;

typedef struct {
	uint32_t gateid;
	UGATE_T* inval;
} input_gate_val_t;

typedef struct {
	uint32_t gateid;
	uint32_t pos;
} a2y_gate_pos_t;


/**
 \def 	KEYS_PER_GATE_IN_TABLE
 \brief	____________________
 */
#define KEYS_PER_GATE_IN_TABLE 2

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
	YaoSharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt, const std::string& circdir = ABY_CIRCUIT_DIR) :
			Sharing(context, role, sharebitlen, circuit, crypt, circdir) {
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
	/* A variable that points to inline functions for key xor */
	YaoKey *m_pKeyOps; /**< A variable that points to inline functions for key xor.*/
	uint32_t m_nANDGates; /**< AND Gates_____________*/
	uint32_t m_nXORGates; /**< XOR Gates_____________*/
	uint32_t m_nUNIVGates; /**< Universal Gates_____________*/

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

	/** Initiator function. This method is invoked from the constructor of the class.*/
	void Init();

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
