/**
 \file 		arithsharing.h
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
 \brief		Arithmetic Sharing class.
 */

#ifndef __ARITHSHARING_H__
#define __ARITHSHARING_H__

#include "sharing.h"
#include <algorithm>
#include "../circuit/arithmeticcircuits.h"

//#define DEBUGARITH
//#define VERIFY_ARITH_MT

template<typename T>
/** Arithemetic Sharing Class. */
class ArithSharing: public Sharing {

public:
	/** Constructor of the class.*/
	ArithSharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt, e_mt_gen_alg mt_alg) :
			Sharing(context, role, sharebitlen, circuit, crypt),
			m_eMTGenAlg{mt_alg},
			m_vConversionMasks(2)
	{
		Init();
	};

	/** Destructor of the class.*/
	~ArithSharing() {
		Reset();
		delete m_cArithCircuit;
	};

	//MEMBER FUNCTIONS OF THE SUPER CLASS
	void Reset();
	void PrepareSetupPhase(ABYSetup* setup);
	void PerformSetupPhase(ABYSetup* setup);
	void FinishSetupPhase(ABYSetup* setup);
	void EvaluateLocalOperations(uint32_t depth);
	void EvaluateInteractiveOperations(uint32_t depth);

	void FinishCircuitLayer();

	void PrepareOnlinePhase();

	void PreComputationPhase() {
		return;
	}

	void InstantiateGate(GATE* gate);

	void GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& bytesize);
	void GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes);

	uint32_t AssignInput(CBitVector& input);
	uint32_t GetOutput(CBitVector& out);

	uint32_t GetMaxCommunicationRounds() {
		return m_cArithCircuit->GetMaxDepth();
	}
	;
	uint32_t GetNumNonLinearOperations() {
		return m_nMTs;
	}
	;

	Circuit* GetCircuitBuildRoutine() {
		return m_cArithCircuit;
	}
	;

	const char* sharing_type() {
		return "Arithmetic";
	}
	;

	void PrintPerformanceStatistics();
	//ENDS HERE...
	/**
	 Evaluating SIMD Gate.
	 \param 	gateid 	Identifier of the gate to be evaluated.
	 */
	void EvaluateSIMDGate(uint32_t gateid);

	/**
	 Evaluating Inversion Gate.
	 \param 	gate 	Object of the gate to be evaluated.
	 */
	void EvaluateINVGate(GATE* gate);
	/**
	 Evaluating Conversion Gate.
	 \param 	gate 	Object of the gate to be evaluated.
	 */
	void EvaluateCONVGate(GATE* gate);

private:

	ArithmeticCircuit* m_cArithCircuit;

	e_mt_gen_alg m_eMTGenAlg;

	uint32_t m_nMTs;
	uint32_t m_nNumCONVs;

	uint64_t m_nTypeBitMask;

        std::vector<uint32_t> m_vMTStartIdx;
        std::vector<uint32_t> m_vMTIdx;
        std::vector<GATE*> m_vMULGates;
        std::vector<GATE*> m_vInputShareGates;
        std::vector<GATE*> m_vOutputShareGates;
        /* We collect conversion shares for round 1 in this vector (SERVER uses
         * them in AssignServerConversionShares) */
        std::vector<GATE*> m_vCONVGates;
        /* We collect conversion shares for round 2 in this vector (CLIENT uses
         * them in AssignClientConversionShares) */
        std::vector<GATE*> m_vCONVGates2;

	uint32_t m_nInputShareSndCtr;
	uint32_t m_nOutputShareSndCtr;

	uint32_t m_nInputShareRcvCtr;
	uint32_t m_nOutputShareRcvCtr;

        std::vector<CBitVector> m_vA; //Dim 1 for all pairs of sender / receiver, Dim 2 for MTs of different bitlengths as sender / receiver
        std::vector<CBitVector> m_vB; //value B of a multiplication triple
        std::vector<CBitVector> m_vS; // temporary value for the computation of the multiplication triples
        std::vector<CBitVector> m_vC; // value C of a multiplication triple
        std::vector<CBitVector> m_vD_snd; //Stores the D values (x ^ a) between an input and the multiplication value a
        std::vector<CBitVector> m_vE_snd; //Stores the E values (y ^ b) between the other input and the multiplication value b
        std::vector<CBitVector> m_vD_rcv;
        std::vector<CBitVector> m_vE_rcv;
        std::vector<CBitVector> m_vResA;
        std::vector<CBitVector> m_vResB;

	CBitVector m_vInputShareSndBuf;
	CBitVector m_vOutputShareSndBuf;

	CBitVector m_vInputShareRcvBuf;
	CBitVector m_vOutputShareRcvBuf;

	CBitVector m_vConvShareSndBuf;
	CBitVector m_vConvShareRcvBuf;

        std::vector<CBitVector> m_vConversionMasks;

	CBitVector m_vConversionRandomness;

	// Global index into conversion buffers for randomness and OTs
	uint32_t m_nConvShareIdx;
	// 2nd layer (client side) needs its own counter to not interfere with prevous layer
	uint32_t m_nConvShareIdx2;
	uint32_t m_nConvShareSndCtr; // Network send counter per round
	uint32_t m_nConvShareRcvCtr; // Network receive counter per round

	/**
	 Share Values
	 \param 	gate 	Object of class Gate
	 */
	void ShareValues(GATE* gate);
	/**
	 Reconstruct Values
	 \param 	gate 	Object of class Gate
	 */
	void ReconstructValue(GATE* gate);
	/**
	 Method for assigning input shares.
	 */
	void AssignInputShares();
	/**
	 Method for assigning output shares.
	 */

	void AssignOutputShares();

	/**
	 Method for selective open of the given gate.
	 \param gate 	Gate Object
	 */
	void SelectiveOpen(GATE* gate);
	/**
	 Method for Evaluating MTs.
	 */
	void EvaluateMTs();
	/**
	 * Write constant value, or 0 for CLIENT, to gs.aval nvals times and backup
	 * initial constant.
	 */
	void EvaluateConstantGate(GATE* gate);
	/**
	 Method for evaluating Add Gate using the gate object.
	 \param 	gate 	Gate Object.
	 */
	void EvaluateADDGate(GATE* gate);
	/**
	 Method for evaluating Sub Gate using the gate object.
	 \param 	gate 	Gate Object.
	 */
	void EvaluateSUBGate(GATE* gate);

	/**
	 * Evaluate multiplication with a constant - offline like addition
	 */
	void EvaluateMULCONSTGate(GATE* gate);
	/**
	 Method for evaluating Multiplication Gate
	 */
	void EvaluateMULGate();

	/**
	 Method for assigning conversion shares.
	 */
	void AssignConversionShares();

	/**
	 Method for assigning server conversion shares.
	 */
	void AssignServerConversionShares();

	/**
	 Method for assigning client conversion shares.
	 */
	void AssignClientConversionShares();

#ifdef VERIFY_ARITH_MT
	//called at setup -> finish
	void VerifyArithMT(ABYSetup* setup);
#endif
	/**
	 Method for initialising MTs.
	 */
	void InitMTs();

	/**
	 Method for computing MTs from OTs
	 */
	void ComputeMTsFromOTs();
	/**
	 Method for Finish MT Generation.
	 */
	void FinishMTGeneration();
	/**
	 Method for initialising.
	 */
	void Init();
	/**
	 Method for initiating a new layer.
	 */
	void InitNewLayer();
};

#endif /* ArithSharing */
