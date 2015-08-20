/**
 \file 		boolsharing.h
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
 \brief		Bool Sharing class.
 */

#ifndef __BOOLSHARING_H__
#define __BOOLSHARING_H__

#include "sharing.h"
#include <algorithm>
#include "../circuit/booleancircuits.h"

//#define DEBUGBOOL
/**
 BOOL SHARING - <DETAILED EXPLANATION PLEASE>
 */
class BoolSharing: public Sharing {

public:
	/** Constructor of the class.*/
	BoolSharing(e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt) :\

			Sharing(role, sharebitlen, circuit, crypt) {
		Init();
	}
	;
	/** Destructor of the class.*/
	virtual ~BoolSharing() {
	}
	;

	//SUPER CLASS MEMBER FUNCTION
	void PrepareSetupPhase(ABYSetup* setup);
	void PerformSetupPhase(ABYSetup* setup);
	void FinishSetupPhase(ABYSetup* setup);
	void EvaluateLocalOperations(uint32_t level);
	void EvaluateInteractiveOperations(uint32_t level);

	void FinishCircuitLayer();

	void PrepareOnlinePhase();

	inline void InstantiateGate(GATE* gate);
	inline void UsedGate(uint32_t gateid);

	void GetDataToSend(vector<BYTE*>& sendbuf, vector<uint32_t>& bytesize);
	void GetBuffersToReceive(vector<BYTE*>& rcvbuf, vector<uint32_t>& rcvbytes);

	void EvaluateSIMDGate(uint32_t gateid);

	Circuit* GetCircuitBuildRoutine() {
		return m_cBoolCircuit;
	}
	;

	uint32_t AssignInput(CBitVector& input);
	uint32_t GetOutput(CBitVector& out);

	uint32_t GetMaxCommunicationRounds() {
		return m_cBoolCircuit->GetMaxDepth();
	}
	;
	uint32_t GetNumNonLinearOperations() {
		return m_nTotalNumMTs;
	}
	;

	void Reset();
	vector<uint32_t> GetNumOTs() {
		return m_nNumMTs;
	}
	;

	const char* sharing_type() {
		return "Boolean";
	}
	;

	void PrintPerformanceStatistics();
	//ENDS HERE
private:
	uint32_t m_nNumANDSizes;

	uint32_t m_nTotalNumMTs;
	vector<uint32_t> m_nNumMTs;
	uint32_t m_nXORGates;

	XORMasking *fMaskFct; // = new XORMasking(1);
	vector<uint32_t> m_vMTStartIdx;
	vector<uint32_t> m_vMTIdx;
	vector<vector<uint32_t> > m_vANDGates;
	vector<uint32_t> m_vInputShareGates;
	vector<uint32_t> m_vOutputShareGates;

	uint32_t m_nInputShareSndSize;
	uint32_t m_nOutputShareSndSize;

	uint32_t m_nInputShareRcvSize;
	uint32_t m_nOutputShareRcvSize;

	vector<CBitVector> m_vA; //Dim 1 for all pairs of sender / receiver, Dim 2 for MTs of different bitlengths as sender / receiver
	vector<CBitVector> m_vB; //value B of a multiplication triple
	vector<CBitVector> m_vS; // temporary value for the computation of the multiplication triples
	vector<CBitVector> m_vC; // value C of a multiplication triple
	vector<CBitVector> m_vD_snd; //Stores the D values (x ^ a) between an input and the multiplication value a
	vector<CBitVector> m_vE_snd; //Stores the E values (y ^ b) between the other input and the multiplication value b
	vector<CBitVector> m_vD_rcv;
	vector<CBitVector> m_vE_rcv;
	vector<CBitVector> m_vResA;
	vector<CBitVector> m_vResB;
	non_lin_vec_ctx* m_vANDs;

	CBitVector m_vInputShareSndBuf;
	CBitVector m_vOutputShareSndBuf;

	CBitVector m_vInputShareRcvBuf;
	CBitVector m_vOutputShareRcvBuf;

	BooleanCircuit* m_cBoolCircuit;

	/** 
	 Share Values
	 \param 	gateid 	GateID
	 */
	inline void ShareValues(uint32_t gateid);
	/** 
	 Reconstruct Values
	 \param 	gateid 	GateID
	 */
	inline void ReconstructValue(uint32_t gateid);

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
	 \param gateid 	Gate Identifier
	 */
	inline void SelectiveOpen(uint32_t gateid);
	/**
	 Method for selective open vector of the given gate.
	 \param gateid 	Gate Identifier
	 */
	inline void SelectiveOpenVec(uint32_t gateid);
	/**
	 Method for Evaluating MTs.
	 */
	void EvaluateMTs();
	/**
	 Method for evaluating AND gate
	 */
	void EvaluateANDGate();
	/**
	 Method for evaluating XOR gate for the inputted
	 gate object.
	 \param gateid		Gate identifier
	 */
	inline void EvaluateXORGate(uint32_t gateid);
	/**
	 Method for evaluating Inversion gate for the inputted
	 gate object.
	 \param gateid		Gate identifier
	 */
	inline void EvaluateINVGate(uint32_t gateid);
	/**
	 Method for evaluating Conversion gate for the inputted
	 gate object.
	 \param gateid		Gate identifier
	 */
	inline void EvaluateCONVGate(uint32_t gateid);
	/**
	 Method for evaluating Constant gate for the inputted
	 gate object.
	 \param gateid		Gate identifier
	 */
	inline void EvaluateConstantGate(uint32_t gateid);
	/**
	 Method for initialising MTs.
	 */
	void InitializeMTs();
	/**
	 Method for computing MTs
	 */
	void ComputeMTs();

	/**
	 Method for initialising.
	 */
	void Init();
	/**
	 Method for initiating a new layer.
	 */
	void InitNewLayer();

};

#endif /* __BOOLSHARING_H__ */
