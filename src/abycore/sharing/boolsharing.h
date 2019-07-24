/**
 \file 		boolsharing.h
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
 \brief		Bool Sharing class.
 */

#ifndef __BOOLSHARING_H__
#define __BOOLSHARING_H__

#include "sharing.h"
#include <algorithm>
#include <map>
#include <vector>
#include "../circuit/booleancircuits.h"
#include <ENCRYPTO_utils/cbitvector.h>

class XORMasking;

//#define DEBUGBOOL
//#define BENCHBOOLTIME
/**
 BOOL SHARING - <DETAILED EXPLANATION PLEASE>
 */

typedef struct op_lut_precomp {
	uint32_t n_inbits; //number of input bits
	uint32_t n_outbits; //number of output bits
	uint32_t n_gates; //number of OP-LUT gates that were built for this input/output bit combination
	CBitVector* rot_val; //stores the random rotation values
	CBitVector* table_mask; //stores the random table
	uint32_t sel_opening_ctr; //keeps track which rotation values have already been used
	uint32_t mask_ctr; //keeps track of which masks have already been used. Counts independently of sel_opening_ctr, since the steps are done separately.
	uint64_t** table_data;//stores the truth table values that are necessary for pre-computation
	CBitVector** rot_OT_vals;//truth table values that are input into the OT by the sender
} op_lut_ctx;

class BoolSharing: public Sharing {

public:
	/** Constructor of the class.*/
	BoolSharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt, const std::string& circdir = ABY_CIRCUIT_DIR) :
			Sharing(context, role, sharebitlen, circuit, crypt, circdir) {
		Init();
	}
	;
	/** Destructor of the class.*/
	~BoolSharing() {
		Reset();
		delete m_cBoolCircuit;
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

	void PreComputationPhase();

	inline void InstantiateGate(GATE* gate);

	void GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& bytesize);
	void GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes);

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
		return m_nTotalNumMTs > 0? m_nTotalNumMTs-GetMaxCommunicationRounds()*8 : m_nTotalNumMTs;
	}
	;

	void Reset();
	std::vector<uint32_t> GetNumOTs() {
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

	uint32_t m_nTotalNumMTs;
	uint32_t m_nOPLUT_Tables;
	std::vector<uint32_t> m_nNumMTs;
	uint32_t m_nXORGates;

	XORMasking *fMaskFct; // = new XORMasking(1);
	std::vector<uint32_t> m_vMTStartIdx;
	std::vector<uint32_t> m_vMTIdx;
	std::vector<std::vector<uint32_t> > m_vANDGates;
	std::vector<uint32_t> m_vInputShareGates;
	std::vector<uint32_t> m_vOutputShareGates;

	uint32_t m_nInputShareSndSize;
	uint32_t m_nOutputShareSndSize;

	uint32_t m_nInputShareRcvSize;
	uint32_t m_nOutputShareRcvSize;

	uint32_t m_nNumANDSizes;


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
	non_lin_vec_ctx* m_vANDs;

	//multiplication triple values A, B and C for use in KK OT ext. Are later written to m_vA, m_vB and mvC. m_vKKS is used for temporary results
	std::vector<CBitVector> m_vKKA;
	std::vector<CBitVector> m_vKKB;
	std::vector<CBitVector> m_vKKC;
	std::vector<CBitVector*> m_vKKS;
	std::vector<CBitVector*> m_vKKChoices;

	//Values that are needed for the OP-LUT protocol. The different dimensions correspond to the different input sizes and output sizes of the LUTs
	std::map<uint64_t, op_lut_ctx*> 	m_vOP_LUT_data; //maps input and output bit-lengths to array indices for the m_vOP_LUT protocol
	std::map<uint64_t, CBitVector*> 	m_vOP_LUT_SndSelOpeningBuf; //maps input and output bit-lengths to a send buffer which stores the selective openings
	std::map<uint64_t, CBitVector*> 	m_vOP_LUT_RecSelOpeningBuf; //maps input and output bit-lengths to a receive buffer stores the received selective openings
	std::map<uint64_t, uint64_t>		m_vOP_LUT_SelOpeningBitCtr; //Counts the bits in m_vOP_LUT_SndSelOpeningBuf to be send and in m_vOP_LUT_RecSelOpeningBuf to be received this round
	std::map<uint64_t, std::vector<uint32_t> > m_vOPLUTGates;



	CBitVector m_vInputShareSndBuf;
	CBitVector m_vOutputShareSndBuf;

	CBitVector m_vInputShareRcvBuf;
	CBitVector m_vOutputShareRcvBuf;

	BooleanCircuit* m_cBoolCircuit;

#ifdef BENCHBOOLTIME
	double m_nCombTime;
	double m_nSubsetTime;
	double m_nCombStructTime;
	double m_nSIMDTime;
	double m_nXORTime;
#endif

	/**
	 Perform the setup phase preparation for MTs
	 \param 	setup	Pointer to an ABYSetup class, which receives the numeber of OTs to be computed
	 */
	void PrepareSetupPhaseMTs(ABYSetup* setup);

	/**
	 Perform the setup phase preparation for OP-LUT
	 \param 	setup	Pointer to an ABYSetup class, which receives the numeber of OTs to be computed
	 */
	void PrepareSetupPhaseOPLUT(ABYSetup* setup);

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
	 Method for selective open of LUTs in the OPLUT protocol
	 \param gateid 	Gate Identifier
	 */
	inline void SelectiveOpenOPLUT(uint32_t gateid);
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
	 Method for assigning values to OP-LUT gates after the interaction of this round has finished.
	 */
	void EvaluateOPLUTGates();
	/**
	 Method for initializing MTs.
	 */
	void InitializeMTs();
	/**
	 Method for computing MTs
	 */
	void ComputeMTs();

	/**
	 Method for store MTs to File
	*/
	void StoreMTsToFile(const char *filename);

	/**
	 Method for read MTs from file
	*/
	void ReadMTsFromFile(const char *filename);
	/**
	Method to check if it is the right nvals or the circuit size.
	*/
	BOOL isCircuitSizeLessThanOrEqualWithValueFromFile(char *filename, uint32_t in_circ_size);


	/**
	 Method for initializing.
	 */
	void Init();
	/**
	 Method for initiating a new layer.
	 */
	void InitNewLayer();

};

#endif /* __BOOLSHARING_H__ */
