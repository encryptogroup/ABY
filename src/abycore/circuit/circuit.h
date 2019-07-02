/**
 \file 		circuit.h
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

 \brief		Contains the class for generic circuits, which is a super-class of Boolean and Arithmetic circuits.
*/

#ifndef CIRCUIT_H_
#define CIRCUIT_H_

#include "abycircuit.h"
#include <functional>

#include <cassert>
#include <deque>
#include <iostream>
#include <string>
#include <vector>

class share;
class boolshare;
class arithshare;

struct non_lin_on_layers {
	uint32_t* num_on_layer;
	uint32_t min_depth;
	uint32_t max_depth;
};

/*
 * Accumulates all objects of vector using binary operation op in a balanced
 * binary tree structure.
 */
template <typename T>
T binary_accumulate(std::vector<T> vals,
	std::function<T (const T&, const T&)>& op) {
	for(size_t j, n{vals.size()}; n > 1; n = j) {
		j = 0;
		for(size_t i{0}; i < n; ++j) {
			if (i + 1 >= n) { // only i+1 == n possible
				vals[j] = vals[i];
				++i;
			} else {
				vals[j] = op(vals[i], vals[i + 1]);
				i += 2;
			}
		}
	}

	return vals[0];
}

/**
 * A binary operation on uint32_t
 * Those are passed to binary_accumulate() as op
 */
using BinaryOp_v_uint32_t = std::function<std::vector<uint32_t>
	(const std::vector<uint32_t>&, const std::vector<uint32_t>&)>;

/** Circuit class */
class Circuit {

public:
	Circuit(ABYCircuit* aby, e_sharing context, e_role myrole, uint32_t bitlen, e_circuit circ) :
			m_cCircuit(aby), m_eContext(context), m_eMyRole(myrole),
			m_nShareBitLen(bitlen), m_eCirctype(circ), m_vGates(aby->GatesVec()) {
		Init();
	}

	virtual ~Circuit() {
	}

	/**
	 	 Method performs the initialization of member objects of the \link Circuit \endlink class. It is called from
	 	 Constructor of the class [\link Circuit(ABYCircuit* aby, e_sharing context, e_role myrole, uint32_t bitlen, e_circuit circ) \endlink]
	 */
	void Init();

	/** Incomplete method */
	void Cleanup();

	/** It will reset all the member objects to zero/clear them.*/
	void Reset();

	/* organizational routines */

	/**
		It is a getter method which will return the value of Bit Length of the \link share \endlink object.
		\return Bit length of \link share \endlink Object.
	*/
	uint32_t GetShareBitLen() {
		return m_nShareBitLen;
	}

	/**
		It is a getter method which will return the value of Maximum Depth.
	*/
	uint32_t GetMaxDepth() {
		return m_nMaxDepth;
	}
	/**
		It is a getter method which returns the Local queue based on the inputed level.
		\param lvl Required level of local queue.
		\return Local queue on the required level
	*/
		std::deque<uint32_t> GetLocalQueueOnLvl(uint32_t lvl) {

		if (lvl < m_vLocalQueueOnLvl.size())
			return m_vLocalQueueOnLvl[lvl];
		else
			return EMPTYQUEUE;
	}

	/**
		It is a getter method which returns the Interactive queue based on the inputed level.
		\param lvl Required level of interactive queue.
		\return Interactive queue on the required level
	*/
		std::deque<uint32_t> GetInteractiveQueueOnLvl(uint32_t lvl) {
		if (lvl < m_vInteractiveQueueOnLvl.size()) {
			return m_vInteractiveQueueOnLvl[lvl];
				} else {
			return EMPTYQUEUE;
				}
	}

	/*
	 * print the number of interactive operations for each layer
	 */
	void PrintInteractiveQueues(){
		  std::vector<std::string> sharingnames {"GMW", "Yao", "Arith", "Yao_Rev", "SPLUT"};

		std::cout << "Interactive Queue Sizes " << sharingnames[this->m_eContext] << std::endl;

		for(uint32_t l = 0; l < GetNumInteractiveLayers(); ++l){
			std::cout << GetInteractiveQueueOnLvl(l).size() << "\t";
		}
		std::cout << std::endl;
	}

	/**
		It is a getter method which returns the number of levels/layers in the Local queue.
		\return Number of layers in the Local Queue.
	*/
	uint32_t GetNumLocalLayers() {
		return m_vLocalQueueOnLvl.size();
	}

	/**
		It is a getter method which returns the number of levels/layers in the Interactive queue.
		\return Number of layers in the Interactive Queue.
	*/
	uint32_t GetNumInteractiveLayers() {
		return m_vInteractiveQueueOnLvl.size();
	}

	/**
		It is a getter method which returns the number of Input bits provided for the given party
		\param	party Party role based on which the number of Input bits are returned.
		\return Number of Input bits for the provided party
	*/
	uint32_t GetNumInputBitsForParty(e_role party) {
		return m_vInputBits[party];
	}
	/**
		It is a getter method which returns the number of Output bits provided for the given party
		\param	party Party role based on which the number of Output bits are returned.
		\return Number of Output bits for the provided party
	*/
	uint32_t GetNumOutputBitsForParty(e_role party) {
		return m_vOutputBits[party];
	}

	/**
		It is a getter method which returns the Input Gates provided for the given party
		\param	party Party role based on which the Input gates are returned.
		\return Input gates for the provided party
	*/
	std::deque<uint32_t> GetInputGatesForParty(e_role party) {
		return m_vInputGates[party];
	}

	/**
		It is a getter method which returns the Output Gates provided for the given party
		\param	party Party role based on which the Output gates are returned.
		\return Output gates for the provided party
	*/
		std::deque<uint32_t> GetOutputGatesForParty(e_role party) {
		return m_vOutputGates[party];
	}


	/*non_lin_on_layers* GetNonLinGatesOnLayers() {
		return &m_vNonLinOnLayer;
	}*/

	e_sharing GetContext() {
		return m_eContext;
	}

	uint32_t GetNumGates() {
		return m_nGates;
	}


	gate_specific GetGateSpecificOutput(uint32_t gateid);
	UGATE_T* GetOutputGateValue(uint32_t gateid);
	uint32_t GetOutputGateValue(uint32_t gateid, UGATE_T*& outval);
	template<class T> void GetOutputGateValueT(uint32_t gateid, T& val) {
		assert(sizeof(T) * 8 >= m_vGates[gateid].nvals * m_nShareBitLen);
		val = *((T*) m_vGates[gateid].gs.val);
	}

	uint32_t GetNumVals(uint32_t gateid) {
		assert(gateid < m_cCircuit->GetGateHead());
		return m_vGates[gateid].nvals;
	}

	/* Common gate-building routines */
	virtual share* PutCONSGate(UGATE_T val, uint32_t bitlen) = 0;
	virtual share* PutCONSGate(uint32_t* val, uint32_t bitlen) = 0;
	virtual share* PutCONSGate(uint8_t* val, uint32_t bitlen) = 0;

	virtual share* PutSIMDCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen) = 0;
	virtual share* PutSIMDCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) = 0;
	virtual share* PutSIMDCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) = 0;


	virtual uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1) = 0;


	/*
	 * Several Put*INGate routines follow below. Note that, for many inputs, only the party who plays the source "role"
	 * (i.e., either SERVER or CLIENT) provides the input. If the other party also inputs a value, this value will be ignored
	 * in the circuit and the other party will use the share, sent by the source party.
	 */
	/* Unfortunately, a template function cannot be used due to virtual */
	virtual share* PutINGate(uint64_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint32_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint16_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint8_t val, uint32_t bitlen, e_role role) = 0;

	/* Unfortunately, a template function cannot be used due to virtual */
	virtual share* PutINGate(uint64_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint32_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint16_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint8_t* val, uint32_t bitlen, e_role role) = 0;

	/* input gate of which the value is assigned by the other party */
	virtual share* PutDummyINGate(uint32_t bitlen) = 0;

	virtual share* PutSIMDINGate(uint32_t nvals, uint64_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutSIMDINGate(uint32_t nvals, uint32_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutSIMDINGate(uint32_t nvals, uint16_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutSIMDINGate(uint32_t nvals, uint8_t val, uint32_t bitlen, e_role role) = 0;

	/* Unfortunately, a template function cannot be used due to virtual */
	virtual share* PutSIMDINGate(uint32_t nvals, uint64_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutSIMDINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutSIMDINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutSIMDINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role) = 0;

	/* SIMD input gate of which the value is assigned by the other party */
	virtual share* PutDummySIMDINGate(uint32_t nvals, uint32_t bitlen) = 0;


	// Shared Input Gates
	/* Unfortunately, a template function cannot be used due to virtual */
	virtual share* PutSharedINGate(uint64_t val, uint32_t bitlen) = 0;
	virtual share* PutSharedINGate(uint32_t val, uint32_t bitlen) = 0;
	virtual share* PutSharedINGate(uint16_t val, uint32_t bitlen) = 0;
	virtual share* PutSharedINGate(uint8_t val, uint32_t bitlen) = 0;

	/* Unfortunately, a template function cannot be used due to virtual */
	virtual share* PutSharedINGate(uint64_t* val, uint32_t bitlen) = 0;
	virtual share* PutSharedINGate(uint32_t* val, uint32_t bitlen) = 0;
	virtual share* PutSharedINGate(uint16_t* val, uint32_t bitlen) = 0;
	virtual share* PutSharedINGate(uint8_t* val, uint32_t bitlen) = 0;

	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint64_t val, uint32_t bitlen) = 0;
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint32_t val, uint32_t bitlen) = 0;
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint16_t val, uint32_t bitlen) = 0;
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint8_t val, uint32_t bitlen) = 0;

	/* Unfortunately, a template function cannot be used due to virtual */
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint64_t* val, uint32_t bitlen) = 0;
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) = 0;
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen) = 0;
	virtual share* PutSharedSIMDINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) = 0;


	virtual share* PutADDGate(share* ina, share* inb) = 0;
	virtual share* PutSUBGate(share* ina, share* inb) = 0;
	virtual share* PutANDGate(share* ina, share* inb) = 0;
	virtual share* PutXORGate(share* ina, share* inb) = 0;
	virtual share* PutMULGate(share* ina, share* inb) = 0;
	virtual share* PutGTGate(share* ina, share* inb) = 0;
	virtual share* PutEQGate(share* ina, share* inb) = 0;
	virtual share* PutMUXGate(share* ina, share* inb, share* sel) = 0;
	virtual share** PutCondSwapGate(share* ina, share* inb, share* sel, BOOL vectorized) = 0;
	virtual share* PutUniversalGate(share* ina, share* inb, uint32_t op_id) = 0;
	virtual share* PutY2BGate(share* ina) = 0;
	virtual share* PutB2AGate(share* ina) = 0;
	virtual share* PutB2YGate(share* ina) = 0;
	virtual share* PutA2YGate(share* ina) = 0;
	share* PutY2AGate(share* ina, Circuit* boolsharingcircuit);
	share* PutA2BGate(share* ina, Circuit* yaosharingcircuit);
	virtual share* PutANDVecGate(share* ina, share* inb) = 0;
	virtual share* PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals) = 0;
	virtual share* PutTruthTableGate(share* in, uint64_t* ttable) = 0;
	virtual share* PutTruthTableMultiOutputGate(share* in, uint32_t out_bits, uint64_t* ttable) = 0;


	share* PutPrintValueGate(share* in, std::string helpstr);
	//TODO: AssertGate and SIMDAssertGate need interfaces for all types as INGate and SIMDINGates
	share* PutAssertGate(share* in, uint64_t* assert_val, uint32_t bitlen);
	share* PutAssertGate(share* in, uint32_t* assert_val, uint32_t bitlen);
	share* PutAssertGate(share* in, uint16_t* assert_val, uint32_t bitlen);
	share* PutAssertGate(share* in, uint8_t* assert_val, uint32_t bitlen);

	share* PutAssertGate(share* in, uint64_t assert_val, uint32_t bitlen);
	share* PutAssertGate(share* in, uint32_t assert_val, uint32_t bitlen);
	share* PutAssertGate(share* in, uint16_t assert_val, uint32_t bitlen);
	share* PutAssertGate(share* in, uint8_t assert_val, uint32_t bitlen);

	template<class T> share* AssertInterfaceConversion(share* in, uint32_t nvals, T* assert_val, uint32_t bitlen);
	share* PutSIMDAssertGate(share* in, uint32_t nvals, uint64_t* assert_val, uint32_t bitlen);
	share* PutSIMDAssertGate(share* in, uint32_t nvals, uint32_t* assert_val, uint32_t bitlen);
	share* PutSIMDAssertGate(share* in, uint32_t nvals, uint16_t* assert_val, uint32_t bitlen);
	share* PutSIMDAssertGate(share* in, uint32_t nvals, uint8_t* assert_val, uint32_t bitlen);

	/**
		The combiner gate takes as input a non-SIMD share ina containing sigma wires and joins them
		to a SIMD share with a single wire with nvals = sigma values. The combiner gate is used to
		group together non-SIMD values before inputting them into a SIMD operation.
		\param 		input 	Input share object containing sigma wires which requires joining.
		\return 			SIMD share object with nvals = sigma.
	*/
	share* PutCombinerGate(share* input);

	/**
		The combiner gate takes as input two non-SIMD share ina and inb containing sigma_a and sigma_b wires and concatenates them
		to a SIMD share with a single wire with nvals = sigma_a + sigma_b values. The combiner gate is used to
		group together non-SIMD values before inputting them into a SIMD operation.
		\param 		ina 	Input share object containing sigma_a wires which requires joining.
		\param 		inb 	Input share object containing sigma_b wires which requires joining.
		\return 			SIMD share object with nvals = sigma_a + sigma_b.
	*/
	share* PutCombinerGate(share* ina, share* inb);

	/**
		The splitter gate takes as input a SIMD share ina with a single wire with nvals values and
		splits it into non-SIMD share with σ = nvals wires, each with nvals = 1 values. The splitter
		gate is the reverse operation to the combiner gate and can be used to transform a SIMD gate
		back into a non-SIMD gate.
	*/
	share* PutSplitterGate(share* input);


	share* PutRepeaterGate(uint32_t nvals, share* input);

	/**
		The subset gate takes as input a SIMD share input with a single wire with multiple values and
		an arbitrary list of positions posids that is of size nvals_out . It returns a SIMD share with a
		single wire that consists nvals_out values of input at the positions specified in posids .
		\param 		input 		input the input share with nvals_in >1. If it contains more than one wire (bitlen>1),then the same subset of nvals is selected from every wire.
		\param 		posids		an array of nvals_out positions to be selected from the input share. Every position must be in the range {0, . . . , nvals_in −1}.
		\param		nvals_out		the number of posids and nvals of the output
		\param		copy_posids	Copy the position references and delete them after use
	*/
	share* PutSubsetGate(share* input, uint32_t* posids, uint32_t nvals_out, bool copy_posids = true);
	//TODO: Explain copy_posids

	/**
		The combineatpos gate takes a SIMD share input with sigma wires as input and combines the
		element at position pos on each wire of input into a new SIMD share with a single wire
		and sigma values on that wire. The CombineAtPosGate is useful when a SIMD share needs to be
		transposed.
		\param 		input 	the input share object containing σ wires and nvals_in values on each wire, which requires joining.
		\param		pos		pos the position at which joining is performed. The value of pos must be in the range {0, ..., nvals_in−1}.
	*/
	share* PutCombineAtPosGate(share* input, uint32_t pos);


	/**
		The PermutationGate takes as input a SIMD share input with σ wires each with nvals_in
		values and a list of positions posids with sigma entries. It returns a single wire SIMD share
		s_out with nvals= sigma values, where the i-th value of s_out comes from the i-th wire of input
		at position posids[i] .
		\param 		input 			the share with sigma input wires and nvals_in values from which the values should be taken.
		\param		positions		the position on the wires from input from which the values should be read.
					posids must have sigma entries, i.e., one entry for each wire in the input share (its bitlength).
					Each position must be in the range {0, ..., nvals_in −1} for the given wire.
	*/
	share* PutPermutationGate(share* input, uint32_t* positions);


	uint32_t PutRepeaterGate(uint32_t input, uint32_t nvals);
	uint32_t PutCombinerGate(std::vector<uint32_t> input);
	uint32_t PutCombineAtPosGate(std::vector<uint32_t> input, uint32_t pos);
	uint32_t PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals_out, bool copy_posids = true);
	uint32_t PutPermutationGate(std::vector<uint32_t> input, uint32_t* positions);
	std::vector<uint32_t> PutSplitterGate(uint32_t input);
	std::vector<uint32_t> PutSplitterGate(uint32_t input, const std::vector<uint32_t>& new_nvals);

	//Templates may not be virtual, hence use dummy functions
	template <class T> uint32_t PutINGate([[maybe_unused]] T val) {
		std::cout << "IN gate not implemented in super-class, stopping!" << std::endl;
		return -1;
	}

	template<class T> uint32_t PutINGate([[maybe_unused]] T val, [[maybe_unused]] e_role role) {
		std::cout << "IN gate not implemented in super-class, stopping!" << std::endl;
		return -1;
	}

	template<class T> uint32_t PutSharedINGate([[maybe_unused]] T val) {
		std::cout << "IN gate not implemented in super-class, stopping!" << std::endl;
		return -1;
	}

	template<class T> uint32_t PutSIMDINGate([[maybe_unused]]uint32_t nvals, [[maybe_unused]] T val) {
		std::cout << "IN gate not implemented in super-class, stopping!" << std::endl;
		return -1;
	}

	template<class T> uint32_t PutSIMDINGate([[maybe_unused]] uint32_t nvals, [[maybe_unused]] T val, [[maybe_unused]] e_role role) {
		std::cout << "IN gate not implemented in super-class, stopping!" << std::endl;
		return -1;
	}

	template<class T> uint32_t PutSharedSIMDINGate([[maybe_unused]]uint32_t nvals, [[maybe_unused]] T val) {
		std::cout << "IN gate not implemented in super-class, stopping!" << std::endl;
		return -1;
	}

	virtual share* PutOUTGate(share* parent, e_role dst) =0;

	virtual share* PutSharedOUTGate(share* parent) =0;


	virtual uint32_t PutINVGate(uint32_t parentid) = 0;
	e_circuit GetCircuitType() {
		return m_eCirctype;
	}

	int GetNumCombGates() {
		return ncombgates;
	}

	int GetNumStructCombGates() {
		return nstructcombgates;
	}

	int GetNumPermGates() {
		return npermgates;
	}

	int GetNumSubsetGates() {
		return nsubsetgates;
	}

	int GetNumSplitGates() {
		return nsplitgates;
	}

	e_role GetRole() {
		return m_eMyRole;
	}

	//Export the constructed circuit in the Bristol circuit file format
	void ExportCircuitInBristolFormat(share* ingates_client, share* ingates_server,
			share* outgates, const char* filename);

protected:
	virtual void UpdateInteractiveQueue(uint32_t gateid) = 0;
	virtual void UpdateLocalQueue(uint32_t gateid) = 0;

	void UpdateInteractiveQueue(share* gateid);
	void UpdateLocalQueue(share* gateid);

	void ResizeNonLinOnLayer(uint32_t new_max_depth);

	share* EnsureOutputGate(share* in);

	ABYCircuit* m_cCircuit; /** ABYCircuit Object  */

	e_sharing m_eContext;
	e_role m_eMyRole;
	uint32_t m_nShareBitLen;
	e_circuit m_eCirctype;
	uint32_t m_nMaxDepth;
	std::vector<GATE>& m_vGates;

	std::vector<std::deque<uint32_t> > m_vLocalQueueOnLvl; //for locally evaluatable gates, first dimension is the level of the gates, second dimension presents the queue on which the gateids are put
	std::vector<std::deque<uint32_t> > m_vInteractiveQueueOnLvl; //for gates that need interaction, first dimension is the level of the gates, second dimension presents the queue on which the gateids are put
	std::vector<std::deque<uint32_t> > m_vInputGates;				//input gates for the parties
	std::vector<std::deque<uint32_t> > m_vOutputGates;				//input gates for the parties
	std::vector<uint32_t> m_vInputBits;				//number of input bits for the parties
	std::vector<uint32_t> m_vOutputBits;				//number of output bits for the parties

	uint32_t ncombgates;
	uint32_t npermgates;
	uint32_t nsubsetgates;
	uint32_t nsplitgates;
	uint32_t nstructcombgates;

	uint32_t m_nMULs;					//number of AND gates in the circuit
	uint32_t m_nCONVGates;				//number of Boolean to arithmetic conversion gates

	uint32_t m_nGates;
	uint32_t m_nRoundsAND;
	uint32_t m_nRoundsXOR;
	std::vector<uint32_t> m_nRoundsIN;
	std::vector<uint32_t> m_nRoundsOUT;

	const std::deque<uint32_t> EMPTYQUEUE;

	//non_lin_on_layers m_vNonLinOnLayer;
};


share* create_new_share(uint32_t size, Circuit* circ);
share* create_new_share(std::vector<uint32_t> vals, Circuit* circ);

#endif /* CIRCUIT_H_ */
