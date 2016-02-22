/**
 \file 		abycircuit.h
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
 \brief		ABYCircuit class.
 */
#ifndef __ABYCIRCUIT_H_
#define __ABYCIRCUIT_H_

#include <math.h>
#include "../util/typedefs.h"
#include <iostream>
#include <limits.h>
#include <deque>
#include "../util/constants.h"

//#define DEBUG_CIRCUIT_CONSTRUCTION

//A macro that defines whether a gate requires interaction
#define IsInteractive(gatetype, gatecontext) (!((gatecontext == C_ARITH && gatetype == G_ADD) || ((gatecontext == C_BOOL || gatecontext == C_YAO) && gatetype == G_XOR)) || (gatetype == G_MUL))
#define ComputeDepth(predecessor) ( (predecessor).depth + (predecessor).nrounds )

#define IsSIMDGate(gatetype) (!!((gatetype)&0x80))

struct GATE;

//TODO redefine outkey as UINT64_T
struct yao_fields {
	//The output wire key
	BYTE* outKey;
	//The permutation bit for point-and-permute
	BYTE* pi;
};

struct input_fields {
	e_role src;
	UGATE_T* inval;
};

struct output_fields {
	e_role dst;
};

struct combine_at_pos_gate {
	uint32_t pos;
};

struct subset_gate {
	uint32_t* posids;
};
struct splitter_fields {
	uint32_t pos;
};

struct permutation_gate {
	uint32_t* posids;
};

struct callback_gate {
	void (*callback)(GATE* gate, void* infos);
	void* infos;
};

struct and_vec_simd {
	uint32_t bitlen;
};

struct struct_combine_gate {
	uint32_t pos_start;
	uint32_t pos_incr;
	uint32_t num_in_gates;
};


//TODO redefine yval as UINT64_T
//TODO store in a specific output field, stored in val right now (which also BOOL values are)
union gate_specific {

	//fields of the combiner gate
	uint32_t* cinput;
	//fields of the standard gate (pos)
	splitter_fields sinput;
	//fields of a yao's garbled circuit gate
	yao_fields yinput;
	BYTE* yval;
	//Arithmetic sharing values, a pointer to a uint16, uint32 or uint64 array with val_size elements
	UGATE_T* aval;
	//fields of the evaluated gate
	UGATE_T* val;
	//fields for the permutation gate. perm is a vector that first has the id i of the input gate and then the pos p of the input gate for n input gates (i_1,p_1,i_2,p_2,...,i_n,p_n)
	permutation_gate perm;
	//fields for the combinepos gate. combinepos first holds the position and then the ids of the input gates it combines
	//TODO: combine the combine and combinepos gate into one gate
	combine_at_pos_gate combinepos;
	//value that is supposed to be shared
	input_fields ishare;
	//gate whose value is reconstructed
	output_fields oshare;
	//values for the subset gate which combines multiple different positions of one gate into another
	subset_gate sub_pos;
	//constant value of a gate
	UGATE_T constval;
	//specific field for the conversion type
	uint32_t pos;
	//callback routine that handles the evaluation. Functionality is defined by the developer
	callback_gate cbgate;
	//field that is used when vector ANDs are performed using SIMD gates
	and_vec_simd avs;
	//is used for structurized combiner gates
	struct_combine_gate struct_comb;
};
typedef union gate_specific gs_t;

struct input_gates {
	union {
		uint32_t parent;
		struct {
			uint32_t left;
			uint32_t right;
		} twin;
		uint32_t* parents;
	} inputs;
	uint32_t ningates;
};

struct GATE {
	bool instantiated;
	e_sharing context;		// the representation of the value stored in the gate (Public / arithmetic sharing / Boolean sharing / Yao sharing)
	e_gatetype type;			// gate type
	uint32_t nrounds;		// specifies the number of interaction rounds that are required when evaluating this gate
	uint32_t nused;			// number of uses of the gate
	uint32_t depth;			// number of AND gates to the root
	uint32_t nvals;			// the number of values that are stored in this gate
	gs_t gs;				// here the differences for the gates come in
	uint32_t sharebitlen;	// bitlength of the shares in the context
	input_gates ingates;		// the number of input gates together with the values of the input gates
};

string GetOpName(e_gatetype op);

struct non_lin_vec_ctx {
	uint32_t bitlen;
	uint32_t numgates;
};

uint32_t FindBitLenPositionInVec(uint32_t bitlen, non_lin_vec_ctx* list, uint32_t listentries);

class ABYCircuit {
public:
	ABYCircuit(uint32_t maxgates);
	virtual ~ABYCircuit() {
		Cleanup();
	}

	void Cleanup();
	void Reset();
	GATE* Gates() {
		return m_pGates;
	}
	uint32_t PutPrimitiveGate(e_gatetype type, uint32_t inleft, uint32_t inright, uint32_t rounds);
	uint32_t PutNonLinearVectorGate(e_gatetype type, uint32_t choiceinput, uint32_t vectorinput, uint32_t rounds);
	uint32_t PutCombinerGate(vector<uint32_t> input);
	vector<uint32_t> PutSplitterGate(uint32_t input);		//, vector<uint32_t> gatelengths = NULL);
	uint32_t PutCombineAtPosGate(vector<uint32_t> input, uint32_t pos);
	uint32_t PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals);
	uint32_t PutStructurizedCombinerGate(vector<uint32_t> input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals);
	uint32_t PutRepeaterGate(uint32_t input, uint32_t nvals);
	vector<uint32_t> PutRepeaterGate(vector<uint32_t> input, uint32_t nvals);
	uint32_t PutPermutationGate(vector<uint32_t> input, uint32_t* positions);

	uint32_t PutOUTGate(uint32_t in, e_role dst, uint32_t rounds);
	vector<uint32_t> PutOUTGate(vector<uint32_t> in, e_role dst, uint32_t rounds);

	uint32_t PutSharedOUTGate(uint32_t in);
	vector<uint32_t> PutSharedOUTGate(vector<uint32_t> in);

	uint32_t PutINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen, e_role src, uint32_t rounds);

	uint32_t PutSharedINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen);

	uint32_t PutConstantGate(e_sharing context, UGATE_T val, uint32_t nvals, uint32_t sharebitlen);
	uint32_t PutINVGate(uint32_t in);
	uint32_t PutCONVGate(vector<uint32_t> in, uint32_t nrounds, e_sharing dst, uint32_t sharebitlen);
	uint32_t PutCallbackGate(vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);
	uint32_t GetGateHead() {
		return m_nNextFreeGate;
	}
	;
	uint32_t GetMaxVectorSize() {
		return m_nMaxVectorSize;
	}

	void FinishCircuitGeneration();

private:

	inline void InitGate(GATE* gate, e_gatetype type);
	inline void InitGate(GATE* gate, e_gatetype type, uint32_t ina);
	inline void InitGate(GATE* gate, e_gatetype type, uint32_t ina, uint32_t inb);
	inline void InitGate(GATE* gate, e_gatetype type, vector<uint32_t>& inputs);

	inline uint32_t GetNumRounds(e_gatetype type, e_sharing context);
	inline void MarkGateAsUsed(uint32_t gateid, uint32_t uses = 1);

	GATE* m_pGates;
	uint32_t m_nNextFreeGate;	// points to the current first unused gate
	uint32_t m_nMaxVectorSize; 	// The maximum vector size in bits, required for correctly instantiating the 0 and 1 gates
	uint32_t m_nMaxGates; 		// Maximal number of gates that is allowed
};

#endif /* __ABYCIRCUIT_H_ */
