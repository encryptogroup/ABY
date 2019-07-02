/**
 \file 		abycircuit.h
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
 \brief		ABYCircuit class.
 */
#ifndef __ABYCIRCUIT_H_
#define __ABYCIRCUIT_H_

#include <math.h>
#include <ENCRYPTO_utils/typedefs.h>
#include "../ABY_utils/ABYconstants.h"
#include <string>
#include <vector>
#include <fstream>
#include <limits.h>
#include <ENCRYPTO_utils/constants.h>
#include <ENCRYPTO_utils/utils.h>

//#define DEBUG_CIRCUIT_CONSTRUCTION

//A macro that defines whether a gate requires interaction
#define IsInteractive(gatetype, gatecontext) (!((gatecontext == C_ARITH && gatetype == G_ADD) || ((gatecontext == C_BOOL || gatecontext == C_YAO) && gatetype == G_XOR)) || (gatetype == G_MUL))
#define ComputeDepth(predecessor) ( (predecessor).depth + (predecessor).nrounds )

#define IsSIMDGate(gatetype) (!!((gatetype)&0x80))

struct GATE;

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
	bool copy_posids;
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

struct tt_gate {
	uint64_t* table;
	uint32_t noutputs;
};

/* Need backup of initial constant value for non-linear gates with constant, as
 * gs.val is set to 0 on CLIENT side. */
struct const_gate{
	UGATE_T* val; // same address as gs.val
	UGATE_T constval; // backup of initial constval
};

union gate_specific {
	//fields of the combiner gate
	uint32_t* cinput;
	//fields of the standard gate (pos)
	splitter_fields sinput;
	//fields of a yao's garbled circuit gate
	yao_fields yinput;
	//the evaluators key in Yao's garbled circuits
	BYTE* yval;
	//Arithmetic sharing values, a pointer to a uint16, uint32 or uint64 array with val_size elements
	UGATE_T* aval;
	//fields of the evaluated gate
	UGATE_T* val;
	//fields for the permutation gate. perm is a vector that first has the id i of the input gate and then the pos p of the input gate for n input gates (i_1,p_1,i_2,p_2,...,i_n,p_n)
	permutation_gate perm;
	//fields for the combinepos gate. combinepos first holds the position and then the ids of the input gates it combines
	combine_at_pos_gate combinepos;
	//value that is supposed to be shared
	input_fields ishare;
	//gate whose value is reconstructed
	output_fields oshare;
	//values for the subset gate which combines multiple different positions of one gate into another
	subset_gate sub_pos;
	//constant value of a gate
	UGATE_T constval;
	//struct of CONST gate with initial value backup
	const_gate constant;
	//specific field for the conversion type
	uint32_t pos;
	//callback routine that handles the evaluation. Functionality is defined by the developer
	callback_gate cbgate;
	//field that is used when vector ANDs are performed using SIMD gates
	and_vec_simd avs;
	//is used for structurized combiner gates
	struct_combine_gate struct_comb;
	//used for the G_TT gate where an arbitrary-sized truth-table is evaluated using OT
	tt_gate tt;
	//used for the PRINT VAL gate where the plaintext value of the gate is printed with the info string below
	const char* infostr;
	//used for the ASSERT gate where the plaintext value of the gate is checked against the plaintext value in assertval
	UGATE_T* assertval;
	//truth-table for the universal gate that identifies the operation that is performed. The first 4 bits identify the result of the truth-table
	uint32_t ttable;
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

std::string GetOpName(e_gatetype op);

struct non_lin_vec_ctx {
	uint32_t bitlen;
	uint32_t numgates;
};

struct tt_lens_ctx {
	uint32_t tt_len;
	uint32_t numgates;
	uint32_t out_bits;
        std::vector<uint64_t*> ttable_values;//only needed for OP-LUT, since the tables need to be known during the setup phase
};

uint32_t FindBitLenPositionInVec(uint32_t bitlen, non_lin_vec_ctx* list, uint32_t listentries);

class ABYCircuit {
public:
	ABYCircuit(uint32_t reservegates);
	virtual ~ABYCircuit() {
		Cleanup();
	}

	void Cleanup();
	void Reset();
	inline std::vector<GATE>& GatesVec() {
		return m_vGates;
	}

	uint32_t PutPrimitiveGate(e_gatetype type, uint32_t inleft, uint32_t inright, uint32_t rounds);
	uint32_t PutNonLinearVectorGate(e_gatetype type, uint32_t choiceinput, uint32_t vectorinput, uint32_t rounds);
	uint32_t PutCombinerGate(std::vector<uint32_t> input);
	uint32_t PutSplitterGate(uint32_t input, uint32_t pos, uint32_t bitlen);
        std::vector<uint32_t> PutSplitterGate(uint32_t input, std::vector<uint32_t> bitlen = std::vector<uint32_t>());		//, vector<uint32_t> gatelengths = NULL);
	uint32_t PutCombineAtPosGate(std::vector<uint32_t> input, uint32_t pos);
	uint32_t PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals_out, bool copy_posids);
	uint32_t PutStructurizedCombinerGate(std::vector<uint32_t> input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals);
	uint32_t PutRepeaterGate(uint32_t input, uint32_t nvals);
        std::vector<uint32_t> PutRepeaterGate(std::vector<uint32_t> input, uint32_t nvals);
	uint32_t PutPermutationGate(std::vector<uint32_t> input, uint32_t* positions);
	uint32_t PutUniversalGate(uint32_t a, uint32_t b, uint32_t op_id, uint32_t nrounds);

	uint32_t PutOUTGate(uint32_t in, e_role dst, uint32_t rounds);
        std::vector<uint32_t> PutOUTGate(std::vector<uint32_t> in, e_role dst, uint32_t rounds);

	uint32_t PutSharedOUTGate(uint32_t in);
        std::vector<uint32_t> PutSharedOUTGate(std::vector<uint32_t> in);

	uint32_t PutINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen, e_role src, uint32_t rounds);

	uint32_t PutSharedINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen);

	uint32_t PutConstantGate(e_sharing context, UGATE_T val, uint32_t nvals, uint32_t sharebitlen);
	uint32_t PutINVGate(uint32_t in);
	uint32_t PutCONVGate(std::vector<uint32_t> in, uint32_t nrounds, e_sharing dst, uint32_t sharebitlen);
	uint32_t PutCallbackGate(std::vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);
	uint32_t PutTruthTableGate(std::vector<uint32_t> in, uint32_t rounds, uint32_t out_bits, uint64_t* truth_table);
	uint32_t PutTruthTableMultiOutputGate(std::vector<uint32_t> in, uint32_t rounds, uint32_t out_bits, uint64_t* truth_table);


	uint32_t PutPrintValGate(std::vector<uint32_t> in, std::string infostr);
	uint32_t PutAssertGate(std::vector<uint32_t> in, uint32_t bitlen, UGATE_T* assert_val);

	uint32_t GetGateHead() {
		return m_vGates.size();
	}

	uint32_t GetTotalDepth() {
		return m_nMaxDepth + 1;
	}

	uint32_t GetMaxVectorSize() {
		return m_nMaxVectorSize;
	}

	//Export the constructed circuit in the Bristol circuit file format
	void ExportCircuitInBristolFormat(std::vector<uint32_t> ingates_client, std::vector<uint32_t> ingates_server,
			std::vector<uint32_t> outgates, const char* filename);

private:
	inline uint32_t currentGateId();
	inline GATE* InitGate(e_gatetype type);
	inline GATE* InitGate(e_gatetype type, uint32_t ina);
	inline GATE* InitGate(e_gatetype type, uint32_t ina, uint32_t inb);
	inline GATE* InitGate(e_gatetype type, std::vector<uint32_t>& inputs);

	inline uint32_t GetNumRounds(e_gatetype type, e_sharing context);
	inline void MarkGateAsUsed(uint32_t gateid, uint32_t uses = 1);

	void ExportGateInBristolFormat(uint32_t gateid, uint32_t& next_gate_id, std::vector<int>& gate_id_map,
			std::vector<int>& constant_map, std::ofstream& outfile);
	void CheckAndPropagateConstant(uint32_t gateid, uint32_t& next_gate_id, std::vector<int>& gate_id_map,
			std::vector<int>& constant_map, std::ofstream& outfile);

	std::vector<GATE> m_vGates;
	uint32_t m_nMaxVectorSize; 	// The maximum vector size in bits, required for correctly instantiating the 0 and 1 gates
	uint32_t m_nMaxDepth;	// maximum depth encountered in the circuit
};

#endif /* __ABYCIRCUIT_H_ */
