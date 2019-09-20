/**
 \file 		abycircuit.cpp
 \author 	michael.zohner@ec-spride.de
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
 \brief		Implementation of ABY Circuit Class.
 */

#include "abycircuit.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <vector>


void ABYCircuit::Cleanup() {
	Reset();
}

ABYCircuit::ABYCircuit(uint32_t reservegates) :
	m_nMaxVectorSize{1},
	m_nMaxDepth{0}
{
	m_vGates.reserve(reservegates);
}

/**
 * Gate ID of the just inserted gate
 */
inline uint32_t ABYCircuit::currentGateId() {
  return m_vGates.size() - 1;
}

inline GATE* ABYCircuit::InitGate(e_gatetype type) {
#ifdef DEBUG_CIRCUIT_CONSTRUCTION
	std::cout << "Putting new gate with type " << type << std::endl;
#endif
	// We abuse resize() to insert a new zero-initialized GATE struct at the end
	// of the gate vector
	m_vGates.resize(m_vGates.size() + 1);
	m_vGates.back().type = type;
	return &(m_vGates.back());
}

inline GATE* ABYCircuit::InitGate(e_gatetype type, uint32_t ina) {
	GATE* gate = InitGate(type);

	assert(ina < GetGateHead());
	gate->depth = ComputeDepth(m_vGates[ina]);
	m_nMaxDepth = std::max(m_nMaxDepth, gate->depth);
	gate->ingates.ningates = 1;
	gate->ingates.inputs.parent = ina;
	gate->context = m_vGates[ina].context;
	gate->sharebitlen = m_vGates[ina].sharebitlen;

	MarkGateAsUsed(ina);
	return gate;
}

inline GATE* ABYCircuit::InitGate(e_gatetype type, uint32_t ina, uint32_t inb) {
	GATE* gate = InitGate(type);

	if(ina >= GetGateHead() || inb >= GetGateHead()) {
		std::cout << "ina = " << ina << ", inb = " << inb << ", nfg = " << GetGateHead() << std::endl;
		assert(ina < GetGateHead() && inb < GetGateHead());

	}
	gate->depth = std::max(ComputeDepth(m_vGates[ina]), ComputeDepth(m_vGates[inb]));
	m_nMaxDepth = std::max(m_nMaxDepth, gate->depth);
	gate->ingates.ningates = 2;
	gate->ingates.inputs.twin.left = ina;
	gate->ingates.inputs.twin.right = inb;

	assert(m_vGates[ina].context == m_vGates[inb].context);
	assert(m_vGates[ina].sharebitlen == m_vGates[inb].sharebitlen);

	gate->context = m_vGates[ina].context;
	gate->sharebitlen = m_vGates[ina].sharebitlen;

	MarkGateAsUsed(ina);
	MarkGateAsUsed(inb);
	return gate;
}

inline GATE* ABYCircuit::InitGate(e_gatetype type, std::vector<uint32_t>& inputs) {
	GATE* gate = InitGate(type);
	gate->ingates.ningates = inputs.size();
	gate->depth = 0;

	if (inputs.size() == 0)
		return gate;
	uint32_t ina = inputs[0];
	assert(ina < GetGateHead());

	gate->depth = ComputeDepth(m_vGates[ina]);
	gate->ingates.inputs.parents = (uint32_t*) malloc(sizeof(uint32_t) * inputs.size());
	memcpy(gate->ingates.inputs.parents, inputs.data(), inputs.size() * sizeof(uint32_t));

	gate->context = m_vGates[ina].context;
	gate->sharebitlen = m_vGates[ina].sharebitlen;

	MarkGateAsUsed(ina);

	for (uint32_t i = 1; i < inputs.size(); i++) {
		assert(inputs[i] < GetGateHead());
		gate->depth = std::max(gate->depth, ComputeDepth(m_vGates[inputs[i]]));
		assert(gate->context == m_vGates[inputs[i]].context);
		assert(gate->sharebitlen == m_vGates[inputs[i]].sharebitlen);

		MarkGateAsUsed(inputs[i]);
	}
	m_nMaxDepth = std::max(m_nMaxDepth, gate->depth);
	return gate;
}

//Add a gate to m_vGates, increase the gateptr, used for G_LIN or G_NON_LIN
uint32_t ABYCircuit::PutPrimitiveGate(e_gatetype type, uint32_t inleft, uint32_t inright, uint32_t rounds) {

	GATE* gate = InitGate(type, inleft, inright);

	gate->nvals = std::min(m_vGates[inleft].nvals, m_vGates[inright].nvals);

	gate->nrounds = rounds;

#ifdef DEBUG_CIRCUIT_CONSTRUCTION
	std::cout << "New primitive gate with id: " << currentGateId() << ", left in = " << inleft << ", right in = " << inright << ", nvals = " << gate->nvals <<
	", depth = " << gate->depth << ", sharingsize = " << gate->sharebitlen << ", nrounds = " << gate->nrounds << std::endl;
#endif

	return currentGateId();
}

//add a vector-MT gate, mostly the same as a standard primitive gate but with explicit choiceinput / vectorinput
uint32_t ABYCircuit::PutNonLinearVectorGate(e_gatetype type, uint32_t choiceinput, uint32_t vectorinput, uint32_t rounds) {
	GATE* gate = InitGate(type, choiceinput, vectorinput);

	assert((m_vGates[vectorinput].nvals % m_vGates[choiceinput].nvals) == 0);

	gate->nvals = m_vGates[vectorinput].nvals;

	gate->nrounds = rounds;

	gate->gs.avs.bitlen = m_vGates[vectorinput].nvals / m_vGates[choiceinput].nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutCombinerGate(std::vector<uint32_t> input) {
	GATE* gate = InitGate(G_COMBINE, input);

	gate->nvals = 0;

	for(uint32_t i = 0; i < input.size(); i++) {
		//std::cout << "size at i = " << i << ": " << m_vGates[input[i]].nvals << std::endl;;
		gate->nvals += m_vGates[input[i]].nvals;
	}

	//std::cout << "Putting combiner gate with nvals = " << gate->nvals << std::endl;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}

//gatelenghts is defaulted to NULL
uint32_t ABYCircuit::PutSplitterGate(uint32_t input, uint32_t pos, uint32_t bitlen) {
	GATE* gate = InitGate(G_SPLIT, input);

	gate->gs.sinput.pos = pos;

	gate->nvals = bitlen;

	return currentGateId();
}

//gatelenghts is defaulted to NULL
std::vector<uint32_t> ABYCircuit::PutSplitterGate(uint32_t input, std::vector<uint32_t> bitlen) {

	uint32_t nvals = m_vGates[input].nvals;
	if(bitlen.size() == 0) {
		bitlen.resize(nvals, 1);
	}
	std::vector<uint32_t> outids(bitlen.size());

	uint32_t ctr = 0;
	for (uint32_t i = 0; i < bitlen.size(); i++) {
		outids[i] = PutSplitterGate(input, ctr, bitlen[i]);
		ctr += bitlen[i];
		//std::cout << "bitlen[" << i << "] = " << bitlen[i] << std::endl;
	}
	//std::cout << "ctr = " << ctr << ", nvals = " << nvals << std::endl;
	//this check is in theory not needed but remains here to notify the developer if a bit was missed
	assert(ctr == nvals);

	return outids;
}

uint32_t ABYCircuit::PutCombineAtPosGate(std::vector<uint32_t> input, uint32_t pos) {
	GATE* gate = InitGate(G_COMBINEPOS, input);

	gate->nvals = input.size();

	gate->gs.combinepos.pos = pos;

	for (uint32_t i = 0; i < input.size(); i++) {
		assert(pos < m_vGates[input[i]].nvals);
	}

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}


uint32_t ABYCircuit::PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals_out, bool copy_posids) {
	GATE* gate = InitGate(G_SUBSET, input);

	gate->nvals = nvals_out;

	//std::cout << "Putting subset gate with nvals = " << nvals << " on pos " << currentGateId() << std::endl;
	//assert(gate->nvals <= m_vGates[input].nvals);

	gate->gs.sub_pos.copy_posids = copy_posids;

	if(copy_posids) {
		gate->gs.sub_pos.posids = (uint32_t*) malloc(sizeof(uint32_t) * gate->nvals);
		memcpy(gate->gs.sub_pos.posids, posids, gate->nvals * sizeof(uint32_t));

	} else {
		gate->gs.sub_pos.posids = posids;
	}

	//std::cout << "copying to " << (uint64_t) gate->gs.sub_pos.posids << " from " << (uint64_t) posids << std::endl;
	//std::cout << "copied" << std::endl;

	//This check can be left out for performance reasons
	uint32_t inputnvals = m_vGates[input].nvals;
	for (uint32_t i = 0; i < gate->nvals; i++) {
		assert(posids[i] < inputnvals);
	}

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutStructurizedCombinerGate(std::vector<uint32_t> input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals) {
	GATE* gate = InitGate(G_STRUCT_COMBINE, input);

	gate->nvals = nvals;

	gate->gs.struct_comb.pos_start = pos_start;
	gate->gs.struct_comb.pos_incr= pos_incr;
	gate->gs.struct_comb.num_in_gates = input.size();

	/*std::cout << "From " << pos_start << " incr: " << pos_incr << " for " << nvals << " vals with max = ";
	for (uint32_t i = 0; i < input.size(); i++) {
		std::cout << m_vGates[input[i]].nvals << "; ";
		//assert(pos_start + ((nvals-1) * pos_incr) <= m_vGates[input[i]].nvals);
	}
	std::cout << std::endl;*/

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}


uint32_t ABYCircuit::PutRepeaterGate(uint32_t input, uint32_t nvals) {
	GATE* gate = InitGate(G_REPEAT, input);

	gate->nvals = nvals;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}

std::vector<uint32_t> ABYCircuit::PutRepeaterGate(std::vector<uint32_t> input, uint32_t nvals) {
	std::vector<uint32_t> out(input.size());
	for (uint32_t i = 0; i < input.size(); i++) {
		out[i] = PutRepeaterGate(input[i], nvals);
	}
	return out;
}

uint32_t ABYCircuit::PutPermutationGate(std::vector<uint32_t> input, uint32_t* positions) {
	GATE* gate = InitGate(G_PERM, input);

	gate->nvals = input.size();

	gate->gs.perm.posids = (uint32_t*) malloc(sizeof(uint32_t) * gate->nvals);

	for (uint32_t i = 0; i < input.size(); i++) {
		assert(positions[i] < m_vGates[input[i]].nvals);
		gate->gs.perm.posids[i] = positions[i];
	}

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutUniversalGate(uint32_t inleft, uint32_t inright, uint32_t op_id, uint32_t nrounds) {
	GATE* gate = InitGate(G_UNIV, inleft, inright);

	gate->nvals = std::min(m_vGates[inleft].nvals, m_vGates[inright].nvals);

	gate->nrounds = nrounds;
	gate->gs.ttable = op_id;

#ifdef DEBUG_CIRCUIT_CONSTRUCTION
	cout << "New Universal Gate with id: " << currentGateId() << ", left in = " << inleft << ", right in = " << inright << ", nvals = " << gate->nvals <<
	", depth = " << gate->depth << ", sharingsize = " << gate->sharebitlen << ", nrounds = " << gate->nrounds << ", and operation_id = " << op_id << endl;
#endif

	return currentGateId();
}

uint32_t ABYCircuit::PutOUTGate(uint32_t in, e_role dst, uint32_t rounds) {
	GATE* gate = InitGate(G_OUT, in);

	gate->nvals = m_vGates[in].nvals;

	gate->gs.oshare.dst = dst;

	gate->nrounds = rounds;

	return currentGateId();
}

uint32_t ABYCircuit::PutSharedOUTGate(uint32_t in) {
	GATE* gate = InitGate(G_SHARED_OUT, in);

	gate->nvals = m_vGates[in].nvals;

	gate->nrounds = 0;

	return currentGateId();
}

uint32_t ABYCircuit::PutINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen, e_role src, uint32_t rounds) {
	GATE* gate = InitGate(G_IN);
	gate->nvals = nvals;
	gate->depth = 0;

	gate->context = context;
	gate->sharebitlen = sharebitlen;
	gate->gs.ishare.src = src;

	gate->nrounds = rounds;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutSharedINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen) {
	GATE* gate = InitGate(G_SHARED_IN);
	gate->nvals = nvals;
	gate->depth = 0;

	gate->context = context;
	gate->sharebitlen = sharebitlen;

	gate->nrounds = 0;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutConstantGate(e_sharing context, UGATE_T val, uint32_t nvals, uint32_t sharebitlen) {
	assert(nvals > 0 && sharebitlen > 0);
	GATE* gate = InitGate(G_CONSTANT);
	gate->gs.constval = val;
	gate->depth = 0;
	gate->nvals = nvals;
	gate->context = context;
	gate->sharebitlen = sharebitlen;
	gate->nrounds = 0;

	if(gate->nvals > m_nMaxVectorSize) {
		m_nMaxVectorSize = gate->nvals;
	}
	return currentGateId();
}

uint32_t ABYCircuit::PutINVGate(uint32_t in) {
	GATE* gate = InitGate(G_INV, in);

	gate->nvals = m_vGates[in].nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutCONVGate(std::vector<uint32_t> in, uint32_t nrounds, e_sharing dst, uint32_t sharebitlen) {
	GATE* gate = InitGate(G_CONV, in);

	gate->sharebitlen = sharebitlen;
	gate->context = dst;
	gate->nrounds = nrounds;
	gate->nvals = m_vGates[in[0]].nvals;

	for (uint32_t i = 0; i < in.size(); i++) {
		assert(gate->nvals == m_vGates[in[i]].nvals);
	}
	return currentGateId();
}

std::vector<uint32_t> ABYCircuit::PutOUTGate(std::vector<uint32_t> in, e_role dst, uint32_t rounds) {
	std::vector<uint32_t> out(in.size());
	for (uint32_t i = 0; i < in.size(); i++) {
		out[i] = PutOUTGate(in[i], dst, rounds);
	}
	return out;
}

std::vector<uint32_t> ABYCircuit::PutSharedOUTGate(std::vector<uint32_t> in) {
	std::vector<uint32_t> out(in.size());
	for (uint32_t i = 0; i < in.size(); i++) {
		out[i] = PutSharedOUTGate(in[i]);
	}
	return out;
}

uint32_t ABYCircuit::PutCallbackGate(std::vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos,
		uint32_t nvals) {
	GATE* gate = InitGate(G_CALLBACK, in);

	gate->gs.cbgate.callback = callback;
	gate->gs.cbgate.infos = infos;

	gate->nrounds = rounds;

	gate->nvals = nvals;

	return currentGateId();
}

uint32_t ABYCircuit::PutTruthTableGate(std::vector<uint32_t> in, uint32_t rounds, uint32_t out_bits,
		uint64_t* truth_table) {
	GATE* gate = InitGate(G_TT, in);

	assert(in.size() < 32);
	assert(in.size() > 0);
	uint32_t tt_len = 1<<(in.size());

	gate->gs.tt.noutputs = out_bits;
	gate->gs.tt.table = (uint64_t*) malloc(bits_in_bytes(pad_to_multiple(tt_len, sizeof(UGATE_T)) * out_bits));
	memcpy(gate->gs.tt.table, truth_table, bits_in_bytes(pad_to_multiple(tt_len, sizeof(UGATE_T)) * out_bits));

	gate->nrounds = rounds;

	gate->nvals = m_vGates[in[0]].nvals*out_bits;
	for(uint32_t i = 1; i < in.size(); i++) {
		assert(gate->nvals/out_bits == m_vGates[in[i]].nvals);
	}

#ifdef DEBUGBOOL_NO_MT
	std::cout << "Putting TT gate at depth " << gate->depth << ", predec. ";
	for(uint32_t i = 0; i < in.size(); i++) {
		std::cout << i << ": " << get_gate_type_name(m_vGates[in[0]].type) << " has depth "
			<< m_vGates[in[0]].depth << " and rounds " << m_vGates[in[0]].nrounds << ", ";
	}
	std::cout << "my nvals = " << gate->nvals << " and " << out_bits << " output bits "<< std::endl;
#endif

	return currentGateId();
}

//TODO change gs.infostr to string
uint32_t ABYCircuit::PutPrintValGate(std::vector<uint32_t> in, std::string infostr) {
	GATE* gate = InitGate(G_PRINT_VAL, in);

	gate->nvals = m_vGates[in[0]].nvals;
	for(uint32_t i = 1; i < in.size(); i++) {
		assert(gate->nvals == m_vGates[in[i]].nvals);
	}

	// buffer is freed in Sharing::EvaluatePrintValGate
	auto buffer = new char[infostr.size() + 1];
	infostr.copy(buffer, infostr.size());
	buffer[infostr.size()] = '\0';
	gate->gs.infostr = buffer;

	return currentGateId();
}


uint32_t ABYCircuit::PutAssertGate(std::vector<uint32_t> in, uint32_t bitlen, UGATE_T* assert_val) {
	GATE* gate = InitGate(G_ASSERT, in);

	gate->nvals = m_vGates[in[0]].nvals;
	for(uint32_t i = 1; i < in.size(); i++) {
		assert(gate->nvals == m_vGates[in[i]].nvals);
	}

	//initialize a new block of memory and copy the assert_val into this block
	uint32_t ugatelen = ceil_divide(bitlen, sizeof(UGATE_T) * 8) * gate->nvals;
	gate->gs.assertval = (UGATE_T*) calloc(ugatelen, sizeof(UGATE_T));
	memcpy(gate->gs.assertval, assert_val, ugatelen * sizeof(UGATE_T));

	return currentGateId();
}



/*uint32_t ABYCircuit::PutTruthTableMultiOutputGate(std::vector<uint32_t> in, uint32_t rounds, uint32_t out_bits,
		uint64_t* truth_table) {
	std::vector<uint32_t> out(out_bits);
	uint64_t offset = ceil_divide((1<<in.size()), sizeof(uint64_t) * 8);
	assert(in.size() > 5);//Safety check for at least 64 truth table bits during development. Can be deleted but there needs to be a note that the next element is padded to the next multiple of 64


	//for(uint32_t i = 0; i < out_bits; i++) {
	//	out[i] = PutTruthTableGate(in, rounds, out_bits, truth_table + i * offset);
	//}



#ifdef DEBUGBOOL_NO_MT
	std::cout << "Putting mutli output TT gate at depth " << gate->depth << ", predec. ";
	for(uint32_t i = 0; i < in.size(); i++) {
		std::cout << i << ": " << get_gate_type_name(m_vGates[in[0]].type) << " has depth "
			<< m_vGates[in[0]].depth << " and rounds " << m_vGates[in[0]].nrounds << ", ";
	}
	std::cout << "my nvals = " << gate->nvals << std::endl;
#endif

	return out;
}*/


void ABYCircuit::ExportCircuitInBristolFormat(std::vector<uint32_t> ingates_client, std::vector<uint32_t> ingates_server,
		std::vector<uint32_t> outgates, const char* filename) {
	//Maps an ABY gate-id into a Bristol gate-id
	std::vector<int> gate_id_map(m_vGates.size(), -1);
	//The ABY output gates are not requried and the circuit has to make sure that the output gates appear last
	std::vector<uint32_t> outgate_map(outgates.size());
	//There are no constants in the Bristol circuit and hence they need to be propagated using this vector. Init with -1 to show that input is not a constant.
	std::vector<int> constant_map(m_vGates.size(), -1);
	//keeps track of the next free gate id in the Bristol circuit
	uint32_t bristol_gate_ctr = 0;
	//a temporary value for assigning the correct id to output gates
	uint32_t outgate_id;
	//counts the number of gates in the bristol circuit
	uint32_t total_bristol_gates = 0;
	//in case a formula computes an output gate, skip this gate
	bool out_gate_present;
	//create a new output file stream to which the circuit is written
	std::ofstream outfile(filename);
	//A gate that holds the zero value
	uint32_t zerogate = 0;

	if (!outfile.is_open()) {
		std::cerr << "Could not open circuit output file" << std::endl;
		return;
	}


	//The input gates for client and server are implicitly defined in the Bristol format and do not need to be given
	//First map the client inputs to gate ids 0 to (#client_in_size-1)
	for(uint32_t i = 0; i < ingates_client.size(); i++) {
		gate_id_map[ingates_client[i]] = i;
	}
	bristol_gate_ctr = ingates_client.size();

	//Next map the server inputs to gate ids #client_in_size to (#client_in_size+#server_in_size-1)
	for(uint32_t i = 0; i < ingates_server.size(); i++) {
		gate_id_map[ingates_server[i]] = i+bristol_gate_ctr;
	}
	bristol_gate_ctr += ingates_server.size();

	//TODO: Circuit export will fail if an output gate depends only on an input gate that is processed with only constant gates (which does not happen atm)

	//Remove the ABY output gates
	for(uint32_t i = 0; i < outgates.size(); i++) {
		outgate_map[i] = m_vGates[outgates[i]].ingates.inputs.parent;
	}

	//Check whether any input gates are also output gates. If so, create an extra XOR gate that evaluates to zero and give the output gates again
	uint32_t n_in_out_gates = 0;
	for(uint32_t i = 0; i < outgates.size(); i++) {
		bool skip = false;
		for(uint32_t j = 0; j < ingates_client.size() && !skip; j++) {
			if(outgate_map[i] == ingates_client[j]) {
				skip = true;
				n_in_out_gates++;
			}
		}
		for(uint32_t j = 0; j < ingates_server.size() && !skip; j++) {
			if(outgate_map[i] == ingates_server[j]) {
				skip = true;
				n_in_out_gates++;
			}
		}
		if(skip && zerogate == 0) {
			zerogate = bristol_gate_ctr++;
		}
	}

	total_bristol_gates = bristol_gate_ctr + n_in_out_gates;
	//count the total number of gates in the Bristol circuit prior to printing the circuit
	for(uint32_t i = 0; i < m_vGates.size(); i++) {
		if(m_vGates[i].type == G_LIN || m_vGates[i].type == G_NON_LIN || m_vGates[i].type == G_INV) {
			total_bristol_gates++;
		}
	}

	//Write the total number of non-input gates and total number of gates first
	outfile << total_bristol_gates - ingates_client.size() - ingates_server.size() << " " << total_bristol_gates << std::endl;
	//Write the number of client / server inputs and output gates
	outfile  << ingates_client.size() << " " << ingates_server.size() << "   " << outgates.size() << std::endl << std::endl;

	if(zerogate > 0) {
		outfile << "2 1 " << 0 << " " << 0 << " " << zerogate << " XOR"<< std::endl;
	}

	//First check whether any input gates are also part of the output. These gates will then be XORed with a zero value and output
	for(uint32_t i = 0; i < outgates.size(); i++) {
		bool skip = false;
		for(uint32_t j = 0; j < ingates_client.size() && !skip; j++) {
			if(outgate_map[i] == ingates_client[j]) {
				skip = true;
				outfile << "2 1 " << ingates_client[j] << " " << zerogate << " " << total_bristol_gates - outgate_map.size() + i << " XOR"<< std::endl;
			}
		}
		for(uint32_t j = 0; j < ingates_server.size() && !skip; j++) {
			if(outgate_map[i] == ingates_server[j]) {
				skip = true;
				outfile << "2 1 " << ingates_server[j] << " " << zerogate << " " << total_bristol_gates - outgate_map.size() + i << " XOR"<< std::endl;
			}
		}
	}

	//Now go through all gates in the ABY circuit
	for(uint32_t i = 0; i < m_vGates.size(); i++) {
		out_gate_present = false;
		//skip the output gates since they need to be in order for the Bristol file format
		for(uint32_t j = 0; j < outgate_map.size(); j++) {
			if (outgate_map[j] == i) {
				out_gate_present = true;
				outgate_id = total_bristol_gates - outgate_map.size() + j;
				continue;
			}
		}
		if(!out_gate_present) {
			ExportGateInBristolFormat(i, bristol_gate_ctr, gate_id_map, constant_map, outfile);
		} else  {
			ExportGateInBristolFormat(i, outgate_id, gate_id_map, constant_map, outfile);
		}
	}
	bristol_gate_ctr += outgate_map.size();

	outfile.close();
	std::cout << "Highest gate: " << bristol_gate_ctr << std::endl;
}

void ABYCircuit::ExportGateInBristolFormat(uint32_t gateid, uint32_t& next_gate_id, std::vector<int>& gate_id_map,
		std::vector<int>& constant_map, std::ofstream& outfile) {
	if(m_vGates[gateid].type == G_IN) {
				//Ignore input gates
	} else if(m_vGates[gateid].type == G_LIN) {
		//enter gate into map
		if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] + constant_map[m_vGates[gateid].ingates.inputs.twin.right] != -2) {
			CheckAndPropagateConstant(gateid, next_gate_id, gate_id_map, constant_map, outfile);
		} else {
			outfile << "2 1 " << gate_id_map[m_vGates[gateid].ingates.inputs.twin.left] << " " << gate_id_map[m_vGates[gateid].ingates.inputs.twin.right] << " " << next_gate_id << " XOR"<< std::endl;
			gate_id_map[gateid] = next_gate_id++;
		}
	} else if(m_vGates[gateid].type == G_NON_LIN) {
		if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] + constant_map[m_vGates[gateid].ingates.inputs.twin.right] != -2) {
			CheckAndPropagateConstant(gateid, next_gate_id, gate_id_map, constant_map, outfile);
		} else {
			outfile << "2 1 " << gate_id_map[m_vGates[gateid].ingates.inputs.twin.left] << " " << gate_id_map[m_vGates[gateid].ingates.inputs.twin.right] << " " << next_gate_id << " AND"<< std::endl;
			gate_id_map[gateid] = next_gate_id++;
		}
	} else if(m_vGates[gateid].type == G_INV) {
		if(constant_map[m_vGates[gateid].ingates.inputs.parent] != -1) {
			if(constant_map[m_vGates[gateid].ingates.inputs.parent] == 0) {
				constant_map[gateid] = constant_map[m_vGates[gateid].ingates.inputs.parent];
			} else {
				constant_map[gateid] = constant_map[m_vGates[gateid].ingates.inputs.parent] ^ 1;
			}
		} else {
			outfile << "1 1 " << gate_id_map[m_vGates[gateid].ingates.inputs.parent]  << " " << next_gate_id << " INV"<< std::endl;
			gate_id_map[gateid] = next_gate_id++;
		}
	} else if(m_vGates[gateid].type == G_CONSTANT) {
		assert(m_vGates[gateid].gs.constval == 0 || m_vGates[gateid].gs.constval == 1);
		constant_map[gateid] = m_vGates[gateid].gs.constval;
	} else if(m_vGates[gateid].type == G_OUT) {
		//Ignore input gates
	} else {
		std::cerr << "Gate type not available in Bristol format: " << get_gate_type_name(m_vGates[gateid].type) << ". Program exits. " << std::endl;
		outfile.close();
		std::exit(EXIT_FAILURE);
	}
}

void ABYCircuit::CheckAndPropagateConstant(uint32_t gateid, uint32_t& next_gate_id, std::vector<int>& gate_id_map,
		std::vector<int>& constant_map, std::ofstream& outfile) {

	//both gates are constant zero
	if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] == 0 && constant_map[m_vGates[gateid].ingates.inputs.twin.right] == 0) {
		constant_map[gateid] = 0;
		return;
	}

	//both gates are constant one
	if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] + constant_map[m_vGates[gateid].ingates.inputs.twin.right] == 2) {
		if(m_vGates[gateid].type == G_LIN) {
			constant_map[gateid] = 0;
		} else if( m_vGates[gateid].type == G_NON_LIN) {
			constant_map[gateid] = 1;
		}
		return;
	}

	//one gate is constant one, the second constant zero
	if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] + constant_map[m_vGates[gateid].ingates.inputs.twin.right] == 1) {
		if(m_vGates[gateid].type == G_LIN) {
			constant_map[gateid] = 1;
		} else if( m_vGates[gateid].type == G_NON_LIN) {
			constant_map[gateid] = 0;
		}
		return;
	}

	//one gate is has a constant zero, the other gate is not a constant
	if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] + constant_map[m_vGates[gateid].ingates.inputs.twin.right] == -1) {
		if(m_vGates[gateid].type == G_LIN) {
			if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] == -1) {
				gate_id_map[gateid] = gate_id_map[m_vGates[gateid].ingates.inputs.twin.left];
			} else {
				gate_id_map[gateid] = gate_id_map[m_vGates[gateid].ingates.inputs.twin.right];
			}
		} else if( m_vGates[gateid].type == G_NON_LIN) {
			constant_map[gateid] = 0;
		}
		return;
	}

	//one gate is has a constant one, the other gate is not a constant
	if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] + constant_map[m_vGates[gateid].ingates.inputs.twin.right] == 0) {
		if(m_vGates[gateid].type == G_LIN) {
			if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] == -1) {
				outfile << "1 1 " << gate_id_map[m_vGates[gateid].ingates.inputs.twin.left]  << " " << next_gate_id << " INV"<< std::endl;
				gate_id_map[gateid] = next_gate_id++;
			} else {
				outfile << "1 1 " << gate_id_map[m_vGates[gateid].ingates.inputs.twin.right]  << " " << next_gate_id << " INV"<< std::endl;
				gate_id_map[gateid] = next_gate_id++;
			}
		} else if( m_vGates[gateid].type == G_NON_LIN) {
			if(constant_map[m_vGates[gateid].ingates.inputs.twin.left] == -1) {
				gate_id_map[gateid] = gate_id_map[m_vGates[gateid].ingates.inputs.twin.left];
			} else {
				gate_id_map[gateid] = gate_id_map[m_vGates[gateid].ingates.inputs.twin.right];
			}
		}
		return;
	}
	//The code must have stopped before from one of the conditions
	assert(false);
	//std::cout << "Ran through code and missed something for " << constant_map[m_vGates[gateid].ingates.inputs.twin.left] << ", " <<  constant_map[m_vGates[gateid].ingates.inputs.twin.right] << std::endl;
}

inline void ABYCircuit::MarkGateAsUsed(uint32_t gateid, uint32_t uses) {
	m_vGates[gateid].nused += uses;
}



uint32_t FindBitLenPositionInVec(uint32_t bitlen, non_lin_vec_ctx* list, uint32_t listentries) {
	uint32_t pos = -1;
	for (uint32_t i = 0; i < listentries; i++) {
		if (list[i].bitlen == bitlen) {
			pos = i;
		}
	}
	return pos;
}

void ABYCircuit::Reset() {
	m_vGates.clear();
	m_nMaxVectorSize = 1;
	m_nMaxDepth = 0;
}
