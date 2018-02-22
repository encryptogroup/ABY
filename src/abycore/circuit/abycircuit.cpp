/**
 \file 		abycircuit.cpp
 \author 	michael.zohner@ec-spride.de
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
 \brief		Implementation of ABY Circuit Class.
 */

#include "abycircuit.h"

void ABYCircuit::Cleanup() {
	Reset();
	free(m_pGates);
}

ABYCircuit::ABYCircuit(uint32_t maxgates) {
	m_nMaxGates = maxgates;
	m_pGates = (GATE*) calloc(maxgates, sizeof(GATE));
	m_nNextFreeGate = 0;
	m_nMaxVectorSize = 1;
	m_nMaxDepth = 0;
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type) {
#ifdef DEBUG_CIRCUIT_CONSTRUCTION
	cout << "Putting new gate with type " << type << endl;
#endif
	if(m_nNextFreeGate >= m_nMaxGates) {
		cerr << "I have more gates than available: " << m_nNextFreeGate << endl;
	}
	assert(m_nNextFreeGate < m_nMaxGates);

	gate->type = type;
	gate->nused = 0;
	gate->nrounds = 0;
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type, uint32_t ina) {
	InitGate(gate, type);

	assert(ina < m_nNextFreeGate);
	gate->depth = ComputeDepth(m_pGates[ina]);
	m_nMaxDepth = max(m_nMaxDepth, gate->depth);
	gate->ingates.ningates = 1;
	gate->ingates.inputs.parent = ina;
	gate->context = m_pGates[ina].context;
	gate->sharebitlen = m_pGates[ina].sharebitlen;

	MarkGateAsUsed(ina);
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type, uint32_t ina, uint32_t inb) {
	InitGate(gate, type);

	if(ina >= m_nNextFreeGate || inb >= m_nNextFreeGate) {
		cout << "ina = " << ina << ", inb = " << inb << ", nfg = " << m_nNextFreeGate << endl;
		assert(ina < m_nNextFreeGate && inb < m_nNextFreeGate);

	}
	gate->depth = max(ComputeDepth(m_pGates[ina]), ComputeDepth(m_pGates[inb]));
	m_nMaxDepth = max(m_nMaxDepth, gate->depth);
	gate->ingates.ningates = 2;
	gate->ingates.inputs.twin.left = ina;
	gate->ingates.inputs.twin.right = inb;

	assert(m_pGates[ina].context == m_pGates[inb].context);
	assert(m_pGates[ina].sharebitlen == m_pGates[inb].sharebitlen);

	gate->context = m_pGates[ina].context;
	gate->sharebitlen = m_pGates[ina].sharebitlen;

	MarkGateAsUsed(ina);
	MarkGateAsUsed(inb);
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type, vector<uint32_t>& inputs) {
	InitGate(gate, type);
	gate->ingates.ningates = inputs.size();
	gate->depth = 0;

	if (inputs.size() == 0)
		return;
	uint32_t ina = inputs[0];
	assert(ina < m_nNextFreeGate);

	gate->depth = ComputeDepth(m_pGates[ina]);
	gate->ingates.inputs.parents = (uint32_t*) malloc(sizeof(uint32_t) * inputs.size());
	memcpy(gate->ingates.inputs.parents, inputs.data(), inputs.size() * sizeof(uint32_t));

	gate->context = m_pGates[ina].context;
	gate->sharebitlen = m_pGates[ina].sharebitlen;

	MarkGateAsUsed(ina);

	for (uint32_t i = 1; i < inputs.size(); i++) {
		assert(inputs[i] < m_nNextFreeGate);
		gate->depth = max(gate->depth, ComputeDepth(m_pGates[inputs[i]]));
		assert(gate->context == m_pGates[inputs[i]].context);
		assert(gate->sharebitlen == m_pGates[inputs[i]].sharebitlen);

		MarkGateAsUsed(inputs[i]);
	}
	m_nMaxDepth = max(m_nMaxDepth, gate->depth);
}

//Add a gate to m_pGates, increase the gateptr, used for G_LIN or G_NON_LIN
uint32_t ABYCircuit::PutPrimitiveGate(e_gatetype type, uint32_t inleft, uint32_t inright, uint32_t rounds) {

	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, type, inleft, inright);

	gate->nvals = min(m_pGates[inleft].nvals, m_pGates[inright].nvals);

	gate->nrounds = rounds;

#ifdef DEBUG_CIRCUIT_CONSTRUCTION
	cout << "New primitive gate with id: " << m_nNextFreeGate << ", left in = " << inleft << ", right in = " << inright << ", nvals = " << gate->nvals <<
	", depth = " << gate->depth << ", sharingsize = " << gate->sharebitlen << ", nrounds = " << gate->nrounds << ", and mindepth = " << mindepth << endl;
#endif

	return m_nNextFreeGate++;
}

//add a vector-MT gate, mostly the same as a standard primitive gate but with explicit choiceinput / vectorinput
uint32_t ABYCircuit::PutNonLinearVectorGate(e_gatetype type, uint32_t choiceinput, uint32_t vectorinput, uint32_t rounds) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, type, choiceinput, vectorinput);

	assert((m_pGates[vectorinput].nvals % m_pGates[choiceinput].nvals) == 0);

	gate->nvals = m_pGates[vectorinput].nvals;

	gate->nrounds = rounds;

	gate->gs.avs.bitlen = m_pGates[vectorinput].nvals / m_pGates[choiceinput].nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutCombinerGate(vector<uint32_t> input) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_COMBINE, input);

	gate->nvals = 0;

	for(uint32_t i = 0; i < input.size(); i++) {
		//cout << "size at i = " << i << ": " << m_pGates[input[i]].nvals << endl;;
		gate->nvals += m_pGates[input[i]].nvals;
	}

	//cout << "Putting combiner gate with nvals = " << gate->nvals << endl;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

//gatelenghts is defaulted to NULL
uint32_t ABYCircuit::PutSplitterGate(uint32_t input, uint32_t pos, uint32_t bitlen) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_SPLIT, input);

	gate->gs.sinput.pos = pos;

	gate->nvals = bitlen;

	return m_nNextFreeGate++;
}

//gatelenghts is defaulted to NULL
vector<uint32_t> ABYCircuit::PutSplitterGate(uint32_t input, vector<uint32_t> bitlen) {

	uint32_t nvals = m_pGates[input].nvals;
	if(bitlen.size() == 0) {
		bitlen.resize(nvals, 1);
	}
	vector<uint32_t> outids(bitlen.size());

	uint32_t ctr = 0;
	for (uint32_t i = 0; i < bitlen.size(); i++) {
		/*GATE* gate = m_pGates + m_nNextFreeGate;
		outids[i] = m_nNextFreeGate;
		InitGate(gate, G_SPLIT, input);

		gate->gs.sinput.pos = ctr;

		gate->nvals = 1;

		ctr += gate->nvals;
		m_nNextFreeGate++;*/
		outids[i] = PutSplitterGate(input, ctr, bitlen[i]);
		ctr += bitlen[i];
		//cout << "bitlen[" << i << "] = " << bitlen[i] << endl;
	}
	//cout << "ctr = " << ctr << ", nvals = " << nvals << endl;
	//this check is in theory not needed but remains here to notify the developer if a bit was missed
	assert(ctr == nvals);

	return outids;
}

uint32_t ABYCircuit::PutCombineAtPosGate(vector<uint32_t> input, uint32_t pos) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_COMBINEPOS, input);

	gate->nvals = input.size();

	gate->gs.combinepos.pos = pos;

	for (uint32_t i = 0; i < input.size(); i++) {
		assert(pos < m_pGates[input[i]].nvals);
	}

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}


uint32_t ABYCircuit::PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals_out, bool copy_posids) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_SUBSET, input);

	gate->nvals = nvals_out;

	//cout << "Putting subset gate with nvals = " << nvals << " on pos " << m_nNextFreeGate << endl;
	//assert(gate->nvals <= m_pGates[input].nvals);

	gate->gs.sub_pos.copy_posids = copy_posids;

	if(copy_posids) {
		gate->gs.sub_pos.posids = (uint32_t*) malloc(sizeof(uint32_t) * gate->nvals);
		memcpy(gate->gs.sub_pos.posids, posids, gate->nvals * sizeof(uint32_t));

	} else {
		gate->gs.sub_pos.posids = posids;
	}

	//cout << "copying to " << (uint64_t) gate->gs.sub_pos.posids << " from " << (uint64_t) posids << endl;
	//cout << "copied" << endl;

	//This check can be left out for performance reasons
	uint32_t inputnvals = m_pGates[input].nvals;
	for (uint32_t i = 0; i < gate->nvals; i++) {
		assert(posids[i] < inputnvals);
	}

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutStructurizedCombinerGate(vector<uint32_t> input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_STRUCT_COMBINE, input);

	gate->nvals = nvals;

	gate->gs.struct_comb.pos_start = pos_start;
	gate->gs.struct_comb.pos_incr= pos_incr;
	gate->gs.struct_comb.num_in_gates = input.size();

	/*cout << "From " << pos_start << " incr: " << pos_incr << " for " << nvals << " vals with max = ";
	for (uint32_t i = 0; i < input.size(); i++) {
		cout << m_pGates[input[i]].nvals << "; ";
		//assert(pos_start + ((nvals-1) * pos_incr) <= m_pGates[input[i]].nvals);
	}
	cout << endl;*/

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}


uint32_t ABYCircuit::PutRepeaterGate(uint32_t input, uint32_t nvals) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_REPEAT, input);

	gate->nvals = nvals;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

vector<uint32_t> ABYCircuit::PutRepeaterGate(vector<uint32_t> input, uint32_t nvals) {
	vector<uint32_t> out(input.size());
	for (uint32_t i = 0; i < input.size(); i++) {
		out[i] = PutRepeaterGate(input[i], nvals);
	}
	return out;
}

uint32_t ABYCircuit::PutPermutationGate(vector<uint32_t> input, uint32_t* positions) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_PERM, input);

	gate->nvals = input.size();

	gate->gs.perm.posids = (uint32_t*) malloc(sizeof(uint32_t) * gate->nvals);

	for (uint32_t i = 0; i < input.size(); i++) {
		assert(positions[i] < m_pGates[input[i]].nvals);
		gate->gs.perm.posids[i] = positions[i];
	}

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutOUTGate(uint32_t in, e_role dst, uint32_t rounds) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_OUT, in);

	gate->nvals = m_pGates[in].nvals;

	gate->gs.oshare.dst = dst;

	gate->nrounds = rounds;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutSharedOUTGate(uint32_t in) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_SHARED_OUT, in);

	gate->nvals = m_pGates[in].nvals;

	gate->nrounds = 0;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen, e_role src, uint32_t rounds) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_IN);
	gate->nvals = nvals;
	gate->depth = 0;

	gate->context = context;
	gate->sharebitlen = sharebitlen;
	gate->gs.ishare.src = src;

	gate->nrounds = rounds;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutSharedINGate(e_sharing context, uint32_t nvals, uint32_t sharebitlen) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_SHARED_IN);
	gate->nvals = nvals;
	gate->depth = 0;

	gate->context = context;
	gate->sharebitlen = sharebitlen;

	gate->nrounds = 0;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutConstantGate(e_sharing context, UGATE_T val, uint32_t nvals, uint32_t sharebitlen) {
	assert(nvals > 0 && sharebitlen > 0);
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_CONSTANT);
	gate->gs.constval = val;
	gate->depth = 0;
	gate->nvals = nvals;
	gate->context = context;
	gate->sharebitlen = sharebitlen;
	gate->nrounds = 0;

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutINVGate(uint32_t in) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_INV, in);

	gate->nvals = m_pGates[in].nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutCONVGate(vector<uint32_t> in, uint32_t nrounds, e_sharing dst, uint32_t sharebitlen) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_CONV, in);

	gate->sharebitlen = sharebitlen;
	gate->context = dst;
	gate->nrounds = nrounds;
	gate->nvals = m_pGates[in[0]].nvals;

	for (uint32_t i = 0; i < in.size(); i++) {
		assert(gate->nvals == m_pGates[in[i]].nvals);
	}
	return m_nNextFreeGate++;
}

vector<uint32_t> ABYCircuit::PutOUTGate(vector<uint32_t> in, e_role dst, uint32_t rounds) {
	vector<uint32_t> out(in.size());
	for (uint32_t i = 0; i < in.size(); i++) {
		out[i] = PutOUTGate(in[i], dst, rounds);
	}
	return out;
}

vector<uint32_t> ABYCircuit::PutSharedOUTGate(vector<uint32_t> in) {
	vector<uint32_t> out(in.size());
	for (uint32_t i = 0; i < in.size(); i++) {
		out[i] = PutSharedOUTGate(in[i]);
	}
	return out;
}

uint32_t ABYCircuit::PutCallbackGate(vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos,
		uint32_t nvals) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_CALLBACK, in);

	gate->gs.cbgate.callback = callback;
	gate->gs.cbgate.infos = infos;

	gate->nrounds = rounds;

	gate->nvals = nvals;

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutTruthTableGate(vector<uint32_t> in, uint32_t rounds, uint32_t out_bits,
		uint64_t* truth_table) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_TT, in);

	assert(in.size() < 32);
	assert(in.size() > 0);
	uint32_t tt_len = 1<<(in.size());

	gate->gs.tt.noutputs = out_bits;
	gate->gs.tt.table = (uint64_t*) malloc(bits_in_bytes(pad_to_multiple(tt_len, sizeof(UGATE_T)) * out_bits));
	memcpy(gate->gs.tt.table, truth_table, bits_in_bytes(pad_to_multiple(tt_len, sizeof(UGATE_T)) * out_bits));

	gate->nrounds = rounds;

	gate->nvals = m_pGates[in[0]].nvals*out_bits;
	for(uint32_t i = 1; i < in.size(); i++) {
		assert(gate->nvals/out_bits == m_pGates[in[i]].nvals);
	}

#ifdef DEBUGBOOL_NO_MT
	cout << "Putting TT gate at depth " << gate->depth << ", predec. ";
	for(uint32_t i = 0; i < in.size(); i++) {
		cout << i << ": " << get_gate_type_name(m_pGates[in[0]].type) << " has depth "
			<< m_pGates[in[0]].depth << " and rounds " << m_pGates[in[0]].nrounds << ", ";
	}
	cout << "my nvals = " << gate->nvals << " and " << out_bits << " output bits "<< endl;
#endif

	return m_nNextFreeGate++;
}

uint32_t ABYCircuit::PutPrintValGate(vector<uint32_t> in, string infostr) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_PRINT_VAL, in);

	gate->nvals = m_pGates[in[0]].nvals;
	for(uint32_t i = 1; i < in.size(); i++) {
		assert(gate->nvals == m_pGates[in[i]].nvals);
	}

	char* tmp = (char*) malloc(sizeof(char*) * (infostr.size() + 1));
	memcpy(tmp, infostr.c_str(), infostr.size());
	tmp[infostr.size()]='\0';
	gate->gs.infostr = (const char*) tmp;

	return m_nNextFreeGate++;
}


uint32_t ABYCircuit::PutAssertGate(vector<uint32_t> in, uint32_t bitlen, UGATE_T* assert_val) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_ASSERT, in);

	gate->nvals = m_pGates[in[0]].nvals;
	for(uint32_t i = 1; i < in.size(); i++) {
		assert(gate->nvals == m_pGates[in[i]].nvals);
	}

	//initialize a new block of memory and copy the assert_val into this block
	uint32_t ugatelen = ceil_divide(bitlen, sizeof(UGATE_T) * 8) * gate->nvals;
	gate->gs.assertval = (UGATE_T*) calloc(ugatelen, sizeof(UGATE_T));
	memcpy(gate->gs.assertval, assert_val, ugatelen * sizeof(UGATE_T));

	return m_nNextFreeGate++;
}



/*uint32_t ABYCircuit::PutTruthTableMultiOutputGate(vector<uint32_t> in, uint32_t rounds, uint32_t out_bits,
		uint64_t* truth_table) {
	vector<uint32_t> out(out_bits);
	uint64_t offset = ceil_divide((1<<in.size()), sizeof(uint64_t) * 8);
	assert(in.size() > 5);//Safety check for at least 64 truth table bits during development. Can be deleted but there needs to be a note that the next element is padded to the next multiple of 64


	//for(uint32_t i = 0; i < out_bits; i++) {
	//	out[i] = PutTruthTableGate(in, rounds, out_bits, truth_table + i * offset);
	//}



#ifdef DEBUGBOOL_NO_MT
	cout << "Putting mutli output TT gate at depth " << gate->depth << ", predec. ";
	for(uint32_t i = 0; i < in.size(); i++) {
		cout << i << ": " << get_gate_type_name(m_pGates[in[0]].type) << " has depth "
			<< m_pGates[in[0]].depth << " and rounds " << m_pGates[in[0]].nrounds << ", ";
	}
	cout << "my nvals = " << gate->nvals << endl;
#endif

	return out;
}*/


void ABYCircuit::ExportCircuitInBristolFormat(vector<uint32_t> ingates_client, vector<uint32_t> ingates_server,
		vector<uint32_t> outgates, const char* filename) {
	//Maps an ABY gate-id into a Bristol gate-id
	vector<int> gate_id_map(m_nNextFreeGate, -1);
	//The ABY output gates are not requried and the circuit has to make sure that the output gates appear last
	vector<uint32_t> outgate_map(outgates.size());
	//There are no constants in the Bristol circuit and hence they need to be propagated using this vector. Init with -1 to show that input is not a constant.
	vector<int> constant_map(m_nNextFreeGate, -1);
	//keeps track of the next free gate id in the Bristol circuit
	uint32_t bristol_gate_ctr = 0;
	//a temporary value for assigning the correct id to output gates
	uint32_t outgate_id;
	//counts the number of gates in the bristol circuit
	uint32_t total_bristol_gates = 0;
	//in case a formula computes an output gate, skip this gate
	bool out_gate_present;
	//create a new output file stream to which the circuit is written
	ofstream outfile(filename);
	//A gate that holds the zero value
	uint32_t zerogate = 0;

	if (!outfile.is_open()) {
		cerr << "Could not open circuit output file" << endl;
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
		outgate_map[i] = m_pGates[outgates[i]].ingates.inputs.parent;
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
	for(uint32_t i = 0; i < m_nNextFreeGate; i++) {
		if(m_pGates[i].type == G_LIN || m_pGates[i].type == G_NON_LIN || m_pGates[i].type == G_INV) {
			total_bristol_gates++;
		}
	}

	//Write the total number of non-input gates and total number of gates first
	outfile << total_bristol_gates - ingates_client.size() - ingates_server.size() << " " << total_bristol_gates << endl;
	//Write the number of client / server inputs and output gates
	outfile  << ingates_client.size() << " " << ingates_server.size() << "   " << outgates.size() << endl << endl;

	if(zerogate > 0) {
		outfile << "2 1 " << 0 << " " << 0 << " " << zerogate << " XOR"<< endl;
	}

	//First check whether any input gates are also part of the output. These gates will then be XORed with a zero value and output
	for(uint32_t i = 0; i < outgates.size(); i++) {
		bool skip = false;
		for(uint32_t j = 0; j < ingates_client.size() && !skip; j++) {
			if(outgate_map[i] == ingates_client[j]) {
				skip = true;
				outfile << "2 1 " << ingates_client[j] << " " << zerogate << " " << total_bristol_gates - outgate_map.size() + i << " XOR"<< endl;
			}
		}
		for(uint32_t j = 0; j < ingates_server.size() && !skip; j++) {
			if(outgate_map[i] == ingates_server[j]) {
				skip = true;
				outfile << "2 1 " << ingates_server[j] << " " << zerogate << " " << total_bristol_gates - outgate_map.size() + i << " XOR"<< endl;
			}
		}
	}

	//Now go through all gates in the ABY circuit
	for(uint32_t i = 0; i < m_nNextFreeGate; i++) {
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
	cout << "Highest gate: " << bristol_gate_ctr << endl;
}

void ABYCircuit::ExportGateInBristolFormat(uint32_t gateid, uint32_t& next_gate_id, vector<int>& gate_id_map,
		vector<int>& constant_map, ofstream& outfile) {
	if(m_pGates[gateid].type == G_IN) {
				//Ignore input gates
	} else if(m_pGates[gateid].type == G_LIN) {
		//enter gate into map
		if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] + constant_map[m_pGates[gateid].ingates.inputs.twin.right] != -2) {
			CheckAndPropagateConstant(gateid, next_gate_id, gate_id_map, constant_map, outfile);
		} else {
			outfile << "2 1 " << gate_id_map[m_pGates[gateid].ingates.inputs.twin.left] << " " << gate_id_map[m_pGates[gateid].ingates.inputs.twin.right] << " " << next_gate_id << " XOR"<< endl;
			gate_id_map[gateid] = next_gate_id++;
		}
	} else if(m_pGates[gateid].type == G_NON_LIN) {
		if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] + constant_map[m_pGates[gateid].ingates.inputs.twin.right] != -2) {
			CheckAndPropagateConstant(gateid, next_gate_id, gate_id_map, constant_map, outfile);
		} else {
			outfile << "2 1 " << gate_id_map[m_pGates[gateid].ingates.inputs.twin.left] << " " << gate_id_map[m_pGates[gateid].ingates.inputs.twin.right] << " " << next_gate_id << " AND"<< endl;
			gate_id_map[gateid] = next_gate_id++;
		}
	} else if(m_pGates[gateid].type == G_INV) {
		if(constant_map[m_pGates[gateid].ingates.inputs.parent] != -1) {
			if(constant_map[m_pGates[gateid].ingates.inputs.parent] == 0) {
				constant_map[gateid] = constant_map[m_pGates[gateid].ingates.inputs.parent];
			} else {
				constant_map[gateid] = constant_map[m_pGates[gateid].ingates.inputs.parent] ^ 1;
			}
		} else {
			outfile << "1 1 " << gate_id_map[m_pGates[gateid].ingates.inputs.parent]  << " " << next_gate_id << " INV"<< endl;
			gate_id_map[gateid] = next_gate_id++;
		}
	} else if(m_pGates[gateid].type == G_CONSTANT) {
		assert(m_pGates[gateid].gs.constval == 0 || m_pGates[gateid].gs.constval == 1);
		constant_map[gateid] = m_pGates[gateid].gs.constval;
	} else if(m_pGates[gateid].type == G_OUT) {
		//Ignore input gates
	} else {
		cerr << "Gate type not available in Bristol format: " << get_gate_type_name(m_pGates[gateid].type) << ". Program exits. " << endl;
		outfile.close();
		exit(0);
	}
}

void ABYCircuit::CheckAndPropagateConstant(uint32_t gateid, uint32_t& next_gate_id, vector<int>& gate_id_map,
		vector<int>& constant_map, ofstream& outfile) {

	//both gates are constant zero
	if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] == 0 && constant_map[m_pGates[gateid].ingates.inputs.twin.right] == 0) {
		constant_map[gateid] = 0;
		return;
	}

	//both gates are constant one
	if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] + constant_map[m_pGates[gateid].ingates.inputs.twin.right] == 2) {
		if(m_pGates[gateid].type == G_LIN) {
			constant_map[gateid] = 0;
		} else if( m_pGates[gateid].type == G_NON_LIN) {
			constant_map[gateid] = 1;
		}
		return;
	}

	//one gate is constant one, the second constant zero
	if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] + constant_map[m_pGates[gateid].ingates.inputs.twin.right] == 1) {
		if(m_pGates[gateid].type == G_LIN) {
			constant_map[gateid] = 1;
		} else if( m_pGates[gateid].type == G_NON_LIN) {
			constant_map[gateid] = 0;
		}
		return;
	}

	//one gate is has a constant zero, the other gate is not a constant
	if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] + constant_map[m_pGates[gateid].ingates.inputs.twin.right] == -1) {
		if(m_pGates[gateid].type == G_LIN) {
			if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] == -1) {
				gate_id_map[gateid] = gate_id_map[m_pGates[gateid].ingates.inputs.twin.left];
			} else {
				gate_id_map[gateid] = gate_id_map[m_pGates[gateid].ingates.inputs.twin.right];
			}
		} else if( m_pGates[gateid].type == G_NON_LIN) {
			constant_map[gateid] = 0;
		}
		return;
	}

	//one gate is has a constant one, the other gate is not a constant
	if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] + constant_map[m_pGates[gateid].ingates.inputs.twin.right] == 0) {
		if(m_pGates[gateid].type == G_LIN) {
			if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] == -1) {
				outfile << "1 1 " << gate_id_map[m_pGates[gateid].ingates.inputs.twin.left]  << " " << next_gate_id << " INV"<< endl;
				gate_id_map[gateid] = next_gate_id++;
			} else {
				outfile << "1 1 " << gate_id_map[m_pGates[gateid].ingates.inputs.twin.right]  << " " << next_gate_id << " INV"<< endl;
				gate_id_map[gateid] = next_gate_id++;
			}
		} else if( m_pGates[gateid].type == G_NON_LIN) {
			if(constant_map[m_pGates[gateid].ingates.inputs.twin.left] == -1) {
				gate_id_map[gateid] = gate_id_map[m_pGates[gateid].ingates.inputs.twin.left];
			} else {
				gate_id_map[gateid] = gate_id_map[m_pGates[gateid].ingates.inputs.twin.right];
			}
		}
		return;
	}
	//The code must have stopped before from one of the conditions
	assert(false);
	//cout << "Ran through code and missed something for " << constant_map[m_pGates[gateid].ingates.inputs.twin.left] << ", " <<  constant_map[m_pGates[gateid].ingates.inputs.twin.right] << endl;
}

inline void ABYCircuit::MarkGateAsUsed(uint32_t gateid, uint32_t uses) {
	m_pGates[gateid].nused += uses;
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
	memset(m_pGates, 0, sizeof(GATE) * m_nMaxGates);
	m_nNextFreeGate = 0;
	m_nMaxVectorSize = 1;
	m_nMaxDepth = 0;
}
