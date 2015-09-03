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
	//TODO
	free(m_pGates);
}

ABYCircuit::ABYCircuit(uint32_t maxgates) {
	m_nMaxGates = maxgates;
	m_pGates = (GATE*) calloc(maxgates, sizeof(GATE));
	m_nNextFreeGate = 0;
	m_nMaxVectorSize = 1;
	//TODO: Init gate 0 and 1 as constant gates
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type) {
#ifdef DEBUG_CIRCUIT_CONSTRUCTION
	cout << "Putting new gate with type " << type << endl;
#endif
	assert(m_nNextFreeGate < m_nMaxGates);

	gate->type = type;
	gate->nused = 0;
	gate->nrounds = 0;
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type, uint32_t ina) {
	InitGate(gate, type);

	assert(ina < m_nNextFreeGate);
	gate->depth = ComputeDepth(m_pGates[ina]);
	gate->ingates.ningates = 1;
	gate->ingates.inputs.parent = ina;
	gate->context = m_pGates[ina].context;
	gate->sharebitlen = m_pGates[ina].sharebitlen;

	MarkGateAsUsed(ina);
}

inline void ABYCircuit::InitGate(GATE* gate, e_gatetype type, uint32_t ina, uint32_t inb) {
	InitGate(gate, type);

	assert(ina < m_nNextFreeGate && inb < m_nNextFreeGate);

	gate->depth = max(ComputeDepth(m_pGates[ina]), ComputeDepth(m_pGates[inb]));
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

	gate->nvals = input.size();

	if (gate->nvals > m_nMaxVectorSize)
		m_nMaxVectorSize = gate->nvals;

	return m_nNextFreeGate++;
}

//gatelenghts is defaulted to NULL
vector<uint32_t> ABYCircuit::PutSplitterGate(uint32_t input) {

	uint32_t nvals;
	nvals = m_pGates[input].nvals;
	vector<uint32_t> outids(nvals);

	for (uint32_t i = 0, ctr = 0; i < nvals; i++) {
		GATE* gate = m_pGates + m_nNextFreeGate;
		outids[i] = m_nNextFreeGate;
		InitGate(gate, G_SPLIT, input);

		gate->gs.sinput.pos = ctr;

		gate->nvals = 1;

		ctr += gate->nvals;
		m_nNextFreeGate++;
	}

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


uint32_t ABYCircuit::PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals) {
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_SUBSET, input);

	gate->nvals = nvals;

	//cout << "Putting subset gate with nvals = " << nvals << " on pos " << m_nNextFreeGate << endl;
	//assert(gate->nvals <= m_pGates[input].nvals);

	gate->gs.sub_pos.posids = (uint32_t*) malloc(sizeof(uint32_t) * gate->nvals);

	//cout << "copying to " << (uint64_t) gate->gs.sub_pos.posids << " from " << (uint64_t) posids << endl;
	memcpy(gate->gs.sub_pos.posids, posids, gate->nvals * sizeof(uint32_t));
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

uint32_t ABYCircuit::PutConstantGate(e_sharing context, UGATE_T val, uint32_t nvals, uint32_t sharebitlen) {
	assert(nvals > 0 && sharebitlen > 0);
	GATE* gate = m_pGates + m_nNextFreeGate;
	InitGate(gate, G_CONSTANT);
	gate->gs.constval = val;
	gate->depth = 0;
	gate->nvals = nvals;
	gate->context = context;
	gate->sharebitlen = sharebitlen;
	//TODO the evaluation of constant gates is not working correctly if the depth is set to 0, change!
	gate->nrounds = 1;

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

//Perform some last administrative tasks
void ABYCircuit::FinishCircuitGeneration() {
	for (uint32_t i = 0; i < m_nNextFreeGate; i++) {
		if (m_pGates[i].nvals == INT_MAX) {
			m_pGates[i].nvals = m_nMaxVectorSize;
			cerr << "Found a max uint32_t at gate " << i << ". Cant guarantee that circuit will be evaluated properly" << endl;
			assert(m_pGates[i].nvals != INT_MAX);
		}
	}
#ifndef BATCH
	cout << "total gates: " << m_nNextFreeGate << endl;
#endif
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
	//TODO: causes segfault in Boolean sharing if only one party gets output, fix!
	/*for(uint32_t i = 0; i < m_nNextFreeGate; i++) {
	 if(m_pGates[i].type == G_OUT)
	 free(m_pGates[i].gs.val);
	 }*/
	memset(m_pGates, 0, sizeof(GATE) * m_nMaxGates);
	m_nNextFreeGate = 0;
	m_nMaxVectorSize = 1;
}
