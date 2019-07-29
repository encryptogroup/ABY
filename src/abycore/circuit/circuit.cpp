/**
 \file 		circuit.cpp
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

 \brief		Circuit class implementation.
*/
#include "circuit.h"
#include "share.h"
#include <cstring>


void Circuit::Init() {
	m_nMaxDepth = 0;
	m_vInputGates.resize(2);
	m_vOutputGates.resize(2);
	m_vInputBits.resize(2, 0);
	m_vOutputBits.resize(2, 0);
	m_vInputBits.resize(2, 0);
	m_vOutputBits.resize(2, 0);

	m_nGates = 0;

	ncombgates = 0;
	npermgates = 0;
	nsubsetgates = 0;
	nsplitgates = 0;
	nstructcombgates = 0;
	//m_vNonLinOnLayer.max_depth = 1;
	//m_vNonLinOnLayer.min_depth = 0;
	//m_vNonLinOnLayer.num_on_layer = (uint32_t*) calloc(m_vNonLinOnLayer.max_depth, sizeof(uint32_t));
}

void Circuit::Cleanup() {
	//TODO implement

	//should not be necessary
	//m_vInputGates.clear();
	//m_vOutputGates.clear();
	//m_vInputBits.clear();
	//m_vOutputBits.clear();
	//m_vInputBits.clear();
	//m_vOutputBits.clear();
}

void Circuit::Reset() {
	m_nMaxDepth = 0;
	m_nGates = 0;

	for (size_t i = 0; i < m_vLocalQueueOnLvl.size(); i++) {
		m_vLocalQueueOnLvl[i].clear();
	}
	m_vLocalQueueOnLvl.resize(0);
	for (size_t i = 0; i < m_vInteractiveQueueOnLvl.size(); i++) {
		m_vInteractiveQueueOnLvl[i].clear();
	}
	m_vInteractiveQueueOnLvl.resize(0);
	for (size_t i = 0; i < m_vInputGates.size(); i++) {
		m_vInputGates[i].clear();
	}
	for (size_t i = 0; i < m_vOutputGates.size(); i++) {
		m_vOutputGates[i].clear();
	}

	for (size_t i = 0; i < m_vInputBits.size(); i++)
		m_vInputBits[i] = 0;
	for (size_t i = 0; i < m_vOutputBits.size(); i++)
		m_vOutputBits[i] = 0;

	// reset number of SIMD gates
	ncombgates = 0;
	nsplitgates = 0;
	npermgates = 0;
	nsubsetgates = 0;
	nstructcombgates = 0;

	//free(m_vNonLinOnLayer.num_on_layer);
	//m_vNonLinOnLayer.max_depth = 0;
	//m_vNonLinOnLayer.min_depth = 0;
}

gate_specific Circuit::GetGateSpecificOutput(uint32_t gateid) {
	assert(m_vGates[gateid].instantiated);
	return m_vGates[gateid].gs;
}

uint32_t Circuit::GetOutputGateValue(uint32_t gateid, UGATE_T*& outval) {
	//assert(m_vGates[gateid].instantiated);
	if(!m_vGates[gateid].instantiated){
		std::cerr << "Output not allowed for this role. Returned value will be wrong!" << std::endl;
		return 0;
	}
	outval = m_vGates[gateid].gs.val;
	return m_vGates[gateid].nvals;
}

UGATE_T* Circuit::GetOutputGateValue(uint32_t gateid) {
	//assert(m_vGates[gateid].instantiated);
	if(!m_vGates[gateid].instantiated){
		std::cerr << "Output not allowed for this role! Returned value will be wrong!" << std::endl;
		return nullptr;
	}
	return m_vGates[gateid].gs.val;
}

/* Converts a Yao share to an Arithmetic share. The boolsharing circuit needs to be from type S_BOOL! */
share* Circuit::PutY2AGate(share* ina, Circuit* boolsharingcircuit) {
	assert(boolsharingcircuit->GetContext() == S_BOOL);
	return PutB2AGate(boolsharingcircuit->PutY2BGate(ina));
}

/* Converts an Arithmetic share to a Bool share. The yaosharing circuit needs to be from type S_YAO or S_YAO_REV! */
share* Circuit::PutA2BGate(share* ina, Circuit* yaosharingcircuit) {
	assert(yaosharingcircuit->GetContext() == S_YAO || yaosharingcircuit->GetContext() == S_YAO_REV);
	return PutY2BGate(yaosharingcircuit->PutA2YGate(ina));
}

/* =========================== SIMD Gates =========================== */



uint32_t Circuit::PutCombinerGate(std::vector<uint32_t> input) {
	uint32_t gateid = m_cCircuit->PutCombinerGate(input);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t Circuit::PutCombineAtPosGate(std::vector<uint32_t> input, uint32_t pos) {
	uint32_t gateid = m_cCircuit->PutCombineAtPosGate(input, pos);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t Circuit::PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals_out, bool copy_posids) {
	uint32_t gateid = m_cCircuit->PutSubsetGate(input, posids, nvals_out, copy_posids);
	UpdateLocalQueue(gateid);
	return gateid;
}
std::vector<uint32_t> Circuit::PutSplitterGate(uint32_t input) {
	std::vector<uint32_t> gateid = m_cCircuit->PutSplitterGate(input);
	for (uint32_t i = 0; i < gateid.size(); i++)
		UpdateLocalQueue(gateid[i]);
	return gateid;
}

std::vector<uint32_t> Circuit::PutSplitterGate(uint32_t input, const std::vector<uint32_t>& new_nvals) {
	std::vector<uint32_t> gateid = m_cCircuit->PutSplitterGate(input, new_nvals);
	for (uint32_t i = 0; i < gateid.size(); i++) {
		UpdateLocalQueue(gateid[i]);
	}
	return gateid;
}

uint32_t Circuit::PutRepeaterGate(uint32_t input, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutRepeaterGate(input, nvals);
	UpdateLocalQueue(gateid);
	return gateid;
}
uint32_t Circuit::PutPermutationGate(std::vector<uint32_t> input, uint32_t* positions) {
	uint32_t gateid = m_cCircuit->PutPermutationGate(input, positions);
	UpdateLocalQueue(gateid);
	return gateid;
}



share* Circuit::PutSubsetGate(share* input, uint32_t* posids, uint32_t nvals_out, bool copy_posids) {
	//share* out = new boolshare(input->size(), this);
	std::vector<uint32_t> tmp(input->get_bitlength());
	for(uint32_t i = 0; i < input->get_bitlength(); i++) {
		//out->set_wire(i, PutSubsetGate(input->get_wire(i), posids, nvals));
		tmp[i] = m_cCircuit->PutSubsetGate(input->get_wire_id(i), posids, nvals_out, copy_posids);
		nsubsetgates++;
	}
	share* out = create_new_share(tmp, this);
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutPermutationGate(share* input, uint32_t* positions) {
	share* out = create_new_share(1, this);
	npermgates++;
	out->set_wire_id(0, m_cCircuit->PutPermutationGate(input->get_wires(),positions));
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutCombineAtPosGate(share* input, uint32_t pos) {
	share* out = create_new_share(1, this);
	out->set_wire_id(0, m_cCircuit->PutCombineAtPosGate(input->get_wires(),pos));
	UpdateLocalQueue(out);
	return out;
}


share* Circuit::PutCombinerGate(share* input) {
	share* out = create_new_share(1, this);
	ncombgates++;
	out->set_wire_id(0, m_cCircuit->PutCombinerGate(input->get_wires()));
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutCombinerGate(share* ina, share* inb) {
	assert(ina->get_circuit_type() == inb->get_circuit_type());
	std::vector<uint32_t> wires(ina->get_bitlength() + inb->get_bitlength());
//	std::cout << "Size on left = " << ina->get_bitlength() << " (" << m_vGates[ina->get_wire_id(0)].nvals << ") on right = " << inb->get_bitlength()
//			<< " ("<< m_vGates[inb->get_wire_id(0)].nvals << ")" << std::endl;

	for(uint32_t i = 0; i < ina->get_bitlength(); i++) {
		wires[i] = ina->get_wire_id(i);
	}
	for(uint32_t i = 0; i < inb->get_bitlength(); i++ ) {
		wires[i+ina->get_bitlength()] = inb->get_wire_id(i);
	}
	share* out = create_new_share(1, this);
	out->set_wire_id(0, m_cCircuit->PutCombinerGate(wires));
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutSplitterGate(share* input) {
	share* out = create_new_share(m_cCircuit->PutSplitterGate(input->get_wire_id(0)), this);
	nsplitgates++;
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutRepeaterGate(uint32_t nvals, share* input) {
	share* out = create_new_share(m_cCircuit->PutRepeaterGate(input->get_wires(), nvals), this);
	UpdateLocalQueue(out);
	return out;
}

void Circuit::UpdateInteractiveQueue(share* gateids) {
	for (uint32_t i = 0; i < gateids->get_bitlength(); i++) {
		UpdateInteractiveQueue(gateids->get_wire_id(i));
	}
}
void Circuit::UpdateLocalQueue(share* gateids) {
	for (uint32_t i = 0; i < gateids->get_bitlength(); i++) {
		UpdateLocalQueue(gateids->get_wire_id(i));
	}
}

/*void Circuit::ResizeNonLinOnLayer(uint32_t new_max_depth) {
	uint32_t* tmpbuf = m_vNonLinOnLayer.num_on_layer;

	m_vNonLinOnLayer.num_on_layer = (uint32_t*) calloc(new_max_depth, sizeof(uint32_t));

	memcpy(m_vNonLinOnLayer.num_on_layer, tmpbuf, m_vNonLinOnLayer.max_depth);
	m_vNonLinOnLayer.max_depth = new_max_depth+1;

	free(tmpbuf);
}*/


// if the wires of the input gate are already from an output gate, copy the input.
// otherwise build a dedicated output gate.
share* Circuit::EnsureOutputGate(share* in) {
	bool is_output = true;
	for (uint32_t i = 0; i < in->get_bitlength(); i++) {
		is_output &= (m_vGates[in->get_wire_id(i)].type == G_OUT);
	}

	share* outgates = in;
	if (!is_output) {
		outgates = PutOUTGate(in, ALL);
	}
	return outgates;
}

share* Circuit::PutPrintValueGate(share* in, std::string helpstr) {
#if ABY_PRODUCTION
	std::cerr << "Production mode enabled - PutPrintValue Gate is omitted" << std::endl;

	return in;
#else
	share* outgates = EnsureOutputGate(in);

	uint32_t tmp = m_cCircuit->PutPrintValGate(outgates->get_wires(), helpstr);
	UpdateLocalQueue(tmp);
	return outgates;

#endif
}

share* Circuit::PutAssertGate(share* in, uint64_t* assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, assert_val, bitlen);
}
share* Circuit::PutAssertGate(share* in, uint32_t* assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, assert_val, bitlen);
}
share* Circuit::PutAssertGate(share* in, uint16_t* assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, assert_val, bitlen);
}
share* Circuit::PutAssertGate(share* in, uint8_t* assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, assert_val, bitlen);
}

share* Circuit::PutAssertGate(share* in, uint64_t assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, &assert_val, bitlen);
}
share* Circuit::PutAssertGate(share* in, uint32_t assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, &assert_val, bitlen);
}
share* Circuit::PutAssertGate(share* in, uint16_t assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, &assert_val, bitlen);
}
share* Circuit::PutAssertGate(share* in, uint8_t assert_val, uint32_t bitlen) {
	return PutSIMDAssertGate(in, 1, &assert_val, bitlen);
}



share* Circuit::PutSIMDAssertGate(share* in, uint32_t nvals, uint64_t* assert_val, uint32_t bitlen) {
#if ABY_PRODUCTION
	std::cerr << "Production mode enabled - Assert Gate is omitted" << std::endl;

	return in;
#else
	share* outgates = EnsureOutputGate(in);

	assert(bitlen == in->get_bitlength());
	for (uint32_t i = 0; i < in->get_bitlength(); i++) {
		assert(m_vGates[in->get_wire_id(i)].nvals == nvals);
	}

	uint32_t tmp = m_cCircuit->PutAssertGate(outgates->get_wires(), bitlen, (UGATE_T*) assert_val);
	UpdateLocalQueue(tmp);

	return outgates;
#endif
}

template<class T> share* Circuit::AssertInterfaceConversion(share* in, uint32_t nvals, T* assert_val, uint32_t bitlen) {
	uint32_t in_elesize = ceil_divide(bitlen, sizeof(T) * 8);
	uint32_t tmp_elesize = ceil_divide(bitlen, sizeof(uint64_t) * 8);
	uint32_t elebytelen = ceil_divide(bitlen, 8);

	uint64_t* tmpbuf = (uint64_t*) calloc(tmp_elesize * nvals, sizeof(uint64_t));

	for (uint32_t i = 0; i < nvals; i++) {
		memcpy(tmpbuf + tmp_elesize * i, assert_val + i * in_elesize, elebytelen);
	}

	share* outshr = PutSIMDAssertGate(in, nvals, tmpbuf, bitlen);

	free(tmpbuf);
	return outshr;
}

share* Circuit::PutSIMDAssertGate(share* in, uint32_t nvals, uint32_t* assert_val, uint32_t bitlen) {
	return AssertInterfaceConversion<uint32_t>(in, nvals, assert_val, bitlen);
}

share* Circuit::PutSIMDAssertGate(share* in, uint32_t nvals, uint16_t* assert_val, uint32_t bitlen) {
	return AssertInterfaceConversion<uint16_t>(in, nvals, assert_val, bitlen);
}

share* Circuit::PutSIMDAssertGate(share* in, uint32_t nvals, uint8_t* assert_val, uint32_t bitlen) {
	return AssertInterfaceConversion<uint8_t>(in, nvals, assert_val, bitlen);
}

//Export the constructed circuit in the Bristol circuit file format
void Circuit::ExportCircuitInBristolFormat(share* ingates_client, share* ingates_server, share* outgates,
		const char* filename) {
	//only works for Boolean circuits
	assert(m_eCirctype == C_BOOLEAN);
	m_cCircuit->ExportCircuitInBristolFormat(ingates_client->get_wires(), ingates_server->get_wires(),
			outgates->get_wires(), filename);
}

share* create_new_share(uint32_t size, Circuit* circ) {
	switch (circ->GetCircuitType()) {
	case C_BOOLEAN:
		return new boolshare(size, circ);
	case C_ARITHMETIC:
		return new arithshare(circ);
	default:
		std::cerr << "Circuit type not recognized" << std::endl;
		return new boolshare(size, circ);
	}
}

share* create_new_share(std::vector<uint32_t> vals, Circuit* circ) {
	switch (circ->GetCircuitType()) {
	case C_BOOLEAN:
		return new boolshare(vals, circ);
	case C_ARITHMETIC:
		return new arithshare(vals, circ);
	default:
		std::cerr << "Circuit type not recognized" << std::endl;
		return new boolshare(vals, circ);
	}
}
