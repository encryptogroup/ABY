/**
 \file 		circuit.cpp
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

 \brief		Circuit class implementation.
*/
#include "circuit.h"

void Circuit::Init() {

	m_pGates = m_cCircuit->Gates();

	m_nMaxDepth = 0;
	m_vInputGates.resize(2);
	m_vOutputGates.resize(2);
	m_vInputBits.resize(2, 0);
	m_vOutputBits.resize(2, 0);

	m_nGates = 0;
}
;

void Circuit::Cleanup() {
	//TODO
}
;

void Circuit::Reset() {
	m_nMaxDepth = 0;
	m_nGates = 0;

	for (int i = 0; i < m_vLocalQueueOnLvl.size(); i++) {
		m_vLocalQueueOnLvl[i].clear();
	}
	m_vLocalQueueOnLvl.resize(0);
	for (int i = 0; i < m_vInteractiveQueueOnLvl.size(); i++) {
		m_vInteractiveQueueOnLvl[i].clear();
	}
	m_vInteractiveQueueOnLvl.resize(0);
	for (int i = 0; i < m_vInputGates.size(); i++) {
		m_vInputGates[i].clear();
	}
	for (int i = 0; i < m_vOutputGates.size(); i++) {
		m_vOutputGates[i].clear();
	}
	for (int i = 0; i < m_vInputBits.size(); i++)
		m_vInputBits[i] = 0;
	for (int i = 0; i < m_vOutputBits.size(); i++)
		m_vOutputBits[i] = 0;
}

uint32_t Circuit::GetOutputGateValue(uint32_t gateid, UGATE_T*& outval) {
	assert(m_pGates[gateid].instantiated);
	outval = m_pGates[gateid].gs.val;
	return m_pGates[gateid].nvals;
}

UGATE_T* Circuit::GetOutputGateValue(uint32_t gateid) {
	assert(m_pGates[gateid].instantiated);
	return m_pGates[gateid].gs.val;
}

template<class T> void Circuit::GetOutputGateValue(uint32_t gateid, T& val) {
	assert(sizeof(T) * 8 > m_pGates[gateid].nvals * m_nShareBitLen);

	val = m_pGates[gateid].gs.val;
}

share* Circuit::PutCombinerGate(share* ina) {
	share* out = create_new_share(1, this, ina->get_circuit_type());
	out->set_gate(0, m_cCircuit->PutCombinerGate(ina->get_gates()));
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutSplitterGate(share* ina) {

	share* out = create_new_share(m_cCircuit->PutSplitterGate(ina->get_gate(0)), this, ina->get_circuit_type());
	UpdateLocalQueue(out);
	return out;
}

share* Circuit::PutRepeaterGate(uint32_t nvals, share* ina) {
	share* out = create_new_share(m_cCircuit->PutRepeaterGate(ina->get_gates(), nvals), this, ina->get_circuit_type());
	UpdateLocalQueue(out);
	return out;
}

void Circuit::UpdateInteractiveQueue(share* gateids) {
	for (uint32_t i = 0; i < gateids->size(); i++) {
		UpdateInteractiveQueue(gateids->get_gate(i));
	}
}
void Circuit::UpdateLocalQueue(share* gateids) {
	for (uint32_t i = 0; i < gateids->size(); i++) {
		UpdateLocalQueue(gateids->get_gate(i));
	}
}

/* =========================== Methods for the share class =========================== */

share::share(uint32_t sharelen, Circuit* circ) {
	m_ngateids.resize(sharelen);
	init(circ);
}

share::share(vector<uint32_t> gates, Circuit* circ) {
	m_ngateids.resize(gates.size());
	m_ngateids = gates;
	init(circ);
}

void share::init(Circuit* circ, uint32_t maxbitlen) {
	m_ccirc = circ;
	m_nmaxbitlen = maxbitlen;
}

uint32_t share::get_gate(uint32_t shareid) {
	assert(shareid < m_ngateids.size());
	return m_ngateids[shareid];
}

void share::set_gate(uint32_t shareid, uint32_t gateid) {
	assert(shareid < m_ngateids.size());
	m_ngateids[shareid] = gateid;
}

/* =========================== Methods for the Boolean share class =========================== */

//TODO: will not work for vectors
uint8_t* boolshare::get_clear_value() {
	uint8_t* out;
	UGATE_T* gatevals;
	uint32_t nvals = m_ccirc->GetNumVals(m_ngateids[0]);
	uint32_t bytelen = ceil_divide(m_ngateids.size(), 8);

	out = (uint8_t*) calloc(ceil_divide(m_ngateids.size(), 8) * nvals, sizeof(uint8_t));

	for (uint32_t i = 0, ibytes; i < m_ngateids.size(); i++) {
		assert(nvals == m_ccirc->GetNumVals(m_ngateids[i]));
		gatevals = m_ccirc->GetOutputGateValue(m_ngateids[i]);

		ibytes = i / 8;
		for (uint32_t j = 0; j < nvals; j++) {
			out[j * bytelen + ibytes] += (((gatevals[j / 64] >> (j % 64)) & 0x01) << (i & 0x07));
		}
	}
	return out;
}


void boolshare::get_clear_value_vec(uint32_t** vec, uint32_t *bitlen, uint32_t *nvals) {
	assert(m_ngateids.size() <= sizeof(uint32_t) * 8);
	UGATE_T* outvalptr;
	uint32_t gnvals = 1;

	*nvals = 1;
	*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], outvalptr);
	*vec = (uint32_t*) calloc(*nvals, sizeof(uint32_t));

	for (uint32_t j = 0; j < *nvals; j++) {
		(*vec)[j] = (outvalptr[j / 64] >> (j % 64)) & 0x01;
	}

	for (uint32_t i = 1; i < m_ngateids.size(); i++) {
		gnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], outvalptr);
		assert(*nvals == gnvals);

		for (uint32_t j = 0; j < *nvals; j++) {
			(*vec)[j] = (*vec)[j] + (((outvalptr[j / 64] >> (j % 64)) & 0x01) << i);
		}
	}
	*bitlen = m_ngateids.size();
	//return nvals;
}

//TODO: copied from 32 bits. Put template in and test later on!
void boolshare::get_clear_value_vec(uint64_t** vec, uint32_t *bitlen, uint32_t *nvals) {
	assert(m_ngateids.size() <= sizeof(uint64_t) * 8);
	UGATE_T* outvalptr;
	uint32_t gnvals = 1;

	*nvals = 1;
	*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], outvalptr);
	*vec = (uint64_t*) calloc(*nvals, sizeof(uint64_t));

	for (uint32_t j = 0; j < *nvals; j++) {
		(*vec)[j] = (outvalptr[j / 64] >> (j % 64)) & 0x01;
	}

	for (uint32_t i = 1; i < m_ngateids.size(); i++) {
		gnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], outvalptr);
		assert(*nvals == gnvals);

		for (uint32_t j = 0; j < *nvals; j++) {
			(*vec)[j] = (*vec)[j] + (((outvalptr[j / 64] >> (j % 64)) & 0x01) << i);
		}
	}
	*bitlen = m_ngateids.size();
	//return nvals;
}


/* =========================== Methods for the Arithmetic share class =========================== */

uint8_t* arithshare::get_clear_value() {
	UGATE_T* gate_val;
	uint32_t nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
	uint8_t* out = (uint8_t*) malloc(nvals * sizeof(uint32_t));
	for (uint32_t i = 0; i < nvals; i++) {
		((uint32_t*) out)[i] = (uint32_t) gate_val[i];
	}
	return out;
}

void arithshare::get_clear_value_vec(uint32_t** vec, uint32_t* bitlen, uint32_t* nvals) {
	//assert(m_ngateids.size() <= sizeof(uint32_t) * 8);

	UGATE_T* gate_val;
	*nvals = 0;
	for(uint32_t i = 0; i < m_ngateids.size(); i++) {
		(*nvals) += m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
	}
	uint32_t sharebytes = ceil_divide(m_ccirc->GetShareBitLen(), 8);

	//*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
	*vec = (uint32_t*) calloc(*nvals, sizeof(uint32_t));

	for(uint32_t i = 0, tmpctr=0, tmpnvals; i < m_ngateids.size(); i++) {
		tmpnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
		//cout << m_ngateids[i] << " gateval = " << gate_val[0] << ", nvals = " << *nvals << ", sharebitlen = " << m_ccirc->GetShareBitLen() << endl;
		for(uint32_t j = 0; j < tmpnvals; j++, tmpctr++) {
			memcpy((*vec)+tmpctr, ((uint8_t*) gate_val)+(j*sharebytes), sharebytes);
		}
	}

	*bitlen = m_ccirc->GetShareBitLen();
}

//TODO: copied from 32 bits. Put template in and test later on!
void arithshare::get_clear_value_vec(uint64_t** vec, uint32_t* bitlen, uint32_t* nvals) {
	//assert(m_ngateids.size() <= sizeof(uint32_t) * 8);

	UGATE_T* gate_val;
	*nvals = 0;
	for(uint32_t i = 0; i < m_ngateids.size(); i++) {
		(*nvals) += m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
	}
	uint32_t sharebytes = ceil_divide(m_ccirc->GetShareBitLen(), 8);

	//*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
	*vec = (uint64_t*) calloc(*nvals, sizeof(uint64_t));

	for(uint32_t i = 0, tmpctr=0, tmpnvals; i < m_ngateids.size(); i++) {
		tmpnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
		//cout << m_ngateids[i] << " gateval = " << gate_val[0] << ", nvals = " << *nvals << ", sharebitlen = " << m_ccirc->GetShareBitLen() << endl;
		for(uint32_t j = 0; j < tmpnvals; j++, tmpctr++) {
			memcpy((*vec)+tmpctr, ((uint8_t*) gate_val)+(j*sharebytes), sharebytes);
		}
	}

	*bitlen = m_ccirc->GetShareBitLen();
}


static share* create_new_share(uint32_t size, Circuit* circ, e_circuit circtype) {
	switch (circtype) {
	case C_BOOLEAN:
		return new boolshare(size, circ);
	case C_ARITHMETIC:
		return new arithshare(circ);
	default:
		cerr << "Circuit type not recognized" << endl;
		return new boolshare(size, circ);
	}
}

static share* create_new_share(vector<uint32_t> vals, Circuit* circ, e_circuit circtype) {
	switch (circtype) {
	case C_BOOLEAN:
		return new boolshare(vals, circ);
	case C_ARITHMETIC:
		return new arithshare(vals, circ);
	default:
		cerr << "Circuit type not recognized" << endl;
		return new boolshare(vals, circ);
	}
}


