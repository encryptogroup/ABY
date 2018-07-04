/**
 \file 		arithmeticcircuits.cpp
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
 \brief		Arithmetic Circuit class.
 */

#include "arithmeticcircuits.h"
#include <cstring>


void ArithmeticCircuit::Init() {
	m_nMULs = 0;
	m_nCONVGates = 0;

	if (m_eContext == S_ARITH) {
		m_nRoundsAND = 1;
		m_nRoundsXOR = 0;
		m_nRoundsIN.resize(2, 1);
		m_nRoundsOUT.resize(3, 1);
	} else { //m_tContext == S_YAO
		//unknown
		std::cerr << "Sharing type not implemented with arithmetic circuits" << std::endl;
		exit(0);
	}
}

void ArithmeticCircuit::Cleanup() {
	//TODO implement
}

share* ArithmeticCircuit::PutMULGate(share* ina, share* inb) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutMULGate(ina->get_wire_id(0), inb->get_wire_id(0)));
	return shr;
}

uint32_t ArithmeticCircuit::PutMULGate(uint32_t inleft, uint32_t inright) {
	// check if one of the inputs is a const gate and then use a MULCONST gate
	// instead.
	if (m_pGates[inleft].type == G_CONSTANT || m_pGates[inright].type == G_CONSTANT) {
#ifdef DEBUGARITH
		std::cout << "MUL(" << inleft << ", " << inright <<
			"): Constant factor present, putting a MULCONST gate instead." << endl;
#endif
		return PutMULCONSTGate(inleft, inright);
	}

	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_NON_LIN, inleft, inright, m_nRoundsAND);
	UpdateInteractiveQueue(gateid);

	if (m_pGates[gateid].nvals != INT_MAX) {
		//TODO implement for NON_LIN_VEC
		m_nMULs += m_pGates[gateid].nvals;
	}
	return gateid;
}

share* ArithmeticCircuit::PutMULCONSTGate(share* ina, share* inb) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutMULCONSTGate(ina->get_wire_id(0), inb->get_wire_id(0)));
	return shr;
}

uint32_t ArithmeticCircuit::PutMULCONSTGate(uint32_t inleft, uint32_t inright) {
	// One of the gates needs to be a constant gate
	assert (m_pGates[inleft].type == G_CONSTANT || m_pGates[inright].type == G_CONSTANT);
	if (m_pGates[inleft].type == G_CONSTANT && m_pGates[inright].type == G_CONSTANT) {
		std::cerr << "MULCONST(" << inleft << "," << inright <<
			"): Both sides are constants, consider just multiplying their values before adding them as CONST gates.\n";
	}

	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_NON_LIN_CONST, inleft, inright, m_nRoundsXOR);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t ArithmeticCircuit::PutADDGate(uint32_t inleft, uint32_t inright) {
	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_LIN, inleft, inright, m_nRoundsXOR);
	UpdateLocalQueue(gateid);
	return gateid;
}

share* ArithmeticCircuit::PutADDGate(share* ina, share* inb) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutADDGate(ina->get_wire_id(0), inb->get_wire_id(0)));
	return shr;
}

uint32_t ArithmeticCircuit::PutSUBGate(uint32_t inleft, uint32_t inright) {

	uint32_t rightinv = m_cCircuit->PutINVGate(inright);
	UpdateLocalQueue(rightinv);
	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_LIN, inleft, rightinv, m_nRoundsXOR);
	UpdateLocalQueue(gateid);
	return gateid;
}

share* ArithmeticCircuit::PutSUBGate(share* ina, share* inb) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutSUBGate(ina->get_wire_id(0), inb->get_wire_id(0)));
	return shr;
}
uint32_t ArithmeticCircuit::PutINGate(e_role src) {
	uint32_t gateid = m_cCircuit->PutINGate(m_eContext, 1, m_nShareBitLen, src, m_nRoundsIN[src]);
	UpdateInteractiveQueue(gateid);
	switch (src) {
	case SERVER:
		m_vInputGates[0].push_back(gateid);
		m_vInputBits[0] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	case CLIENT:
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[1] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	case ALL:
		m_vInputGates[0].push_back(gateid);
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[0] += (m_pGates[gateid].nvals * m_nShareBitLen);
		m_vInputBits[1] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	default:
		std::cerr << "Role not recognized" << std::endl;
		break;
	}

	return gateid;
}

uint32_t ArithmeticCircuit::PutSharedINGate() {
	uint32_t gateid = m_cCircuit->PutSharedINGate(m_eContext, 1, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t ArithmeticCircuit::PutSIMDINGate(uint32_t ninvals, e_role src) {
	uint32_t gateid = m_cCircuit->PutINGate(m_eContext, ninvals, m_nShareBitLen, src, m_nRoundsIN[src]);
	UpdateInteractiveQueue(gateid);
	switch (src) {
	case SERVER:
		m_vInputGates[0].push_back(gateid);
		m_vInputBits[0] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	case CLIENT:
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[1] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	case ALL:
		m_vInputGates[0].push_back(gateid);
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[0] += (m_pGates[gateid].nvals * m_nShareBitLen);
		m_vInputBits[1] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	default:
		std::cerr << "Role not recognized" << std::endl;
		break;
	}

	return gateid;
}


uint32_t ArithmeticCircuit::PutSharedSIMDINGate(uint32_t ninvals) {
	uint32_t gateid = m_cCircuit->PutSharedINGate(m_eContext, ninvals, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}


share* ArithmeticCircuit::PutDummyINGate(uint32_t bitlen) {
	std::vector<uint32_t> wires(1);
	wires[0] = PutINGate((e_role) !m_eMyRole);
	return new arithshare(wires, this);
}
share* ArithmeticCircuit::PutDummySIMDINGate(uint32_t nvals, uint32_t bitlen) {
	std::vector<uint32_t> wires(1);
	wires[0] = PutSIMDINGate(nvals, (e_role) !m_eMyRole);
	return new arithshare(wires, this);
}


template<class T> uint32_t ArithmeticCircuit::PutSharedINGate(T val) {
	uint32_t gateid = PutSharedINGate();
	GATE* gate = m_pGates + gateid;
	gate->gs.val = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));

	*gate->gs.val = (UGATE_T) val;
	gate->instantiated = true;
	return gateid;
}


template<class T> uint32_t ArithmeticCircuit::PutSIMDINGate(uint32_t nvals, T val, e_role role) {
	uint32_t gateid = PutSIMDINGate(nvals, role);
	if (role == m_eMyRole) {
		GATE* gate = m_pGates + gateid;
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));

		*gate->gs.ishare.inval = (UGATE_T) val;
		gate->instantiated = true;
	}

	return gateid;
}

template<class T> uint32_t ArithmeticCircuit::PutSharedSIMDINGate(uint32_t nvals, T val) {
	uint32_t gateid = PutSharedSIMDINGate(nvals);
	GATE* gate = m_pGates + gateid;
	gate->gs.val = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));

	*gate->gs.val = (UGATE_T) val;
	gate->instantiated = true;
	return gateid;
}


template<class T> share* ArithmeticCircuit::InternalPutINGate(uint32_t nvals, T val, uint32_t bitlen, e_role role) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutSIMDINGate(nvals, val, role));
	return shr;
}


template<class T> share* ArithmeticCircuit::InternalPutSharedINGate(uint32_t nvals, T val, uint32_t bitlen) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutSharedSIMDINGate(nvals, val));
	return shr;
}


template<class T> share* ArithmeticCircuit::InternalPutINGate(uint32_t nvals, T* val, uint32_t bitlen, e_role role) {
	assert(bitlen <= m_nShareBitLen);
	share* shr = new arithshare(this);
	uint32_t gateid = PutSIMDINGate(nvals, role);
	uint32_t iters = sizeof(UGATE_T) / sizeof(T);
	assert(iters > 0);
	shr->set_wire_id(0, gateid);

	if (role == m_eMyRole) {
		GATE* gate = m_pGates + gateid;
		uint32_t sharebytelen = ceil_divide(m_nShareBitLen, 8);
		uint32_t inbytelen = ceil_divide(bitlen, 8);
		gate->gs.ishare.inval = (UGATE_T*) calloc(nvals, PadToMultiple(sharebytelen, sizeof(UGATE_T)));
		for(uint32_t i = 0; i < nvals; i++) {
			memcpy(((uint8_t*) gate->gs.ishare.inval) + i * sharebytelen, val+i, inbytelen);
		}

		gate->instantiated = true;
	}

	return shr;
}


template<class T> share* ArithmeticCircuit::InternalPutSharedINGate(uint32_t nvals, T* val, uint32_t bitlen) {
	assert(bitlen <= m_nShareBitLen);
	share* shr = new arithshare(this);
	uint32_t gateid = PutSharedSIMDINGate(nvals);
	uint32_t iters = sizeof(UGATE_T) / sizeof(T);
	assert(iters > 0);
	shr->set_wire_id(0, gateid);

	GATE* gate = m_pGates + gateid;
	uint32_t sharebytelen = ceil_divide(m_nShareBitLen, 8);
	uint32_t inbytelen = ceil_divide(bitlen, 8);
	gate->gs.val = (UGATE_T*) calloc(nvals, PadToMultiple(sharebytelen, sizeof(UGATE_T)));
	for(uint32_t i = 0; i < nvals; i++) {
		memcpy(((uint8_t*) gate->gs.val) + i * sharebytelen, val+i, inbytelen);
	}
	gate->instantiated = true;
	return shr;
}

uint32_t ArithmeticCircuit::PutOUTGate(uint32_t parentid, e_role dst) {
	uint32_t gateid = m_cCircuit->PutOUTGate(parentid, dst, m_nRoundsOUT[dst]);
	UpdateInteractiveQueue(gateid);

	switch (dst) {
	case SERVER:
		m_vOutputGates[0].push_back(gateid);
		m_vOutputBits[0] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	case CLIENT:
		m_vOutputGates[1].push_back(gateid);
		m_vOutputBits[1] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	case ALL:
		m_vOutputGates[0].push_back(gateid);
		m_vOutputGates[1].push_back(gateid);
		m_vOutputBits[0] += (m_pGates[gateid].nvals * m_nShareBitLen);
		m_vOutputBits[1] += (m_pGates[gateid].nvals * m_nShareBitLen);
		break;
	default:
		std::cerr << "Role not recognized" << std::endl;
		break;
	}

	return gateid;
}

share* ArithmeticCircuit::PutOUTGate(share* parent, e_role dst) {
	share* shr = new arithshare(parent->get_bitlength(), this);
	for (uint32_t i = 0; i < parent->get_bitlength(); i++) {
		shr->set_wire_id(i, PutOUTGate(parent->get_wire_id(i), dst));
	}

	return shr;
}

std::vector<uint32_t> ArithmeticCircuit::PutSharedOUTGate(std::vector<uint32_t> parentids) {
	std::vector<uint32_t> out = m_cCircuit->PutSharedOUTGate(parentids);
	for(uint32_t i = 0; i < out.size(); i++) {
		UpdateLocalQueue(out[i]);
	}
	return out;
}

share* ArithmeticCircuit::PutSharedOUTGate(share* parent) {
	return new arithshare(PutSharedOUTGate(parent->get_wires()), this);
}



uint32_t ArithmeticCircuit::PutINVGate(uint32_t parentid) {
	uint32_t gateid = m_cCircuit->PutINVGate(parentid);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t ArithmeticCircuit::PutCONVGate(std::vector<uint32_t> parentids) {
	uint32_t gateid = m_cCircuit->PutCONVGate(parentids, 2, S_ARITH, m_nShareBitLen);
	UpdateInteractiveQueue(gateid);
	m_nCONVGates += m_pGates[gateid].nvals;
	return gateid;
}

//TODO: use bitlen in PutConstantGate
share* ArithmeticCircuit::PutCONSGate(UGATE_T val, uint32_t bitlen) {
	assert(bitlen <= m_nShareBitLen);
	std::vector<uint32_t> gateid(1);
	gateid[0] = PutConstantGate(val, 1);
	return new arithshare(gateid, this);
}

share* ArithmeticCircuit::PutSIMDCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen) {
	assert(bitlen <= m_nShareBitLen);
	std::vector<uint32_t> gateid(1);
	gateid[0] = PutConstantGate(val, nvals);
	return new arithshare(gateid, this);
}

share* ArithmeticCircuit::PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals) {
	std::vector<uint32_t> gateid(1);
	gateid[0] = m_cCircuit->PutCallbackGate(in->get_wires(), rounds, callback, infos, nvals);
	if(rounds > 0) {
		UpdateInteractiveQueue(gateid[0]);
	} else {
		UpdateLocalQueue(gateid[0]);
	}
	return new arithshare(gateid, this);
}

share* ArithmeticCircuit::PutTruthTableGate(share* in, uint64_t* ttable) {
	std::cerr << "PutTruthTableGate not implemented in ArithmeticCircuit!!" << std::endl;
	return NULL;
}

share* ArithmeticCircuit::PutTruthTableMultiOutputGate(share* in, uint32_t out_bits, uint64_t* ttable) {
	std::cerr << "PutTruthTableMultiOutputGate not implemented in ArithmeticCircuit!!" << std::endl;
	return NULL;
}


share* ArithmeticCircuit::PutCONSGate(uint8_t* val, uint32_t bitlen) {
	//TODO
	std::cerr << "Not implemented yet!" << std::endl;
	return NULL; //new arithshare(0, this);
}

share* ArithmeticCircuit::PutSIMDCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) {
	//TODO
	std::cerr << "Not implemented yet!" << std::endl;
	return NULL; //new arithshare(0, this);
}


share* ArithmeticCircuit::PutCONSGate(uint32_t* val, uint32_t bitlen) {
	//TODO
	std::cerr << "Not implemented yet!" << std::endl;
	return NULL; //new arithshare(0, this);
}

share* ArithmeticCircuit::PutSIMDCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) {
	//TODO
	std::cerr << "Not implemented yet!" << std::endl;
	return NULL; //new arithshare(0, this);
}


uint32_t ArithmeticCircuit::PutConstantGate(UGATE_T val, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutConstantGate(m_eContext, val, nvals, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t ArithmeticCircuit::PutB2AGate(std::vector<uint32_t> ina) {
	return PutCONVGate(ina);
}

share* ArithmeticCircuit::PutB2AGate(share* ina) {
	share* shr = new arithshare(this);
	shr->set_wire_id(0, PutCONVGate(ina->get_wires()));
	return shr;
}

//enqueue interactive gate queue
void ArithmeticCircuit::UpdateInteractiveQueue(uint32_t gateid) {
	if (m_pGates[gateid].depth + 1 > m_vInteractiveQueueOnLvl.size()) {
		m_vInteractiveQueueOnLvl.resize(m_pGates[gateid].depth + 1);
		if (m_pGates[gateid].depth + 1 > m_nMaxDepth) {
			m_nMaxDepth = m_pGates[gateid].depth + 1;
		}
	}
	m_vInteractiveQueueOnLvl[m_pGates[gateid].depth].push_back(gateid);
}

//enqueue locally evaluated gate queue
void ArithmeticCircuit::UpdateLocalQueue(uint32_t gateid) {
	if (m_pGates[gateid].depth + 1 > m_vLocalQueueOnLvl.size()) {
		m_vLocalQueueOnLvl.resize(m_pGates[gateid].depth + 1);
		if (m_pGates[gateid].depth + 1 > m_nMaxDepth) {
			m_nMaxDepth = m_pGates[gateid].depth + 1;
		}
	}
	m_vLocalQueueOnLvl[m_pGates[gateid].depth].push_back(gateid);
}

void ArithmeticCircuit::Reset() {
	Circuit::Reset();
	m_nMULs = 0;
	m_nCONVGates = 0;
	m_nMaxDepth = 0;

	for (uint32_t i = 0; i < m_vLocalQueueOnLvl.size(); i++) {
		m_vLocalQueueOnLvl[i].clear();
	}
	m_vLocalQueueOnLvl.resize(0);
	for (uint32_t i = 0; i < m_vInteractiveQueueOnLvl.size(); i++) {
		m_vInteractiveQueueOnLvl[i].clear();
	}
	m_vInteractiveQueueOnLvl.resize(0);
	for (uint32_t i = 0; i < m_vInputGates.size(); i++) {
		m_vInputGates[i].clear();
	}
	for (uint32_t i = 0; i < m_vOutputGates.size(); i++) {
		m_vOutputGates[i].clear();
	}
	for (uint32_t i = 0; i < m_vInputBits.size(); i++)
		m_vInputBits[i] = 0;
	for (uint32_t i = 0; i < m_vOutputBits.size(); i++)
		m_vOutputBits[i] = 0;
}
