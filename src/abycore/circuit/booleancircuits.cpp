/**
 \file 		booleancircuits.cpp
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
 \brief		A collection of boolean circuits for boolean and yao sharing in the ABY framework
 */

#include "booleancircuits.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#ifdef HW_DEBUG
#include <memory>
#endif

void BooleanCircuit::Init() {
	m_nShareBitLen = 1;
	m_nNumANDSizes = 1;
	m_vANDs = (non_lin_vec_ctx*) malloc(sizeof(non_lin_vec_ctx) * m_nNumANDSizes);
	m_vANDs[0].bitlen = 1;
	m_vANDs[0].numgates = 0;

	//Instantiate with regular 1 output AND gate
	m_vTTlens.resize(1);
	m_vTTlens[0].resize(1);
	m_vTTlens[0][0].resize(1);
	m_vTTlens[0][0][0].tt_len = 4;
	m_vTTlens[0][0][0].numgates = 0;
	m_vTTlens[0][0][0].out_bits = 1;

	//m_vTTlens = (non_lin_vec_ctx*) malloc(sizeof(tt_lens_ctx) * m_nNumTTSizes);

	m_nGates = 0;
	if (m_eContext == S_BOOL) {
		m_nRoundsAND = 1;
		m_nRoundsXOR = 0;
		m_nRoundsIN.resize(2, 1);
		m_nRoundsOUT.resize(3, 1);
	} else if(m_eContext == S_SPLUT) {
		m_nRoundsAND = 1;
		m_nRoundsXOR = 0;
		m_nRoundsIN.resize(2, 1);
		m_nRoundsOUT.resize(3, 1);
	} else if (m_eContext == S_YAO || m_eContext == S_YAO_REV) {
		m_nRoundsAND = 0;
		m_nRoundsXOR = 0;
		m_nRoundsIN.resize(2);
		m_nRoundsIN[0] = 1;
		m_nRoundsIN[1] = 2;
		m_nRoundsOUT.resize(3, 1);
		m_nRoundsOUT[1] = 0; //the client already holds the output bits from the start
	} else {
		std::cerr << "Sharing type not implemented for Boolean circuit" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	m_nB2YGates = 0;
	m_nA2YGates = 0;
	m_nNumXORVals = 0;
	m_nNumXORGates = 0;
	m_nYSwitchGates = 0;
	m_nUNIVGates = 0;

}

/*void BooleanCircuit::UpdateANDsOnLayers() {

}*/

void BooleanCircuit::Cleanup() {
	//TODO implement completely

	free(m_vANDs);

// should not be necessary:
//	m_vTTlens[0][0].clear();
//	m_vTTlens[0].clear();
//	m_vTTlens.clear();
//	m_nRoundsIN.clear();
//	m_nRoundsOUT.clear();

}

uint32_t BooleanCircuit::PutANDGate(uint32_t inleft, uint32_t inright) {
	uint32_t gateid;
	if(m_eContext != S_SPLUT) {
		gateid = m_cCircuit->PutPrimitiveGate(G_NON_LIN, inleft, inright, m_nRoundsAND);

		if (m_eContext == S_BOOL) {
			UpdateInteractiveQueue(gateid);
		} else if (m_eContext == S_YAO || m_eContext == S_YAO_REV) {
			//if context == YAO, no communication round is required
			UpdateLocalQueue(gateid);
		} else {
			std::cerr << "Context not recognized" << std::endl;
		}

		if (m_vGates[gateid].nvals != INT_MAX) {
			m_vANDs[0].numgates += m_vGates[gateid].nvals;
		} else {
			std::cerr << "INT_MAX not allowed as nvals" << std::endl;
		}
	} else {
		std::vector<uint32_t> in(2);
		uint64_t andttable=8;
		in[0] = inleft;
		in[1] = inright;
		gateid = PutTruthTableGate(in, 1, &andttable);
	}
	return gateid;
}

std::vector<uint32_t> BooleanCircuit::PutANDGate(std::vector<uint32_t> inleft, std::vector<uint32_t> inright) {
	PadWithLeadingZeros(inleft, inright);
	uint32_t resultbitlen = inleft.size();
	std::vector<uint32_t> out(resultbitlen);
	for (uint32_t i = 0; i < resultbitlen; i++){
		out[i] = PutANDGate(inleft[i], inright[i]);
	}
	return out;
}

share* BooleanCircuit::PutANDGate(share* ina, share* inb) {
	return new boolshare(PutANDGate(ina->get_wires(), inb->get_wires()), this);
}

uint32_t BooleanCircuit::PutVectorANDGate(uint32_t choiceinput, uint32_t vectorinput) {
	if (m_eContext != S_BOOL) {
		std::cerr << "Building a vector AND gate is currently only possible for GMW!" << std::endl;
		//TODO: prevent error by putting repeater gate on choiceinput and an AND gate between choiceinput and vectorinput
		return 0;
	}


	uint32_t gateid = m_cCircuit->PutNonLinearVectorGate(G_NON_LIN_VEC, choiceinput, vectorinput, m_nRoundsAND);
	UpdateInteractiveQueue(gateid);

	//std::cout << "Putting a vector and gate between a gate with " << m_vGates[choiceinput].nvals << " and " <<
	//		m_vGates[vectorinput].nvals << ", res gate has nvals = " << m_vGates[gateid].nvals << std::endl;


	if (m_vGates[gateid].nvals != INT_MAX) {
		//Update vector AND sizes
		//find location of vector AND bitlength
		//int pos = FindBitLenPositionInVec(m_vGates[gateid].nvals, m_vANDs, m_nNumANDSizes);
		int pos = FindBitLenPositionInVec(m_vGates[gateid].gs.avs.bitlen, m_vANDs, m_nNumANDSizes);
		if (pos == -1) {
			//Create new entry for the bit-length
			m_nNumANDSizes++;
			non_lin_vec_ctx* temp = (non_lin_vec_ctx*) malloc(sizeof(non_lin_vec_ctx) * m_nNumANDSizes);
			memcpy(temp, m_vANDs, (m_nNumANDSizes - 1) * sizeof(non_lin_vec_ctx));
			free(m_vANDs);
			m_vANDs = temp;
			//m_vANDs[m_nNumANDSizes - 1].bitlen = m_vGates[gateid].nvals;
			m_vANDs[m_nNumANDSizes - 1].bitlen = m_vGates[gateid].gs.avs.bitlen;
			m_vANDs[m_nNumANDSizes - 1].numgates = m_vGates[choiceinput].nvals; //1
		} else {
			//increase number of vector ANDs for this bitlength by one
			m_vANDs[pos].numgates+=m_vGates[choiceinput].nvals;
		}
	}
	return gateid;
}

share* BooleanCircuit::PutXORGate(share* ina, share* inb) {
	return new boolshare(PutXORGate(ina->get_wires(), inb->get_wires()), this);
}

uint32_t BooleanCircuit::PutXORGate(uint32_t inleft, uint32_t inright) {
	//std::cout << "inleft = " << inleft << ", inright = " << inright << std::endl;
	uint32_t gateid = m_cCircuit->PutPrimitiveGate(G_LIN, inleft, inright, m_nRoundsXOR);
	UpdateLocalQueue(gateid);
	m_nNumXORVals += m_vGates[gateid].nvals;
	m_nNumXORGates += 1;
	return gateid;
}

std::vector<uint32_t> BooleanCircuit::PutXORGate(std::vector<uint32_t> inleft, std::vector<uint32_t> inright) {
	PadWithLeadingZeros(inleft, inright);
	uint32_t resultbitlen = inleft.size();
	std::vector<uint32_t> out(resultbitlen);
	for (uint32_t i = 0; i < resultbitlen; i++){
		out[i] = PutXORGate(inleft[i], inright[i]);
	}
	return out;
}

uint32_t BooleanCircuit::PutINGate(e_role src) {
	uint32_t gateid = m_cCircuit->PutINGate(m_eContext, 1, m_nShareBitLen, src, m_nRoundsIN[src]);
	UpdateInteractiveQueue(gateid);
	switch (src) {
	case SERVER:
		m_vInputGates[0].push_back(gateid);
		m_vInputBits[0] += m_vGates[gateid].nvals;
		break;
	case CLIENT:
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[1] += m_vGates[gateid].nvals;
		break;
	case ALL:
		m_vInputGates[0].push_back(gateid);
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[0] += m_vGates[gateid].nvals;
		m_vInputBits[1] += m_vGates[gateid].nvals;
		break;
	default:
		std::cerr << "Role not recognized" << std::endl;
		break;
	}

	return gateid;
}

uint32_t BooleanCircuit::PutSIMDINGate(uint32_t ninvals, e_role src) {
	uint32_t gateid = m_cCircuit->PutINGate(m_eContext, ninvals, m_nShareBitLen, src, m_nRoundsIN[src]);
	UpdateInteractiveQueue(gateid);
	switch (src) {
	case SERVER:
		m_vInputGates[0].push_back(gateid);
		m_vInputBits[0] += m_vGates[gateid].nvals;
		break;
	case CLIENT:
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[1] += m_vGates[gateid].nvals;
		break;
	case ALL:
		m_vInputGates[0].push_back(gateid);
		m_vInputGates[1].push_back(gateid);
		m_vInputBits[0] += m_vGates[gateid].nvals;
		m_vInputBits[1] += m_vGates[gateid].nvals;
		break;
	default:
		std::cerr << "Role not recognized" << std::endl;
		break;
	}

	return gateid;
}


share* BooleanCircuit::PutDummyINGate(uint32_t bitlen) {
	std::vector<uint32_t> wires(bitlen);
	for(uint32_t i = 0; i < bitlen; i++) {
		wires[i] = PutINGate((e_role) !m_eMyRole);
	}
	return new boolshare(wires, this);
}
share* BooleanCircuit::PutDummySIMDINGate(uint32_t nvals, uint32_t bitlen) {
	std::vector<uint32_t> wires(bitlen);
	for(uint32_t i = 0; i < bitlen; i++) {
		wires[i] = PutSIMDINGate(nvals, (e_role) !m_eMyRole);
	}
	return new boolshare(wires, this);
}


uint32_t BooleanCircuit::PutSharedINGate() {
	uint32_t gateid = m_cCircuit->PutSharedINGate(m_eContext, 1, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t BooleanCircuit::PutSharedSIMDINGate(uint32_t ninvals) {
	uint32_t gateid = m_cCircuit->PutSharedINGate(m_eContext, ninvals, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}


uint32_t BooleanCircuit::PutINGate(uint64_t val, e_role role) {
	//return PutINGate(nvals, &val, role);
	uint32_t gateid = PutINGate(role);
	if (role == m_eMyRole) {
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));
		memcpy(gate->gs.ishare.inval, &val, ceil_divide(1 * m_nShareBitLen, 8));

		gate->instantiated = true;
	}

	return gateid;
}


uint32_t BooleanCircuit::PutSharedINGate(uint64_t val) {
	uint32_t gateid = PutSharedINGate();
	//assign value
	GATE* gate = &(m_vGates[gateid]);
	gate->gs.val = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));
	memcpy(gate->gs.val, &val, ceil_divide(1 * m_nShareBitLen, 8));

	gate->instantiated = true;
	return gateid;
}

uint32_t BooleanCircuit::PutSIMDINGate(uint32_t nvals, uint64_t val, e_role role) {
	//return PutINGate(nvals, &val, role);
	uint32_t gateid = PutSIMDINGate(nvals, role);
	if (role == m_eMyRole) {
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));
		memcpy(gate->gs.ishare.inval, &val, ceil_divide(nvals * m_nShareBitLen, 8));

		gate->instantiated = true;
	}

	return gateid;
}

uint32_t BooleanCircuit::PutSharedSIMDINGate(uint32_t nvals, uint64_t val) {
	//return PutINGate(nvals, &val, role);
	uint32_t gateid = PutSharedSIMDINGate(nvals);

	//assign value
	GATE* gate = &(m_vGates[gateid]);
	gate->gs.val = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));
	memcpy(gate->gs.val, &val, ceil_divide(nvals * m_nShareBitLen, 8));

	gate->instantiated = true;
	return gateid;
}


uint32_t BooleanCircuit::PutYaoSharedSIMDINGate(uint32_t nvals, yao_fields keys) {
	uint32_t gateid = PutSharedSIMDINGate(nvals);
	//assign value
	GATE* gate = &(m_vGates[gateid]);
	//TODO: fixed to 128-bit security atm. CHANGE
	uint8_t keybytelen = ceil_divide(128, 8);
	if(m_eMyRole == SERVER) {
		gate->gs.yinput.outKey = (uint8_t*) malloc(keybytelen * nvals);
		memcpy(gate->gs.yinput.outKey, keys.outKey, keybytelen * nvals);
		gate->gs.yinput.pi = (uint8_t*) malloc(nvals);
		memcpy(gate->gs.yinput.pi, keys.pi, nvals);
	} else {
		gate->gs.yval = (uint8_t*) malloc(keybytelen * nvals);
		memcpy(gate->gs.yval, keys.outKey, keybytelen * nvals);
	}

	gate->instantiated = true;
	return gateid;

}

share* BooleanCircuit::PutYaoSharedSIMDINGate(uint32_t nvals, yao_fields* keys, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	for(uint32_t i = 0; i < bitlen; i++) {
		shr->set_wire_id(i, PutYaoSharedSIMDINGate(nvals, keys[i]));
	}
	return shr;
}


uint32_t BooleanCircuit::PutOUTGate(uint32_t parentid, e_role dst) {
	uint32_t gateid = m_cCircuit->PutOUTGate(parentid, dst, m_nRoundsOUT[dst]);

	UpdateInteractiveQueue(gateid);

	switch (dst) {
	case SERVER:
		m_vOutputGates[0].push_back(gateid);
		m_vOutputBits[0] += m_vGates[gateid].nvals;
		break;
	case CLIENT:
		m_vOutputGates[1].push_back(gateid);
		m_vOutputBits[1] += m_vGates[gateid].nvals;
		break;
	case ALL:
		m_vOutputGates[0].push_back(gateid);
		m_vOutputGates[1].push_back(gateid);
		m_vOutputBits[0] += m_vGates[gateid].nvals;
		m_vOutputBits[1] += m_vGates[gateid].nvals;
		break;
	default:
		std::cerr << "Role not recognized" << std::endl;
		break;
	}

	return gateid;
}

share* BooleanCircuit::PutOUTGate(share* parent, e_role dst) {
	return new boolshare(PutOUTGate(parent->get_wires(), dst), this);
}

std::vector<uint32_t> BooleanCircuit::PutOUTGate(std::vector<uint32_t> parentids, e_role dst) {
	std::vector<uint32_t> gateid = m_cCircuit->PutOUTGate(parentids, dst, m_nRoundsOUT[dst]);

	//TODO: optimize
	for (uint32_t i = 0; i < gateid.size(); i++) {
		UpdateInteractiveQueue(gateid[i]);
		switch (dst) {
		case SERVER:
			m_vOutputGates[0].push_back(gateid[i]);
			m_vOutputBits[0] += m_vGates[gateid[i]].nvals;
			break;
		case CLIENT:
			m_vOutputGates[1].push_back(gateid[i]);
			m_vOutputBits[1] += m_vGates[gateid[i]].nvals;
			break;
		case ALL:
			m_vOutputGates[0].push_back(gateid[i]);
			m_vOutputGates[1].push_back(gateid[i]);
			m_vOutputBits[0] += m_vGates[gateid[i]].nvals;
			m_vOutputBits[1] += m_vGates[gateid[i]].nvals;
			break;
		default:
			std::cerr << "Role not recognized" << std::endl;
			break;
		}
	}

	return gateid;
}


std::vector<uint32_t> BooleanCircuit::PutSharedOUTGate(std::vector<uint32_t> parentids) {
	std::vector<uint32_t> out = m_cCircuit->PutSharedOUTGate(parentids);
	for(uint32_t i = 0; i < out.size(); i++) {
		UpdateLocalQueue(out[i]);
	}
	return out;
}

share* BooleanCircuit::PutSharedOUTGate(share* parent) {
	return new boolshare(PutSharedOUTGate(parent->get_wires()), this);
}

share* BooleanCircuit::PutCONSGate(UGATE_T val, uint32_t bitlen) {
	return PutSIMDCONSGate(1, val, bitlen);
}

share* BooleanCircuit::PutCONSGate(uint8_t* val, uint32_t bitlen) {
	return PutSIMDCONSGate(1, val, bitlen);
}

share* BooleanCircuit::PutCONSGate(uint32_t* val, uint32_t bitlen) {
	return PutSIMDCONSGate(1, val, bitlen);
}

share* BooleanCircuit::PutSIMDCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	for(uint32_t i = 0; i < bitlen; ++i) {
		shr->set_wire_id(i, PutConstantGate((val >> i) & 1, nvals));
	}
	return shr;
}

share* BooleanCircuit::PutSIMDCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	for(uint32_t i = 0; i < bitlen; ++i) {
		uint32_t shift = i % 8;
		shr->set_wire_id(i, PutConstantGate((val[(i / 8)] & (1 << shift)) >> shift, nvals));
	}
	return shr;
}

share* BooleanCircuit::PutSIMDCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) {
	share* shr = new boolshare(bitlen, this);
	for(uint32_t i = 0; i < bitlen; ++i) {
		uint32_t shift = i % 32;
		shr->set_wire_id(i, PutConstantGate((val[(i / 32)] & (1 << shift)) >> shift, nvals));
	}
	return shr;
}


uint32_t BooleanCircuit::PutConstantGate(UGATE_T val, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutConstantGate(m_eContext, val, nvals, m_nShareBitLen);
	UpdateLocalQueue(gateid);
	return gateid;
}

uint32_t BooleanCircuit::PutINVGate(uint32_t parentid) {
	uint32_t gateid = m_cCircuit->PutINVGate(parentid);
	UpdateLocalQueue(gateid);
	return gateid;
}

std::vector<uint32_t> BooleanCircuit::PutINVGate(std::vector<uint32_t> parentid) {
	std::vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < out.size(); i++)
		out[i] = PutINVGate(parentid[i]);
	return out;
}

share* BooleanCircuit::PutINVGate(share* parent) {
	return new boolshare(PutINVGate(parent->get_wires()), this);
}

uint32_t BooleanCircuit::PutY2BCONVGate(uint32_t parentid) {
	std::vector<uint32_t> in(1, parentid);
	uint32_t gateid = m_cCircuit->PutCONVGate(in, 1, S_BOOL, m_nShareBitLen);
	m_vGates[gateid].depth++;
	UpdateLocalQueue(gateid);
	//a Y input gate cannot be parent to a Y2B gate. Alternatively, put a Boolean input gate
	assert(m_vGates[parentid].type != G_IN);

	return gateid;
}

uint32_t BooleanCircuit::PutB2YCONVGate(uint32_t parentid) {
	std::vector<uint32_t> in(1, parentid);
	uint32_t gateid = m_cCircuit->PutCONVGate(in, 2, S_YAO, m_nShareBitLen);
	UpdateInteractiveQueue(gateid);

	//treat similar to input gate of client and server
	m_nB2YGates += m_vGates[gateid].nvals;

	return gateid;
}

uint32_t BooleanCircuit::PutYSwitchRolesGate(uint32_t parentid) {
	std::vector<uint32_t> in(1, parentid);
	assert(m_eContext == S_YAO || m_eContext == S_YAO_REV);
	assert(m_vGates[in[0]].context != m_eContext);
	uint32_t gateid = m_cCircuit->PutCONVGate(in, 2, m_eContext, m_nShareBitLen);
	UpdateInteractiveQueue(gateid);

	//treat similar to input gate of client and server
	m_nYSwitchGates += m_vGates[gateid].nvals;

	return gateid;
}

std::vector<uint32_t> BooleanCircuit::PutYSwitchRolesGate(std::vector<uint32_t> parentid) {
	std::vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < parentid.size(); i++) {
		out[i] = PutYSwitchRolesGate(parentid[i]);
	}

	return out;
}


std::vector<uint32_t> BooleanCircuit::PutY2BCONVGate(std::vector<uint32_t> parentid) {
	std::vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < parentid.size(); i++) {
		out[i] = PutY2BCONVGate(parentid[i]);
	}
	return out;
}

std::vector<uint32_t> BooleanCircuit::PutB2YCONVGate(std::vector<uint32_t> parentid) {
	std::vector<uint32_t> out(parentid.size());
	for (uint32_t i = 0; i < parentid.size(); i++) {
		out[i] = PutB2YCONVGate(parentid[i]);
	}

	return out;
}

share* BooleanCircuit::PutY2BGate(share* ina) {
	return new boolshare(PutY2BCONVGate(ina->get_wires()), this);
}

share* BooleanCircuit::PutB2YGate(share* ina) {
	return new boolshare(PutB2YCONVGate(ina->get_wires()), this);
}

share* BooleanCircuit::PutYSwitchRolesGate(share* ina) {
	return new boolshare(PutYSwitchRolesGate(ina->get_wires()), this);
}

std::vector<uint32_t> BooleanCircuit::PutA2YCONVGate(std::vector<uint32_t> parentid) {
	std::vector<uint32_t> srvshares(m_vGates[parentid[0]].sharebitlen);
	std::vector<uint32_t> clishares(m_vGates[parentid[0]].sharebitlen);

	for (uint32_t i = 0; i < m_vGates[parentid[0]].sharebitlen; i++) {
		srvshares[i] = m_cCircuit->PutCONVGate(parentid, 1, S_YAO, m_nShareBitLen);
		m_vGates[srvshares[i]].gs.pos = 2 * i;
		m_vGates[srvshares[i]].depth++; //increase depth by 1 since yao is evaluated before arith
		UpdateInteractiveQueue(srvshares[i]);

		clishares[i] = m_cCircuit->PutCONVGate(parentid, 2, S_YAO, m_nShareBitLen);
		m_vGates[clishares[i]].gs.pos = 2 * i + 1;
		m_vGates[clishares[i]].depth++; //increase depth by 1 since yao is evaluated before arith
		UpdateInteractiveQueue(clishares[i]);
	}

	m_nA2YGates += m_vGates[parentid[0]].nvals * m_vGates[parentid[0]].sharebitlen;


	return PutAddGate(srvshares, clishares);
}

share* BooleanCircuit::PutA2YGate(share* ina) {
	return new boolshare(PutA2YCONVGate(ina->get_wires()), this);
}

uint32_t BooleanCircuit::PutStructurizedCombinerGate(std::vector<uint32_t> input, uint32_t pos_start,
		uint32_t pos_incr, uint32_t nvals) {
	uint32_t gateid = m_cCircuit->PutStructurizedCombinerGate(input, pos_start, pos_incr, nvals);
	UpdateLocalQueue(gateid);
	return gateid;
}

share* BooleanCircuit::PutStructurizedCombinerGate(share* input, uint32_t pos_start,
		uint32_t pos_incr, uint32_t nvals) {
	share* out= new boolshare(1, this);
	nstructcombgates++;
	out->set_wire_id(0, PutStructurizedCombinerGate(input->get_wires(), pos_start, pos_incr, nvals));
	return out;
}

uint32_t BooleanCircuit::PutUniversalGate(uint32_t a, uint32_t b, uint32_t op_id) {
	uint32_t gateid;

	if(m_eContext == S_YAO) { //In case of Yao, put universal gate
		gateid = m_cCircuit->PutUniversalGate(a, b, op_id, m_nRoundsAND);
		UpdateLocalQueue(gateid);
		m_nUNIVGates+=m_vGates[gateid].nvals;
	} else if (m_eContext == S_BOOL) { //In case of GMW, replace universal gate by sub-circuit
		gateid = PutUniversalGateCircuit(a, b, op_id);
	} else {
		std::cerr << "Context not recognized in PutUniversalGate" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	return gateid;
}

std::vector<uint32_t> BooleanCircuit::PutUniversalGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t op_id) {
	uint32_t niters = std::min(a.size(), b.size());
	std::vector<uint32_t> output(niters);
	for(uint32_t i = 0; i < niters; i++) {
		output[i] = PutUniversalGate(a[i], b[i], op_id);
	}
	return output;
}

share* BooleanCircuit::PutUniversalGate(share* a, share* b, uint32_t op_id) {
	return new boolshare(PutUniversalGate(a->get_wires(), b->get_wires(), op_id), this);

}

uint32_t BooleanCircuit::PutCallbackGate(std::vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*),
		void* infos, uint32_t nvals) {

	uint32_t gateid = m_cCircuit->PutCallbackGate(in, rounds, callback, infos, nvals);

	if(rounds > 0) {
		UpdateInteractiveQueue(gateid);
	} else {
		UpdateLocalQueue(gateid);
	}
	return gateid;
}

share* BooleanCircuit::PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*),
		void* infos, uint32_t nvals) {
	return new boolshare(PutCallbackGate(in->get_wires(), rounds, callback, infos, nvals), this);
}

/*uint64_t* transposeTT(uint32_t dima, uint32_t dimb, uint64_t* ttable) {
	uint32_t longbits = sizeof(uint64_t) * 8;
	uint64_t* newtt = (uint64_t*) calloc(bits_in_bytes(dima * dimb), sizeof(uint8_t));

	std::cout << "dima = " << dima << ", dimb = " << dimb << std::endl;
	std::cout << "Before Transposing: " << (hex) << std::endl;

	for(uint32_t i = 0; i < ceil_divide(dima * dimb, longbits); i++) {
		std::cout << ttable[i] << " ";
	}
	std::cout << (dec) << std::endl;

	for(uint32_t i = 0; i < dima; i++) {
		for(uint32_t j = 0; j < dimb; j++) {
			uint32_t idxsrc = (i * dimb + j);
			uint32_t idxdst = (j * dima  + i);
			newtt[idxdst / longbits] |= (((ttable[idxsrc / longbits] >> (idxsrc % longbits)) & 0x01) << (idxdst % longbits));
		}
	}
	std::cout << "After Transposing: " << (hex) << std::endl;
	for(uint32_t i = 0; i < ceil_divide(dima * dimb, longbits); i++) {
		std::cout << newtt[i] << " ";
	}
	std::cout << (dec) << std::endl;

	return newtt;
}*/

std::vector<uint32_t> BooleanCircuit::PutTruthTableMultiOutputGate(std::vector<uint32_t> in, uint32_t out_bits,
		uint64_t* ttable) {
	//assert(m_eContext == S_BOOL_NO_MT);

	//uint32_t tmpgate = m_cCircuit->PutTruthTableGate(in, 1, out_bits, ttable);
	//UpdateInteractiveQueue(tmpgate);

	//Transpose truth table
	//ttable = transposeTT(1<<in.size(), out_bits, ttable);
	uint32_t tmpgate = PutTruthTableGate(in, out_bits, ttable);
	std::vector<uint32_t> bitlens(out_bits, m_vGates[in[0]].nvals);
	//assert(out_bits <= 8);

	std::vector<uint32_t> output = m_cCircuit->PutSplitterGate(tmpgate, bitlens);
	for(uint32_t i = 0; i < output.size(); i++) {
		UpdateLocalQueue(output[i]);
	}

	return output;
}

share* BooleanCircuit::PutTruthTableMultiOutputGate(share* in, uint32_t output_bitlen, uint64_t* ttable) {
	return new boolshare(PutTruthTableMultiOutputGate(in->get_wires(), output_bitlen, ttable), this);
}

uint32_t BooleanCircuit::PutTruthTableGate(std::vector<uint32_t> in, uint32_t out_bits, uint64_t* ttable) {

	assert(m_eContext == S_SPLUT || m_eContext == S_BOOL);
	uint32_t gateid = m_cCircuit->PutTruthTableGate(in, 1, out_bits, ttable);
	UpdateTruthTableSizes(1<<in.size(), gateid, out_bits);

	UpdateInteractiveQueue(gateid);

	return gateid;
}


share* BooleanCircuit::PutTruthTableGate(share* in, uint64_t* ttable) {
	boolshare* out = new boolshare(1, this);
	out->set_wire_id(0, PutTruthTableGate(in->get_wires(), 1, ttable));
	return out;
}

//check if the len exists, otherwise allocate new and update
void BooleanCircuit::UpdateTruthTableSizes(uint32_t len, uint32_t gateid, uint32_t out_bits) {
	//check depth and resize if required
	uint32_t depth = m_vGates[gateid].depth;
	uint32_t nvals = m_vGates[gateid].nvals/out_bits;
	if(depth >= m_vTTlens.size()) {
		uint32_t old_depth = m_vTTlens.size();
		uint32_t nlens = m_vTTlens[0].size();
		m_vTTlens.resize(depth+1);
		//copy old values from 0-pos
		for(uint32_t i = old_depth; i < m_vTTlens.size(); i++) {
			m_vTTlens[i].resize(nlens);
			for(uint32_t j = 0; j < nlens; j++) {
				uint32_t nouts = m_vTTlens[0][j].size();
				m_vTTlens[i][j].resize(nouts);
				for(uint32_t k = 0; k < nouts; k++) {
					m_vTTlens[i][j][k].numgates = 0;
					m_vTTlens[i][j][k].tt_len = m_vTTlens[0][j][k].tt_len;
					m_vTTlens[i][j][k].out_bits = m_vTTlens[0][j][k].out_bits;
				}
			}
		}
	}

	//check whether the address for the input sizes already exist
	bool ins_exist = false;
	bool outs_exist = false;
	uint32_t id;
	for(uint32_t i = 0; i < m_vTTlens[0].size() && !ins_exist; i++) {
		if(len == m_vTTlens[depth][i][0].tt_len) {
			//check whether the bitlen already exists for the input size
			ins_exist = true;
			id = i;
			for(uint32_t j = 0; j < m_vTTlens[depth][i].size() && !outs_exist; j++) {
				if(m_vTTlens[depth][i][j].out_bits == out_bits) {
					outs_exist = true;
					m_vTTlens[depth][i][j].numgates += nvals;
					//In case of OP-LUT, also save the truth table which is needed in the setup phase
					if(m_eContext == S_BOOL) {
						for(uint32_t n = 0; n < nvals; n++) {
							m_vTTlens[depth][i][j].ttable_values.push_back(m_vGates[gateid].gs.tt.table);
						}
					}
				}
			}
		}
	}
	//the input size does not exist, create new one!
	if(!ins_exist) {
		uint32_t old_in_lens = m_vTTlens[0].size();
		for(uint32_t i = 0; i < m_vTTlens.size(); i++) {
			m_vTTlens[i].resize(old_in_lens+1);
			m_vTTlens[i][old_in_lens].resize(1);
			m_vTTlens[i][old_in_lens][0].tt_len = len;
			m_vTTlens[i][old_in_lens][0].numgates = 0;
			m_vTTlens[i][old_in_lens][0].out_bits = out_bits;
		}
		//m_vTTlens[depth][old_lens].tt_len = len;//should work without this too
		m_vTTlens[depth][old_in_lens][0].numgates = nvals;
		//In case of OP-LUT, also save the truth table which is needed in the setup phase
		if(m_eContext == S_BOOL) {
			for(uint32_t n = 0; n < nvals; n++) {
				m_vTTlens[depth][old_in_lens][0].ttable_values.push_back(m_vGates[gateid].gs.tt.table);
			}
		}
		outs_exist = true;
	}

	//the out size do not exist; create new
	if(!outs_exist) {
		uint32_t old_out_lens = m_vTTlens[0][id].size();
		for(uint32_t i = 0; i < m_vTTlens.size(); i++) {
			m_vTTlens[i][id].resize(old_out_lens+1);
			m_vTTlens[i][id][old_out_lens].tt_len = len;
			m_vTTlens[i][id][old_out_lens].numgates = 0;
			m_vTTlens[i][id][old_out_lens].out_bits = out_bits;
		}
		//m_vTTlens[depth][id][old_out_lens].tt_len = len;//should work without this too
		m_vTTlens[depth][id][old_out_lens].numgates = nvals;
		//In case of OP-LUT, also save the truth table which is needed in the setup phase
		if(m_eContext == S_BOOL) {
			for(uint32_t n = 0; n < nvals; n++) {
				m_vTTlens[depth][id][old_out_lens].ttable_values.push_back(m_vGates[gateid].gs.tt.table);
			}
		}
		outs_exist = true;
	}
}


//enqueue interactive gate queue
void BooleanCircuit::UpdateInteractiveQueue(uint32_t gateid) {
	if (m_vGates[gateid].depth + 1 > m_vInteractiveQueueOnLvl.size()) {
		m_vInteractiveQueueOnLvl.resize(m_vGates[gateid].depth + 1);
		if (m_vGates[gateid].depth + 1 > m_nMaxDepth) {
			m_nMaxDepth = m_vGates[gateid].depth + 1;
		}
	}
	m_vInteractiveQueueOnLvl[m_vGates[gateid].depth].push_back(gateid);
	m_nGates++;
}

//enqueue locally evaluated gate queue
void BooleanCircuit::UpdateLocalQueue(uint32_t gateid) {
	if (m_vGates[gateid].depth + 1 > m_vLocalQueueOnLvl.size()) {
		//std::cout << "increasing size of local queue" << std::endl;
		m_vLocalQueueOnLvl.resize(m_vGates[gateid].depth + 1);
		if (m_vGates[gateid].depth + 1 > m_nMaxDepth) {
			m_nMaxDepth = m_vGates[gateid].depth + 1;
		}
	}
	m_vLocalQueueOnLvl[m_vGates[gateid].depth].push_back(gateid);

	m_nGates++;
}

share* BooleanCircuit::PutLeftShifterGate(share* in, uint32_t pos) {
	return new boolshare(PutLeftShifterGate(in->get_wires(), in->get_max_bitlength(), pos, in->get_nvals()), this);
}

//shift val by pos positions to the left and fill lower wires with zeros
std::vector<uint32_t> BooleanCircuit::PutLeftShifterGate(std::vector<uint32_t> val, uint32_t max_bitlen, uint32_t pos, uint32_t nvals) {
	assert(pos < max_bitlen); // cannot shift beyond last bit
	uint32_t zerogate = PutConstantGate(0, nvals);
	std::vector<uint32_t> out(pos, zerogate);
	uint32_t newsize = pos + val.size();
	uint32_t extra_bits = newsize > max_bitlen ? (newsize - max_bitlen) : 0;
	out.reserve(newsize - extra_bits);
	out.insert(out.end(), val.cbegin(), val.cend() - extra_bits);
	return out;
}

// Builds a universal gate that output op_id depending on the circuit
uint32_t BooleanCircuit::PutUniversalGateCircuit(uint32_t a, uint32_t b, uint32_t op_id) {
	uint32_t nvals = std::max(m_vGates[a].nvals, m_vGates[b].nvals);

	uint32_t c0 = PutConstantGate(op_id & 0x01, nvals);
	uint32_t c1 = PutConstantGate((op_id>>1) & 0x01, nvals);
	uint32_t c2 = PutConstantGate((op_id>>2) & 0x01, nvals);
	uint32_t c3 = PutConstantGate((op_id>>3) & 0x01, nvals);

	uint32_t c0c1 =	PutXORGate(c0, c1);
	uint32_t c2c3 =	PutXORGate(c2, c3);

	uint32_t bc0c1 = PutANDGate(b, c0c1);
	uint32_t bc2c3 = PutANDGate(b, c2c3);

	uint32_t o0 = PutXORGate(c0, bc0c1);
	uint32_t o1 = PutXORGate(c2, bc2c3);

	uint32_t o0o1 = PutXORGate(o0, o1);
	uint32_t ao0o1 = PutANDGate(a, o0o1);

	return	PutXORGate(o0, ao0o1);
}

share* BooleanCircuit::PutADDGate(share* ina, share* inb) {
	//also output the carry of the result as long as the additional carry does not exceed the maximum bit length of the higher of both inputs
	bool carry = std::max(ina->get_bitlength(), inb->get_bitlength()) < std::max(ina->get_max_bitlength(), inb->get_max_bitlength());
	return new boolshare(PutAddGate(ina->get_wires(), inb->get_wires(), carry), this);
}


std::vector<uint32_t> BooleanCircuit::PutAddGate(std::vector<uint32_t> left, std::vector<uint32_t> right, BOOL bCarry) {
	PadWithLeadingZeros(left, right);
	if (m_eContext == S_BOOL) {
		return PutDepthOptimizedAddGate(left, right, bCarry);
	} if (m_eContext == S_SPLUT) {
		return PutLUTAddGate(left, right, bCarry);
	} else {
		return PutSizeOptimizedAddGate(left, right, bCarry);
	}
}



//a + b, do we need a carry?
std::vector<uint32_t> BooleanCircuit::PutSizeOptimizedAddGate(std::vector<uint32_t> a, std::vector<uint32_t> b, BOOL bCarry) {
	// left + right mod (2^Rep)
	// Construct C[i] gates
	PadWithLeadingZeros(a, b);
	uint32_t inputbitlen = a.size();// + (!!bCarry);
	std::vector<uint32_t> C(inputbitlen);
	uint32_t axc, bxc, acNbc;

	C[0] = PutXORGate(a[0], a[0]);//PutConstantGate(0, m_vGates[a[0]].nvals); //the second parameter stands for the number of vals

	uint32_t i = 0;
	for (; i < inputbitlen - 1; i++) {
		//===================
		// New Gates
		// a[i] xor c[i]
		axc = PutXORGate(a[i], C[i]);

		// b[i] xor c[i]
		bxc = PutXORGate(b[i], C[i]);

		// axc AND bxc
		acNbc = PutANDGate(axc, bxc);

		// C[i+1]
		C[i + 1] = PutXORGate(C[i], acNbc);
	}

#ifdef ZDEBUG
	std::cout << "Finished carry generation" << std::endl;
#endif

	if (bCarry) {
		axc = PutXORGate(a[i], C[i]);

		// b[i] xor c[i]
		bxc = PutXORGate(b[i], C[i]);

		// axc AND bxc
		acNbc = PutANDGate(axc, bxc);
	}

#ifdef ZDEBUG
	std::cout << "Finished additional carry generation" << std::endl;
#endif

	// Construct a[i] xor b[i] gates
	std::vector<uint32_t> AxB(inputbitlen);
	for (uint32_t i = 0; i < inputbitlen; i++) {
		// a[i] xor b[i]
		AxB[i] = PutXORGate(a[i], b[i]);
	}

#ifdef ZDEBUG
	std::cout << "Finished parity on inputs" << std::endl;
#endif

	// Construct Output gates of Addition
	std::vector<uint32_t> out(inputbitlen + (!!bCarry));
	for (uint32_t i = 0; i < inputbitlen; i++) {
		out[i] = PutXORGate(C[i], AxB[i]);
	}

#ifdef ZDEBUG
	std::cout << "Finished parity on inputs xor carries" << std::endl;
#endif

	if (bCarry)
		out[inputbitlen] = PutXORGate(C[i], acNbc);

#ifdef ZDEBUG
	std::cout << "Finished parity on additional carry and inputs" << std::endl;
#endif

	return out;
}



//TODO: there is a bug when adding 3 and 1 as two 2-bit numbers and expecting a carry
std::vector<uint32_t> BooleanCircuit::PutDepthOptimizedAddGate(std::vector<uint32_t> a, std::vector<uint32_t> b, BOOL bCARRY, bool vector_and) {
	PadWithLeadingZeros(a, b);
	uint32_t id, inputbitlen = std::min(a.size(), b.size());
	std::vector<uint32_t> out(a.size() + bCARRY);
	std::vector<uint32_t> parity(a.size()), carry(inputbitlen), parity_zero(inputbitlen);
	uint32_t zerogate = PutConstantGate(0, m_vGates[a[0]].nvals);
	share* zero_share = new boolshare(2, this);
	share* ina = new boolshare(2, this);
	share* sel = new boolshare(1, this);
	share* s_out = new boolshare(2, this);
	zero_share->set_wire_id(0, zerogate);
	zero_share->set_wire_id(1, zerogate);

	for (uint32_t i = 0; i < inputbitlen; i++) { //0-th layer
		parity[i] = PutXORGate(a[i], b[i]);
		parity_zero[i] = parity[i];
		carry[i] = PutANDGate(a[i], b[i]);
	}

	for (uint32_t i = 1; i <= (uint32_t) ceil(log(inputbitlen) / log(2)); i++) {
		for (uint32_t j = 0; j < inputbitlen; j++) {
			if (j % (uint32_t) pow(2, i) >= pow(2, (i - 1))) {
				id = pow(2, (i - 1)) + pow(2, i) * ((uint32_t) floor(j / (pow(2, i)))) - 1;
				if(m_eContext == S_BOOL && vector_and) {
					ina->set_wire_id(0, carry[id]);
					ina->set_wire_id(1, parity[id]);
					sel->set_wire_id(0, parity[j]);
					PutMultiMUXGate(&ina, &zero_share, sel, 1, &s_out);
					//carry[j] = PutINVGate(PutANDGate(PutINVGate(s_out->get_wire(0)), PutINVGate(carry[j])));
					carry[j] = PutXORGate(s_out->get_wire_id(0), carry[j]);
					parity[j] = s_out->get_wire_id(1);
				} else {
					//carry[j] = PutINVGate(PutANDGate(PutINVGate(PutANDGate(parity[j], carry[id])), PutINVGate(carry[j]))); // c = (p and c-1) or c = (((p and c-1) xor 1) and (c xor 1)) xor 1)
					carry[j] = PutXORGate(carry[j], PutANDGate(parity[j], carry[id])); // c = c XOR (p and c-1), from ShallowCC
					parity[j] = PutANDGate(parity[j], parity[id]);
				}
			}
		}
	}
	out[0] = parity_zero[0];
	for (uint32_t i = 1; i < inputbitlen; i++) {
		out[i] = PutXORGate(parity_zero[i], carry[i - 1]);
	}
	if (bCARRY)	//Do I expect a carry in the most significant bit position?
		out[inputbitlen] = carry[inputbitlen - 1];

	delete zero_share;
	delete ina;
	delete sel;
	delete s_out;
	return out;
}


// A carry-save adder
std::vector<std::vector<uint32_t> > BooleanCircuit::PutCarrySaveGate(std::vector<uint32_t> a, std::vector<uint32_t> b, std::vector<uint32_t> c, uint32_t inbitlen, bool carry) {
	std::vector<uint32_t> axc(inbitlen);
	std::vector<uint32_t> acNbc(inbitlen);
	std::vector<std::vector<uint32_t> > out(2);

	/*PutPrintValueGate(new boolshare(a, this), "Carry Input A");
	PutPrintValueGate(new boolshare(b, this), "Carry Input B");
	PutPrintValueGate(new boolshare(c, this), "Carry Input C");*/

	for (uint32_t i = 0; i < inbitlen; i++) {
		axc[i] = PutXORGate(a[i],c[i]); //i*3 - 2
		acNbc[i] = PutANDGate(axc[i], PutXORGate(b[i],c[i])); //2+i*3
	}

	if(carry) {
		out[0].resize(inbitlen+1);
		out[0][inbitlen] = PutConstantGate(0, GetNumVals(out[0][0]));
		out[1].resize(inbitlen+1);
		out[1][inbitlen] = PutXORGate(acNbc[inbitlen-1],c[inbitlen-1]);
	} else {
		out[0].resize(inbitlen);
		out[1].resize(inbitlen);
	}

	for (uint32_t i = 0; i < inbitlen; i++) {
		out[0][i] = PutXORGate(b[i],axc[i]);
	}

	out[1][0] = PutConstantGate(0, GetNumVals(out[0][0]));
	for (uint32_t i = 0; i < inbitlen-1; i++) {
		out[1][i+1] = PutXORGate(acNbc[i],c[i]);
	}

	/*PutPrintValueGate(new boolshare(out[0], this), "Carry Output 0");
	PutPrintValueGate(new boolshare(out[1], this), "Carry Output 1");*/

	return out;
}



/*
 * In implementation of the Brent-Kung adder for the Bool-No-MT sharing. To process the values, 5 LUTs are needed:
 * 1) for the inputs, 2) for intermediate carry-forwarding, 3) for critical path on inputs, 4) for the critical path, 5) for the inverse carry tree.
 */
std::vector<uint32_t> BooleanCircuit::PutLUTAddGate(std::vector<uint32_t> a, std::vector<uint32_t> b, BOOL bCARRY) {
	uint32_t inputbitlen = std::max(a.size(), b.size());
	PadWithLeadingZeros(a, b);
	std::vector<uint32_t> out(a.size() + bCARRY);
	std::vector<uint32_t> parity(inputbitlen), carry(inputbitlen), parity_zero(inputbitlen), tmp;
	std::vector<uint32_t> lut_in(2*inputbitlen);
	uint32_t max_ins = 4, processed_ins;

	uint32_t n_crit_ins = std::min(inputbitlen, (uint32_t) max_ins);
	std::vector<uint32_t> tmpout;

	//std::cout << "Building a LUT add gate for " << inputbitlen << " input bits" << std::endl;

	//step 1: process the input values and generate carry / parity signals
	//compute the parity bits for the zero-th layer. Are needed for the result
	for (uint32_t i = 0; i < inputbitlen; i++) { //0-th layer
		parity_zero[i] = PutXORGate(a[i], b[i]);
		parity[i] = parity_zero[i];
	}

	lut_in.clear();
	lut_in.resize(n_crit_ins*2);
	for(uint32_t i = 0; i < n_crit_ins; i++) {
		lut_in[2*i] = a[i];
		lut_in[2*i+1] = b[i];
	}
	//process the first bits on the critical path and obtain the carry bits
	//std::cout << "building a crit path input gate with nins = " << n_crit_ins << std::endl;
	tmp = PutTruthTableMultiOutputGate(lut_in, n_crit_ins, (uint64_t*) m_vLUT_ADD_CRIT_IN[n_crit_ins-1]);
	for(uint32_t i = 0; i < tmp.size(); i++) {
		carry[i] = tmp[i];
	}

	//process the remaining input bits to have all carry / parity signals
	for(uint32_t i = n_crit_ins; i < inputbitlen; ) {
		processed_ins = std::min(inputbitlen - i, max_ins);
		//assign values to the LUT
		lut_in.clear();
		lut_in.resize(2*processed_ins);

		//std::cout << "building a standard input gate with nins = " << processed_ins << ", i = " << i << " and first val = " << (hex) << m_vLUT_ADD_IN[processed_ins-1][0] <<(dec)<<
		//		", lut_in.size() = " << lut_in.size() << ", expecting nouts = " << m_vLUT_ADD_N_OUTS[processed_ins-1] << std::endl;
		//std::cout << "Inputs: ";
		for(uint32_t j = 0; j < processed_ins; j++) {
			lut_in[2*j] = a[i+j];
			lut_in[2*j+1] = b[i+j];
			//std::cout << i + j << ", ";
		}
		//process inputs via LUT and write updated gates into carry / parity vectors
		tmp = PutTruthTableMultiOutputGate(lut_in, m_vLUT_ADD_N_OUTS[processed_ins-1], (uint64_t*) m_vLUT_ADD_IN[processed_ins-1]);
		//std::cout << ", outputs = " << i;
		carry[i] = tmp[0];
		if(processed_ins > 1) {
			//std::cout << ", " << i+1;
			parity[i+1] = tmp[1];
			carry[i+1] = tmp[2];
			if(processed_ins > 2) {
				//std::cout << ", " << i+2;
				carry[i+2] = tmp[3];
				if(processed_ins > 3) {
					//std::cout << ", " << i+3;
					parity[i+3] = tmp[4];
					carry[i+3] = tmp[5];
				}
			}
		}
		//std::cout << std::endl;
		i+= processed_ins;
	}

	//step 2: process the carry / parity signals and forward them in the tree
	for(uint32_t d = 1; d < ceil_log2(inputbitlen+1)/2; d++) {
		//step 2.1: process the carry signals on the critical path
		uint32_t base = 8 * (1<<(2*(d-1)));
		uint32_t dist = base/2;

		processed_ins = 1+ std::min((inputbitlen - base)/dist, max_ins-2);
		//std::cout << "critical intermediate base = " << base << ", dist = " << dist << ", processed_ins = " << processed_ins << std::endl;

		lut_in.clear();
		lut_in.resize(2*processed_ins+1);
		lut_in[0] = carry[(base-1)-dist];
		for(uint32_t j = 0; j < processed_ins; j++) {
			lut_in[2*j+1] = parity[(base-1)+j*(dist)];
			lut_in[2*j+2] = carry[(base-1)+j*(dist)];
		}
		//std::cout << "building a crit-path lut with " << lut_in.size() << " input wires: " << base-1-dist << ", ";
		/*for(uint32_t j = 0; j < processed_ins; j++) {
			std::cout << base+j*dist << ", ";
		}
		std::cout << std::endl;*/
		tmp = PutTruthTableMultiOutputGate(lut_in, processed_ins, (uint64_t*) m_vLUT_ADD_CRIT[processed_ins-1]);
		for(uint32_t j = 0; j < tmp.size(); j++) {
			carry[base-1+j*dist] = tmp[j];
		}

		//step 2.2: forward carry and parity signals down the tree
		for(uint32_t i = (base+3*dist)-1; i+dist < inputbitlen; i+=(4*dist)) {
			processed_ins = std::min(ceil_divide((inputbitlen - (i+dist)),2*dist), max_ins-2);
			//std::cout << "intermediate base = " << i << ", dist = " << dist << ", processed_ins = " << processed_ins << std::endl;

			lut_in.clear();
			lut_in.resize(4*processed_ins);
			//std::cout << "building an internal lut with " << lut_in.size() << " input wires: ";

			for(uint32_t j = 0; j < processed_ins*2; j++) {
				lut_in[2*j] = parity[i+j*(dist)];
				lut_in[2*j+1] = carry[i+j*(dist)];
				//std::cout << i+j*dist << ", ";
			}
			//std::cout << std::endl;
			tmp = PutTruthTableMultiOutputGate(lut_in, processed_ins*2, (uint64_t*) m_vLUT_ADD_INTERNAL[processed_ins-1]);
			//std::cout << "Truth table = " << m_vLUT_ADD_INTERNAL[processed_ins-1][0] << std::endl;
			for(uint32_t j = 0; j < tmp.size()/2; j++) {
				//std::cout << "writing bit " << 2*j << " and " << 2*j+1 << " to parity/carry position " << i+dist+2*j*dist << std::endl;
				parity[i+dist+j*2*dist] = tmp[2*j];
				carry[i+dist+j*2*dist] = tmp[2*j+1];
			}
		}

	}

	//std::cout << "Doing " << (floor_log2(inputbitlen/5)/2)+1 << " iterations on the inverse carry tree, " << floor_log2(inputbitlen/5) << ", " << inputbitlen/5 << std::endl;
	//step 3: build the inverse carry tree
	//d increases with d = 0: 5, d = 1: 20, d = 2: 80; d = 3: 320, ...
	for(int32_t d = (floor_log2(inputbitlen/5)/2); d >= 0; d--) {
		//for d = 0: 4, for d = 1: 16, for d = 2: 64
		uint32_t start = 4 * (1<<(2*d));
		//for start = 4: 1, start = 16: 4, start = 64: 16
		uint32_t dist = start/4;
		//std::cout << "d = " << d << ", start = " << start << ", dist = " << dist << std::endl;
		for(uint32_t i = start; i < inputbitlen; i+=start) {
			//processed_ins here needs to be between 1 and 3
			//processed_ins = std::min(inputbitlen - i, max_ins-1);
			processed_ins = std::min((inputbitlen - i)/dist, max_ins-1);
			if(processed_ins > 0) {
				//assign values to the LUT
				lut_in.clear();
				lut_in.resize(2*processed_ins+1);
				lut_in[0] = carry[i-1];
				for(uint32_t j = 0; j < processed_ins; j++) {
					lut_in[2*j+1] = parity[(i-1)+(j+1)*dist];
					lut_in[2*j+2] = carry[(i-1)+(j+1)*dist];
				}
				//std::cout << "wanting to build gate "<< std::endl;
				//std::cout << "Building INV gate with " << processed_ins << " inputs: " << i-1;
				/*for(uint32_t j = 0; j < processed_ins; j++) {
					std::cout << ", " << (i-1)+(j+1)*dist;
				}*/
				//std::cout << std::endl;
				tmp = PutTruthTableMultiOutputGate(lut_in, processed_ins, (uint64_t*) m_vLUT_ADD_INV[processed_ins-1]);
				//std::cout << "done" << std::endl;
				//copy resulting carry bit into carries
				//std::cout << ", and " << tmp.size() << " outputs: ";
				for(uint32_t j = 0; j < tmp.size(); j++) {
					carry[(i-1)+(j+1)*dist] = tmp[j];
					//std::cout << (i-1)+(j+1)*dist << ", ";
				}
				//std::cout << std::endl;
			}
			//i+= dist;//(processed_ins+1);
		}
	}


	//step 4: compute the outputs from the carry signals and the parity bits at the zero-th level
	out[0] = parity_zero[0];
	for (uint32_t i = 1; i < inputbitlen; i++) {
		out[i] = PutXORGate(parity_zero[i], carry[i - 1]);
	}
	if (bCARRY)	//Do I expect a carry in the most significant bit position?
		out[inputbitlen] = carry[inputbitlen - 1];

	return out;
}

std::vector<uint32_t> BooleanCircuit::PutMulGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t resultbitlen, bool depth_optimized, bool vector_ands) {
	PadWithLeadingZeros(a, b);
	// std::cout << "a.size() = " << a.size() << ", b.size() = " << b.size() << std::endl;
	uint32_t inputbitlen = a.size();

	if(inputbitlen == 1) {
		return PutANDGate(a, b);
	}

	std::vector<std::vector<uint32_t> > vAdds(inputbitlen);
	uint32_t zerogate = PutConstantGate(0, m_vGates[a[0]].nvals);

	resultbitlen = std::min(resultbitlen, 2 * inputbitlen);

	if(m_eContext == S_BOOL && vector_ands) {
		share *ina, *inb, **mulout, *zero_share;
		ina = new boolshare(a, this);
		inb = new boolshare(b, this);
		zero_share = new boolshare(inputbitlen, this);

		mulout = (share**) malloc(sizeof(share*) * inputbitlen);

		for(uint32_t i = 0; i < inputbitlen; i++) {
			mulout[i] = new boolshare(inputbitlen, this);
			zero_share->set_wire_id(i, zerogate);
		}

		for(uint32_t i = 0; i < inputbitlen; i++) {
			PutMultiMUXGate(&ina, &zero_share, inb->get_wire_ids_as_share(i),  1, &(mulout[i]));
		}

		for (uint32_t i = 0, ctr; i < inputbitlen; i++) {
			ctr = 0;
			vAdds[i].resize(resultbitlen);

			for (uint32_t j = 0; j < i && ctr < resultbitlen; j++, ctr++) {
				vAdds[i][ctr] = zerogate;
			}
			for (uint32_t j = 0; j < inputbitlen && ctr < resultbitlen; j++, ctr++) {
				vAdds[i][ctr] = mulout[j]->get_wire_id(i);//(a[j], b[i]);
			}
			for (uint32_t j = i; j < inputbitlen && ctr < resultbitlen; j++, ctr++) {
				vAdds[i][ctr] = zerogate;
			}
		}

		free(mulout);
	} else {
	// Compute AND between all bits
#ifdef ZDEBUG
	std::cout << "Starting to construct multiplication gate for " << inputbitlen << " bits" << std::endl;
#endif

		for (uint32_t i = 0, ctr; i < inputbitlen; i++) {
			ctr = 0;
			vAdds[i].resize(resultbitlen);
#ifdef ZDEBUG
			std::cout << "New Iteration with ctr = " << ctr << ", and resultbitlen = " << resultbitlen << std::endl;
#endif
			for (uint32_t j = 0; j < i && ctr < resultbitlen; j++, ctr++) {
				vAdds[i][ctr] = zerogate;
			}
			for (uint32_t j = 0; j < inputbitlen && ctr < resultbitlen; j++, ctr++) {
				vAdds[i][ctr] = PutANDGate(a[j], b[i]);
			}
			for (uint32_t j = i; j < inputbitlen && ctr < resultbitlen; j++, ctr++) {
				vAdds[i][ctr] = zerogate;
			}
		}
	}


	if (depth_optimized) {
		std::vector<std::vector<uint32_t> > out = PutCSNNetwork(vAdds);
		return PutDepthOptimizedAddGate(out[0], out[1]);
	} else {
		return PutWideAddGate(vAdds);
	}
}



share* BooleanCircuit::PutMULGate(share* ina, share* inb) {
	//set the resulting bit length to be the smallest of: 1) bit length of the products or 2) the highest maximum bit length between ina and inb
	uint32_t resultbitlen = std::min(ina->get_bitlength() + inb->get_bitlength(), std::max(ina->get_max_bitlength(), inb->get_max_bitlength()));
	return new boolshare(PutMulGate(ina->get_wires(), inb->get_wires(), resultbitlen), this);
}

share* BooleanCircuit::PutGTGate(share* ina, share* inb) {
	share* shr = new boolshare(1, this);
	shr->set_wire_id(0, PutGTGate(ina->get_wires(), inb->get_wires()));
	return shr;
}
share* BooleanCircuit::PutEQGate(share* ina, share* inb) {
	share* shr = new boolshare(1, this);
	shr->set_wire_id(0, PutEQGate(ina->get_wires(), inb->get_wires()));
	return shr;
}
share* BooleanCircuit::PutMUXGate(share* ina, share* inb, share* sel) {
	return new boolshare(PutMUXGate(ina->get_wires(), inb->get_wires(), sel->get_wire_id(0)), this);
}

std::vector<uint32_t> BooleanCircuit::PutWideAddGate(std::vector<std::vector<uint32_t> > ins) {
	// build a balanced binary tree
	std::vector<std::vector<uint32_t> >& survivors = ins;

	while (survivors.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < survivors.size();) {
			if (i + 1 >= survivors.size()) {
				survivors[j++] = survivors[i++];
			} else {
				survivors[j++] = PutSizeOptimizedAddGate(survivors[i], survivors[i + 1], false);
				i += 2;
			}
		}
		survivors.resize(j);
	}

	return survivors[0];
}

std::vector<std::vector<uint32_t> > BooleanCircuit::PutCSNNetwork(std::vector<std::vector<uint32_t> > ins) {
	// build a balanced carry-save network
	uint32_t inputbitlen = ins[0].size();
	uint32_t wires = ins.size();
	std::vector<std::vector<uint32_t> > survivors(wires * 2);// = ins;
	std::vector<std::vector<uint32_t> > carry_lines(wires-2);
	std::vector<std::vector<uint32_t> > rem(8);
	std::vector<std::vector<uint32_t> > out(2);
	int p_head=wires, p_tail = 0, c_head = 0, c_tail = 0;//, temp_gates;
	std::vector<uint32_t> dummy(inputbitlen);

	for(uint32_t i = 0; i < ins.size(); i++) {
		survivors[i] = ins[i];
	}

	if(ins.size() < 3)
		return ins;

	while(wires > 2) {
		for(; c_tail<c_head-2; c_tail+=3) {
#ifdef ZDEBUG
			std::cout << "ctail: " << c_tail << ", c_head: " << c_head << std::endl;
#endif
			//temp_gates = m_nFrontier;
			out = PutCarrySaveGate(carry_lines[c_tail], carry_lines[c_tail+1], carry_lines[c_tail+2], inputbitlen);
#ifdef ZDEBUG
	std::cout << "Computing Carry CSA for gates " << survivors[p_tail] << ", " << survivors[p_tail+1] << ", " << survivors[p_tail+2] << " and bitlen: " << (2*inputbitlen-1) << ", gates before: " << temp_gates << ", gates after: " << m_nFrontier << std::endl;
#endif
			survivors[p_head++] = out[0];
			carry_lines[c_head++] = out[1];
			wires--;
		}
		for(; p_tail<p_head-2; p_tail+=3) {
#ifdef ZDEBUG
			std::cout << "ptail: " << p_tail << ", p_head: " << p_head << std::endl;
#endif
			//temp_gates = m_nFrontier;
			out = PutCarrySaveGate(survivors[p_tail], survivors[p_tail+1], survivors[p_tail+2], inputbitlen);
#ifdef ZDEBUG
	std::cout << "Computing Parity CSA for gates " << survivors[p_tail] << ", " << survivors[p_tail+1] << ", " << survivors[p_tail+2] << " and bitlen: " << (2*inputbitlen-1) <<  ", gates before: " << temp_gates << ", gates after: " << m_nFrontier << std::endl;
#endif
			survivors[p_head++] = out[0];
			carry_lines[c_head++] = out[1];
			wires--;
		}
		if((p_head-p_tail) < 3 && (c_head-c_tail) < 3 && wires > 2)	{
#ifdef ZDEBUG
	std::cout << "Less than 3 in both, Carry and XOR" << std::endl;
#endif
			uint32_t left = (p_head-p_tail) + (c_head-c_tail);
			rem[0] = survivors[p_tail];
			rem[1] = (p_head-p_tail)>1? survivors[p_tail+1] : carry_lines[c_tail];
			rem[2] = (p_head-p_tail)>1? carry_lines[c_tail] : carry_lines[c_tail+1];
			rem[3] = left > 3? carry_lines[c_tail+1] : dummy;//the dummy value should never be used!
			for(uint32_t j = 0; j < left && wires > 2; j+=3)	{
#ifdef ZDEBUG
				std::cout << "left: " << left << ", j: " << j << std::endl;
#endif
				//temp_gates = m_nFrontier;
				out = PutCarrySaveGate(rem[j], rem[j+1], rem[j+2], inputbitlen);
#ifdef ZDEBUG
	std::cout << "Computing Finish CSA for gates " << rem[j] << ", " << rem[j+1] << ", " << rem[j+2] << " and bitlen: " << (2*inputbitlen-1) << ", wires: " << wires << ", gates before: " << temp_gates << ", gates after: " << m_nFrontier << std::endl;
#endif
				rem[left++] = out[0];
				rem[left++] = out[1];
				wires--;
			}
#ifdef ZDEBUG
			std::cout << "Computed last CSA gate, wires = " << wires << ", ending " << std::endl;
#endif
		}
	}
#ifdef ZDEBUG
	std::cout << "Returning" << std::endl;
#endif
	return out;
}


std::vector<uint32_t> BooleanCircuit::PutSUBGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t max_bitlength) {
	//pad with leading zeros
	if(a.size() < max_bitlength) {
		uint32_t zerogate = PutConstantGate(0, m_vGates[a[0]].nvals);
		a.resize(max_bitlength, zerogate);
	}
	if(b.size() < max_bitlength) {
		uint32_t zerogate = PutConstantGate(0, m_vGates[a[0]].nvals);
		b.resize(max_bitlength, zerogate);
	}

	uint32_t bitlen = a.size();
	std::vector<uint32_t> C(bitlen);
	uint32_t i, ainvNbxc, ainvxc, bxc;
	std::vector<uint32_t> ainv(bitlen);
	std::vector<uint32_t> out(bitlen);

	for (i = 0; i < bitlen; i++) {
		ainv[i] = PutINVGate(a[i]);
	}

	C[0] = PutConstantGate(0, m_vGates[a[0]].nvals);

	for (i = 0; i < bitlen - 1; i++) {
		//===================
		// New Gates
		// ainv[i] XOR c[i]
		ainvxc = PutXORGate(ainv[i], C[i]);

		// b[i] xor c[i]
		bxc = PutXORGate(b[i], C[i]);

		// (ainv[i] xor c[i]) AND (b[i] xor c[i])
		ainvNbxc = PutANDGate(ainvxc, bxc);

		// C[i+1] -> c[i] xor (ainv[i] xor c[i]) AND (b[i] xor c[i])
		C[i + 1] = PutXORGate(ainvNbxc, C[i]);
	}

	for (i = 0; i < bitlen; i++) {
		// a[i] xor b[i] xor C[i]
		bxc = PutXORGate(b[i], C[i]);
		out[i] = PutXORGate(bxc, a[i]);
	}

	return out;
}

share* BooleanCircuit::PutSUBGate(share* ina, share* inb) {
	return new boolshare(PutSUBGate(ina->get_wires(), inb->get_wires(), std::max(ina->get_max_bitlength(), inb->get_max_bitlength())), this);
}




//computes: ci = a > b ? 1 : 0; but assumes both values to be of equal length!
uint32_t BooleanCircuit::PutGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b) {
	PadWithLeadingZeros(a, b);

	if (m_eContext == S_YAO) {
		return PutSizeOptimizedGTGate(a, b);
	} else if(m_eContext == S_BOOL) {
		return PutDepthOptimizedGTGate(a, b);
	} else {
		return PutLUTGTGate(a, b);
	}
}

//computes: ci = a > b ? 1 : 0; but assumes both values to be of equal length!
uint32_t BooleanCircuit::PutSizeOptimizedGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b) {
	PadWithLeadingZeros(a, b);
	uint32_t ci = 0, ci1, ac, bc, acNbc;
	ci = PutConstantGate((UGATE_T) 0, m_vGates[a[0]].nvals);
	for (uint32_t i = 0; i < a.size(); i++, ci = ci1) {
		ac = PutXORGate(a[i], ci);
		bc = PutXORGate(b[i], ci);
		acNbc = PutANDGate(ac, bc);
		ci1 = PutXORGate(a[i], acNbc);
	}

	return ci;
}


uint32_t BooleanCircuit::PutDepthOptimizedGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b) {
	PadWithLeadingZeros(a, b);
	uint32_t i, rem;
	uint32_t inputbitlen = std::min(a.size(), b.size());
	std::vector<uint32_t> agtb(inputbitlen);
	std::vector<uint32_t> eq(inputbitlen);

	//Put the leaf comparison nodes from which the tree is built
	for (i = 0; i < inputbitlen; i++) {
		agtb[i] = PutANDGate(a[i], PutINVGate(b[i])); //PutBitGreaterThanGate(a[i], b[i]);
	}

	//compute the pairwise bit equality from bits 1 to bit inputbitlen
	for (i = 1;  i < inputbitlen; i++) {
		eq[i] = PutINVGate(PutXORGate(a[i], b[i]));
	}

	rem = inputbitlen;

	while (rem > 1) {
		uint32_t j = 0;
		//std::cout << "New iter with " << size << " element remaining"<< std::endl;
		for (i = 0; i < rem;) {
			if (i + 1 >= rem) {
				agtb[j] = agtb[i];
				eq[j] = eq[i];
				i++;
				j++;
			} else {
				//std::cout << j << " = GT" << i+1 << " XOR " << " ( EQ" << i+1 << " AND GT" << i << ")" << std::endl;
				agtb[j] = PutXORGate(agtb[i+1], PutANDGate(eq[i+1], agtb[i]));
				if(j > 0) {
					eq[j] = PutANDGate(eq[i], eq[i+1]);
				}
				i += 2;
				j++;
			}
		}
		rem = j;
	}


#ifdef ZDEBUG
	std::cout << "Finished greater than tree with adress: " << agtb[0] << ", and bitlength: " << a.size() << std::endl;
#endif
	return agtb[0];
}

uint32_t BooleanCircuit::PutLUTGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b) {
	// build a balanced 8-wise tree
	uint32_t nins, maxins = 8, minins = 0, j = 0;
	std::vector<uint32_t> lut_ins, tmp;

	//copy a and b into an internal state
	assert(a.size() == b.size());
	std::vector<uint32_t> state(a.size() + b.size());
	for(uint32_t i = 0; i < a.size(); i++) {
		state[2*i] = a[i];
		state[2*i+1] = b[i];
	}

	//build the leaf nodes for the tree
	for(uint32_t i = 0; i < state.size(); ) {
		//assign inputs for this node
		nins = std::min(maxins, (uint32_t) state.size() - i);

		//nins should always be a multiple of two
		assert((nins & 0x01) == 0);
		lut_ins.clear();
		lut_ins.assign(state.begin() + i, state.begin() + i + nins);
		tmp = PutTruthTableMultiOutputGate(lut_ins, 2, (uint64_t*) m_vLUT_GT_IN[(nins/2)-1]);
		//std::cout << "using lut " << (hex) << m_vLUT_GT_IN[(nins/2)-1][0] << (dec) << std::endl;

		//assign gt bit and eq bit to state
		state[j] = tmp[0];
		state[j+1] = tmp[1];

		i+=nins;
		j+=2;
	}

	//resize the state since we processed input bits
	state.resize(j);

	//build the tree for the remaining bits
	while (state.size() > 2) {
		j = 0;
		for (uint32_t i = 0; i < state.size();) {
			nins = std::min(maxins, (uint32_t) state.size()-i);

			//it is not efficient to build a gate here so copy the wires to the next level
			if(nins <= minins && state.size() > minins) {
				for(; i < state.size();) {
					state[j++] = state[i++];
				}
			} else {
				lut_ins.clear();
				lut_ins.assign(state.begin() + i, state.begin() + i + nins);
				tmp = PutTruthTableMultiOutputGate(lut_ins, 2, (uint64_t*) m_vLUT_GT_INTERNAL[nins/2-2]);
				state[j] = tmp[0];
				state[j+1] = tmp[1];

				i += nins;
				j += 2;
			}

		}
		state.resize(j);
	}
	return state[0];
}


uint32_t BooleanCircuit::PutEQGate(std::vector<uint32_t> a, std::vector<uint32_t> b) {
	PadWithLeadingZeros(a, b);

	uint32_t inputbitlen = a.size(), temp;
	std::vector<uint32_t> xors(inputbitlen);
	for (uint32_t i = 0; i < inputbitlen; i++) {
		temp = PutXORGate(a[i], b[i]);
		xors[i] = PutINVGate(temp);
	}

	// AND of all xor's
	if(m_eContext == S_SPLUT) {
		return PutLUTWideANDGate(xors);
	} else {
		return PutWideGate(G_NON_LIN, xors);
	}
}



uint32_t BooleanCircuit::PutORGate(uint32_t a, uint32_t b) {
	return PutINVGate(PutANDGate(PutINVGate(a), PutINVGate(b)));
}

std::vector<uint32_t> BooleanCircuit::PutORGate(std::vector<uint32_t> a, std::vector<uint32_t> b) {
	uint32_t reps = std::max(a.size(), b.size());
	PadWithLeadingZeros(a, b);
	std::vector<uint32_t> out(reps);
	for (uint32_t i = 0; i < reps; i++) {
		out[i] = PutORGate(a[i], b[i]);
	}
	return out;
}

share* BooleanCircuit::PutORGate(share* a, share* b) {
	return new boolshare(PutORGate(a->get_wires(), b->get_wires()), this);
}

/* if c [0] = s & a[0], c[1] = s & a[1], ...*/
share* BooleanCircuit::PutANDVecGate(share* ina, share* inb) {
	uint32_t inputbitlen = ina->get_bitlength();
	share* out = new boolshare(inputbitlen, this);

	if (m_eContext == S_BOOL) {
		for (uint32_t i = 0; i < inputbitlen; i++) {
			out->set_wire_id(i, PutVectorANDGate(inb->get_wire_id(i), ina->get_wire_id(i)));
		}
	} else {
		//std::cout << "Putting usual AND gate" << std::endl;
		for (uint32_t i = 0; i < inputbitlen; i++) {
			uint32_t bvec = PutRepeaterGate(inb->get_wire_id(i), m_vGates[ina->get_wire_id(i)].nvals);
			out->set_wire_id(i, PutANDGate(ina->get_wire_id(i), bvec));
		}
	}
	return out;
}

/* if s == 0 ? b : a*/
std::vector<uint32_t> BooleanCircuit::PutMUXGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t s, BOOL vecand) {
	std::vector<uint32_t> out;
	uint32_t inputbitlen = std::max(a.size(), b.size());
	uint32_t sab, ab;

	PadWithLeadingZeros(a, b);

	out.resize(inputbitlen);

	uint32_t nvals=1;
	for(uint32_t i = 0; i < a.size(); i++) {
		if(m_vGates[a[i]].nvals > nvals)
			nvals = m_vGates[a[i]].nvals;
	}
	for(uint32_t i = 0; i < b.size(); i++)
		if(m_vGates[b[i]].nvals > nvals)
			nvals = m_vGates[b[i]].nvals;

	if (m_eContext == S_BOOL && vecand && nvals == 1) {
		uint32_t avec = PutCombinerGate(a);
		uint32_t bvec = PutCombinerGate(b);

		out = PutSplitterGate(PutVecANDMUXGate(avec, bvec, s));

	} else {
		for (uint32_t i = 0; i < inputbitlen; i++) {
			ab = PutXORGate(a[i], b[i]);
			sab = PutANDGate(s, ab);
			out[i] = PutXORGate(b[i], sab);
		}
	}

	return out;
}

share* BooleanCircuit::PutVecANDMUXGate(share* a, share* b, share* s) {
	return new boolshare(PutVecANDMUXGate(a->get_wires(), b->get_wires(), s->get_wires()), this);
}

/* if s == 0 ? b : a*/
std::vector<uint32_t> BooleanCircuit::PutVecANDMUXGate(std::vector<uint32_t> a, std::vector<uint32_t> b, std::vector<uint32_t> s) {
	uint32_t nmuxes = a.size();
	PadWithLeadingZeros(a, b);

	std::vector<uint32_t> out(nmuxes);

	//std::cout << "Putting Vector AND gate" << std::endl;

	for (uint32_t i = 0; i < nmuxes; i++) {
		out[i] = PutVecANDMUXGate(a[i], b[i], s[i]);
	}

	return out;
}

/* if s == 0 ? b : a*/
uint32_t BooleanCircuit::PutVecANDMUXGate(uint32_t a, uint32_t b, uint32_t s) {
	uint32_t ab, sab;
	ab = PutXORGate(a, b);
	if (m_eContext == S_BOOL) {
		sab = PutVectorANDGate(s, ab);
	} else {
		sab = PutANDGate(s, ab);
	}
	return PutXORGate(b, sab);
}




uint32_t BooleanCircuit::PutWideGate(e_gatetype type, std::vector<uint32_t> ins) {
	// build a balanced binary tree
	std::vector<uint32_t>& survivors = ins;

	while (survivors.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < survivors.size();) {
			if (i + 1 >= survivors.size()) {
				survivors[j++] = survivors[i++];
			} else {
				if (type == G_NON_LIN)
					survivors[j++] = PutANDGate(survivors[i], survivors[i + 1]);
				else
					survivors[j++] = PutXORGate(survivors[i], survivors[i + 1]);

				i += 2;
			}
		}
		survivors.resize(j);
	}
	return survivors[0];
}


//compute the AND over all inputs
uint32_t BooleanCircuit::PutLUTWideANDGate(std::vector<uint32_t> ins) {
	// build a balanced 8-wise tree
	std::vector<uint32_t>& survivors = ins;
	uint64_t* lut = (uint64_t*) calloc(4, sizeof(uint64_t));
	uint32_t nins, maxins = 7, minins = 3;
	std::vector<uint32_t> lut_ins;
	uint32_t table_bitlen = sizeof(uint64_t) * 8;
	/*std::cout << "Building a balanced tree" << std::endl;
	std::cout << "Input gates: ";
	for(uint32_t i = 0; i < ins.size(); i++) {
		std::cout << ins[i] << ", ";
	}
	std::cout << std::endl;*/

	while (survivors.size() > 1) {
		uint32_t j = 0;

		for (uint32_t i = 0; i < survivors.size();) {
			nins = std::min((uint32_t) survivors.size()-i, maxins);
			if(nins <= minins && survivors.size() > minins) {
				for(; i < survivors.size();) {
					survivors[j++] = survivors[i++];
				}
			} else {
				lut_ins.clear();
				lut_ins.assign(ins.begin() + i, ins.begin() + i + nins);
				/*std::cout << "Combining " << nins << " gates: ";
				for(uint32_t k = 0; k < lut_ins.size(); k++) {
					std::cout << lut_ins[k] << ", ";
				}*/
				memset(lut, 0, bits_in_bytes(table_bitlen));
				lut[((1L<<nins)-1) / table_bitlen] = 1L << (((1L<<nins)-1) % table_bitlen);

				survivors[j++] = PutTruthTableGate(lut_ins, 1, lut);
				//std::cout << " to gate " << survivors[j-1] << std::endl;

				/*std::cout << "LUT: ";
				for(uint32_t k = 0; k < 4; k++) {
					std::cout << (hex) << lut[k] << ", " << (dec);
				}
				std::cout << std::endl;*/

				i += nins;
			}

		}
		survivors.resize(j);
	}
	return survivors[0];
}

//if s == 0: a stays a, else a becomes b, share interface
share** BooleanCircuit::PutCondSwapGate(share* a, share* b, share* s, BOOL vectorized) {
	share** s_out = (share**) malloc(sizeof(share*) *2);

	std::vector<std::vector<uint32_t> > out = PutCondSwapGate(a->get_wires(), b->get_wires(), s->get_wire_id(0), vectorized);
	s_out[0] = new boolshare(out[0], this);
	s_out[1] = new boolshare(out[1], this);
	return s_out;
}


//if s == 0: a stays a, else a becomes b
std::vector<std::vector<uint32_t> > BooleanCircuit::PutCondSwapGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t s, BOOL vectorized) {
	std::vector<std::vector<uint32_t> > out(2);
	uint32_t inputbitlen = std::max(a.size(), b.size());
	PadWithLeadingZeros(a, b);

	out[0].resize(inputbitlen);
	out[1].resize(inputbitlen);

	uint32_t ab, snab, svec;

	if (m_eContext == S_BOOL && !vectorized) {
		//Put combiner and splitter gates
		uint32_t avec = PutCombinerGate(a);
		uint32_t bvec = PutCombinerGate(b);

		ab = PutXORGate(avec, bvec);
		snab = PutVectorANDGate(s, ab);
		out[0] = PutSplitterGate(PutXORGate(snab, avec));
		out[1] = PutSplitterGate(PutXORGate(snab, bvec));
	} else {
		if (m_vGates[s].nvals < m_vGates[a[0]].nvals)
			svec = PutRepeaterGate(s, m_vGates[a[0]].nvals);
		else
			svec = s;

		for (uint32_t i = 0; i < inputbitlen; i++) {
			ab = PutXORGate(a[i], b[i]);
			snab = PutANDGate(svec, ab);

			//swap here to change swap-behavior of condswap
			out[0][i] = PutXORGate(snab, a[i]);
			out[1][i] = PutXORGate(snab, b[i]);
		}
	}

	return out;
}

//Returns val if b==1 and 0 else
std::vector<uint32_t> BooleanCircuit::PutELM0Gate(std::vector<uint32_t> val, uint32_t b) {
	std::vector<uint32_t> out(val.size());
	for (uint32_t i = 0; i < val.size(); i++) {
		out[i] = PutANDGate(val[i], b);
	}
	return out;
}

share* BooleanCircuit::PutMaxGate(const std::vector<share*>& a) {
	std::vector<std::vector<uint32_t>> max(a.size());
	std::transform(a.cbegin(), a.cend(), max.begin(),
			[](share* s){return s->get_wires();});
	return new boolshare(PutMaxGate(max), this);
}

share* BooleanCircuit::PutMaxGate(share** a, uint32_t size) {
	std::vector<share*> v(a, a+size);
	return PutMaxGate(v);
}

std::vector<uint32_t> BooleanCircuit::PutMaxGate(const std::vector<std::vector<uint32_t>>& ws) {
	BinaryOp_v_uint32_t op = [this](auto a, auto b) {
				uint32_t cmp = (m_eContext == S_YAO) ?
					this->PutSizeOptimizedGTGate(a, b) :
					this->PutDepthOptimizedGTGate(a, b);
				return this->PutMUXGate(a, b, cmp);
			};
	return binary_accumulate(ws, op);
}

share* BooleanCircuit::PutMinGate(share** a, uint32_t nvals) {
	std::vector<std::vector<uint32_t> > min(nvals);
	uint32_t i;
	for (i = 0; i < nvals; i++) {
		min[i] = a[i]->get_wires();
	}
	return new boolshare(PutMinGate(min), this);
}


std::vector<uint32_t> BooleanCircuit::PutMinGate(std::vector<std::vector<uint32_t> > a) {
	// build a balanced binary tree
	uint32_t cmp;
	std::vector<std::vector<uint32_t> > m_vELMs = a;

	while (m_vELMs.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < m_vELMs.size();) {
			if (i + 1 >= m_vELMs.size()) {
				m_vELMs[j] = m_vELMs[i];
				i++;
				j++;
			} else {
				//	cmp = bc->PutGTTree(m_vELMs[i], m_vELMs[i+1]);
				if (m_eContext == S_YAO) {
					cmp = PutSizeOptimizedGTGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
				} else {
					cmp = PutDepthOptimizedGTGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
				}

				i += 2;
				j++;
			}
		}
		m_vELMs.resize(j);
	}
	return m_vELMs[0];
}



// vals = values, ids = indicies of each value, n = size of vals and ids
void BooleanCircuit::PutMinIdxGate(share** vals, share** ids, uint32_t nvals, share** minval_shr, share** minid_shr) {
	std::vector<std::vector<uint32_t> > val(nvals);
	std::vector<std::vector<uint32_t> > id(nvals);

	std::vector<uint32_t> minval(1);
	std::vector<uint32_t> minid(1);

	for (uint32_t i = 0; i < nvals; i++) {
		/*val[i].resize(a[i]->size());
		for(uint32_t j = 0; j < a[i]->size(); j++) {
			val[i][j] = a[i]->get_wire(j);//->get_wires();
		}

		ids[i].resize(b[i]->size());
		for(uint32_t j = 0; j < b[i]->size(); j++) {
			ids[i][j] = b[i]->get_wire(j);
		}*/
		val[i] = vals[i]->get_wires();
		id[i] = ids[i]->get_wires();
	}

	PutMinIdxGate(val, id, minval, minid);

	*minval_shr = new boolshare(minval, this);
	*minid_shr = new boolshare(minid, this);
}


// vals = values, ids = indicies of each value, n = size of vals and ids
void BooleanCircuit::PutMinIdxGate(std::vector<std::vector<uint32_t> > vals, std::vector<std::vector<uint32_t> > ids,
		std::vector<uint32_t>& minval, std::vector<uint32_t>& minid) {
	// build a balanced binary tree
	uint32_t cmp;
	std::vector<std::vector<uint32_t> > m_vELMs = vals;

#ifdef USE_MULTI_MUX_GATES
	uint32_t nvariables = 2;
	share **vala, **valb, **valout, *tmpval, *tmpidx, *cond;
	if(m_eContext == S_BOOL) {
		vala = (share**) malloc(sizeof(share*) * nvariables);
		valb = (share**) malloc(sizeof(share*) * nvariables);
		valout = (share**) malloc(sizeof(share*) * nvariables);
		tmpval = new boolshare(vals[0].size(), this);
		tmpidx = new boolshare(ids[0].size(), this);
		cond = new boolshare(1, this);
	}
#endif

	while (m_vELMs.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < m_vELMs.size();) {
			if (i + 1 >= m_vELMs.size()) {
				m_vELMs[j] = m_vELMs[i];
				ids[j] = ids[i];
				i++;
				j++;
			} else {
				//	cmp = bc->PutGTTree(m_vELMs[i], m_vELMs[i+1]);
				if (m_eContext == S_BOOL) {
					cmp = PutDepthOptimizedGTGate(m_vELMs[i], m_vELMs[i + 1]);
#ifdef USE_MULTI_MUX_GATES
					//Multimux
					cond->set_wire_id(0, cmp);
					vala[0] = new boolshare(m_vELMs[i+1], this);
					vala[1] = new boolshare(ids[i+1], this);

					valb[0] = new boolshare(m_vELMs[i], this);
					valb[1] = new boolshare(ids[i], this);

					valout[0] = tmpval;
					valout[1] = tmpidx;

					PutMultiMUXGate(vala, valb, cond, nvariables, valout);
					m_vELMs[j] = tmpval->get_wires();
					ids[j] = tmpidx->get_wires();
#else
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp, false);
					ids[j] = PutMUXGate(ids[i + 1], ids[i], cmp, false);
#endif
				} else {
					cmp = PutSizeOptimizedGTGate(m_vELMs[i], m_vELMs[i + 1]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					ids[j] = PutMUXGate(ids[i + 1], ids[i], cmp);

				}

				i += 2;
				j++;
			}
		}
		m_vELMs.resize(j);
		ids.resize(j);
	}
	minval = m_vELMs[0];
	minid = ids[0];

#ifdef USE_MULTI_MUX_GATES
	if(m_eContext == S_BOOL) {
		free(vala);
		free(valb);
		free(valout);
		delete tmpval;
		delete tmpidx;
		delete cond;
	}
#endif
}

/**Max....*/

// vals = values, ids = indicies of each value, n = size of vals and ids
void BooleanCircuit::PutMaxIdxGate(share** vals, share** ids, uint32_t nvals, share** maxval_shr, share** maxid_shr) {
	std::vector<std::vector<uint32_t> > val(nvals);
	std::vector<std::vector<uint32_t> > id(nvals);

	std::vector<uint32_t> maxval(1);
	std::vector<uint32_t> maxid(1);

	for (uint32_t i = 0; i < nvals; i++) {
		/*val[i].resize(a[i]->size());
		for(uint32_t j = 0; j < a[i]->size(); j++) {
			val[i][j] = a[i]->get_wire(j);//->get_wires();
		}

		ids[i].resize(b[i]->size());
		for(uint32_t j = 0; j < b[i]->size(); j++) {
			ids[i][j] = b[i]->get_wire(j);
		}*/
		val[i] = vals[i]->get_wires();
		id[i] = ids[i]->get_wires();
	}

	//std::cout<<"Size: "<<val.size()<<std::endl;
	PutMaxIdxGate(val, id, maxval, maxid);

	*maxval_shr = new boolshare(maxval, this);
	*maxid_shr = new boolshare(maxid, this);
}


// vals = values, ids = indicies of each value, n = size of vals and ids
void BooleanCircuit::PutMaxIdxGate(std::vector<std::vector<uint32_t> > vals, std::vector<std::vector<uint32_t> > ids,
		std::vector<uint32_t>& maxval, std::vector<uint32_t>& maxid) {
	// build a balanced binary tree
	uint32_t cmp;
	std::vector<std::vector<uint32_t> > m_vELMs = vals;
#ifdef USE_MULTI_MUX_GATES
	uint32_t nvariables = 2;
	share **vala, **valb, **valout, *tmpval, *tmpidx, *cond;
	if(m_eContext == S_BOOL) {
		vala = (share**) malloc(sizeof(share*) * nvariables);
		valb = (share**) malloc(sizeof(share*) * nvariables);
		valout = (share**) malloc(sizeof(share*) * nvariables);
		tmpval = new boolshare(vals[0].size(), this);
		tmpidx = new boolshare(ids[0].size(), this);
		cond = new boolshare(1, this);
	}
#endif

	while (m_vELMs.size() > 1) {
		unsigned j = 0;
		for (unsigned i = 0; i < m_vELMs.size();) {
			if (i + 1 >= m_vELMs.size()) {
				m_vELMs[j] = m_vELMs[i];
				ids[j] = ids[i];
				i++;
				j++;
			} else {
				if (m_eContext == S_BOOL) {
					cmp = PutDepthOptimizedGTGate(m_vELMs[i+1], m_vELMs[i]);

#ifdef USE_MULTI_MUX_GATES
					//Multimux
					cond->set_wire_id(0, cmp);
					vala[0] = new boolshare(m_vELMs[i+1], this);
					vala[1] = new boolshare(ids[i+1], this);

					valb[0] = new boolshare(m_vELMs[i], this);
					valb[1] = new boolshare(ids[i], this);

					valout[0] = tmpval;
					valout[1] = tmpidx;

					PutMultiMUXGate(vala, valb, cond, nvariables, valout);
					m_vELMs[j] = tmpval->get_wires();
					ids[j] = tmpidx->get_wires();
#else
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					ids[j] = PutMUXGate(ids[i + 1], ids[i], cmp);
#endif
				} else {
					cmp = PutSizeOptimizedGTGate(m_vELMs[i + 1], m_vELMs[i]);
					m_vELMs[j] = PutMUXGate(m_vELMs[i + 1], m_vELMs[i], cmp);
					ids[j] = PutMUXGate(ids[i + 1], ids[i], cmp);

				}

				i += 2;
				j++;
			}
		}
		m_vELMs.resize(j);
		ids.resize(j);
	}
	maxval = m_vELMs[0];
	maxid = ids[0];

#ifdef USE_MULTI_MUX_GATES
	if(m_eContext == S_BOOL) {
		free(vala);
		free(valb);
		free(valout);
		delete tmpval;
		delete tmpidx;
		delete cond;
	}
#endif
}




std::vector<uint32_t> BooleanCircuit::PutFPGate(const std::string func, std::vector<uint32_t> inputs, uint8_t bitsize, uint32_t nvals){
	std::string fn = m_cCircuitFileDir;

	//if there is no "/" at the end, append it
	if ((fn.size() > 0) && (fn.compare(fn.size()-1, 1, "/") != 0)) {
		fn += "/";
	}
	fn += "fp_";
	fn += func;
	fn += "_";
	//std::cout << "bs = " << (uint32_t) bitsize << std::endl;
	fn += std::to_string(bitsize);
	fn += ".aby";
	//std::cout << "opening " << fn.c_str() << std::endl;
	return PutGateFromFile(fn.c_str(), inputs, nvals);
}


std::vector<uint32_t> BooleanCircuit::PutFPGate(const std::string func, std::vector<uint32_t> ina, std::vector<uint32_t> inb, uint8_t bitsize, uint32_t nvals){
	ina.insert(ina.end(), inb.begin(), inb.end());
	return PutFPGate(func, ina, bitsize, nvals);
}


std::vector<uint32_t> BooleanCircuit::PutGateFromFile(const std::string filename, std::vector<uint32_t> inputs, uint32_t nvals){
	std::string line;
	std::vector<uint32_t> tokens, outputs;
	std::map<uint32_t, uint32_t> wires;

	std::ifstream myfile;

	//std::cout << "opening " << filename <<  std::endl;
	myfile.open(filename.c_str());

	uint32_t file_input_size = 0;

	if (myfile.is_open()) {
		while (getline(myfile, line)) {

			if (line != "") {

				tokenize_verilog(line, tokens);

				switch (line.at(0)) {

				case 'S': // Server input wire ids
					assert(inputs.size() >= tokens.size() + file_input_size);

					for (uint32_t i = 0; i < tokens.size(); i++) {
						wires[tokens[i]] = inputs[i + file_input_size];
					}
					file_input_size += tokens.size();
					break;

				case 'C': // Client input wire ids
					assert(inputs.size() >= tokens.size() + file_input_size);

					for (uint32_t i = 0; i < tokens.size(); i++) {
						wires[tokens[i]] = inputs[i + file_input_size];
					}
					file_input_size += tokens.size();
					break;

				case '0': // Constant Zero Gate
					wires[tokens[0]] = PutConstantGate(0, nvals);
					break;

				case '1': // Constant One Gate
					wires[tokens[0]] = PutConstantGate(1, nvals);
					break;

				case 'A': // AND Gate
					wires[tokens[2]] = PutANDGate(wires[tokens[0]], wires[tokens[1]]);
					break;

				case 'X': // XOR Gate
					wires[tokens[2]] = PutXORGate(wires[tokens[0]], wires[tokens[1]]);
					break;

				case 'V': // OR Gate
					wires[tokens[2]] = PutORGate(wires[tokens[0]], wires[tokens[1]]);
					break;

				case 'M': // MUX Gate
					wires[tokens[3]] = PutVecANDMUXGate(wires[tokens[1]], wires[tokens[0]], wires[tokens[2]]);
					break;

				case 'I': // INV Gate
					wires[tokens[1]] = PutINVGate(wires[tokens[0]]);
					break;

				case 'O': // List of output wires
					for (uint32_t i = 0; i < tokens.size(); i++) {
						outputs.push_back(wires[tokens[i]]);
					}
					break;
				}
			}
		}
		myfile.close();

		if (file_input_size < inputs.size()) {
			std::cerr << "Warning: Input sizes didn't match! Less inputs read from circuit file than passed to it!" << std::endl;
		}
	}

	else {
		std::cerr << "Error: Unable to open circuit file " << filename << std::endl;
		std::exit(EXIT_FAILURE);
	}

	wires.clear();
	tokens.clear();

	return outputs;
}

std::vector<uint32_t> BooleanCircuit::PutUniversalCircuitFromFile(const std::string filename, const std::string p1filename, std::vector<uint32_t> p2inputs, uint32_t nvals){
	std::string line;
	std::string p1line;
	std::vector<uint32_t> tokens, outputs, p1tokens;
	std::map<uint32_t, uint32_t> wires;
	std::vector<std::vector<uint32_t> > tmp;
	std::vector<uint32_t> tmp_wire1;
	std::vector<uint32_t> tmp_wire2;
	std::vector<uint32_t> p1inputs, p1inputsgate;

	std::ifstream p1file;

	p1file.open(p1filename);

	uint32_t p1file_input_size = 0;

	if(!p1file.is_open()) {
		std::cerr << "Error: Unable to open programming file " << p1filename << std::endl;
		std::exit(EXIT_FAILURE);
	}
	#ifdef DEBUG_UC
	std::cout << "Server Input Control Bits " ;
	#endif
	while (getline(p1file, p1line)){
		if (p1line != "") {
			tokenize(p1line, p1tokens);
			p1inputs.push_back(this->PutSIMDINGate(nvals, p1tokens[0], SERVER));
			if(m_eMyRole == SERVER) {
				p1inputsgate.push_back(p1tokens[0]);
			}
			else{
				p1inputsgate.push_back(0);
			}
			#ifdef DEBUG_UC
			std::cout << p1tokens[0] << std::endl;
			#endif
			p1file_input_size += 1;
		}
	}
	#ifdef DEBUG_UC
	std::cout << std::endl;
	#endif
	p1file.close();
	#ifdef DEBUG_UC
	std::cout << "P1file input size: " << p1file_input_size << std::endl;
	#endif

	if (p1file_input_size != p1inputs.size()) {
		std::cerr << "Warning: Input sizes didn't match! Less inputs read from circuit file than passed to it!" << std::endl;
	}

	std::ifstream myfile;

	myfile.open(filename);

	uint32_t file_input_size = 0;
	uint32_t p1_counter = 0;

	if (!myfile.is_open()) {
		std::cerr << "Error: Unable to open circuit file " << filename << std::endl;
		std::exit(EXIT_FAILURE);
	}
	while (getline(myfile, line)) {

		if (line != "") {

			tokenize_verilog(line, tokens);

			switch (line.at(0)) {

			case 'C': // Client input wire ids
				assert(p2inputs.size() >= tokens.size() + file_input_size - 1);
				#ifdef DEBUG_UC
							std::cout << "Client Input Wire IDs " ;
				#endif
				for (uint32_t i = 0; i < tokens.size(); i++) {
					wires[tokens[i]] = p2inputs[i + file_input_size];
					#ifdef DEBUG_UC
					std::cout << tokens[i] << " ";
					#endif
				}
				file_input_size += tokens.size();
				#ifdef DEBUG_UC
				std::cout << "number of inputs" << file_input_size << std::endl;
				#endif
				break;

			case 'Y': // MUX Gate
			#ifdef DEBUG_UC
					std::cout << "Y Gate " << tokens[2] << " = Y(" << tokens[0]
					<< " , " << tokens[1] << ") c = " << p1inputs[p1_counter] << std::endl;
			#endif
				wires[tokens[2]] = PutVecANDMUXGate(wires[tokens[0]], wires[tokens[1]], p1inputs[p1_counter]);
				p1_counter++;
				break;

			case 'U': // Universal Gate
			#ifdef DEBUG_UC
				std::cout << "Universal Gate " << tokens[2] << " = U(" << tokens[0]
						<< " , " << tokens[1] << ") op = " << p1inputs[p1_counter] << std::endl;
			#endif
				wires[tokens[2]] =
					PutUniversalGate(wires[tokens[0]], wires[tokens[1]], p1inputsgate[p1_counter]);
				p1_counter++;
				break;

			case 'X': // X Gate
			#ifdef DEBUG_UC
					std::cout << "X Gate (" << tokens[2] << " , " << tokens[3] << ")"
					<< "= X(" << tokens[0] << " , " << tokens[1] << ") c = "
							<< p1inputs[p1_counter] << std::endl;
			#endif
				tmp_wire1.clear();
				tmp_wire2.clear();
				tmp_wire1.push_back(wires[tokens[0]]);
				tmp_wire2.push_back(wires[tokens[1]]);
				tmp = PutCondSwapGate( tmp_wire1, tmp_wire2, p1inputs[p1_counter], true );
				wires[tokens[2]] = tmp[0][0];
				wires[tokens[3]] = tmp[1][0];
							p1_counter++;
				break;

			case 'O': // List of output wires
			#ifdef DEBUG_UC
				std::cout << "Output Wires ";
			#endif
				for (uint32_t i = 0; i < tokens.size(); i++) {
					outputs.push_back(wires[tokens[i]]);
					#ifdef DEBUG_UC
					std::cout << tokens[i] << " ";
					#endif
				}
				#ifdef DEBUG_UC
				std::cout << std::endl;
				#endif
				break;
			}
		}
	}

	myfile.close();

	if (file_input_size < p2inputs.size()) {
		std::cerr << "Warning: Input sizes didn't match! Less inputs read from circuit file than passed to it! " << file_input_size << "  " << p2inputs.size() << std::endl;
	}

	return outputs;
}

void BooleanCircuit::GetInputLengthFromFile(const std::string filename, uint32_t& client_input, uint32_t& server_input){
	std::string line;
	std::vector<uint32_t> tokens;
	std::ifstream myfile;

	//std::cout << "opening " << filename <<  std::endl;
	myfile.open(filename.c_str());

	client_input = 0;
	server_input = 0;

	if (!myfile.is_open()) {
		std::cerr << "Error: Unable to open circuit file " << filename << std::endl;
		std::exit(EXIT_FAILURE);
	}
	while (getline(myfile, line)) {

		if (line != "") {

			tokenize_verilog(line, tokens);

			switch (line.at(0)) {

			case 'C': // Client input wire ids
				client_input += tokens.size();
				#ifdef DEBUG_UC
				std::cout << line << std::endl;
				std::cout << client_input << std::endl;
				#endif
				break;
			case 'X': // Server input wire ids
				server_input += 1;
				break;
			case 'Y': // Server input wire ids
				server_input += 1;
				break;
			case 'U': // Server input wire ids
				server_input += 1;
				break;
			}
		}
	}
	myfile.close();
}

share* BooleanCircuit::PutLUTGateFromFile(const std::string filename, share* input) {
	return new boolshare(PutLUTGateFromFile(filename, input->get_wires()), this);
}

std::vector<uint32_t> BooleanCircuit::PutLUTGateFromFile(const std::string filename, std::vector<uint32_t> inputs){
	std::string line;
	std::vector<uint32_t> tokens, outputs;
	std::map<uint32_t, uint32_t> wires;
	std::vector<uint32_t> lut_inputs, lut_outputs, token_outputs;

	uint32_t n_inputs, n_outputs, ttable_vals, ctr;
	std::ifstream myfile;

	uint32_t* ttable;

	//std::cout << "opening " << filename <<  std::endl;
	myfile.open(filename.c_str());

	if (myfile.is_open()) {
		while (getline(myfile, line)) {

			if (line != "") {

				tokenize_verilog(line, tokens);

				switch (line.at(0)) {

				case 'I': // map the input wires to the gate
					assert(inputs.size() == tokens.size());

					//std::cout << "Input wires to Gate: ";
					for (uint32_t i = 0; i < tokens.size(); i++) {
						wires[tokens[i]] = inputs[i];
						//std::cout << wires[tokens[i]] << ", ";
					}
					//std::cout << std::endl;
					break;

				case 'X': // XOR Gate
					wires[tokens[2]] = PutXORGate(wires[tokens[0]], wires[tokens[1]]);
					break;


				case 'A': // Assign Operation
					wires[tokens[1]] = wires[tokens[0]];
					break;

				case 'N': // Logical NOT Operation
					wires[tokens[1]] = PutINVGate(wires[tokens[0]]);
					break;

				case 'L': // Parse LUT
					ctr = 0;
					//First value specifies the number of input wires
					n_inputs = tokens[ctr++];
					//Second value specifies the number of output wires
					n_outputs = tokens[ctr++];

					//std::cout << "n_inputs: " << n_inputs << ", n_outputs = " << n_outputs << std::endl;
					//next will follow n_inputs input wires. Prepare to assign them to a temporary vector for later use
					lut_inputs.resize(n_inputs);
					//std::cout << "Inputs to LUT: ";
					for(uint32_t i = 0; i < n_inputs; i++) {
						lut_inputs[i] = wires[tokens[ctr++]];
						//std::cout << tokens[ctr-1] << "(" << wires[tokens[ctr-1]] << "), ";
					}
					//std::cout << std::endl;

					//next up are the contents of the LUT for each output wire, which is broken into ceil(2^{n_inputs} / 32) 32-bit values.
					//For each output wire, we first have the content, followed by the id of the output wire.
					token_outputs.resize(n_outputs);
					ttable_vals = ceil_divide(1<<n_inputs, sizeof(uint32_t) * 8);
					ttable = (uint32_t*) malloc(ceil_divide(1<<n_inputs, sizeof(UGATE_T) * 8) * n_outputs * sizeof(UGATE_T));
					//std::cout << "(" << ttable_vals << ") TTable values : " << std::endl;;
					for(uint32_t i = 0; i < n_outputs; i++) {
						//std::cout << "Output wire " << i << ": ";
						token_outputs[i] = tokens[ctr++];
						//std::cout << "(" << token_outputs[i] << ")" << std::endl;
					}

					for(uint32_t i = 0; i < n_outputs; i++) {
						for(uint32_t j = 0; j < ttable_vals; j++) {
							ttable[i*ttable_vals + j] = tokens[ctr++];
							//std::cout << ttable[i*ttable_vals+j] << " ";
						}
					}

					//Build the LUT gate
					lut_outputs = PutTruthTableMultiOutputGate(lut_inputs, n_outputs, (uint64_t*) ttable);

					//do the mapping for all output gates
					//std::cout << "Outputs from LUT: ";
					for(uint32_t i = 0; i < n_outputs; i++) {
						wires[token_outputs[i]] = lut_outputs[i];
						//std::cout << wires[token_outputs[i]] <<", ";
					}
					//std::cout << std::endl;

					break;

				case 'O': // map the output wires from the gate to the output of this function
					//std::cout << std::endl << "Setting output wires: ";
					for (uint32_t i = 0; i < tokens.size(); i++) {
						outputs.push_back(wires[tokens[i]]);
						//std::cout << tokens[i] << "(" << wires[tokens[i]] << "), ";
					}
					//std::cout << std::endl;
					break;
				}
			}
		}
		myfile.close();
	}

	else {
		std::cerr << "Error: Unable to open circuit file " << filename << std::endl;
		std::exit(EXIT_FAILURE);
	}

	wires.clear();
	tokens.clear();

	return outputs;
}


uint32_t BooleanCircuit::GetInputLengthFromFile(const std::string filename){
	std::string line;
	std::vector<uint32_t> tokens;
	std::ifstream myfile;

	//std::cout << "opening " << filename <<  std::endl;
	myfile.open(filename.c_str());

	uint32_t file_input_size = 0;

	if (myfile.is_open()) {
		while (getline(myfile, line)) {

			if (line != "") {

				tokenize_verilog(line, tokens);

				switch (line.at(0)) {

				case 'S': // Server input wire ids
					file_input_size += tokens.size();
					break;

				case 'C': // Client input wire ids
					file_input_size += tokens.size();
					break;
				}
			}
		}
		myfile.close();
	}

	else {
		std::cerr << "Error: Unable to open circuit file " << filename << std::endl;
		std::exit(EXIT_FAILURE);
	}

	tokens.clear();

	return file_input_size;
}

uint32_t BooleanCircuit::PutIdxGate(uint32_t r, uint32_t maxidx) {
	if (r > maxidx) {
		r = maxidx;
		std::cout << "Warning: Index bigger than maxidx for IndexGate" << std::endl;
	}
	uint32_t digit, limit = ceil_log2(maxidx);
	std::vector<uint32_t> temp(limit);	// = m_nFrontier;
#ifdef ZDEBUG
			std::cout << "index for r = " << r << std::endl;
#endif
	for (uint32_t j = 0; j < limit; j++) {
		digit = (r >> j) & 1;

		temp[j] = PutConstantGate((UGATE_T) digit, 1);
		//std::cout << "gate: " << out[j] << ": " << digit << std::endl;
	}

	return PutCombinerGate(temp);
}

void BooleanCircuit::PutMultiMUXGate(share** Sa, share** Sb, share* sel, uint32_t nshares, share** Sout) {

	std::vector<uint32_t> inputsa, inputsb;
	uint32_t bitlen = 0;
	uint32_t nvals = m_vGates[sel->get_wire_id(0)].nvals;

	//Yao not allowed, if so just put standard muxes
	assert(m_eContext == S_BOOL);

	for(uint32_t i = 0; i < nshares; i++) {
		bitlen += Sa[i]->get_bitlength();
	}
	uint32_t total_nvals = bitlen * nvals;
	share* vala = new boolshare(bitlen, this);
	share* valb = new boolshare(bitlen, this);

	//std::cout << "setting gate" << std::endl;
	for(uint32_t i = 0, idx; i < bitlen; i++) {
		for(uint32_t j = 0, ctr = 0; j < nshares && (i >= ctr || j == 0); j++) {
			if(i < (ctr+Sa[j]->get_bitlength())) {
				idx = i - ctr;
				//std::cout << "for i = " << i << " taking j = " << j << " and ctr = " << ctr << std::endl;
				vala->set_wire_id(i, Sa[j]->get_wire_id(idx));
				valb->set_wire_id(i, Sb[j]->get_wire_id(idx));
			}
			ctr+=Sa[j]->get_bitlength();
		}
	}

	share* avec = PutStructurizedCombinerGate(vala, 0, 1, total_nvals);
	share* bvec = PutStructurizedCombinerGate(valb, 0, 1, total_nvals);

	share* out = PutVecANDMUXGate(avec, bvec, sel);

	//std::cout << "Setting out gates "  << std::endl;
	for(uint32_t i = 0, idx; i < bitlen; i++) {
		for(uint32_t j = 0, ctr = 0; j < nshares && (i >= ctr || j == 0); j++) {
			if(i < (ctr+Sa[j]->get_bitlength())) {
				idx = i - ctr;
				Sout[j]->set_wire_id(idx, PutStructurizedCombinerGate(out, i, bitlen, nvals)->get_wire_id(0));
			}
			ctr+=Sa[j]->get_bitlength();
		}

	}

}

void BooleanCircuit::Reset() {
	Circuit::Reset();

	free(m_vANDs);
	m_nNumANDSizes = 1;
	m_vANDs = (non_lin_vec_ctx*) malloc(sizeof(non_lin_vec_ctx) * m_nNumANDSizes);
	m_vANDs[0].bitlen = 1;
	m_vANDs[0].numgates = 0;
	m_nB2YGates = 0;
	m_nA2YGates = 0;
	m_nYSwitchGates = 0;
	m_nNumXORVals = 0;
	m_nNumXORGates = 0;
	m_nUNIVGates = 0;

	m_vTTlens.resize(1);
	m_vTTlens[0].resize(1);
	m_vTTlens[0][0].resize(1);
	m_vTTlens[0][0][0].tt_len = 4;
	m_vTTlens[0][0][0].numgates = 0;
	m_vTTlens[0][0][0].out_bits = 1;
	m_vTTlens[0][0][0].ttable_values.clear();
}

void BooleanCircuit::PadWithLeadingZeros(std::vector<uint32_t> &a, std::vector<uint32_t> &b) {
	uint32_t maxlen = std::max(a.size(), b.size());
	if(a.size() != b.size()) {
		uint32_t zerogate = PutConstantGate(0, m_vGates[a[0]].nvals);
		a.resize(maxlen, zerogate);
		b.resize(maxlen, zerogate);
	}
}

share* BooleanCircuit::PutFullAdderGate(uint32_t a, uint32_t b, uint32_t carry_in) {
	std::vector<uint32_t> out(2);

#ifdef FA_DEBUG
	std::vector<uint32_t> v_a(1); v_a[0]=a;
	std::vector<uint32_t> v_b(1); v_b[0]=b;
	std::vector<uint32_t> v_c_in(1); v_c_in[0]=carry_in;
	share * s_a = new boolshare(v_a, this);
	share * s_b = new boolshare(v_b, this);
	share * s_c_in = new boolshare(v_c_in, this);

	PutPrintValueGate(s_a, "a");
	PutPrintValueGate(s_b, "b");
	PutPrintValueGate(s_c_in, "carry_in");

	share * s_a_xor_b = PutXORGate(s_a, s_b);
	share * s_b_xor_c_in = PutXORGate(s_b, s_c_in);
	share * s_and = PutANDGate(s_a_xor_b, s_b_xor_c_in);


	PutPrintValueGate(s_a_xor_b, "a^b");
	PutPrintValueGate(s_b_xor_c_in, "b^c_in");
	PutPrintValueGate(s_and, "(a^b)&(b^c_in)");
#endif

	uint32_t a_xor_b = PutXORGate(a,b);
	out[1] = PutXORGate(PutANDGate(a_xor_b, PutXORGate(b, carry_in)),b);
	out[0] = PutXORGate(a_xor_b, carry_in);

	share* s_out = new boolshare(out, this);

#ifdef FA_DEBUG
	std::vector<uint32_t> in(3);
	in[2] = a;
	in[1] = b;
	in[0] = carry_in;
	share* s_in = new boolshare(in, this);

	PutPrintValueGate(s_in, "Full Adder Input");
	PutPrintValueGate(s_out, "Full Adder Output");
#endif

	return s_out;
}

share* BooleanCircuit::PutADDChainGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t carry_in) {
	PadWithLeadingZeros(a, b);
	std::vector<uint32_t> out(a.size());
	std::vector<uint32_t> v_c_in(1); v_c_in[0] = carry_in;
	share * last = PutFullAdderGate(a[0], b[0], carry_in);
	out[0] = last->get_wires()[0];
#ifdef AC_DEBUG
	share * s_c_in = new boolshare(v_c_in, this);
	PutPrintValueGate(s_c_in, "carry in");
	PutPrintValueGate(last, "last");
#endif
	for (size_t i = 1; i < out.size(); ++i) {
		share * tmp = PutFullAdderGate(a[i], b[i], last->get_wires()[1]);
		out[i] = tmp->get_wires()[0];
		last = tmp;
#ifdef AC_DEBUG
		PutPrintValueGate(new boolshare(std::vector<uint32_t>(&a[i], &a[i+1]), this), "a i");
		PutPrintValueGate(new boolshare(std::vector<uint32_t>(&b[i], &b[i+1]), this), "b i");
		PutPrintValueGate(tmp, "tmp");
#endif
	}
	std::vector<uint32_t> l = last->get_wires();
	if (last->get_wires()[1] && out.size() < last->get_max_bitlength())
		out.insert(out.end(), &l[1], &l[2]);
#ifdef AC_DEBUG
	PutPrintValueGate(last, "last last");
	PutPrintValueGate(new boolshare(out, this), "out");
#endif
	return new boolshare(out, this);
}

share* BooleanCircuit::PutHammingWeightGate(share* s_in) {
	return PutHammingWeightGate(s_in, s_in->get_bitlength());
}

share* BooleanCircuit::PutHammingWeightGate(share* s_in, uint32_t bitlen) {
#ifdef HW_DEBUG
	PutPrintValueGate(s_in, "INPUT_BUILD");
#endif
	// force all nvals equal assert
	s_in->get_nvals();
	std::vector<uint32_t> wires = s_in->get_wires();
	return PutHammingWeightGateRec(wires.data(), bitlen);
}

share* BooleanCircuit::PutHammingWeightGateRec(uint32_t * wires, uint32_t bitlen) {
	share* out;
	uint32_t nvals = GetNumVals(wires[0]);

	UGATE_T zero = 0u;
	share* zero_share = PutSIMDCONSGate(nvals, zero, 1);
	uint32_t zero_wire = zero_share->get_wire_id(0);

#ifdef HW_DEBUG
	std::vector<uint32_t> in(wires, wires + bitlen);
	share * s = new boolshare(in, this);
	PutPrintValueGate(s, "INPUT3");
	delete s;
#endif

	if (bitlen > 3) {
		share *v, *u;
		uint32_t i;
		size_t bitlen_v = pow(2, (uint) (log(bitlen) / log(2))) - 1;
		size_t bitlen_u = bitlen - bitlen_v - 1;

#ifdef HW_DEBUG
		std::cout << "Input bitlen: " << bitlen << "\tBitlen v: " << bitlen_v <<
				"\tBitlen u: " << bitlen_u << "\tBitlen i: " <<
				bitlen - bitlen_v - bitlen_u << std::endl;
#endif
		//build v
		v = PutHammingWeightGateRec(&wires[bitlen - bitlen_v], bitlen_v);

		//build u
		if (bitlen_u > 0) {
			u = PutHammingWeightGateRec(&wires[1], bitlen_u);
		} else {
			u = zero_share;
		}

		//build i
		if (bitlen - bitlen_v > 0) {
			i = wires[0];
		} else {
			i = zero_wire;
		}
#ifdef HW_DEBUG
		PutPrintValueGate(v, "V");
		PutPrintValueGate(u, "U");
		std::vector<uint32_t> v_i(1, i);
		PutPrintValueGate(std::make_unique<boolshare>(v_i, this).get(), "i");
		std::cout << std::endl;
#endif
		out = PutADDChainGate(v->get_wires(), u->get_wires(), i);
		delete v;
		if (bitlen_u>0) delete u; // u == zero_share otherwise and deleted later
	} else if (bitlen > 2)
		out = PutFullAdderGate(wires[2], wires[1], wires[0]);
	else if (bitlen > 1) {
		out = PutFullAdderGate(wires[1], wires[0], zero_wire);
	} else if (bitlen > 0) {
		std::vector<uint32_t> out_v(1, wires[0]);
		out = new boolshare(out_v, this);
	} else {
		return zero_share;
	}

	delete zero_share;
	return out;
}

share* BooleanCircuit::PutUint2DoubleGate(share* input){
	UINT32 from;
	FP64 to;
	return PutConvTypeGate(input, &from, &to);
}

share*  BooleanCircuit::PutConvTypeGate(share * value, ConvType* from, ConvType* to, uint32_t nvals){
	return new boolshare(PutConvTypeGate(value->get_wires(), from, to, nvals), this);
}

std::vector<uint32_t>  BooleanCircuit::PutConvTypeGate(std::vector<uint32_t> wires, ConvType* from, ConvType* to, uint32_t nvals){
	switch(to->getType()){
		case ENUM_FP_TYPE:
			return PutUint2FpGate(wires, (UINTType*)from , (FPType*)to, nvals);
		// case ENUM_UINT_TYPE:
		// 	return PutFp2UintGate(wires, (FPType*)from , (UINTType*)to);
		default:
			std::cout <<"Unknown data type in CONVType %zu" << to << std::endl;
			std::exit(EXIT_FAILURE);
	}
}


//TODO: value is in wires, remove paramter "from"?
std::vector<uint32_t> BooleanCircuit::PutUint2FpGate(std::vector<uint32_t> wires, [[maybe_unused]] UINTType* from, FPType* to, uint32_t nvals){

#ifdef UINT2FP_DEBUG
	PutPrintValueGate(new boolshare(wires, this), "INPUT");
	std::cout << "wires size: " << wires.size() << std::endl;
#endif
	//constants
	uint64_t zero = 0, one = 1;
	uint32_t one_bit_len = 1;
	share* zero_gate = PutSIMDCONSGate(nvals, zero, one_bit_len);
	share* one_gate = PutSIMDCONSGate(nvals, one, one_bit_len);
	//pad to the length of fraction or remove the most significant bits
	wires.resize(to->getNumOfDigits(), zero_gate->get_wires()[0]);
	share * s_in = new boolshare(wires, this);

	//check if input is zero
	share* eq_zero = PutEQGate(zero_gate, s_in);

	//calculate prefix or
	std::vector<uint32_t> prefix_or = PutPreOrGate(wires);
	share * s_prefix_or = new boolshare(prefix_or, this);

#ifdef UINT2FP_DEBUG
	PutPrintValueGate(s_prefix_or, "PREFIX OR");
#endif

	std::vector<uint32_t> reversed_preor;
	reversed_preor.insert(reversed_preor.begin(), prefix_or.rbegin(), prefix_or.rend());
	share * value = new boolshare(PutINVGate(reversed_preor), this);

	value->set_max_bitlength(to->getNumOfDigits()+1);
	std::vector<uint32_t> tmp_inv_out = value->get_wires();

	std::vector<uint32_t> power_of_2;
	power_of_2.insert(power_of_2.begin(), tmp_inv_out.begin(), tmp_inv_out.end());
	power_of_2.push_back(one_gate->get_wires()[0]);
	share * p2 = new boolshare(power_of_2,this);

	value = PutHammingWeightGate(p2, nvals);

	value = new boolshare(PutBarrelLeftShifterGate(s_in->get_wires(), value->get_wires(), nvals), this);
	std::vector<uint32_t> tmp_fract = value->get_wires();
	tmp_fract.resize(to->getNumOfDigits());

	value = new boolshare(tmp_fract ,this);

	std::vector<uint32_t> value_v = value->get_wires();

#ifdef UINT2FP_DEBUG
	PutPrintValueGate(value, "VALUE");
#endif

	std::reverse(value_v.begin(), value_v.end());

	value_v.resize(to->getNumOfDigits(), zero_gate->get_wires()[0]);

#ifdef UINT2FP_DEBUG
	//PutPrintValueGate(new boolshare(value_v, this), "RESIZED");
	std::cout << "fraction vector size: " << value_v.size() << std::endl;
#endif

	//Calculate number of 1-bits in Prefix OR output
	share* pre_or_for_exp = PutHammingWeightGate(s_prefix_or, nvals);

#ifdef UINT2FP_DEBUG
	std::cout << "HW out size: " << pre_or_for_exp->get_wires().size() << std::endl;
	PutPrintValueGate(pre_or_for_exp, "pre or for exp");
#endif

	share * exp = PutSIMDCONSGate(nvals, (uint64_t)(to->getExpBias()-1), to->getExpBits());

#ifdef UINT2FP_DEBUG
	PutPrintValueGate(exp, "exp initialized with bias");
	std::cout << "bias bit length: " << exp->get_wires().size() << std::endl;
#endif

	exp = PutADDGate(exp, pre_or_for_exp);

	std::vector<uint32_t> tmp_exp = exp->get_wires();
	//exp = PutXORGate(exp, PutMUXGate(zero_gate,exp,eq_zero));
	exp = PutMUXGate(exp, zero_gate, eq_zero);

	tmp_exp.resize(to->getExpBits(), zero_gate->get_wires()[0]);

	std::vector<uint32_t> v_out(1);
	v_out[0]=zero_gate->get_wires()[0];
	std::vector<uint32_t> exp_v(&tmp_exp[0], &tmp_exp[to->getExpBits()]);
	v_out.insert(v_out.end() ,exp_v.rbegin(), exp_v.rend());

#ifdef UINT2FP_DEBUG
	std::cout << "out+exp size: " << v_out.size() << std::endl;
#endif

	v_out.insert(v_out.end(), value_v.begin(), value_v.end());

#ifdef UINT2FP_DEBUG
	PutPrintValueGate(new boolshare(exp_v, this), "exponent");
	PutPrintValueGate(new boolshare(value_v, this), "fraction");
#endif

	std::reverse(v_out.begin(), v_out.end());

#ifdef UINT2FP_DEBUG
	std::cout << "Num of gates, end:" << GetNumGates() << std::endl;
	//PutPrintValueGate(new boolshare(v_out, this), "RESULT");
#endif

	return v_out;
}

/*
// TODO implement PutFP2INTGate
std::vector<uint32_t> BooleanCircuit::PutFp2UintGate(std::vector<uint32_t> wires, FPType* from, UINTType* to){
	std::vector<uint32_t> out;
	std::cout << "PutFP2INTGate is not implemented yet" << std::endl;
	std::exit(EXIT_FAILURE);
	return out;
}
*/

share * BooleanCircuit::PutPreOrGate(share * input){
	return new boolshare(PutPreOrGate(input->get_wires()), this);
}

std::vector<uint32_t> BooleanCircuit::PutPreOrGate(std::vector<uint32_t> wires){
	//TODO optimize circuit
	if(!wires.size()){
		std::cout << "PreORGate wires of size 0. Exitting." << std::endl;
		std::exit(EXIT_FAILURE);
	}
	std::vector <uint32_t> out(wires.size());
	out[wires.size()-1] = wires[wires.size()-1];

	if(wires.size()==1)
		return out;

	uint32_t tmp = PutORGate(wires[wires.size()-1], wires[wires.size()-2]);
	out[wires.size()-2] = tmp;

	if(wires.size()==2)
		return out;

	for(size_t i = 2; i < wires.size(); i++){
		tmp = PutORGate(tmp, wires[wires.size()-i-1]);
		out[wires.size()-i-1]= tmp;
	}
	return out;
}

share * BooleanCircuit::PutBarrelLeftShifterGate(share * input, share * n){
	return new boolshare(PutBarrelLeftShifterGate(input->get_wires(), n->get_wires()), this);
}

std::vector<uint32_t> BooleanCircuit::PutBarrelLeftShifterGate(std::vector<uint32_t> wires,
		std::vector<uint32_t> n, uint32_t nvals){
	uint n_size = (uint)(log(wires.size())/log(2));
	auto step = pow(2, (double)n_size);
	auto out_size = step*2;

	std::vector<uint32_t> res(out_size);
	std::vector<uint32_t> last;

	uint64_t zero = 0;
	share* zero_gate = PutSIMDCONSGate(nvals, zero, 1);

	n.resize(n_size, zero_gate->get_wires()[0]);
	wires.resize(out_size, zero_gate->get_wires()[0]);
	for(int i = n_size; i >=0 ; i--, step/=2){
		for(auto j = 0; j < out_size; j++){
			std::vector<uint32_t> tmp_right(1);
			std::vector<uint32_t> tmp_left(1);
			if(step == out_size/2){
				tmp_right[0] = wires[j];
				tmp_left[0] = j < step ? zero_gate->get_wires()[0] : wires[j-step];
			}
			else{
				tmp_right[0] = last[j];
				tmp_left[0] = j < step ? zero_gate->get_wires()[0] : last[j-step];
			}
			res[j] = PutMUXGate(tmp_left, tmp_right, n[i])[0];
		}
		last.clear();
		last.insert(last.begin(), res.begin(), res.end());
	}
	return res;
}

share * BooleanCircuit::PutBarrelRightShifterGate(share * input, share * n){
	return new boolshare(PutBarrelRightShifterGate(input->get_wires(), n->get_wires()), this);
}

std::vector<uint32_t> BooleanCircuit::PutBarrelRightShifterGate(std::vector<uint32_t> wires, std::vector<uint32_t> n){
	std::reverse(wires.begin(), wires.end());
	std::vector<uint32_t> res = PutBarrelLeftShifterGate(wires, n);
	std::reverse(res.begin(), res.end());
	res.erase(res.begin(), res.begin() + wires.size());
	return res;
}

share * BooleanCircuit::PutFPGate(share * in, op_t op, uint8_t bitlen, uint32_t nvals, fp_op_setting s){
	// if bitlen/nvals were not set manually, use values from input
	if (bitlen == 0) {
		bitlen = in->get_bitlength();
	}
	if (nvals == 0) {
		nvals = in->get_nvals();
	}
	const char * o;
	switch(op){
		case COS:
				o = "ieee_cos";
		   break;
		case EXP:
				o = "nostatus_exp";
		   break;
		case EXP2:
				o = "nostatus_exp2";
		   break;
		case LN:
				o = "nostatus_ln";
		   break;
		case LOG2:
				o = "nostatus_log2";
		   break;
		case SIN:
				o = "ieee_sin";
		   break;
		case SQR:
				o = s==no_status ? "nostatus_sqr" : "ieee_sqr";
		   break;
		case SQRT:
				o = s==no_status ? "nostatus_sqrt" : "ieee_sqrt";
		   break;
		default:
			std::cerr << "Wrong operation in floating point gate with one input.";
			std::exit(EXIT_FAILURE);
	}
	return new boolshare(PutFPGate(o, in->get_wires(), bitlen, nvals), this);
}

share * BooleanCircuit::PutFPGate(share * in_a, share * in_b, op_t op, uint8_t bitlen, uint32_t nvals, fp_op_setting s){
	// if bitlen/nvals were not set manually, use values from input
	if (bitlen == 0) {
		bitlen = in_a->get_bitlength();
	}
	if (nvals == 0) {
		nvals = in_a->get_nvals();
	}
	const char * o;
	switch(op){
		case ADD:
				o = s==no_status ? "nostatus_add" : "ieee_add";
		   break;
		case CMP:
				o = "nostatus_cmp";
		   break;
		case DIV:
				o = s==no_status ? "nostatus_div" : "ieee_div";
		   break;
		case MUL:
				o = s==no_status ? "nostatus_mult" : "ieee_mult";
		   break;
		case SUB:
				o = s==no_status ? "nostatus_sub" : "ieee_sub";
		   break;
		default:
			std::cerr << "Wrong operation in floating point gate with two inputs.";
			std::exit(EXIT_FAILURE);
	}
	return new boolshare(PutFPGate(o, in_a->get_wires(), in_b->get_wires(), bitlen, nvals), this);
}
