/**
 \file 		sharing.cpp
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
 \brief		Sharing class implementation.
 */
#include "sharing.h"
#include "../circuit/circuit.h"
#include "../circuit/abycircuit.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cassert>
#include <cstring>

#if __has_include(<filesystem>)
#include <filesystem>
namespace filesystem = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#else
#error "C++17 filesystem library not found"
#endif

#include <iostream>
#include <iomanip>

Sharing::Sharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt) {
	m_eContext = context;
	m_nShareBitLen = sharebitlen;
	m_pCircuit = circuit;
	m_pGates = m_pCircuit->Gates();
	m_eRole = role;
	m_cCrypto = crypt;
	m_nSecParamBytes = ceil_divide(m_cCrypto->get_seclvl().symbits, 8);
	m_ePhaseValue = ePreCompDefault;
	m_nFilePos = -1;
	m_nTypeBitLen = sharebitlen;
}

Sharing::~Sharing() {
}

void Sharing::EvaluateCallbackGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	void (*callback)(GATE*, void*) = gate->gs.cbgate.callback;
	void* infos = gate->gs.cbgate.infos;
	InstantiateGate(gate);

	callback(gate, infos);

	for(uint32_t i = 0; i < gate->ingates.ningates; i++)
		UsedGate(gate->ingates.inputs.parents[i]);
	free(gate->ingates.inputs.parents);
}

/**Precomputation phasevalue getter and setter functions*/
void Sharing::SetPreCompPhaseValue(ePreCompPhase in_phase_value) {

	m_ePhaseValue = in_phase_value;
}

ePreCompPhase Sharing::GetPreCompPhaseValue() {
	return m_ePhaseValue;
}
void Sharing::PreCompFileDelete() {
	uint64_t truncation_size;
	filesystem::path filename;
	if(m_eRole == SERVER) {
		filename = "pre_comp_server.dump";
	} else {
		filename = "pre_comp_client.dump";
	}

	if((filesystem::exists(filename))&&(GetPreCompPhaseValue() == ePreCompRead)) {

		if(m_nFilePos >= filesystem::file_size(filename)) {
			filesystem::remove(filename);
		}
		else {
			truncation_size = filesystem::file_size(filename) - m_nFilePos;
			std::error_code ec;
			filesystem::resize_file(filename, truncation_size, ec);
			if(ec) {
				std::cout << "Error occured in truncate:" << ec.message() << std::endl;
			}
		}
	}
}



/*
 * Read the plaintext value from an output gate and parse it to a standardized form that can be output
 */

UGATE_T* Sharing::ReadOutputValue(uint32_t gateid, e_circuit circ_type, uint32_t* bitlen) {
	uint32_t nvals, ugate_bits, val_offset, valbytelen;
	UGATE_T* value;
	GATE *parentgate, *gate;

	gate = m_pGates + gateid;
	nvals = gate->nvals;
	ugate_bits = sizeof(UGATE_T) * 8;

	//in case the values are in Boolean form, reformat them.
	switch (circ_type) {
		case C_BOOLEAN:
			*bitlen = gate->ingates.ningates;
			val_offset = ceil_divide((*bitlen), ugate_bits);
			value = (UGATE_T*) calloc(val_offset * nvals, sizeof(UGATE_T));

			for (uint32_t i = 0; i < *bitlen; i++) {
				parentgate = m_pGates + gate->ingates.inputs.parents[i];
				assert(parentgate->nvals == nvals);
				assert(parentgate->instantiated);

				for (uint32_t j = 0; j < nvals; j++) {
					value[i / ugate_bits + j * val_offset] += (((parentgate->gs.val[j/ugate_bits] >> (j % ugate_bits)) & 0x01) << (i % ugate_bits));
				}
			}
			break;
		case C_ARITHMETIC:
			*bitlen = m_nTypeBitLen;
			valbytelen = ceil_divide((*bitlen), 8);

			parentgate = m_pGates + gate->ingates.inputs.parents[0];
			value = (UGATE_T*) calloc(nvals, sizeof(UGATE_T));

			for(uint32_t i = 0; i < nvals; i++) {
				memcpy(value + i, ((uint8_t*) parentgate->gs.aval) + i * valbytelen, valbytelen);
			}
			break;
		default:
			std::cerr << "Gate type in printer gate not recognized. Stopping" << std::endl;
			exit(0);
	}

	return value;
}

/*
 * Check the plaintext value of a gate to a reference value that was given by the developer
 */
void Sharing::EvaluateAssertGate(uint32_t gateid, e_circuit circ_type) {
	uint32_t bitlen, nvals;
	//get the gate value in a standardized form
	UGATE_T* value = ReadOutputValue(gateid, circ_type, &bitlen);

	nvals = m_pGates[gateid].nvals;

	uint32_t ugate_len = ceil_divide(bitlen, sizeof(UGATE_T) * 8) * nvals;

	//check gate value against reference
	for(uint32_t i = 0; i < ugate_len; i++) {
		if(m_pGates[gateid].gs.assertval[i] != value[i]) {
			std::cout << "Data in Assert gate is not matching for nval = " << i << ": Circuit " << value[i] <<
					" vs. Reference " << m_pGates[gateid].gs.assertval[i] << std::endl;
		}
		assert(m_pGates[gateid].gs.assertval[i] == value[i]);
	}

	free(value);
	free(m_pGates[gateid].gs.assertval);
}




/*
 * Print the plaintext values of gates for all sharings
 */
void Sharing::EvaluatePrintValGate(uint32_t gateid, e_circuit circ_type) {
	uint32_t bitlen, nvals;
	//get the gate value in a standardized form
	UGATE_T* value = ReadOutputValue(gateid, circ_type, &bitlen);

	nvals = m_pGates[gateid].nvals;

	//print the resulting value depending on its bitlength and nvals
	if(bitlen <= 64) {//for bitlen <= 64 print numbers
		if(nvals == 1) { //for non-SIMD wires a different format is used
			std::cout << m_pGates[gateid].gs.infostr << ": " << value[0] << std::endl;
		} else {
			std::cout << m_pGates[gateid].gs.infostr << ": ";
			for(uint32_t i = 0; i < nvals; i++) {
				std::cout << "[" << i << "]: " << value[i] << "; ";//std::endl;
			}
			std::cout << std::endl;
		}
	} else {// for bitlen > 64 print hex values
		if(nvals == 1) { //for non-SIMD wires a different format is used
			std::cout << m_pGates[gateid].gs.infostr << ": ";
			for(uint32_t i = 0; i < ceil_divide(bitlen, 8); i++) {
				std::cout << std::setw(2) << std::setfill('0') << (std::hex) << (uint32_t) ((uint8_t*) value)[i] << (std::dec);
			}
			std::cout << std::endl;
		} else {
			std::cout << m_pGates[gateid].gs.infostr << ": " << std::endl;
			for(uint32_t i = 0; i < nvals; i++) {
				std::cout << "[" << i << "]: ";
				for(uint32_t j = 0; j < ceil_divide(bitlen, 8); j++) {
					std::cout << (std::hex) << (uint32_t) ((uint8_t*) value)[i * ceil_divide(bitlen, 8) + j] << (std::dec);
				}
				std::cout << std::endl;
			}
		}
	}

	free(value);
	delete[] m_pGates[gateid].gs.infostr;
}

// Delete dynamically allocated gate contents depending on gate type
void Sharing::FreeGate(GATE *gate) {
	e_sharing context = gate->context;
	e_role role = m_eRole;
	if(context == S_YAO_REV) {
		role = (role == SERVER ? CLIENT : SERVER);
		context = S_YAO;
	}
	switch(context) {
	case S_BOOL:
	case S_ARITH:
	case S_SPLUT:
		free(gate->gs.val);
		break;
	case S_YAO:
		if(role == SERVER) {
			// input gates are freed before
			if(gate->type == G_IN || gate->type == G_CONV) { break; }
			free(gate->gs.yinput.outKey);
			free(gate->gs.yinput.pi);
		} else {
			free(gate->gs.yval);
		}
		break;
	}
	gate->instantiated = false;
}

// Mark gate as used. If it is no longer needed, free it.
void Sharing::UsedGate(uint32_t gateid) {
	GATE *gate = &m_pGates[gateid];
	if(!gate->instantiated) { return; }
	gate->nused--;
	if(!gate->nused && gate->type != G_CONV) {
		FreeGate(gate);
	}
}
