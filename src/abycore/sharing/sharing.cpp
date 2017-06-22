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

	char filename[21];
	uint64_t truncation_size;
	if(m_eRole == SERVER) {
		strcpy(filename, "pre_comp_server.dump");
	}
	else {
		strcpy(filename, "pre_comp_client.dump");
	}

	if((FileExists(filename))&&(GetPreCompPhaseValue() == ePreCompRead)) {

		if(m_nFilePos >= FileSize(filename)) {
			remove(filename);
		}
		else {
			truncation_size = FileSize(filename) - m_nFilePos;
			if(truncate(filename, truncation_size))
                        cout << "Error occured in truncate" << endl;
		}
	}
}

/**File operations method.*/
BOOL Sharing::FileExists(char *filename) {

	if( access( filename, F_OK ) != -1 ) {
	    return TRUE;
	} else {
	    return FALSE;
	}
}

BOOL Sharing::FileEmpty(char *filename) {

	FILE *fp = fopen(filename, "rb");
	fseek(fp, 0L, SEEK_END);
	//return (!feof(fp))? false:true;
	return (ftell(fp)==0)? TRUE:FALSE;
}

uint64_t Sharing::FileSize(char *filename) {

	FILE *fp = fopen(filename, "rb");
	uint64_t file_size;
	fseek(fp, 0L, SEEK_END);
	file_size = ftell(fp);
	fclose(fp);
	return file_size;
}

//TODO switch on gate and perform SIMD gate routine


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
			cerr << "Gate type in printer gate not recognized. Stopping" << endl;
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
			cout << "Data in Assert gate is not matching for nval = " << i << ": Circuit " << value[i] <<
					" vs. Reference " << m_pGates[gateid].gs.assertval[i] << endl;
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
			cout << m_pGates[gateid].gs.infostr << ": " << value[0] << endl;
		} else {
			cout << m_pGates[gateid].gs.infostr << ": ";
			for(uint32_t i = 0; i < nvals; i++) {
				cout << "[" << i << "]: " << value[i] << "; ";//endl;
			}
			cout << endl;
		}
	} else {// for bitlen > 64 print hex values
		if(nvals == 1) { //for non-SIMD wires a different format is used
			cout << m_pGates[gateid].gs.infostr << ": ";
			for(uint32_t i = 0; i < ceil_divide(bitlen, 8); i++) {
				cout << setw(2) << setfill('0') << (hex) << (uint32_t) ((uint8_t*) value)[i] << (dec);
			}
			cout << endl;
		} else {
			cout << m_pGates[gateid].gs.infostr << ": " << endl;
			for(uint32_t i = 0; i < nvals; i++) {
				cout << "[" << i << "]: ";
				for(uint32_t j = 0; j < ceil_divide(bitlen, 8); j++) {
					cout << (hex) << (uint32_t) ((uint8_t*) value)[i * ceil_divide(bitlen, 8) + j] << (dec);
				}
				cout << endl;
			}
		}
	}

	free(value);
	free((char*) m_pGates[gateid].gs.infostr);
}

// What needs to be deleted depends on the gate's context, not the sharing
// from which the deletion was initiated. This is why this method is here
// in the Sharing superclass and not its subclasses.
void Sharing::UsedGate(uint32_t gateid) {
	GATE *gate = &m_pGates[gateid];
	if(!gate->instantiated) { return; }
	gate->nused--;
	if(!gate->nused) {
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
				free(gate->gs.yinput.outKey);
				free(gate->gs.yinput.pi);
			} else {
				free(gate->gs.yval);
			}
		}
		gate->instantiated = false;
	}
}
