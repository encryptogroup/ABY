/**
 \file 		lowmccircuit.cpp
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
 \brief		Prototypical benchmark implementation of LowMCCiruit. Attention: Does not yield correct result!
 */
#include "lowmccircuit.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/crypto/crypto.h>

static uint32_t m_nRndCtr;
static uint32_t* m_tGrayCode;
static uint32_t* m_tGrayCodeIncrement;
static uint32_t m_nZeroGate;

//sboxes (m), key-length (k), statesize (n), data (d), rounds (r)
int32_t test_lowmc_circuit(e_role role, const std::string& address, uint16_t port, uint32_t nvals, uint32_t nthreads,
		e_mt_gen_alg mt_alg, e_sharing sharing, uint32_t statesize, uint32_t keysize,
		uint32_t sboxes, uint32_t rounds, uint32_t maxnumgates, crypto* crypt) {

	LowMCParams param = { sboxes, keysize, statesize, keysize == 80 ? 64 : (uint32_t) 128, rounds };
	return test_lowmc_circuit(role, address, port, nvals, nthreads, mt_alg, sharing, &param, maxnumgates, crypt);
}

int32_t test_lowmc_circuit(e_role role, const std::string& address, uint16_t port, uint32_t nvals, uint32_t nthreads,
		e_mt_gen_alg mt_alg, e_sharing sharing, LowMCParams* param, uint32_t reservegates, crypto* crypt) {

	uint32_t bitlen = 32, ctr = 0, exp_key_bitlen = param->blocksize * (param->nrounds+1), zero_gate;

	ABYParty* party;
	if(reservegates > 0)
		party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg, reservegates);
	else
		party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg);

	std::vector<Sharing*>& sharings = party->GetSharings();

	CBitVector input, key;
	input.Create(param->blocksize * nvals, crypt);

	//Use a dummy key for benchmark reasons
	key.Create(exp_key_bitlen, crypt);

	uint8_t* output;

	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
	//Circuit build routine works for Boolean circuits only
	assert(circ->GetCircuitType() == C_BOOLEAN);

	share *s_in, *s_key, *s_ciphertext;
	s_in = circ->PutSIMDINGate(nvals, input.GetArr(), param->blocksize, CLIENT);
	s_key = circ->PutINGate(key.GetArr(), exp_key_bitlen, SERVER);
	s_key = circ->PutRepeaterGate(nvals, s_key);
	zero_gate = circ->PutConstantGate(0, nvals);

	s_ciphertext = BuildLowMCCircuit(s_in, s_key, (BooleanCircuit*) circ, param, zero_gate, crypt);

	s_ciphertext = circ->PutOUTGate(s_ciphertext, ALL);

	party->ExecCircuit();

	output = s_ciphertext->get_clear_value_ptr();

	CBitVector out;
	out.AttachBuf(output, (uint64_t) ceil_divide(param->blocksize, 8) * nvals);

	std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) << std::endl;

	return 1;
}

share* BuildLowMCCircuit(share* val, share* key, BooleanCircuit* circ, LowMCParams* param, uint32_t zerogate, crypto* crypt) {
	uint32_t round, byte, i, j, k;
	m_nRndCtr = 0;
	uint32_t nsboxes = param->nsboxes;
	uint32_t statesize = param->blocksize;
	uint32_t nrounds = param->nrounds;

	std::vector<uint32_t> state(statesize);
	m_vRandomBits.Create(2 * statesize * statesize * nrounds + nrounds * statesize, crypt);
	m_nZeroGate = zerogate;

	//Build the GrayCode for the optimal window-size
	m_tGrayCode = BuildGrayCode(statesize);
	m_tGrayCodeIncrement = BuildGrayCodeIncrement(statesize);

	//copy the input to the current state
	for (i = 0; i < statesize; i++)
		state[i] = val->get_wire_id(i);

	LowMCAddRoundKey(state, key->get_wires(), statesize, 0, circ); //ARK
	for (round = 0; round < nrounds; round++) {

		//substitution via 3-bit SBoxes
		LowMCPutSBoxLayer(state, nsboxes, circ);

		//multiply state with GF2Matrix
		//LowMCMultiplyState(state, statesize, circ);//Naive version of the state multiplication
		FourRussiansMatrixMult(state, statesize, circ);//4 Russians version of the state multiplication
		//LowMCMultiplyStateCallback(state, statesize, circ); //use callbacks to perform the multiplication in plaintext

		//XOR constants
		LowMCXORConstants(state, statesize, circ);

		//XOR with multiplied key
		LowMCXORMultipliedKey(state, key->get_wires(), statesize, round, circ);

	}

	free(m_tGrayCode);
	free(m_tGrayCodeIncrement);

#if PRINT_PERFORMANCE_STATS
	std::cout << "Total Number of Boolean Gates: " << circ->GetNumGates() << std::endl;
#endif

	return new boolshare(state, circ);
}

void LowMCAddRoundKey(std::vector<uint32_t>& val, std::vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		val[i] = circ->PutXORGate(val[i], key[i+(1+round) * lowmcstatesize]);
	}
}

//Multiply the state using a linear matrix
void LowMCMultiplyState(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
	std::vector<uint32_t> tmpstate(lowmcstatesize);
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		tmpstate[i] = 0;
		for (uint32_t j = 0; j < lowmcstatesize; j++, m_nRndCtr++) {
			if (m_vRandomBits.GetBit(m_nRndCtr)) {
				tmpstate[i] = circ->PutXORGate(tmpstate[i], state[j]);
			}
		}
	}
}

//XOR constants on the state
void LowMCXORConstants(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
	for (uint32_t i = 0; i < lowmcstatesize; i++, m_nRndCtr++) {
		if (m_vRandomBits.GetBit(m_nRndCtr)) {
			state[i] = circ->PutINVGate(state[i]);
		}
	}

}

//Multiply the key with a 192x192 matrix and XOR the result on the state.
void LowMCXORMultipliedKey(std::vector<uint32_t>& state, std::vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
	uint32_t tmp;
	/*for(uint32_t i = 0; i < MPCC_STATE_SIZE; i++) {
	 tmp = 0;
	 for(uint32_t j = 0; j < MPCC_STATE_SIZE; j++, m_nRndCtr++) {
	 if(m_vRandomBits.GetBit(m_nRndCtr)) {
	 tmp = PutXORGate(tmp, key[j]);
	 }
	 }
	 state[i] = PutXORGate(state[i], tmp);
	 }*/
	//Assume outsourced key-schedule
	for (uint32_t i = 0; i < lowmcstatesize; i++) {
		state[i] = circ->PutXORGate(state[i], key[i+(1+round) * lowmcstatesize]);
	}

}

//Put a layer of 3-bit LowMC SBoxes
void LowMCPutSBoxLayer(std::vector<uint32_t>& input, uint32_t nsboxes, BooleanCircuit* circ) {
	for (uint32_t i = 0; i < nsboxes * 3; i += 3) {
		LowMCPutSBox(input[i], input[i + 1], input[i + 2], circ);
	}
}

//Put a 3-bit LowMC SBoxes
void LowMCPutSBox(uint32_t& o1, uint32_t& o2, uint32_t& o3, BooleanCircuit* circ) {
	uint32_t i1 = o1;
	uint32_t i2 = o2;
	uint32_t i3 = o3;

	uint32_t ni1 = circ->PutINVGate(i1);
	uint32_t ni2 = circ->PutINVGate(i2);
	uint32_t ni3 = circ->PutINVGate(i3);

	//C = B * C + A
	o1 = circ->PutXORGate(circ->PutANDGate(i2, i3), i1);

	//E = A * (NOT C) + B
	o2 = circ->PutXORGate(circ->PutANDGate(i1, ni3), i2);

	//F = (NOT ((NOT B) * (NOT A))) + C
	o3 = circ->PutXORGate(circ->PutINVGate(circ->PutANDGate(ni2, ni1)), i3);
}

void FourRussiansMatrixMult(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
	//round to nearest square for optimal window size
	uint32_t wsize = floor_log2(lowmcstatesize) - 2;

	//will only work if the statesize is a multiple of the window size
	uint32_t* lutptr;
	uint32_t* lut = (uint32_t*) malloc(sizeof(uint32_t) * (1 << wsize));
	uint32_t i, j, bitctr, tmp = 0;

	lut[0] = m_nZeroGate;	//circ->PutConstantGate(0, 1);

	std::vector<uint32_t> tmpstate(ceil_divide(lowmcstatesize, wsize) * wsize, lut[0]);
	//pad the state to a multiple of the window size and fill with zeros
	std::vector<uint32_t> state_pad(ceil_divide(lowmcstatesize, wsize) * wsize, lut[0]);
	for (i = 0; i < lowmcstatesize; i++)
		state_pad[i] = state[i];

	for (i = 0, bitctr = 0; i < ceil_divide(lowmcstatesize, wsize); i++) { //for each column-window
		for (j = 1; j < (1 << wsize); j++) {
			lut[m_tGrayCode[j]] = circ->PutXORGate(lut[m_tGrayCode[j - 1]], state_pad[i * wsize + m_tGrayCodeIncrement[j - 1]]);
		}

		for (j = 0; j < lowmcstatesize; j++, bitctr += wsize) {
			m_vRandomBits.GetBits((BYTE*) &tmp, bitctr, wsize);
			tmpstate[i] = circ->PutXORGate(tmpstate[j], lut[tmp]);
		}
	}

	for (i = 0; i < lowmcstatesize; i++)
		state[i] = tmpstate[i];

	free(lut);
}

void LowMCMultiplyStateCallback(std::vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
	std::vector<uint32_t> tmpstate(lowmcstatesize);
	UGATE_T*** fourrussiansmat;

	circ->PutCallbackGate(state, 0, &CallbackBuild4RMatrixAndMultiply, (void*) fourrussiansmat, 1);
	for (uint32_t i = 1; i < lowmcstatesize-1; i++) {
		matmul* mulinfos = (matmul*) malloc(sizeof(matmul));
		mulinfos->column = i;
		//mulinfos->matrix = (UGATE_T) fourrussiansmat;

		tmpstate[i] = circ->PutCallbackGate(state, 0, &CallbackMultiplication, (void*) mulinfos, 1);
	}
	circ->PutCallbackGate(state, 0, &CallbackMultiplyAndDestroy4RMatrix, (void*) fourrussiansmat, 1);


	for (uint32_t i = 0; i < lowmcstatesize; i++)
		state[i] = tmpstate[i];
}

void CallbackMultiplication(GATE* gate, void* matinfos) {
	std::cout << "Performing multiplication" << std::endl;
	for(uint32_t i = 0; i < gate->ingates.ningates; i++) {

	}
	//alternatively, check if i == 0 and then call CallbackBuild4RMatrix(gate, matinfos.matrix); and check if i == statesize-1 and delete matrix
	free(matinfos);
}

void CallbackBuild4RMatrixAndMultiply(GATE* gate, void* mat) {
	//for(uint32_t i = 0; i < )
	//TODO
	std::cout << "Building 4 Russians matrix" << std::endl;
}

void CallbackMultiplyAndDestroy4RMatrix(GATE* gate, void* matrix) {
	//TODO
}

uint32_t* BuildGrayCode(uint32_t length) {
	uint32_t* gray_code = (uint32_t*) malloc(sizeof(uint32_t) * length);
	for(uint32_t i = 0; i < length; ++i) {
		gray_code[i] = i ^ (i >> 1);
	}
	return gray_code;
}

uint32_t* BuildGrayCodeIncrement(uint32_t length) {
	uint32_t* gray_code_increment = (uint32_t*) malloc(sizeof(uint32_t) * length);
	for(uint32_t i = 0; i < length; ++i) {
		gray_code_increment[i] = 0;
	}
	uint32_t length_inc = 2;
	while(length_inc < length) {
		uint32_t length_count = length_inc - 1;
		while(length_count <= length) {
			(gray_code_increment[length_count])++;
			length_count += length_inc;
		}
		length_inc <<= 1; 
	}
	return gray_code_increment;
}
