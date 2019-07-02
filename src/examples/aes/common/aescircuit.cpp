/**
 \file 		aescircuit.cpp
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
 \brief		Implementation of AESCiruit
 */
#include "aescircuit.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>

static uint32_t* pos_even;
static uint32_t* pos_odd;


int32_t test_aes_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads,
		e_mt_gen_alg mt_alg, e_sharing sharing, [[maybe_unused]] bool verbose, bool use_vec_ands, bool expand_in_sfe, bool client_only) {
	uint32_t bitlen = 32;
	uint32_t aes_key_bits;
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
	std::vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	CBitVector input, key, verify;

	//ids that are required for the vector_and optimization
	if(use_vec_ands) {
		pos_even = (uint32_t*) malloc(sizeof(uint32_t) * nvals);
		pos_odd = (uint32_t*) malloc(sizeof(uint32_t) * nvals);
		for(uint32_t i = 0; i < nvals; i++) {
			pos_even[i] = 2*i;
			pos_odd[i] = 2*i+1;
		}
	}

	aes_key_bits = crypt->get_aes_key_bytes() * 8;
	input.Create(AES_BITS * nvals, crypt);
	verify.Create(AES_BITS * nvals);
	key.CreateBytes(AES_EXP_KEY_BYTES);

	uint8_t aes_test_key[AES_KEY_BYTES];
	srand(7438);
	for(uint32_t i = 0; i < AES_KEY_BYTES; i++) {
		aes_test_key[i] = (uint8_t) (rand() % 256);
	}
	uint8_t expanded_key[AES_EXP_KEY_BYTES];
	ExpandKey(expanded_key, aes_test_key);
	key.Copy(expanded_key, 0, AES_EXP_KEY_BYTES);
	uint8_t* output;

	CBitVector out(nvals * AES_BITS);

	if(sharing == S_YAO_REV) {
		//Currently the expand_in_sfe and client_only features are not supported in S_YAO_REV
		assert(expand_in_sfe == false && client_only == false);

		Circuit* yao_circ = sharings[S_YAO]->GetCircuitBuildRoutine();
		Circuit* yao_rev_circ = sharings[S_YAO_REV]->GetCircuitBuildRoutine();

		uint32_t nyao_circs, nyao_rev_circs;
		nyao_rev_circs = (nvals/2);
		nyao_circs = nvals - nyao_rev_circs;

		share *s_in_yao, *s_in_yao_rev, *s_key_yao, *s_key_yao_rev, *s_ciphertext_yao, *s_ciphertext_yao_rev;

		s_in_yao = yao_circ->PutSIMDINGate(nyao_circs, input.GetArr(), aes_key_bits, CLIENT);
		if(nyao_rev_circs > 0)
			s_in_yao_rev = yao_rev_circ->PutSIMDINGate(nyao_rev_circs, input.GetArr() + nyao_circs * AES_BYTES, aes_key_bits, SERVER);

		s_key_yao = yao_circ->PutINGate(key.GetArr(), aes_key_bits * (AES_ROUNDS + 1), SERVER);
		s_key_yao = yao_circ->PutRepeaterGate(nyao_circs,s_key_yao);

		if(nyao_rev_circs > 0) {
			s_key_yao_rev = yao_rev_circ->PutINGate(key.GetArr(), aes_key_bits * (AES_ROUNDS + 1), CLIENT);
			s_key_yao_rev = yao_rev_circ->PutRepeaterGate(nyao_rev_circs,s_key_yao_rev);
		}

		s_ciphertext_yao = BuildAESCircuit(s_in_yao, s_key_yao, (BooleanCircuit*) yao_circ, use_vec_ands);
		if(nyao_rev_circs > 0) {
			s_ciphertext_yao_rev = BuildAESCircuit(s_in_yao_rev, s_key_yao_rev, (BooleanCircuit*) yao_rev_circ, use_vec_ands);
		}

		party->ExecCircuit();

		output = s_ciphertext_yao->get_clear_value_ptr();
		out.SetBytes(output, 0L, (uint64_t) AES_BYTES * nyao_circs);

		if(nyao_rev_circs > 0) {
			output = s_ciphertext_yao_rev->get_clear_value_ptr();
			out.SetBytes(output, (uint64_t) AES_BYTES * nyao_circs, (uint64_t) AES_BYTES * nyao_rev_circs);
		}

	} else {
		Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
		//Circuit build routine works for Boolean circuits only right now
		assert(circ->GetCircuitType() == C_BOOLEAN);

		share *s_in, *s_key, *s_ciphertext;
		s_in = circ->PutSIMDINGate(nvals, input.GetArr(), aes_key_bits, CLIENT);
		e_role key_inputter;
		if(client_only) {
			key_inputter = CLIENT;
		} else {
			key_inputter = SERVER;
		}
		if(expand_in_sfe) {
			s_key = circ->PutINGate(aes_test_key, AES_KEY_BITS, key_inputter);
			s_key = BuildKeyExpansion(s_key, (BooleanCircuit*) circ, use_vec_ands);
		} else {
			s_key = circ->PutINGate(key.GetArr(), aes_key_bits * (AES_ROUNDS + 1), key_inputter);
		}
		s_key = circ->PutRepeaterGate(nvals,s_key);

		s_ciphertext = BuildAESCircuit(s_in, s_key, (BooleanCircuit*) circ, use_vec_ands);
		s_ciphertext = circ->PutOUTGate(s_ciphertext, ALL);

		party->ExecCircuit();

		output = s_ciphertext->get_clear_value_ptr();

		out.SetBytes(output, 0L, (uint64_t) AES_BYTES * nvals);
	}

	verify_AES_encryption(input.GetArr(), key.GetArr(), nvals, verify.GetArr(), crypt);

#ifndef BATCH
	std::cout << "Testing AES encryption in " << get_sharing_name(sharing) << " sharing: " << std::endl;
#endif
	for (uint32_t i = 0; i < nvals; i++) {
#ifndef BATCH
		if(!verbose) {
			std::cout << "(" << i << ") Input:\t";
			input.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
			std::cout << "(" << i << ") Key:\t";
			key.PrintHex(0, AES_KEY_BYTES);
			std::cout << "(" << i << ") Circ:\t";
			out.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
			std::cout << "(" << i << ") Verify:\t";
			verify.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
		}
#endif
		assert(verify.IsEqual(out, i*AES_BITS, (i+1)*AES_BITS));
	}
#ifndef BATCH
	std::cout << "all tests succeeded" << std::endl;
#else
	std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_GARBLE) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) <<
			"\t" << party->GetSentData(P_TOTAL) + party->GetReceivedData(P_TOTAL) << "\t";
	if(sharing == S_YAO_REV) {
		std::cout << sharings[S_YAO]->GetNumNonLinearOperations() +sharings[S_YAO_REV]->GetNumNonLinearOperations() << "\t" << sharings[S_YAO]->GetMaxCommunicationRounds()<< std::endl;
	} else  {
		std::cout << sharings[sharing]->GetNumNonLinearOperations()	<< "\t" << sharings[sharing]->GetMaxCommunicationRounds()<< std::endl;
	}
#endif
	delete crypt;
	delete party;

	if(use_vec_ands) {
		free(pos_even);
		free(pos_odd);
	}
	free(output);
	return 0;
}

share* BuildAESCircuit(share* val, share* key, BooleanCircuit* circ, bool use_vec_ands) {
	uint32_t round, i, j, k;
	std::vector<std::vector<std::vector<uint32_t> > > state(AES_STATE_COLS); //the state is treated as a matrix
	std::vector<std::vector<std::vector<uint32_t> > > state_temp(AES_STATE_COLS); //the state is treated as a matrix
	std::vector<uint32_t> out(128);


	for (i = 0; i < AES_STATE_COLS; i++) {
		state[i].resize(AES_STATE_ROWS);
		state_temp[i].resize(AES_STATE_ROWS);

		for (j = 0; j < AES_STATE_ROWS; j++) {
			state[i][j].resize(8);
			state_temp[i][j].resize(8);

			for (k = 0; k < 8; k++) {
				state[i][j][k] = val->get_wire_id(((i * AES_STATE_COLS) + j) * 8 + k);
			}
		}
	}

	for (round = 0; round < AES_ROUNDS; round++) {
		for (i = 0; i < AES_STATE_COLS; i++) {
			for (j = 0; j < AES_STATE_ROWS; j++) {
				state[i][j] = AddAESRoundKey(state[i][j], key->get_wires(), (round * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, circ); //ARK
				state_temp[(i - j) & 0x3][j] = PutAESSBoxGate(state[i][j], circ, use_vec_ands);
			}
		}

		for (i = 0; i < AES_STATE_COLS; i++) {
			if (round < 9)
				state[i] = PutAESMixColumnGate(state_temp[i], circ); //MixColumns
			else
				state = state_temp;
		}
	}

	for (i = 0; i < AES_STATE_COLS; i++) {
		for (j = 0; j < AES_STATE_ROWS; j++) {
			state[i][j] = AddAESRoundKey(state[i][j], key->get_wires(), (AES_ROUNDS * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, circ);
			for (k = 0; k < 8; k++) {
				out[(i * AES_STATE_ROWS + j) * 8 + k] = state[i][j][k];
			}
		}
	}

	//free(pos_even);
	//free(pos_odd);

	return new boolshare(out, circ);
}

std::vector<uint32_t> AddAESRoundKey(std::vector<uint32_t>& val, std::vector<uint32_t> key, uint32_t keyaddr, BooleanCircuit* circ) {
	std::vector<uint32_t> out(8);
	for (uint32_t i = 0; i < 8; i++) {
		out[i] = circ->PutXORGate(val[i], key[keyaddr + i]);
	}
	return out;
}

//Pretty straight - forward, shift by 1 to the left and if input_msb is 1, then XOR with 0x1b
std::vector<uint32_t> Mul2(std::vector<uint32_t>& element, BooleanCircuit* circ) {
	std::vector<uint32_t> out(8);
	out[0] = element[7];
	out[1] = circ->PutXORGate(element[0], element[7]);
	out[2] = element[1];
	out[3] = circ->PutXORGate(element[2], element[7]);
	out[4] = circ->PutXORGate(element[3], element[7]);
	out[5] = element[4];
	out[6] = element[5];
	out[7] = element[6];
	return out;
}

std::vector<std::vector<uint32_t> > PutAESMixColumnGate(std::vector<std::vector<uint32_t> >& rows, BooleanCircuit* circ) {
	uint32_t i, j, temp;
	std::vector<std::vector<uint32_t> > out(4);
	std::vector<std::vector<uint32_t> > temp_mul2(4);

	if (rows.size() != 4) {
		std::cout << "There have to be exactly four rows!" << std::endl;
	}
	for (j = 0; j < 4; j++) {
		out[j].resize(8);
		temp_mul2[j].resize(8);
		temp_mul2[j] = Mul2(rows[j], circ);
	}
	for (j = 0; j < 4; j++) {
		for (i = 0; i < 8; i++) {
			temp = circ->PutXORGate(temp_mul2[j][i], temp_mul2[(j + 1) % 4][i]);
			temp = circ->PutXORGate(temp, rows[(j + 1) % 4][i]);
			temp = circ->PutXORGate(temp, rows[(j + 2) % 4][i]);
			out[j][i] = circ->PutXORGate(temp, rows[(j + 3) % 4][i]);
		}
	}

	return out;
}


std::vector<uint32_t> PutAESSBoxGate(std::vector<uint32_t> input, BooleanCircuit* circ, bool use_vec_ands) {
	if(circ->GetContext() == S_SPLUT) {
		return AESSBox_Forward_SPLUT(input, circ);
	} else if(circ->GetContext() == S_YAO || circ->GetContext() == S_YAO_REV) {
		return AESSBox_Forward_BP_Size_Optimized(input, circ);
	} else if(circ->GetContext() == S_BOOL) {
		if(use_vec_ands)
			return AESSBox_Forward_BP_VecMTs_Optimized(input, circ, pos_even, pos_odd);
		else
			return AESSBox_Forward_BP_Depth_Optimized(input, circ);
	} else {
		std::cerr << "Sharing type not supported!" << std::endl;
		exit(0);
	}
}

//The Boyar-Peralta depth optimized SBox circuit (34 AND gates, Depth 4)
std::vector<uint32_t> AESSBox_Forward_BP_Depth_Optimized(std::vector<uint32_t> input, BooleanCircuit* circ) {
	std::vector<uint32_t> gates(141);

	//constant 1
	gates[140] = 0;
	std::vector<uint32_t> out(8);
	for (uint32_t i = 0; i < 8; i++) {
		gates[i] = input[i];
	}

	for (uint32_t i = 8; i < 132; i++) { //process all gates
		if (do_isANDGate[i])
			gates[i] = circ->PutANDGate(gates[do_wire_mapping[i - 8][0]], gates[do_wire_mapping[i - 8][1]]);
		else {
			if (do_wire_mapping[i - 8][1] != INV_GATE_ID) {
				gates[i] = circ->PutXORGate(gates[do_wire_mapping[i - 8][0]], gates[do_wire_mapping[i - 8][1]]);
			} else {
				gates[i] = circ->PutINVGate(gates[do_wire_mapping[i - 8][0]]);
			}
		}
	}

	for (uint32_t i = 132; i < 140; i++) {
		out[i - 132] = circ->PutXORGate(gates[do_wire_mapping[i - 8][0]], gates[do_wire_mapping[i - 8][1]]);
	}
	return out;
}

//The Boyar-Peralta size optimized SBox circuit (32 AND gates, Depth 6)
std::vector<uint32_t> AESSBox_Forward_BP_Size_Optimized(std::vector<uint32_t> input, BooleanCircuit* circ) {
	std::vector<uint32_t> x(8);
	std::vector<uint32_t> y(22);
	std::vector<uint32_t> t(68);
	std::vector<uint32_t> s(8);
	std::vector<uint32_t> z(18);
	std::vector<uint32_t> out(8);

	for(uint32_t i = 0; i < x.size(); i++) {
		x[i] = input[7-i];
	}

	//Top linear transform
	y[14] = circ->PutXORGate(x[3], x[5]);
	y[13] = circ->PutXORGate(x[0], x[6]);
	y[9] = circ->PutXORGate(x[0], x[3]);

	y[8] = circ->PutXORGate(x[0], x[5]);
	t[0] = circ->PutXORGate(x[1], x[2]);
	y[1] = circ->PutXORGate(t[0], x[7]);

	y[4] = circ->PutXORGate(y[1], x[3]);
	y[12] = circ->PutXORGate(y[13], y[14]);
	y[2] = circ->PutXORGate(y[1], x[0]);

	y[5] = circ->PutXORGate(y[1], x[6]);
	y[3] = circ->PutXORGate(y[5], y[8]);
	t[1] = circ->PutXORGate(x[4], y[12]);

	y[15] = circ->PutXORGate(t[1], x[5]);
	y[20] = circ->PutXORGate(t[1], x[1]);
	y[6] = circ->PutXORGate(y[15], x[7]);

	y[10] = circ->PutXORGate(y[15], t[0]);
	y[11] = circ->PutXORGate(y[20], y[9]);
	y[7] = circ->PutXORGate(x[7], y[11]);

	y[17] = circ->PutXORGate(y[10], y[11]);
	y[19] = circ->PutXORGate(y[10], y[8]);
	y[16] = circ->PutXORGate(t[0], y[11]);

	y[21] = circ->PutXORGate(y[13], y[16]);
	y[18] = circ->PutXORGate(x[0], y[16]);

	//Middle Non-Linear Transform, Box 1
	t[2]=circ->PutANDGate(y[12], y[15]);
	t[3]=circ->PutANDGate(y[3], y[6]);
	t[4]=circ->PutXORGate(t[3], t[2]);

	t[5]=circ->PutANDGate(y[4], x[7]);
	t[6]=circ->PutXORGate(t[5], t[2]);
	t[7]=circ->PutANDGate(y[13], y[16]);

	t[8]=circ->PutANDGate(y[5], y[1]);
	t[9]=circ->PutXORGate(t[8], t[7]);
	t[10]=circ->PutANDGate(y[2], y[7]);

	t[11]=circ->PutXORGate(t[10], t[7]);
	t[12]=circ->PutANDGate(y[9], y[11]);
	t[13]=circ->PutANDGate(y[14], y[17]);

	t[14]=circ->PutXORGate(t[13], t[12]);
	t[15]=circ->PutANDGate(y[8], y[10]);
	t[16]=circ->PutXORGate(t[15], t[12]);

	t[17]=circ->PutXORGate(t[4], t[14]);
	t[18]=circ->PutXORGate(t[6], t[16]);
	t[19]=circ->PutXORGate(t[9], t[14]);

	t[20]=circ->PutXORGate(t[11], t[16]);
	t[21]=circ->PutXORGate(t[17], y[20]);
	t[22]=circ->PutXORGate(t[18], y[19]);

	t[23]=circ->PutXORGate(t[19], y[21]);
	t[24]=circ->PutXORGate(t[20], y[18]);

	//Middle Non-Linear Transform, Box 2
	t[25]=circ->PutXORGate(t[21], t[22]);
	t[26]=circ->PutANDGate(t[21], t[23]);
	t[27]=circ->PutXORGate(t[24], t[26]);

	t[28]=circ->PutANDGate(t[25], t[27]);
	t[29]=circ->PutXORGate(t[28], t[22]);
	t[30]=circ->PutXORGate(t[23], t[24]);

	t[31]=circ->PutXORGate(t[22], t[26]);
	t[32]=circ->PutANDGate(t[31], t[30]);
	t[33]=circ->PutXORGate(t[32], t[24]);

	t[34]=circ->PutXORGate(t[23], t[33]);
	t[35]=circ->PutXORGate(t[27], t[33]);
	t[36]=circ->PutANDGate(t[24], t[35]);

	t[37]=circ->PutXORGate(t[36], t[34]);
	t[38]=circ->PutXORGate(t[27], t[36]);
	t[39]=circ->PutANDGate(t[29], t[38]);

	t[40]=circ->PutXORGate(t[25], t[39]);

	//Middle Non-Linear Transform, Box 3
	t[41]=circ->PutXORGate(t[40], t[37]);
	t[42]=circ->PutXORGate(t[29], t[33]);
	t[43]=circ->PutXORGate(t[29], t[40]);

	t[44]=circ->PutXORGate(t[33], t[37]);
	t[45]=circ->PutXORGate(t[42], t[41]);
	z[0]=circ->PutANDGate(t[44], y[15]);

	z[1]=circ->PutANDGate(t[37], y[6]);
	z[2]=circ->PutANDGate(t[33], x[7]);
	z[3]=circ->PutANDGate(t[43], y[16]);

	z[4]=circ->PutANDGate(t[40], y[1]);
	z[5]=circ->PutANDGate(t[29], y[7]);
	z[6]=circ->PutANDGate(t[42], y[11]);

	z[7]=circ->PutANDGate(t[45], y[17]);
	z[8]=circ->PutANDGate(t[41], y[10]);
	z[9]=circ->PutANDGate(t[44], y[12]);

	z[10]=circ->PutANDGate(t[37], y[3]);
	z[11]=circ->PutANDGate(t[33], y[4]);
	z[12]=circ->PutANDGate(t[43], y[13]);

	z[13]=circ->PutANDGate(t[40], y[5]);
	z[14]=circ->PutANDGate(t[29], y[2]);
	z[15]=circ->PutANDGate(t[42], y[9]);

	z[16]=circ->PutANDGate(t[45], y[14]);
	z[17]=circ->PutANDGate(t[41], y[8]);

	//Bottom Non-Linear Transform
	t[46]=circ->PutXORGate(z[15], z[16]);
	t[47]=circ->PutXORGate(z[10], z[11]);
	t[48]=circ->PutXORGate(z[5], z[13]);

	t[49]=circ->PutXORGate(z[9], z[10]);
	t[50]=circ->PutXORGate(z[2], z[12]);
	t[51]=circ->PutXORGate(z[2], z[5]);

	t[52]=circ->PutXORGate(z[7], z[8]);
	t[53]=circ->PutXORGate(z[0], z[3]);
	t[54]=circ->PutXORGate(z[6], z[7]);

	t[55]=circ->PutXORGate(z[16], z[17]);
	t[56]=circ->PutXORGate(z[12], t[48]);
	t[57]=circ->PutXORGate(t[50], t[53]);

	t[58]=circ->PutXORGate(z[4], t[46]);
	t[59]=circ->PutXORGate(z[3], t[54]);
	t[60]=circ->PutXORGate(t[46], t[57]);

	t[61]=circ->PutXORGate(z[14], t[57]);
	t[62]=circ->PutXORGate(t[52], t[58]);
	t[63]=circ->PutXORGate(t[49], t[58]);

	t[64]=circ->PutXORGate(z[4], t[59]);
	t[65]=circ->PutXORGate(t[61], t[62]);
	t[66]=circ->PutXORGate(z[1], t[63]);

	s[0]=circ->PutXORGate(t[59], t[63]);
	s[6]=circ->PutXORGate(t[56], circ->PutINVGate(t[62]));
	s[7]=circ->PutXORGate(t[48], circ->PutINVGate(t[60]));

	t[67]=circ->PutXORGate(t[64], t[65]);
	s[3]=circ->PutXORGate(t[53], t[66]);
	s[4]=circ->PutXORGate(t[51], t[66]);

	s[5]=circ->PutXORGate(t[47], t[65]);
	s[1]=circ->PutXORGate(t[64], circ->PutINVGate(s[3]));
	s[2]=circ->PutXORGate(t[55], circ->PutINVGate(t[67]));

	for(uint32_t i = 0; i < out.size(); i++) {
		out[i] = s[7-i];
	}

	return out;
}


//The Boyar-Peralta depth optimized SBox circuit (34 AND gates, Depth 4) with vector-MTs
std::vector<uint32_t> AESSBox_Forward_BP_VecMTs_Optimized(std::vector<uint32_t> input, BooleanCircuit* circ, uint32_t* buf_pos_even, uint32_t* buf_pos_odd) {
	std::vector<uint32_t> U(8);
	std::vector<uint32_t> T(28);
	std::vector<uint32_t> M(64);
	std::vector<uint32_t> L(30);
	std::vector<uint32_t> S(8);
	std::vector<uint32_t> out(8);

	for(uint32_t i = 0; i < U.size(); i++) {
		U[i] = input[7-i];
	}

	//Top linear transform in forward direction
	T[1] = circ->PutXORGate(U[0], U[3]);
	T[2] = circ->PutXORGate(U[0], U[5]);
	T[3] = circ->PutXORGate(U[0], U[6]);
	T[4] = circ->PutXORGate(U[3], U[5]);
	T[5] = circ->PutXORGate(U[4], U[6]);
	T[6] = circ->PutXORGate(T[1], T[5]);
	T[7] = circ->PutXORGate(U[1], U[2]);
	T[8] = circ->PutXORGate(U[7], T[6]);
	T[9] = circ->PutXORGate(U[7], T[7]);
	T[10] = circ->PutXORGate(T[6], T[7]);
	T[11] = circ->PutXORGate(U[1], U[5]);
	T[12] = circ->PutXORGate(U[2], U[5]);
	T[13] = circ->PutXORGate(T[3], T[4]);
	T[14] = circ->PutXORGate(T[6], T[11]);
	T[15] = circ->PutXORGate(T[5], T[11]);
	T[16] = circ->PutXORGate(T[5], T[12]);
	T[17] = circ->PutXORGate(T[9], T[16]);
	T[18] = circ->PutXORGate(U[3], U[7]);
	T[19] = circ->PutXORGate(T[7], T[18]);
	T[20] = circ->PutXORGate(T[1], T[19]);
	T[21] = circ->PutXORGate(U[6], U[7]);
	T[22] = circ->PutXORGate(T[7], T[21]);
	T[23] = circ->PutXORGate(T[2], T[22]);
	T[24] = circ->PutXORGate(T[2], T[10]);
	T[25] = circ->PutXORGate(T[20], T[17]);
	T[26] = circ->PutXORGate(T[3], T[16]);
	T[27] = circ->PutXORGate(T[1], T[12]);


	//Middle layer
	M[1] = circ->PutANDGate(T[13], T[6]);
	M[2] = circ->PutANDGate(T[23], T[8]);
	M[3] = circ->PutXORGate(T[14], M[1]);
	M[4] = circ->PutANDGate(T[19], U[7]);
	M[5] = circ->PutXORGate(M[4], M[1]);
	M[6] = circ->PutANDGate(T[3], T[16]);
	M[7] = circ->PutANDGate(T[22], T[9]);
	M[8] = circ->PutXORGate(T[26], M[6]);
	M[9] = circ->PutANDGate(T[20], T[17]);
	M[10] = circ->PutXORGate(M[9], M[6]);
	M[11] = circ->PutANDGate(T[1], T[15]);
	M[12] = circ->PutANDGate(T[4], T[27]);
	M[13] = circ->PutXORGate(M[12], M[11]);
	M[14] = circ->PutANDGate(T[2], T[10]);
	M[15] = circ->PutXORGate(M[14], M[11]);
	M[16] = circ->PutXORGate(M[3], M[2]);
	M[17] = circ->PutXORGate(M[5], T[24]);
	M[18] = circ->PutXORGate(M[8], M[7]);
	M[19] = circ->PutXORGate(M[10], M[15]);
	M[20] = circ->PutXORGate(M[16], M[13]);
	M[21] = circ->PutXORGate(M[17], M[15]);
	M[22] = circ->PutXORGate(M[18], M[13]);
	M[23] = circ->PutXORGate(M[19], T[25]);
	M[24] = circ->PutXORGate(M[22], M[23]);

	//Vec-AND opti block
	std::vector<uint32_t> tmp = Two_In_AND_Vec_Gate(M[20], M[22], M[23], circ, buf_pos_even, buf_pos_odd);
	M[25] = tmp[0];//circ->PutANDGate(M[20], M[22]);
	M[31] = tmp[1];//circ->PutANDGate(M[20], M[23]);

	M[26] = circ->PutXORGate(M[21], M[25]);
	M[27] = circ->PutXORGate(M[20], M[21]);
	M[28] = circ->PutXORGate(M[23], M[25]);

	//Vec-AND opti block
	tmp = Two_In_AND_Vec_Gate(M[27], M[28], M[31], circ, buf_pos_even, buf_pos_odd);
	M[29] = tmp[0];//circ->PutANDGate(M[28], M[27]);
	M[32] = tmp[1];//circ->PutANDGate(M[27], M[31]);


	M[30] = circ->PutANDGate(M[26], M[24]);

	M[33] = circ->PutXORGate(M[27], M[25]);
	M[34] = circ->PutANDGate(M[21], M[22]);
	M[35] = circ->PutANDGate(M[34], M[24]);
	M[36] = circ->PutXORGate(M[24], M[25]);
	M[37] = circ->PutXORGate(M[21], M[29]);
	M[38] = circ->PutXORGate(M[32], M[33]);
	M[39] = circ->PutXORGate(M[23], M[30]);
	M[40] = circ->PutXORGate(M[35], M[36]);
	M[41] = circ->PutXORGate(M[38], M[40]);
	M[42] = circ->PutXORGate(M[37], M[39]);
	M[43] = circ->PutXORGate(M[37], M[38]);
	M[44] = circ->PutXORGate(M[39], M[40]);
	M[45] = circ->PutXORGate(M[42], M[41]);

	//Vector-MT optimized part
	tmp = Two_In_AND_Vec_Gate(M[44], T[6], T[13], circ, buf_pos_even, buf_pos_odd);
	M[46] = tmp[0];//circ->PutANDGate(M[44], T[6]);
	M[55] = tmp[1];//circ->PutANDGate(M[44], T[13]);

	tmp = Two_In_AND_Vec_Gate(M[40], T[8], T[23], circ, buf_pos_even, buf_pos_odd);
	M[47] = tmp[0];//circ->PutANDGate(M[40], T[8]);
	M[56] = tmp[1];//circ->PutANDGate(M[40], T[23]);

	tmp = Two_In_AND_Vec_Gate(M[39], U[7], T[19], circ, buf_pos_even, buf_pos_odd);
	M[48] = tmp[0];//circ->PutANDGate(M[39], U[7]);
	M[57] = tmp[1];//circ->PutANDGate(M[39], T[19]);

	tmp = Two_In_AND_Vec_Gate(M[43], T[16], T[3], circ, buf_pos_even, buf_pos_odd);
	M[49] = tmp[0];//circ->PutANDGate(M[43], T[16]);
	M[58] = tmp[1];//circ->PutANDGate(M[43], T[3]);

	tmp = Two_In_AND_Vec_Gate(M[38], T[9], T[22], circ, buf_pos_even, buf_pos_odd);
	M[50] = tmp[0];//circ->PutANDGate(M[38], T[9]);
	M[59] = tmp[1];//circ->PutANDGate(M[38], T[22]);

	tmp = Two_In_AND_Vec_Gate(M[37], T[17], T[20], circ, buf_pos_even, buf_pos_odd);
	M[51] = tmp[0];//circ->PutANDGate(M[37], T[17]);
	M[60] = tmp[1];//circ->PutANDGate(M[37], T[20]);

	tmp = Two_In_AND_Vec_Gate(M[42], T[15], T[1], circ, buf_pos_even, buf_pos_odd);
	M[52] = tmp[0];//circ->PutANDGate(M[42], T[15]);
	M[61] = tmp[1];//circ->PutANDGate(M[42], T[1]);

	tmp = Two_In_AND_Vec_Gate(M[45], T[27], T[4], circ, buf_pos_even, buf_pos_odd);
	M[53] = tmp[0];//circ->PutANDGate(M[45], T[27]);
	M[62] = tmp[1];//circ->PutANDGate(M[45], T[4]);


	tmp = Two_In_AND_Vec_Gate(M[41], T[10], T[2], circ, buf_pos_even, buf_pos_odd);
	M[54] = tmp[0];//circ->PutANDGate(M[41], T[10]);
	M[63] = tmp[1];//circ->PutANDGate(M[41], T[2]);

	//Bottom linear layer
	L[0] = circ->PutXORGate(M[61], M[62]);
	L[1] = circ->PutXORGate(M[50], M[56]);
	L[2] = circ->PutXORGate(M[46], M[48]);
	L[3] = circ->PutXORGate(M[47], M[55]);
	L[4] = circ->PutXORGate(M[54], M[58]);
	L[5] = circ->PutXORGate(M[49], M[61]);
	L[6] = circ->PutXORGate(M[62], L[5]);
	L[7] = circ->PutXORGate(M[46], L[3]);
	L[8] = circ->PutXORGate(M[51], M[59]);
	L[9] = circ->PutXORGate(M[52], M[53]);
	L[10] = circ->PutXORGate(M[53], L[4]);
	L[11] = circ->PutXORGate(M[60], L[2]);
	L[12] = circ->PutXORGate(M[48], M[51]);
	L[13] = circ->PutXORGate(M[50], L[0]);
	L[14] = circ->PutXORGate(M[52], M[61]);
	L[15] = circ->PutXORGate(M[55], L[1]);
	L[16] = circ->PutXORGate(M[56], L[0]);
	L[17] = circ->PutXORGate(M[57], L[1]);
	L[18] = circ->PutXORGate(M[58], L[8]);
	L[19] = circ->PutXORGate(M[63], L[4]);
	L[20] = circ->PutXORGate(L[0], L[1]);
	L[21] = circ->PutXORGate(L[1], L[7]);
	L[22] = circ->PutXORGate(L[3], L[12]);
	L[23] = circ->PutXORGate(L[18], L[2]);
	L[24] = circ->PutXORGate(L[15], L[9]);
	L[25] = circ->PutXORGate(L[6], L[10]);
	L[26] = circ->PutXORGate(L[7], L[9]);
	L[27] = circ->PutXORGate(L[8], L[10]);
	L[28] = circ->PutXORGate(L[11], L[14]);
	L[29] = circ->PutXORGate(L[11], L[17]);

	//Outputs
	S[0] = circ->PutXORGate(L[6], L[24]);
	S[1] = circ->PutXORGate(L[16], circ->PutINVGate(L[26]));
	S[2] = circ->PutXORGate(L[19], circ->PutINVGate(L[28]));
	S[3] = circ->PutXORGate(L[6], L[21]);
	S[4] = circ->PutXORGate(L[20], L[22]);
	S[5] = circ->PutXORGate(L[25], L[29]);
	S[6] = circ->PutXORGate(L[13], circ->PutINVGate(L[27]));
	S[7] = circ->PutXORGate(L[6], circ->PutINVGate(L[23]));

	for(uint32_t i = 0; i < out.size(); i++) {
		out[i] = S[7-i];
	}

	return out;
}

//computes out[0]=s*a and out[1]=s*b using vector-AND gates
std::vector<uint32_t> Two_In_AND_Vec_Gate(uint32_t s, uint32_t a, uint32_t b, BooleanCircuit* circ,
		uint32_t* buf_pos_even, uint32_t* buf_pos_odd) {
	uint32_t ngates = 2;
	std::vector<uint32_t> out(ngates);
	std::vector<uint32_t> in(ngates);
	in[0] = a;
	in[1] = b;
	uint32_t vec_in = circ->PutStructurizedCombinerGate(in, 0, 1, ngates*circ->GetNumVals(a));

	uint32_t val = circ->PutVectorANDGate(s, vec_in);
	out[0] = circ->PutSubsetGate(val, buf_pos_even, circ->GetNumVals(a), false);
	out[1] = circ->PutSubsetGate(val, buf_pos_odd, circ->GetNumVals(b), false);

	return out;
}

std::vector<uint32_t> AESSBox_Forward_SPLUT(std::vector<uint32_t> input, BooleanCircuit* circ) {
	std::vector<uint32_t> out(8);

	//out = circ->PutTruthTableMultiOutputGate(input, 8, (uint64_t*) aes_sbox_multi_out_ttable);
	out = circ->PutTruthTableMultiOutputGate(input, 8, (uint64_t*) aes_sbox_multi_seq_out_ttable);

	return out;
}

// The basic construction was partally taken from the KeyExpansion function of the
// tiny-AES-c project, https://github.com/kokke/tiny-AES-c
// This function produces NB_CONSTANT(AES_ROUNDS+1) round keys in SFE.
// The round keys are used in each round to decrypt the states.
share* BuildKeyExpansion(share* key, BooleanCircuit* circ, bool use_vec_ands) {

	//TODO make the function SIMD-able if multiple keys are needed
	assert(key->get_nvals() == 1);

	//During the function the representation of the extended key is bytewise
	std::vector<std::vector<uint32_t>> ex_key_vec(AES_EXP_KEY_BYTES, std::vector<uint32_t>(8));

	uint32_t i, j, k;

	// The first round key is the key itself.
	{
		std::vector<uint32_t> key_vec = key->get_wires();
		for (i = 0; i < key_vec.size(); i++) {
			ex_key_vec[i / 8][i % 8] = key_vec[i];
		}
	}

	std::vector<uint32_t> s_rc[RCON_SIZE];

	for(i = 0; i < RCON_SIZE; i++) {
		uint8_t rc_temp = Rcon[i];
		s_rc[i] = circ->PutCONSGate(rc_temp, 8)->get_wires();
	}

	std::vector<std::vector<uint32_t>> tempa(4); // Used for the column/row operations

	// All other round keys are found from the previous round keys.
	for (i = AES_STATE_COLS; i < NB_CONSTANT * (AES_ROUNDS + 1); ++i) {
		{
			k = (i - 1) * 4;
			tempa[0] = ex_key_vec[k];
			tempa[1] = ex_key_vec[k + 1];
			tempa[2] = ex_key_vec[k + 2];
			tempa[3] = ex_key_vec[k + 3];
		}

		if (i % AES_STATE_COLS == 0) {
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				const std::vector<uint32_t> u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}

			// SubWord() is a function that takes a four-byte input word and
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				tempa[0] = PutAESSBoxGate(tempa[0], circ, use_vec_ands);
				tempa[1] = PutAESSBoxGate(tempa[1], circ, use_vec_ands);
				tempa[2] = PutAESSBoxGate(tempa[2], circ, use_vec_ands);
				tempa[3] = PutAESSBoxGate(tempa[3], circ, use_vec_ands);
			}
			tempa[0] = circ->PutXORGate(tempa[0], s_rc[i/AES_STATE_COLS]);
		}
#if AES_STATE_KEY_BITS == 256
		if (i % AES_STATE_COLS == 4) {
			// Function Subword()
			{
				tempa[0] = PutAESSBoxGate(tempa[0], circ, use_vec_ands);
				tempa[1] = PutAESSBoxGate(tempa[1], circ, use_vec_ands);
				tempa[2] = PutAESSBoxGate(tempa[2], circ, use_vec_ands);
				tempa[3] = PutAESSBoxGate(tempa[3], circ, use_vec_ands);
			}
		}
#endif
		k = (i - AES_STATE_COLS) * 4;
		j = i * 4;
		ex_key_vec[j] = circ->PutXORGate(ex_key_vec[k], tempa[0]);
		ex_key_vec[j + 1] = circ->PutXORGate(ex_key_vec[k + 1], tempa[1]);
		ex_key_vec[j + 2] = circ->PutXORGate(ex_key_vec[k + 2], tempa[2]);
		ex_key_vec[j + 3] = circ->PutXORGate(ex_key_vec[k + 3], tempa[3]);
	}

	std::vector<uint32_t> result(AES_EXP_KEY_BITS);
	for(uint32_t i = 0; i < AES_EXP_KEY_BYTES; i++) {
		for(uint32_t j = 0; j < 8; j++) {
			result[i * 8 + j] = ex_key_vec[i][j];
		}
	}
	return new boolshare(result, circ);
}

void verify_AES_encryption(uint8_t* input, uint8_t* key, uint32_t nvals, uint8_t* out, crypto* crypt) {
	AES_KEY_CTX* aes_key = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	crypt->init_aes_key(aes_key, key);
	for (uint32_t i = 0; i < nvals; i++) {
		crypt->encrypt(aes_key, out + i * AES_BYTES, input + i * AES_BYTES, AES_BYTES);
	}
	free(aes_key);
}

// Copied from the KeyExpansion function of the
// tiny-AES-c project, https://github.com/kokke/tiny-AES-c, original license is public domain
// This function produces NB_CONSTANT(AES_ROUNDS+1) round keys.
// The round keys are used in each round to decrypt the states.
void ExpandKey(uint8_t* roundKey, const uint8_t* key) {
//static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
//{
	unsigned i, j, k;
	uint8_t tempa[4]; // Used for the column/row operations

	// The first round key is the key itself.
	for (i = 0; i < AES_STATE_COLS; ++i) {
			roundKey[(i * 4) + 0] = key[(i * 4) + 0];
			roundKey[(i * 4) + 1] = key[(i * 4) + 1];
			roundKey[(i * 4) + 2] = key[(i * 4) + 2];
			roundKey[(i * 4) + 3] = key[(i * 4) + 3];
	}

	// All other round keys are found from the previous round keys.
	for (i = AES_STATE_COLS; i < NB_CONSTANT * (AES_ROUNDS + 1); ++i) {
		{
			k = (i - 1) * 4;
			tempa[0] = roundKey[k + 0];
			tempa[1] = roundKey[k + 1];
			tempa[2] = roundKey[k + 2];
			tempa[3] = roundKey[k + 3];
		}

		if (i % AES_STATE_COLS == 0) {
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				const uint8_t u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}

			// SubWord() is a function that takes a four-byte input word and
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				tempa[0] = plaintext_aes_sbox[tempa[0]];
				tempa[1] = plaintext_aes_sbox[tempa[1]];
				tempa[2] = plaintext_aes_sbox[tempa[2]];
				tempa[3] = plaintext_aes_sbox[tempa[3]];
			}

			tempa[0] = tempa[0] ^ Rcon[i/AES_STATE_COLS];
		}
#if AES_STATE_KEY_BITS == 256
			if (i % AES_STATE_COLS == 4) {
			// Function Subword()
			{
				tempa[0] = plaintext_aes_sbox[tempa[0]];
				tempa[1] = plaintext_aes_sbox[tempa[1]];
				tempa[2] = plaintext_aes_sbox[tempa[2]];
				tempa[3] = plaintext_aes_sbox[tempa[3]];
			}
		}
#endif
		j = i * 4;
		k = (i - AES_STATE_COLS) * 4;
		roundKey[j + 0] = roundKey[k + 0] ^ tempa[0];
		roundKey[j + 1] = roundKey[k + 1] ^ tempa[1];
		roundKey[j + 2] = roundKey[k + 2] ^ tempa[2];
		roundKey[j + 3] = roundKey[k + 3] ^ tempa[3];
	}
}
