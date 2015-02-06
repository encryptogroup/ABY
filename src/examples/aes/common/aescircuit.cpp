/**
 \file 		aescircuit.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Implementation of AESCiruit
 */
#include "aescircuit.h"

int32_t test_aes_circuit(e_role role, char* address, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {
	uint32_t bitlen = 32;
	uint32_t aes_key_bits;
	ABYParty* party = new ABYParty(role, address, seclvl, bitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	CBitVector input, key, verify;

	aes_key_bits = crypt->get_aes_key_bytes() * 8;
	input.Create(AES_BITS * nvals, crypt);
	verify.Create(AES_BITS * nvals);
	key.CreateBytes(AES_EXP_KEY_BYTES);

	//TODO create random key and perform key schedule, right now a static (expanded) key is used
	key.Copy((uint8_t*) AES_TEST_EXPANDED_KEY, 0, AES_EXP_KEY_BYTES);
	uint8_t* output;

	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
	//Circuit build routine works for Boolean circuits only right now
	assert(circ->GetCircuitType() == C_BOOLEAN);

	share *s_in, *s_key, *s_ciphertext;
	s_in = circ->PutINGate(nvals, input.GetArr(), aes_key_bits, CLIENT);
	s_key = circ->PutINGate(1, key.GetArr(), aes_key_bits * (AES_ROUNDS + 1), SERVER);
	s_key = circ->PutRepeaterGate(nvals, s_key);

	s_ciphertext = BuildAESCircuit(s_in, s_key, (BooleanCircuit*) circ);

	s_ciphertext = circ->PutOUTGate(s_ciphertext, ALL);

	party->ExecCircuit();

	output = s_ciphertext->get_clear_value();

	CBitVector out;
	out.AttachBuf(output, (uint64_t) AES_BYTES * nvals);

	verify_AES_encryption(input, key, nvals, verify, crypt);

	cout << "Testing AES encryption in " << get_sharing_name(sharing) << " sharing: " << endl;
	for (uint32_t i = 0; i < nvals; i++) {
		cout << "(" << i << ") Input:\t";
		input.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
		cout << "(" << i << ") Key:\t";
		key.PrintHex(0, AES_KEY_BYTES);
		cout << "(" << i << ") Circ:\t";
		out.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
		cout << "(" << i << ") Verify:\t";
		verify.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
		assert(verify.IsEqual(out, i*AES_BITS, (i+1)*AES_BITS));
	}

	return 0;
}

share* BuildAESCircuit(share* val, share* key, BooleanCircuit* circ) {
	uint32_t round, byte, i, j, k;
	vector<vector<vector<uint32_t> > > state(AES_STATE_COLS); //the state is treated as a matrix
	vector<vector<vector<uint32_t> > > state_temp(AES_STATE_COLS); //the state is treated as a matrix
	vector<uint32_t> out(128);

	for (i = 0; i < AES_STATE_COLS; i++) {
		state[i].resize(AES_STATE_ROWS);
		state_temp[i].resize(AES_STATE_ROWS);

		for (j = 0; j < AES_STATE_ROWS; j++) {
			state[i][j].resize(8);
			state_temp[i][j].resize(8);

			for (k = 0; k < 8; k++) {
				state[i][j][k] = val->get_gate(((i * AES_STATE_COLS) + j) * 8 + k);
			}
		}
	}

	for (round = 0; round < AES_ROUNDS; round++) {
		for (i = 0; i < AES_STATE_COLS; i++) {
			for (j = 0; j < AES_STATE_ROWS; j++) {
				state[i][j] = AddAESRoundKey(state[i][j], key->get_gates(), (round * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, circ); //ARK
				state_temp[(i - j) & 0x3][j] = AESSBox_Forward_BP(state[i][j], circ); // SBox + ShiftRows
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
			state[i][j] = AddAESRoundKey(state[i][j], key->get_gates(), (AES_ROUNDS * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, circ);
			for (k = 0; k < 8; k++) {
				out[(i * AES_STATE_ROWS + j) * 8 + k] = state[i][j][k];
			}
		}
	}

	return new boolshare(out, circ);
}

vector<uint32_t> AddAESRoundKey(vector<uint32_t>& val, vector<uint32_t>& key, uint32_t keyaddr, BooleanCircuit* circ) {
	vector<uint32_t> out(8);
	for (uint32_t i = 0; i < 8; i++) {
		out[i] = circ->PutXORGate(val[i], key[keyaddr + i]);
	}
	return out;
}

//Pretty straight - forward, shift by 1 to the left and if input_msb is 1, then XOR with 0x1b
vector<uint32_t> Mul2(vector<uint32_t>& element, BooleanCircuit* circ) {
	vector<uint32_t> out(8);
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

vector<vector<uint32_t> > PutAESMixColumnGate(vector<vector<uint32_t> >& rows, BooleanCircuit* circ) {
	UINT i, j, temp;
	vector<vector<uint32_t> > out(4);
	vector<vector<uint32_t> > temp_mul2(4);

	if (rows.size() != 4) {
		cout << "There have to be exactly four rows!" << endl;
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

//The Boyar-Peralta depth 16 SBox circuit
vector<uint32_t> AESSBox_Forward_BP(vector<uint32_t>& input, BooleanCircuit* circ) {
	vector<uint32_t> gates(141);

	//constant 1
	gates[140] = 0;
	vector<uint32_t> out(8);
	for (uint32_t i = 0; i < 8; i++) {
		gates[i] = input[i];
	}

	for (uint32_t i = 8; i < 132; i++) { //process all gates
		if (isANDGate[i])
			gates[i] = circ->PutANDGate(gates[wire_mapping[i - 8][0]], gates[wire_mapping[i - 8][1]]);
		else {
			if (wire_mapping[i - 8][1] != INV_GATE_ID) {
				gates[i] = circ->PutXORGate(gates[wire_mapping[i - 8][0]], gates[wire_mapping[i - 8][1]]);
			} else {
				gates[i] = circ->PutINVGate(gates[wire_mapping[i - 8][0]]);
			}
		}
	}

	for (uint32_t i = 132; i < 140; i++) {
		out[i - 132] = circ->PutXORGate(gates[wire_mapping[i - 8][0]], gates[wire_mapping[i - 8][1]]);
	}
	return out;
}

void verify_AES_encryption(CBitVector input, CBitVector key, uint32_t nvals, CBitVector& out, crypto* crypt) {
	AES_KEY_CTX* aes_key = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
	crypt->init_aes_key(aes_key, key.GetArr());
	for (uint32_t i = 0; i < nvals; i++) {
		crypt->encrypt(aes_key, out.GetArr() + i * AES_BYTES, input.GetArr() + i * AES_BYTES, AES_BYTES);
	}
	free(aes_key);
}

