/**
 \file 		aescircuit.h
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
 \brief		Implementation of AESCiruit
 */

#ifndef __AESCIRCUIT_H_
#define __AESCIRCUIT_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/util/crypto/crypto.h"
#include <cassert>

#define AES_ROUNDS 10
#define AES_STATE_SIZE 16
#define AES_STATE_SIZE_BITS 128

//Size of the expanded key
#define AES_EXP_KEY_BITS 1408
#define AES_EXP_KEY_BYTES AES_EXP_KEY_BITS/8

#define AES_STATE_COLS 4
#define AES_STATE_ROWS AES_STATE_SIZE/AES_STATE_COLS
#define INV_GATE_ID 666

const uint8_t AES_TEST_KEY[AES_KEY_BYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

const uint8_t AES_TEST_INPUT[AES_BYTES] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

const uint8_t AES_TEST_EXPANDED_KEY[AES_EXP_KEY_BITS] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x63, 0x63, 0x63,
		0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
		0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99, 0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81, 0x75, 0x9e, 0x42, 0xb2,
		0x7e, 0x91, 0xee, 0x2b, 0x7f, 0x2e, 0x2b, 0x88, 0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90, 0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c,
		0x99, 0xff, 0x09, 0x37, 0x6a, 0xb4, 0x9b, 0xa7, 0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b, 0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b, 0xf0, 0x9b, 0x0e, 0xf9, 0x03, 0x33,
		0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f, 0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde, 0x4c, 0x66, 0x49, 0x41,
		0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11, 0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e };

//is the gate an AND or an XOR gate
const BOOL isANDGate[140] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

//gate mapping of the AES Sbox
const uint32_t wire_mapping[140][2] = { { 7, 4 }, { 7, 2 }, { 7, 1 }, { 4, 2 }, { 3, 1 }, { 8, 8 + 4 }, { 6, 5 }, { 0, 8 + 5 }, { 0, 8 + 6 }, { 8 + 5, 8 + 6 }, { 6, 2 }, { 5, 2 },
		{ 8 + 2, 8 + 3 }, { 8 + 5, 8 + 10 }, { 8 + 4, 8 + 10 }, { 8 + 4, 8 + 11 }, { 8 + 8, 8 + 15 }, { 4, 0 }, { 8 + 6, 8 + 17 }, { 8, 8 + 18 }, { 1, 0 }, { 8 + 6, 8 + 20 }, { 8
				+ 1, 8 + 21 }, { 8 + 1, 8 + 9 }, { 8 + 19, 8 + 16 }, { 8 + 2, 8 + 15 }, { 8, 8 + 11 }, { 8 + 12, 8 + 5 }, { 8 + 22, 8 + 7 }, { 8 + 13, 35 }, { 8 + 18, 0 }, { 35
				+ 3, 35 }, { 8 + 2, 8 + 15 }, { 8 + 21, 8 + 8 }, { 8 + 25, 35 + 5 }, { 8 + 19, 8 + 16 }, { 35 + 8, 35 + 5 }, { 8, 8 + 14 }, { 8 + 3, 8 + 26 }, { 35 + 11, 35 + 10 },
		{ 8 + 1, 8 + 9 }, { 35 + 13, 35 + 10 }, { 35 + 2, 35 + 1 }, { 35 + 4, 8 + 23 }, { 35 + 7, 35 + 6 }, { 35 + 9, 35 + 14 }, { 35 + 15, 35 + 12 }, { 35 + 16, 35 + 14 }, { 35
				+ 17, 35 + 12 }, { 35 + 18, 8 + 24 }, { 35 + 21, 35 + 22 }, { 35 + 21, 35 + 19 }, { 35 + 20, 35 + 24 }, { 35 + 19, 35 + 20 }, { 35 + 22, 35 + 24 }, { 35 + 27, 35
				+ 26 }, { 35 + 25, 35 + 23 }, { 35 + 19, 35 + 22 }, { 35 + 26, 35 + 30 }, { 35 + 26, 35 + 24 }, { 35 + 20, 35 + 21 }, { 35 + 23, 35 + 33 }, { 35 + 23, 35 + 24 }, {
				35 + 20, 35 + 28 }, { 35 + 31, 35 + 32 }, { 35 + 22, 35 + 29 }, { 35 + 34, 35 + 35 }, { 35 + 37, 35 + 39 }, { 35 + 36, 35 + 38 }, { 35 + 36, 35 + 37 }, { 35 + 38,
				35 + 39 }, { 35 + 41, 35 + 40 }, { 35 + 43, 8 + 5 }, { 35 + 39, 8 + 7 }, { 35 + 38, 0 }, { 35 + 42, 8 + 15 }, { 35 + 37, 8 + 8 }, { 35 + 36, 8 + 16 }, { 35 + 41, 8
				+ 14 }, { 35 + 44, 8 + 26 }, { 35 + 40, 8 + 9 }, { 35 + 43, 8 + 12 }, { 35 + 39, 8 + 22 }, { 35 + 38, 8 + 18 }, { 35 + 42, 8 + 2 }, { 35 + 37, 8 + 21 }, { 35 + 36,
				8 + 19 }, { 35 + 41, 8 }, { 35 + 44, 8 + 3 }, { 35 + 40, 8 + 1 }, { 35 + 60, 35 + 61 }, { 35 + 49, 35 + 55 }, { 35 + 45, 35 + 47 }, { 35 + 46, 35 + 54 }, { 35 + 53,
				35 + 57 }, { 35 + 48, 35 + 60 }, { 35 + 61, 98 + 5 }, { 35 + 45, 98 + 3 }, { 35 + 50, 35 + 58 }, { 35 + 51, 35 + 52 }, { 35 + 52, 98 + 4 }, { 35 + 59, 98 + 2 }, {
				35 + 47, 35 + 50 }, { 35 + 49, 98 }, { 35 + 51, 35 + 60 }, { 35 + 54, 98 + 1 }, { 35 + 55, 98 }, { 35 + 56, 98 + 1 }, { 35 + 57, 98 + 8 }, { 35 + 62, 98 + 4 }, {
				98, 98 + 1 }, { 98 + 1, 98 + 7 }, { 98 + 3, 98 + 12 }, { 98 + 18, 98 + 2 }, { 98 + 15, 98 + 9 }, { 98 + 6, 98 + 10 }, { 98 + 7, 98 + 9 }, { 98 + 8, 98 + 10 }, { 98
				+ 11, 98 + 14 }, { 98 + 11, 98 + 17 }, { 98 + 16, INV_GATE_ID }, { 98 + 19, INV_GATE_ID }, { 98 + 13, INV_GATE_ID }, { 98 + 6, INV_GATE_ID }, { 98 + 33, 98 + 23 },
		{ 98 + 32, 98 + 27 }, { 98 + 25, 98 + 29 }, { 98 + 20, 98 + 22 }, { 98 + 6, 98 + 21 }, { 98 + 31, 98 + 28 }, { 98 + 30, 98 + 26 }, { 98 + 6, 98 + 24 } };

void verify_AES_encryption(uint8_t* input, uint8_t* key, uint32_t nvals, uint8_t* out, crypto* crypt);
int32_t test_aes_circuit(e_role role, char* address, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing);
share* BuildAESCircuit(share* val, share* key, BooleanCircuit* circ);
vector<uint32_t> AddAESRoundKey(vector<uint32_t>& val, vector<uint32_t> key, uint32_t keyaddr, BooleanCircuit* circ);
vector<uint32_t> Mul2(vector<uint32_t>& element, BooleanCircuit* circ);
vector<vector<uint32_t> > PutAESMixColumnGate(vector<vector<uint32_t> >& rows, BooleanCircuit* circ);
vector<uint32_t> AESSBox_Forward_BP(vector<uint32_t>& input, BooleanCircuit* circ);

#endif /* __AESCIRCUIT_H_ */
