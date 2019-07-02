/**
 \file 		aescircuit.h
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

#ifndef __AESCIRCUIT_H_
#define __AESCIRCUIT_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cassert>

class BooleanCircuit;

// If you change these values and want to test the functionallity with test_aes_circuit,
// you will have to change the AES_BITS, AES_BYTES, AES_KEY_BITS and AES_KEY_BYTES definitions
// on the constant.h definition on the encrypto utils as well.
// WARNING: Currently a correct running of the algorithms cannot be guaranteed if these values are changed.
// There might be some work to do.
#define AES_STATE_KEY_BITS 128
#define AES_STATE_SIZE_BITS 128

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// It is used for the key expansion algorithm
// Please extend the array if the aes key size changes
#define RCON_SIZE 11
const uint8_t Rcon[RCON_SIZE] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

#define NB_CONSTANT 4

#define INV_GATE_ID 666

// Derived constants or constants to AES
#if (AES_STATE_KEY_BITS == 192)
	#define AES_ROUNDS 12
	#define AES_STATE_COLS 6
#elif (AES_STATE_KEY_BITS == 256)
	#define AES_ROUNDS 14
	#define AES_STATE_COLS 8
#else //AES_STATE_KEY__BITS == 128
	#define AES_ROUNDS 10
	#define AES_STATE_COLS 4
#endif

#define AES_STATE_SIZE (AES_STATE_SIZE_BITS/8)

// Size of the key
#define AES_STATE_KEY_BYTES (AES_STATE_KEY_BITS/8)

// Size of the expanded key
#define AES_EXP_KEY_BYTES (AES_STATE_KEY_BYTES*(AES_ROUNDS+1))
#define AES_EXP_KEY_BITS (AES_EXP_KEY_BYTES*8)

#define AES_STATE_ROWS (AES_STATE_SIZE/AES_STATE_COLS)

const uint64_t aes_sbox_ttables[8][4] =
		{{ 0xb14ede67096c6eedL, 0x68ab4bfa8acb7a13L, 0x10bdb210c006eab5L, 0x4f1ead396f247a04L},
		{ 0x7bae007d4c53fc7dL, 0xe61a4c5e97816f7aL, 0x6a450b2ef33486b4L, 0xc870974094ead8a9L},
		{ 0xa16387fb3b48b4c6L, 0x23a869a2a428c424L, 0x577d64e03b0c3ffbL, 0xac39b6c0d6ce2efcL},
		{ 0x109020a2193d586aL, 0x2568ea2effa8527dL, 0xe9da849cf6ac6c1bL, 0x4e9ddb76c892fb1bL},
		{ 0xc2b0f97752b8b11eL, 0xf7f17a494ce30f58L, 0x2624b286bc48ecb4L, 0xf210a3aece472e53L},
		{ 0xf8045f7b6d98dd7fL, 0x6bc2aa4e0d787aa4L, 0x7d8dcc4706319e08L, 0x54b248130b4f256fL},
		{ 0x980a3cc2c2fdb4ffL, 0xe4851b3bf3ab2560L, 0x3f6bcb91b30db559L, 0x21e0b83325591782L},
		{ 0x5caa2ec7bf977090L, 0xe7bac28f866aac82L, 0x4cb3770196ca0329L, 0x52379de7b844e3e1L},
};

const uint64_t aes_sbox_multi_out_ttable[32] =
		{0xb14ede67096c6eedL, 0x68ab4bfa8acb7a13L, 0x10bdb210c006eab5L, 0x4f1ead396f247a04L,
		 0x7bae007d4c53fc7dL, 0xe61a4c5e97816f7aL, 0x6a450b2ef33486b4L, 0xc870974094ead8a9L,
		 0xa16387fb3b48b4c6L, 0x23a869a2a428c424L, 0x577d64e03b0c3ffbL, 0xac39b6c0d6ce2efcL,
		 0x109020a2193d586aL, 0x2568ea2effa8527dL, 0xe9da849cf6ac6c1bL, 0x4e9ddb76c892fb1bL,
		 0xc2b0f97752b8b11eL, 0xf7f17a494ce30f58L, 0x2624b286bc48ecb4L, 0xf210a3aece472e53L,
		 0xf8045f7b6d98dd7fL, 0x6bc2aa4e0d787aa4L, 0x7d8dcc4706319e08L, 0x54b248130b4f256fL,
		 0x980a3cc2c2fdb4ffL, 0xe4851b3bf3ab2560L, 0x3f6bcb91b30db559L, 0x21e0b83325591782L,
		 0x5caa2ec7bf977090L, 0xe7bac28f866aac82L, 0x4cb3770196ca0329L, 0x52379de7b844e3e1L
};

const uint64_t aes_sbox_multi_seq_out_ttable[32] =
		{ 0xc56f6bf27b777c63L , 0x76abd7fe2b670130L , 0xf04759fa7dc982caL , 0xc072a49cafa2d4adL ,
		0xccf73f362693fdb7L , 0x1531d871f1e5a534L , 0x9a059618c323c704L , 0x75b227ebe2801207L ,
		0xa05a6e1b1a2c8309L , 0x842fe329b3d63b52L , 0x5bb1fc20ed00d153L , 0xcf584c4a39becb6aL ,
		0x85334d43fbaaefd0L , 0xa89f3c507f02f945L , 0xf5389d928f40a351L , 0xd2f3ff1021dab6bcL ,
		0x1744975fec130ccdL , 0x73195d643d7ea7c4L , 0x88902a22dc4f8160L , 0xdb0b5ede14b8ee46L ,
		0x5c2406490a3a32e0L , 0x79e4959162acd3c2L , 0xa94ed58d6d37c8e7L , 0x8ae7a65eaf4566cL ,
		0xc6b4a61c2e2578baL , 0x8a8bbd4b1f74dde8L , 0xef6034866b53e70L , 0x9e1dc186b9573561L ,
		0x948ed9691198f8e1L , 0xdf2855cee9871e9bL , 0x6842e6bf0d89a18cL , 0x16bb54b00f2d9941L ,
};


const unsigned char plaintext_aes_sbox[256] =
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};


//const uint64_t aes_sbox_ttables[] = { b14ede67096c6eed68ab4bfa8acb7a1310bdb210c006eab54f1ead396f247a04}, { 7bae007d4c53fc7de61a4c5e97816f7a6a450b2ef33486b4c870974094ead8a9}, { a16387fb3b48b4c623a869a2a428c424577d64e03b0c3ffbac39b6c0d6ce2efc}, { 109020a2193d586a2568ea2effa8527de9da849cf6ac6c1b4e9ddb76c892fb1b}, { c2b0f97752b8b11ef7f17a494ce30f582624b286bc48ecb4f210a3aece472e53}, { f8045f7b6d98dd7f6bc2aa4e0d787aa47d8dcc4706319e0854b248130b4f256f}, { 980a3cc2c2fdb4ffe4851b3bf3ab25603f6bcb91b30db55921e0b83325591782}, { 5caa2ec7bf977090e7bac28f866aac824cb3770196ca032952379de7b844e3e1}

//is the gate an AND or an XOR gate for the depth-optimized S-Box
const BOOL do_isANDGate[140] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

//gate mapping of the depth-optimized AES Sbox
const uint32_t do_wire_mapping[140][2] = { { 7, 4 }, { 7, 2 }, { 7, 1 }, { 4, 2 }, { 3, 1 }, { 8, 8 + 4 }, { 6, 5 }, { 0, 8 + 5 }, { 0, 8 + 6 }, { 8 + 5, 8 + 6 }, { 6, 2 }, { 5, 2 },
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


//Testing functions
void verify_AES_encryption(uint8_t* input, uint8_t* key, uint32_t nvals, uint8_t* out, crypto* crypt);
/**
 \param		role the role of the user; possible roles: "CLIENT" and "SERVER"
 \param		adress the adress of the server the client connects to
 \param 	port the port of the server the client connects to
 \param		seclvl	the definition of the security level the SFE should be using, see on <ENCRYPTO_utils/crypto/crypto.h>
				to get more information
 \param		nvals the amount of concurrent encryptions to be calculated
 \param		nthreads the amount of threads used
 \param 		mt_alg the Oblivious Extension algorithm to be used; see e_mt_gen_alg in the ABYConstants.h for possible algorithms
 \param		sharing the sharing algorithm to be used; see e_sharing in the ABYConstants.h for possible algorithms
 \param		verbose if true some output values will be suppressed for printing; default is false
 \param		use_vec_ands if true the vector AND optimization for AES circuit for Bool sharing will be usedM default is false
 \param		expand_in_sfe if true the key will be expanded in the SFE, otherwise the key will be expanded before the SFE; default is false
 \param		client_only if true both the key and the values will be inputted by the client; default is false
*/
int32_t test_aes_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, bool verbose = false, bool use_vec_ands = false, bool expand_in_sfe = false, bool client_only = false);
/**
 \param		key the key to be expanded
 \param		roundKey the result as the expansion of the small key. WARNING: This function uses call by reference,
				therefore you must preallocate AES_EXP_KEY_BYTES bytes before calling this function.
 \brief		This function precalculates the expansion of the given (small) key into the expanded key for the AES encryption.
 */
void ExpandKey(uint8_t* roundKey, const uint8_t* key);

//SFE functions
/**
 \param		val the value to be encrypted
 \param		key the expanded key which encrypts the value
 \param		circ the circuit which generates and evaluates the SFE
 \param 	use_vec_ands if true the vector optimaziation will be used during the SBox replacement, default is false
 \brief		This function calculates a ciphertext using AES given the val to be enctypted and the keyin SFE.
 */
share* BuildAESCircuit(share* val, share* key, BooleanCircuit* circ, bool use_vec_ands=false);
/**
 \param		key the key to be expanded during SFE, the key must not be a SIMD share with nvals > 1
 \param		circ the circuit which generates and evaluates the SFE
 \param 	use_vec_ands if true the vector optimaziation will be used during the SBox replacement, default is false
 \brief		This function calculates the expansion of the given (small) key into the expanded key for the AES encryption during SFE.
 */
share* BuildKeyExpansion(share* key, BooleanCircuit* circ, bool use_vec_ands = false);

//Helper functions used for the implementation of the SFE functions above;
std::vector<uint32_t> AddAESRoundKey(std::vector<uint32_t>& val, std::vector<uint32_t> key, uint32_t keyaddr, BooleanCircuit* circ);
std::vector<uint32_t> Mul2(std::vector<uint32_t>& element, BooleanCircuit* circ);
std::vector<std::vector<uint32_t> > PutAESMixColumnGate(std::vector<std::vector<uint32_t> >& rows, BooleanCircuit* circ);
std::vector<uint32_t> PutAESSBoxGate(std::vector<uint32_t> input, BooleanCircuit* circ, bool use_vec_ands);
std::vector<uint32_t> AESSBox_Forward_BP_Depth_Optimized(std::vector<uint32_t> input, BooleanCircuit* circ);
std::vector<uint32_t> AESSBox_Forward_BP_Size_Optimized(std::vector<uint32_t> input, BooleanCircuit* circ);
std::vector<uint32_t> AESSBox_Forward_BP_VecMTs_Optimized(std::vector<uint32_t> input, BooleanCircuit* circ, uint32_t* buf_pos_even, uint32_t* buf_pos_odd);
std::vector<uint32_t> AESSBox_Forward_SPLUT(std::vector<uint32_t> input, BooleanCircuit* circ);
std::vector<uint32_t> Two_In_AND_Vec_Gate(uint32_t s, uint32_t a, uint32_t b, BooleanCircuit* circ, uint32_t* buf_pos_even, uint32_t* buf_pos_odd);

#endif /* __AESCIRCUIT_H_ */
