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
 \brief		Implementation of the SHA1 hash function (which should not be used in practice anymore!)
 */

#ifndef __SHA1_CIRCUIT_H_
#define __SHA1_CIRCUIT_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cassert>

class BooleanCircuit;

#define ABY_SHA1_INPUT_BITS 512
#define ABY_SHA1_INPUT_BYTES ABY_SHA1_INPUT_BITS/8

#define ABY_SHA1_OUTPUT_BITS 160
#define ABY_SHA1_OUTPUT_BYTES ABY_SHA1_OUTPUT_BITS/8

#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

const uint32_t ABY_SHA1_H0 = 0x67452301;
const uint32_t ABY_SHA1_H1 = 0xEFCDAB89;
const uint32_t ABY_SHA1_H2 = 0x98BADCFE;
const uint32_t ABY_SHA1_H3 = 0x10325476;
const uint32_t ABY_SHA1_H4 = 0xC3D2E1F0;

const uint32_t ABY_SHA1_K0 = 0x5A827999;
const uint32_t ABY_SHA1_K1 = 0x6ED9EBA1;
const uint32_t ABY_SHA1_K2 = 0x8F1BBCDC;
const uint32_t ABY_SHA1_K3 = 0xCA62C1D6;

int32_t test_sha1_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing);

share* BuildSHA1Circuit(share* s_msgS, share* s_msgC, uint8_t* msgS, uint8_t* msgC, uint8_t* int_out, uint32_t nvals, BooleanCircuit* circ);
share* process_block(share* s_msg, uint8_t* msg, uint8_t* tmp_int_out, share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ);


void init_variables(share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ);
void break_message_to_chunks(share** s_w, share* s_msg, uint32_t* w, uint8_t* msg, BooleanCircuit* circ);
void expand_ws(share** s_w, uint32_t* w, BooleanCircuit* circ);
void sha1_main_loop(share** s_h, share** s_w, uint32_t* h, uint32_t* w, uint32_t nvals, BooleanCircuit* circ);
void verify_SHA1_hash(uint8_t* msgS, uint8_t* msgC, uint32_t msgbytes_per_party, uint32_t nvals, uint8_t* hash);



#endif /* __SHA1_CIRCUIT_H_ */
