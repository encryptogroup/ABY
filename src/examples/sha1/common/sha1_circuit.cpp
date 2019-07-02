/**
 \file 		sha1_circuit.cpp
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
#include "sha1_circuit.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cstring>

int32_t test_sha1_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {
	uint32_t bitlen = 32;
	uint32_t sha1bits_per_party = ABY_SHA1_INPUT_BITS/2;
	uint32_t sha1bytes_per_party = bits_in_bytes(sha1bits_per_party);
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	std::vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	CBitVector msgS, msgC, verify;
	// uint32_t testvec = 0x616263;

	//The plaintext output computation will only be done once instead of nvals times!
	uint8_t* plain_out = (uint8_t*) malloc(ABY_SHA1_OUTPUT_BYTES);

	msgS.Create(sha1bits_per_party * nvals, crypt);
	msgC.Create(sha1bits_per_party * nvals, crypt);
	//Result for this should be: 0098ba824b5c16427bd7a1122a5a442a25ec644d
	//for(uint32_t i = 0; i < sha1bytes_per_party; i++) {
	//	msgS.SetByte(i, 0x61);
	//	msgC.SetByte(i, 0x61);
	//}
	//msgS.SetBits((uint8_t*) &testvec, 0, 24);

	verify.Create(ABY_SHA1_OUTPUT_BITS * nvals);

	uint8_t* output;

	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
	//Circuit build routine works for Boolean circuits only right now
	assert(circ->GetCircuitType() == C_BOOLEAN);

	share *s_msgS, *s_msgC, *s_hash_out;
	s_msgS = circ->PutSIMDINGate(nvals, msgS.GetArr(), sha1bits_per_party, SERVER);
	s_msgC = circ->PutSIMDINGate(nvals, msgC.GetArr(), sha1bits_per_party, CLIENT);

	s_hash_out = BuildSHA1Circuit(s_msgS, s_msgC, msgS.GetArr(), msgC.GetArr(), plain_out, nvals, (BooleanCircuit*) circ);

	s_hash_out = circ->PutOUTGate(s_hash_out, ALL);

	party->ExecCircuit();

	output = s_hash_out->get_clear_value_ptr();

	CBitVector out;
	out.AttachBuf(output, (uint64_t) ABY_SHA1_OUTPUT_BITS * nvals);

	verify_SHA1_hash(msgS.GetArr(), msgC.GetArr(), sha1bytes_per_party, nvals, verify.GetArr());

#ifndef BATCH
	std::cout << "Plaintext output: " << (hex) << std::endl;
	for(uint32_t i = 0; i < 20; i++) {
		std::cout << (uint32_t) plain_out[i];
	}
	std::cout << (dec) << std::endl;


	std::cout << "Testing SHA1 hash in " << get_sharing_name(sharing) << " sharing: " << std::endl;
#endif
	for (uint32_t i = 0; i < nvals; i++) {
#ifndef BATCH
		std::cout << "(" << i << ") Server Input:\t";
		msgS.PrintHex(i * sha1bytes_per_party, (i + 1) * sha1bytes_per_party);
		std::cout << "(" << i << ") Client Input:\t";
		msgC.PrintHex(i * sha1bytes_per_party, (i + 1) * sha1bytes_per_party);
		std::cout << "(" << i << ") Circ:\t";
		out.PrintHex(i * ABY_SHA1_OUTPUT_BYTES, (i + 1) * ABY_SHA1_OUTPUT_BYTES);
		std::cout << "(" << i << ") Verify:\t";
		verify.PrintHex(i * ABY_SHA1_OUTPUT_BYTES, (i + 1) * ABY_SHA1_OUTPUT_BYTES);
#endif
		assert(verify.IsEqual(out, i*ABY_SHA1_OUTPUT_BITS, (i+1)*ABY_SHA1_OUTPUT_BITS));
	}

	delete crypt;
	delete party;

	return 0;
}

/* Steps are taken from the wikipedia article on SHA1 */
share* BuildSHA1Circuit(share* s_msgS, share* s_msgC, uint8_t* msgS, uint8_t* msgC, uint8_t* plain_out, uint32_t nvals, BooleanCircuit* circ) {

	uint32_t party_in_bitlen = ABY_SHA1_INPUT_BITS/2;
	uint32_t party_in_bytelen = ABY_SHA1_INPUT_BYTES/2;

	//Copy shared input into one msg
	share* s_msg = new boolshare(ABY_SHA1_INPUT_BITS, circ);
	for(uint32_t i = 0; i < party_in_bitlen; i++) {
		s_msg->set_wire_id(i, s_msgS->get_wire_id(i));
		s_msg->set_wire_id(i+party_in_bitlen, s_msgC->get_wire_id(i));
	}

	//Copy plaintext input into one msg
	uint8_t* tmp_plain_out = (uint8_t*) malloc(ABY_SHA1_OUTPUT_BYTES);
	uint8_t* msg = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);
	memcpy(msg, msgS, party_in_bytelen);
	memcpy(msg+party_in_bytelen, msgC, party_in_bytelen);

	//initialize state variables
	share** s_h = (share**) malloc(sizeof(share*) * 5);
	uint32_t* h = (uint32_t*) malloc(sizeof(uint32_t) * 5);
	init_variables(s_h, h, nvals, circ);

	/*
	 * Process this message block
	 */
	share* out = process_block(s_msg, msg, tmp_plain_out, s_h, h, nvals, circ);

	/*
	 * Do the final SHA1 Result computation.
	 * TODO: The remaining block should be padded and processed here. However, since the
	 * input bit length is fixed to 512 bit, the padding is constant.
	 */
	uint64_t zero = 0;
	uint64_t one = 1;
	share* s_zero = circ->PutSIMDCONSGate(nvals, zero, 1);
	share* s_one = circ->PutSIMDCONSGate(nvals, one, 1);
	for(uint32_t i = 0; i < 512; i++) {
		if(i != 7 && i != 497) {
			s_msg->set_wire_id(i, s_zero->get_wire_id(0));
		} else {
			s_msg->set_wire_id(i, s_one->get_wire_id(0));
		}
	}
	for(uint32_t i = 0; i < 64; i++) {
		if(i == 0) {
			msg[0] = 0x80;
		} else if (i == 62) {
			msg[62] = 0x02;
		} else {
			msg[i] = 0;
		}
	}

	out = process_block(s_msg, msg, tmp_plain_out, s_h, h, nvals, circ);

	memcpy(plain_out, tmp_plain_out, ABY_SHA1_OUTPUT_BYTES);

	free(s_h);
	free(h);
	return out;
}

/*
 * Initialize variables
 * h0 = 0x67452301
 * h1 = 0xEFCDAB89
 * h2 = 0x98BADCFE
 * h3 = 0x10325476
 * h4 = 0xC3D2E1F0
 */

void init_variables(share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ) {
	s_h[0] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H0, 32);
	s_h[1] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H1, 32);
	s_h[2] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H2, 32);
	s_h[3] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H3, 32);
	s_h[4] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H4, 32);

	h[0] = ABY_SHA1_H0;
	h[1] = ABY_SHA1_H1;
	h[2] = ABY_SHA1_H2;
	h[3] = ABY_SHA1_H3;
	h[4] = ABY_SHA1_H4;
}



share* process_block(share* s_msg, uint8_t* msg, uint8_t* plain_out, share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ) {
	//share* out = new share(1, circ);
	share* out = new boolshare(ABY_SHA1_OUTPUT_BITS, circ);
	share** s_w = (share**) malloc(sizeof(share*) * 80);
	uint32_t* w = (uint32_t*) malloc(sizeof(uint32_t) * 80);


	//break message into 512-bit chunks
	//for each chunk
	//    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	break_message_to_chunks(s_w, s_msg, w, msg, circ);

    //for i from 16 to 79
     //   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
	expand_ws(s_w, w, circ);

	//Main Loop; result is written into s_h
	sha1_main_loop(s_h, s_w, h, w, nvals, circ);

	for(uint32_t i = 0, wid; i < 5; i++) {
		for(uint32_t j = 0; j < 32; j++) {
			if(j < 8) {
				wid = 24;
			} else if (j < 16) {
				wid = 16;
			} else if(j < 24) {
				wid = 8;
			} else {
				wid = 0;
			}
			out->set_wire_id(i*32+j, s_h[i]->get_wire_id(wid + (j%8)));
		}
	}

	for(uint32_t i = 0; i < 5; i++) {
		plain_out[i*4] = (h[i]>>24)&0xFF;
		plain_out[i*4+1] = (h[i]>>16)&0xFF;
		plain_out[i*4+2] = (h[i]>>8)&0xFF;
		plain_out[i*4+3] = (h[i])&0xFF;
	}
	free(s_w);
	free(w);

	return out;
}


//break a 512 bit input message into 16 32-bit words in bit endian
void break_message_to_chunks(share** s_w, share* s_msg, uint32_t* w, uint8_t* msg, BooleanCircuit* circ) {
	for(uint32_t i = 0; i < 16; i++) {
		s_w[i] = new boolshare(32, circ);
	}
	//iterate over message bytes
	uint32_t wid;
	for(uint32_t i = 0; i < 16; i++) {
		//iterate over bits
		for(uint32_t j = 0; j < 32; j++) {
			if(j < 8) {
				wid = 24;
			} else if (j < 16) {
				wid = 16;
			} else if(j < 24) {
				wid = 8;
			} else {
				wid = 0;
			}
			s_w[i]->set_wire_id((j%8)+wid, s_msg->get_wire_id(i*32+ j));
		}
		w[i] = msg[i*4] << 24;
		w[i] |= (msg[i*4+1] << 16);
		w[i] |= (msg[i*4+2] << 8);
		w[i] |= msg[i*4+3];

	}
}

//for i from 16 to 79
 //   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
void expand_ws(share** s_w, uint32_t* w, BooleanCircuit* circ) {
	share* s_wtmp;
	for(uint32_t i = 16; i < 80; i++) {
		s_w[i] = new boolshare(32, circ);
		s_wtmp = circ->PutXORGate(s_w[i-3], s_w[i-8]);
		s_wtmp = circ->PutXORGate(s_wtmp, s_w[i-14]);
		s_wtmp = circ->PutXORGate(s_wtmp, s_w[i-16]);
		//leftrotate by 1
		for(uint32_t j = 0; j < 32; j++) {
			s_w[i]->set_wire_id((j+1)%32, s_wtmp->get_wire_id(j));
		}

		w[i] = SHA1CircularShift(1, w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
	}
}

void sha1_main_loop(share** s_h, share** s_w, uint32_t* h, uint32_t* w, uint32_t nvals, BooleanCircuit* circ) {
	/*
	 * Initialize hash value for this chunk:
	 * a = h0; b = h1; c = h2; d = h3; e = h4
	*/
	share *s_a, *s_b, *s_c, *s_d, *s_e;
	s_a = new boolshare(32, circ);
	s_b = new boolshare(32, circ);
	s_c = new boolshare(32, circ);
	s_d = new boolshare(32, circ);
	s_e = new boolshare(32, circ);

	s_a->set_wire_ids(s_h[0]->get_wires());
	s_b->set_wire_ids(s_h[1]->get_wires());
	s_c->set_wire_ids(s_h[2]->get_wires());
	s_d->set_wire_ids(s_h[3]->get_wires());
	s_e->set_wire_ids(s_h[4]->get_wires());

	uint32_t a, b, c, d, e;
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

	/*
	 * Main loop
	 * for i from 0 to 79
	 */
	share *s_f, *s_k, *s_tmp;
	uint32_t f, k, tmp;
	for(uint32_t i = 0; i < 80; i++) {

		if(i < 20) {
		/*
		 * if 0 ≤ i ≤ 19 then
		 *     f = (b and c) xor ((not b) and d)
		 *     k = 0x5A827999
		 */
			s_f = circ->PutANDGate(s_b, s_c);
			s_tmp = circ->PutINVGate(s_b);
			s_tmp = circ->PutANDGate(s_tmp, s_d);
			s_f = circ->PutXORGate(s_f, s_tmp);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K0, 32);

			f = (b & c) | ((~b) & d);
			k = ABY_SHA1_K0;
		} else if(i < 40) {
		/*
         * else if 20 ≤ i ≤ 39
         * 		f = b xor c xor d
         * 		k = 0x6ED9EBA1
		 */
			s_f = circ->PutXORGate(s_b, s_c);
			s_f = circ->PutXORGate(s_f, s_d);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K1, 32);

			f = b ^ c ^ d;
			k = ABY_SHA1_K1;
		} else if(i < 60) {
		/*
         * else if 40 ≤ i ≤ 59
         * 		f = (b and c) xor (b and d) xor (c and d)
         *  	k = 0x8F1BBCDC
		 */
			s_f = circ->PutANDGate(s_b, s_c);
			s_tmp = circ->PutANDGate(s_b, s_d);
			s_f = circ->PutXORGate(s_f, s_tmp);
			s_tmp = circ->PutANDGate(s_c, s_d);
			s_f = circ->PutXORGate(s_f, s_tmp);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K2, 32);

			f = (b & c) | (b & d) | (c & d);
			k = ABY_SHA1_K2;
		} else if(i < 80) {
			/*
      	  	 * else if 60 ≤ i ≤ 79
             * 		f = b xor c xor d
             * 		k = 0xCA62C1D6
			 */
			s_f = circ->PutXORGate(s_b, s_c);
			s_f = circ->PutXORGate(s_f, s_d);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K3, 32);

			f = (b ^ c ^ d);
			k = ABY_SHA1_K3;
		}
		/*
		 * temp = (a leftrotate 5) + f + e + k + w[i]
		 */
		s_tmp = new boolshare(32, circ);
		for(uint32_t j = 0; j <32; j++) {
			s_tmp->set_wire_id((j+5)%32, s_a->get_wire_id(j));
		}
		s_tmp = circ->PutADDGate(s_tmp, s_f);
		s_tmp = circ->PutADDGate(s_tmp, s_e);
		s_tmp = circ->PutADDGate(s_tmp, s_k);
		s_tmp = circ->PutADDGate(s_tmp, s_w[i]);

		tmp = SHA1CircularShift(5, a);
		tmp = (tmp + f) & 0xFFFFFFFF;
		tmp = (tmp + e) & 0xFFFFFFFF;
		tmp = (tmp + k) & 0xFFFFFFFF;
		tmp = (tmp + w[i]) & 0xFFFFFFFF;

		// e = d
		s_e->set_wire_ids(s_d->get_wires());
		e = d;
        // d = c
		s_d->set_wire_ids(s_c->get_wires());
		d = c;
		// c = b leftrotate 30
		for(uint32_t j = 0; j <32; j++) {
			s_c->set_wire_id((j+30)%32, s_b->get_wire_id(j));
		}
		c = SHA1CircularShift(30, b);
		// b = a
		s_b->set_wire_ids(s_a->get_wires());
		b = a;
		// a = temp
		s_a->set_wire_ids(s_tmp->get_wires());
		a = tmp;

	}


	/*
	 * Set output; Add this chunk's hash to result so far:
	 * h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d; h4 = h4 + e
	 */
	s_h[0] = circ->PutADDGate(s_h[0], s_a);
	s_h[1] = circ->PutADDGate(s_h[1], s_b);
	s_h[2] = circ->PutADDGate(s_h[2], s_c);
	s_h[3] = circ->PutADDGate(s_h[3], s_d);
	s_h[4] = circ->PutADDGate(s_h[4], s_e);

	h[0] = (h[0] + a) & 0xFFFFFFFF;
	h[1] = (h[1] + b) & 0xFFFFFFFF;
	h[2] = (h[2] + c) & 0xFFFFFFFF;
	h[3] = (h[3] + d) & 0xFFFFFFFF;
	h[4] = (h[4] + e) & 0xFFFFFFFF;
}

void verify_SHA1_hash(uint8_t* msgS, uint8_t* msgC, uint32_t msgbytes_per_party, uint32_t nvals, uint8_t* hash) {

	uint8_t* input_buf = (uint8_t*) calloc(ABY_SHA1_INPUT_BYTES, sizeof(uint8_t));
	crypto* crypt_tmp = new crypto(80, (uint8_t*) const_seed);

	for(uint32_t i = 0; i < nvals; i++) {
		memcpy(input_buf, msgS + i * msgbytes_per_party, msgbytes_per_party);
		memcpy(input_buf + msgbytes_per_party, msgC + i * msgbytes_per_party, msgbytes_per_party);
		crypt_tmp->hash(hash+i*ABY_SHA1_OUTPUT_BYTES, ABY_SHA1_OUTPUT_BYTES, input_buf, ABY_SHA1_INPUT_BYTES);
	}
	delete crypt_tmp;
}
