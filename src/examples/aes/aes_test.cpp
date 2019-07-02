/**
 \file 		aes_test.cpp
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
 \brief		AES Test class implementation.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/aescircuit.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nvals,
		uint32_t* secparam, std::string* address, uint16_t* port, e_sharing* sharing, bool* verbose, uint32_t* nthreads,
		bool* use_vec_ands, bool* expand_in_sfe, bool* client_only) {

	uint32_t int_role = 0, int_port = 0, int_sharing = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			{ (void*) nvals, T_NUM, "n", "Number of parallel operation elements", false, false },
			{ (void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
			{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			{ (void*) &int_sharing, T_NUM, "g", "Sharing in which the AES circuit should be evaluated [0: BOOL, 1: YAO, 4: SP_LUT], default: BOOL", false, false },
			{ (void*) verbose, T_FLAG, "v", "Do not print the result of the evaluation, default: off", false, false },
			{ (void*) nthreads, T_NUM, "t", "Number of threads, default: 1", false, false },
			{ (void*) use_vec_ands, T_FLAG, "u", "Use vector AND optimization for AES circuit for Bool sharing, default: off", false, false },
			{ (void*) expand_in_sfe, T_FLAG, "x", "Calculate the key expansion during the SFE, default: false", false, false },
			{ (void*) client_only, T_FLAG, "c", "Both the key and the value are inputted by the client, default: false", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	assert(int_sharing < S_LAST);
	assert(int_sharing != S_ARITH);
	*sharing = (e_sharing) int_sharing;

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 1, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	bool verbose = false;
	bool use_vec_ands = false;
	bool expand_in_sfe = false;
	bool client_only = false;
	e_mt_gen_alg mt_alg = MT_OT;

	e_sharing sharing = S_BOOL;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port, &sharing, &verbose, &nthreads, &use_vec_ands, &expand_in_sfe, &client_only);

	seclvl seclvl = get_sec_lvl(secparam);

	test_aes_circuit(role, address, port, seclvl, nvals, nthreads, mt_alg, sharing, verbose, use_vec_ands, expand_in_sfe, client_only);

	return 0;
}

