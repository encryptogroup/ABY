/**
 \file 		threshold-euclidean-dist.cpp
 \author	michael.zohner@ec-spride.de
 \author	oleksandr.tkachenko@crisp-da.de
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
 \brief		2D SIMD Threshold Euclidean distance Test class implementation.
 *              Implements the functionality from PST’15 (http://ieeexplore.ieee.org/document/7232947/).
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/threshold-euclidean-dist.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* operationbitlen,
		uint32_t* secparam, std::string* address, uint16_t* port, uint32_t * n, bool* only_yao) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] = { 
            { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
            { (void*) n, T_NUM, "n", "Number of parallel evaluations", true, false },
            { (void*) operationbitlen, T_NUM, "b", "Bit-length of threshold; input length is set to a quarter of this value; only values allowed are 32 (inputlengh=8) and 64 (inputlength=16), default 64", false, false },
            { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
            { (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
            { (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
            { (void*) n, T_NUM, "n", "Number of parallel evaluations, default: 1000", false, false },
            { (void*) only_yao, T_FLAG, "y", "Force using only the Yao sharing: false", false, false }
            };

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

	assert(*operationbitlen == 64 || *operationbitlen == 32);

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t operationbitlen = 64, secparam = 128, nthreads = 2;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
        uint32_t n = 1000;
	e_mt_gen_alg mt_alg = MT_OT;
        bool only_yao = false;

	read_test_options(&argc, &argv, &role, &operationbitlen,
                &secparam, &address, &port, &n, &only_yao);

	seclvl seclvl = get_sec_lvl(secparam);

	test_min_eucliden_dist_circuit(role, address, port,
                seclvl, operationbitlen, nthreads, mt_alg, S_ARITH, S_YAO, n, only_yao);

	return 0;
}

