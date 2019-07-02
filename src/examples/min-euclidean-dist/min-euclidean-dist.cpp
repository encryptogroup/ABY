/**
 \file 		min-euclidean-dist.cpp
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
 \brief		Minimum Euclidean distance Test class implementation.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/min-euclidean-dist-circuit.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nvals, uint32_t* dim, uint32_t* secparam, std::string* address, uint16_t* port, int32_t* sharing, ePreCompPhase* pre_comp_value) {

	uint32_t int_role = 0, int_port = 0, int_precomp = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
		{(void*) nvals, T_NUM, "n", "Server's database size", true, false },
		{(void*) dim, T_NUM, "d", "Dimension of input elements", true, false },
		{(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
		{(void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
		{(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
		{(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
		{(void*) sharing, T_NUM, "g", "Minimum sharing (0: Boolean (default); 1: Yao)", false, false },
		{(void*) &int_precomp, T_NUM, "c", "PrecompPhase: 0/1/2/3", false, false }
	};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	assert(int_precomp < 4);
	*role = (e_role) int_role;
	*pre_comp_value = (ePreCompPhase) int_precomp;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 500, secparam = 128, nthreads = 1, dim = 6;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t sharing = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	ePreCompPhase precomp_phase_value;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &dim, &secparam, &address, &port, &sharing, &precomp_phase_value);

	seclvl seclvl = get_sec_lvl(secparam);

	e_sharing min_sharing = S_BOOL;

	if(sharing == 1){
		min_sharing = S_YAO;
	}

	test_min_eucliden_dist_circuit(role, address, port, seclvl, nvals, dim, nthreads, mt_alg, S_ARITH, min_sharing, precomp_phase_value);

	return 0;
}
