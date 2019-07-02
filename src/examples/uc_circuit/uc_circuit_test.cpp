/**
 \file 		uc_gate_test.cpp
 \author	kiss@encrypto.cs.tu-darmstadt.de
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
 \brief		Test the universal circuit evaluation
 */

#include "common/uc_circuit.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* secparam, std::string* address,
		uint16_t* port, e_sharing* sharing, std::string* filename, std::string* p1filename, uint32_t* nruns) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			  {	(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
			  { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			  {	(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			  {	(void*) sharing, T_NUM, "c", "Sharing [0: GMW, 1: Yao), default: Yao", false, false },
			  {	(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			  {	(void*) filename, T_STR, "f", "UC file", false, false } ,
			  {	(void*) p1filename, T_STR, "e", "Programming file", false, false },
			  { (void*) nruns, T_NUM, "i", "Number of repeated Iterations, default: 1", false, false }
			  };

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
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

	assert(*sharing < 2 && *sharing >= 0);
	std::cout << std::endl;

	return 1;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, nvals = 1, secparam = 128, nthreads = 1, nruns = 1;
	uint16_t port = 7766;
	uint32_t p2input = 0;
	std::string address = "127.0.0.1";
	e_mt_gen_alg mt_alg = MT_OT;
	e_sharing sharing = S_BOOL;
	std::string filename = "../../bin/uc/adder_circ.txt";
	std::string p1filename = "../../bin/uc/adder_prog.txt";

	read_test_options(&argc, &argv, &role, &bitlen, &secparam, &address, &port, &sharing, &filename, &p1filename, &nruns);

	seclvl seclvl = get_sec_lvl(secparam);

	test_universal_circuit(role, (char*) address.c_str(), port, seclvl, nvals, bitlen, nthreads, mt_alg, sharing, filename, p1filename);

	return 0;
}

