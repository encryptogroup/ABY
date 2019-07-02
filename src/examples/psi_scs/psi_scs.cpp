/**
 \file 		psi_scs.cpp
 \author	michael.zohner@cased.de
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
 \brief		Private Set Intersection with Sort-Compare-Shuffle of "Huang, Katz, Evans:
 	 	 	Private Set Intersection: Are Garbled Circuits better than Custom Protocols?
 	 	 	At NDSS 2012".
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/sort_compare_shuffle.h"

#define MAX_SCS_PROT 4

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* neles, uint32_t* secparam, string* address,
		uint16_t* port, int32_t* test_op, uint32_t* prot_version, bool* verify) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			  {	(void*) neles, T_NUM, "n",	"Number of elements", true, false },
			  {	(void*) bitlen, T_NUM, "b", "Bit-length", true, false },
			  { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			  {	(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			  {	(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			  {	(void*) prot_version, T_NUM, "y", "Version of the protocol [0: S+C BOOL & S BOOL, 1: S+C Yao & S Yao, 2: S+C Yao & S BOOL, 3: S+C Yao & S Yao_Rev], default: BOOL & BOOL", false, false },
			  {	(void*) verify, T_FLAG, "v", "Verify Output, default: true", false, false }
			};

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	assert(*prot_version < MAX_SCS_PROT);

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return 1;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, neles = 31, secparam = 128, nthreads = 1, prot_version = 0;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	bool verify_output = true;

	read_test_options(&argc, &argv, &role, &bitlen, &neles, &secparam, &address,
			&port, &test_op, &prot_version, &verify_output);

	seclvl seclvl = get_sec_lvl(secparam);

	srand(time(0));//(unsigned)time(0));

	test_psi_scs_circuit(role, address, port, seclvl, neles, bitlen, nthreads, mt_alg, prot_version, verify_output);


	cout << "PSI circuit successfully executed" << endl;

	return 0;
}
