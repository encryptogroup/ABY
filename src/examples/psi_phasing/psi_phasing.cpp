/**
 \file 		psi_phasing.cpp
 \author	michael.zohner@ec-spride.de
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
 \brief		Private Set Intersection Test class implementation.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/phasing_circuit.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* neles, uint32_t* secparam, std::string* address,
		uint16_t* port, int32_t* test_op, double* epsilon, e_sharing* sharing, uint32_t* nthreads,
		uint32_t* n_partner_eles, int* stash, uint32_t* maxbin, uint32_t* nhashfuns) {

	uint32_t int_role = 0, int_port = 0, int_sharing = 0;;
	bool useffc = false;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			  {	(void*) neles, T_NUM, "n",	"Number of elements", true, false },
			  {	(void*) bitlen, T_NUM, "b", "Bit-length", true, false },
			  {	(void*) epsilon, T_DOUBLE, "e", "Epsilon for Cuckoo hashing, default: 1.2", false, false },
			  { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			  {	(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			  {	(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			  { (void*) &int_sharing, T_NUM, "g", "Sharing in which the PSI circuit should be evaluated [0: BOOL, 1: YAO, 4: SP_LUT], default: BOOL", false, false },
			  { (void*) nthreads, T_NUM, "t", "Numboer of threads, default: 1", false, false },
			  {	(void*) n_partner_eles, T_NUM, "u",	"Number of partner elements", false, false },
			  {	(void*) stash, T_NUM, "c",	"Cuckoo hashing stash size, leaving empty will set stash size according to Tab V in eprint/2016/930 with 2^{-40}", false, false },
			  {	(void*) maxbin, T_NUM, "m",	"Maximum bin size parameter, leaving empty will compute maxbin internally to achieve 2^{-40} security (might take some time)", false, false },
			  {	(void*) nhashfuns, T_NUM, "h",	"Number of hash functions for the hashing schemes, default: 3", false, false },
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

	assert(int_sharing < S_LAST);
	assert(int_sharing != S_ARITH);
	*sharing = (e_sharing) int_sharing;

	assert(*epsilon >= 1);

	if(*n_partner_eles==0) {
		*n_partner_eles = *neles;
	}

	//delete options;

	return 1;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, neles = 31, secparam = 128, nthreads = 1, partner_neles=0, server_neles, client_neles;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	double epsilon = 1.2;
	e_sharing sharing = S_BOOL;
	int stash = -1;
	uint32_t maxbin = 0;
	uint32_t nhashfuns = 3;

	read_test_options(&argc, &argv, &role, &bitlen, &neles, &secparam, &address,
			&port, &test_op, &epsilon, &sharing, &nthreads, &partner_neles, &stash, &maxbin, &nhashfuns);

	seclvl seclvl = get_sec_lvl(secparam);

	if(role == SERVER) {
		server_neles = neles;
		client_neles = partner_neles;
	} else {
		server_neles = partner_neles;
		client_neles = neles;
	}

	//if(useyao) {
	test_phasing_circuit(role, address, port, seclvl, server_neles, client_neles, bitlen,
			epsilon, nthreads, mt_alg, sharing, stash, maxbin, nhashfuns);
	/*} else {
		test_phasing_circuit(role, address, seclvl, neles, bitlen,
				epsilon, nthreads, mt_alg, S_BOOL);
	}*/


#ifndef BATCH
	std::cout << "PSI circuit successfully executed" << std::endl;
#endif

	return 0;
}

