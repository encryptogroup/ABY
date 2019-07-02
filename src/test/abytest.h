/**
 \file 		abytest.h
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
 \brief		ABY Test class.
 */

#ifndef MAINS_ABYTEST_H_
#define MAINS_ABYTEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include "../abycore/aby/abyparty.h"
#include "../abycore/circuit/circuit.h"
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../abycore/sharing/sharing.h"
#include "../examples/psi_scs/common/sort_compare_shuffle.h"
#include "../examples/psi_phasing/common/phasing_circuit.h"
#include "../examples/aes/common/aescircuit.h"
#include "../examples/sha1/common/sha1_circuit.h"
#include "../examples/lowmc/common/lowmccircuit.h"
#include "../examples/min-euclidean-dist/common/min-euclidean-dist-circuit.h"

bool run_tests(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg,
		int32_t testop, uint32_t num_test_runs, bool quiet, bool ignore_verification, bool randomseed);

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nreps, uint32_t* secparam,
		string* address, uint16_t* port, int32_t* test_op, uint32_t* num_test_runs, e_mt_gen_alg *mt_alg, bool* quiet, bool* ignore_verification, bool* randomseed);

int32_t test_standard_ops(aby_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t num_test_runs, uint32_t nops,
		e_role role, bool quiet, bool ignore_verification);

int32_t test_vector_ops(aby_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t nvals, uint32_t num_test_runs,
		uint32_t nops, e_role role, bool quiet, bool ignore_verification);

string get_op_name(e_operation op);

#endif /* MAINS_ABYTEST_H_ */
