/**
 \file 		abytest.h
 \author	michael.zohner@ec-spride.de
 \copyright	________________
 \brief		ABY Test class.
 */

#ifndef MAINS_ABYTEST_H_
#define MAINS_ABYTEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../abycore/util/typedefs.h"
#include "../abycore/util/crypto/crypto.h"
#include "../abycore/aby/abyparty.h"
#include "../abycore/util/timer.h"
#include "../abycore/util/parse_options.h"
#include "../abycore/sharing/sharing.h"
#include "../examples/aes/common/aescircuit.h"
//#include "../examples/lowmc/common/lowmccircuit.h"

typedef struct {
	e_operation op;
	e_sharing sharing;
	string opname;

} test_ops_t;

bool run_tests(e_role role, char* address, seclvl seclvl, uint32_t bitlen, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, int32_t testop, bool verbose);

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nreps, uint32_t* secparam, string* address, uint16_t* port, int32_t* test_op,
		bool* verbose);

int32_t test_standard_ops(test_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t num_test_runs, uint32_t nops, bool verbose);

int32_t test_vector_ops(test_ops_t* test_ops, ABYParty* party, uint32_t nvals, uint32_t bitlen, uint32_t num_test_runs, uint32_t nops, bool verbose);

string get_op_name(e_operation op);

#endif /* MAINS_ABYTEST_H_ */
