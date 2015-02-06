/**
 \file 		abytest.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	________________
 \brief		ABYTest class implementation.
 */

#include "abytest.h"

static const test_ops_t test_all_ops[] = { { OP_IO, S_BOOL, "iobool" }, { OP_XOR, S_BOOL, "xorbool" }, { OP_AND, S_BOOL, "andbool" }, { OP_ADD, S_BOOL, "addbool" }, { OP_MUL,
		S_BOOL, "mulbool" }, { OP_CMP, S_BOOL, "cmpbool" }, { OP_EQ, S_BOOL, "eqbool" }, { OP_MUX, S_BOOL, "muxbool" }, { OP_SUB, S_BOOL, "subbool" }, { OP_IO, S_YAO, "ioyao" }, {
		OP_XOR, S_YAO, "xoryao" }, { OP_AND, S_YAO, "andyao" }, { OP_IO, S_ARITH, "ioarith" }, { OP_ADD, S_YAO, "addyao" }, { OP_MUL, S_YAO, "mulyao" },
		{ OP_CMP, S_YAO, "cmpyao" }, { OP_EQ, S_YAO, "eqyao" }, { OP_MUX, S_YAO, "muxyao" }, { OP_SUB, S_YAO, "subyao" }, { OP_ADD, S_ARITH, "addarith" }, { OP_MUL, S_ARITH,
				"mularith" }, { OP_Y2B, S_YAO, "y2b" }, { OP_B2A, S_BOOL, "b2a" }, { OP_B2Y, S_BOOL, "b2y" }, { OP_A2Y, S_ARITH, "a2y" }, { OP_AND_VEC, S_BOOL, "vec-and" } };

//static const test_ops_t test_single_op [] {{OP_ADD, S_BOOL, "distinct_op"}};

/*
 * List of failing tests:
 * 		- (currently empty)
 */
int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 65, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	bool verbose = false;
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port, &test_op, &verbose);

	seclvl seclvl = get_sec_lvl(secparam);

	run_tests(role, (char*) address.c_str(), seclvl, bitlen, nvals, nthreads, mt_alg, test_op, verbose);

	test_aes_circuit(role, (char*) address.c_str(), seclvl, nvals, nthreads, mt_alg, S_BOOL);
	test_aes_circuit(role, (char*) address.c_str(), seclvl, nvals, nthreads, mt_alg, S_YAO);

	//test_lowmc_circuit(role, (char*) address.c_str(), seclvl, nvals, nthreads, mt_alg, S_BOOL, (LowMCParams*) &stp);

	cout << "All tests successfully passed" << endl;

	return 0;
}

bool run_tests(e_role role, char* address, seclvl seclvl, uint32_t bitlen, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, int32_t test_op, bool verbose) {
	ABYParty* party = new ABYParty(role, address, seclvl, bitlen, nthreads, mt_alg);

	uint32_t num_test_runs = 5, nops;
	uint64_t seed = 0xAAAAAAAAAAAAAAAA;

	UGATE_T val;

	test_ops_t* test_ops;

	if (test_op > -1) {
		test_ops = new test_ops_t;
		assert(test_op < sizeof(test_all_ops) / sizeof(test_ops_t));
		test_ops->op = test_all_ops[test_op].op;
		test_ops->opname = test_all_ops[test_op].opname;
		test_ops->sharing = test_all_ops[test_op].sharing;
		nops = 1;
	} else {
		test_ops = (test_ops_t*) test_all_ops;
		nops = sizeof(test_all_ops) / sizeof(test_ops_t);
	}

	srand(seed);
	//srand(time(NULL));

	test_standard_ops(test_ops, party, bitlen, num_test_runs, nops, verbose);
	test_vector_ops(test_ops, party, bitlen, nvals, num_test_runs, nops, verbose);

	return true;
}

int32_t test_standard_ops(test_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t num_test_runs, uint32_t nops, bool verbose) {
	uint32_t a = 0, b = 0, c, verify, sa, sb, *avec, *bvec;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;

	for (uint32_t r = 0; r < num_test_runs; r++) {
		for (uint32_t i = 0; i < nops; i++) {
			Circuit* circ = sharings[test_ops[i].sharing]->GetCircuitBuildRoutine();
			a = (uint32_t) rand() % ((uint64_t) 1<<bitlen);
			b = (uint32_t) rand() % ((uint64_t) 1<<bitlen);

			shra = circ->PutINGate(1, a, bitlen, SERVER);
			shrb = circ->PutINGate(1, b, bitlen, CLIENT);

			switch (test_ops[i].op) {
			case OP_IO:
				shrres = shra;
				verify = a;
				break;
			case OP_ADD:
				shrres = circ->PutADDGate(shra, shrb);
				verify = a + b;
				break;
			case OP_SUB:
				shrres = circ->PutSUBGate(shra, shrb);
				verify = a - b;
				break;
			case OP_MUL:
				shrres = circ->PutMULGate(shra, shrb);
				verify = a * b;
				break;
			case OP_XOR:
				shrres = circ->PutXORGate(shra, shrb);
				verify = a ^ b;
				break;
			case OP_AND:
				shrres = circ->PutANDGate(shra, shrb);
				verify = a & b;
				break;
			case OP_CMP:
				shrres = circ->PutGEGate(shra, shrb);
				verify = a > b;
				break;
			case OP_EQ:
				shrres = circ->PutEQGate(shra, shrb);
				verify = a == b;
				break;
			case OP_MUX:
				sa = rand() % 2;
				sb = rand() % 2;
				shrsel = circ->PutXORGate(circ->PutINGate(1, sa, 1, SERVER), circ->PutINGate(1, sb, 1, CLIENT));
				shrres = circ->PutMUXGate(shra, shrb, shrsel);
				verify = sa ^ sb == 0 ? b : a;
				break;
			case OP_Y2B:
				shrres = circ->PutADDGate(shra, shrb);
				bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				shrres = bc->PutY2BGate(shrres);
				shrres = bc->PutMULGate(shrres, shrres);
				circ = bc;
				verify = (a + b) * (a + b);
				break;
			case OP_B2A:
				shrres = circ->PutADDGate(shra, shrb);
				ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				shrres = ac->PutB2AGate(shrres);
				shrres = ac->PutMULGate(shrres, shrres);
				circ = ac;
				verify = (a + b) * (a + b);
				break;
			case OP_B2Y:
				shrres = circ->PutADDGate(shra, shrb);
				yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				shrres = yc->PutB2YGate(shrres);
				shrres = yc->PutMULGate(shrres, shrres);
				circ = yc;
				verify = (a + b) * (a + b);
				break;
			case OP_A2Y:
				shrres = circ->PutMULGate(shra, shrb);
				yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				shrres = yc->PutA2YGate(shrres);
				shrres = yc->PutADDGate(shrres, shrres);
				circ = yc;
				verify = (a * b) + (a * b);
				break;
			case OP_AND_VEC:
				shra = circ->PutCombinerGate(shra);
				shrres = circ->PutANDVecGate(shra, shrb);
				shrres = circ->PutSplitterGate(shrres);
				verify = (b & 0x01) * a;
				break;
			default:
				shrres = circ->PutADDGate(shra, shrb);
				verify = a + b;
				break;
			}
			shrout = circ->PutOUTGate(shrres, ALL);

			if (!verbose)
				cout << "Running test no. " << i << " on operation " << test_ops[i].opname;
			cout << endl;
			party->ExecCircuit();

			c = shrout->get_clear_value<uint32_t>();
			if (!verbose)
				cout << ", values: a = " << a << ", b = " << b << ", c = " << c << ", verify = " << verify << endl;
			party->Reset();
			assert(verify == c);
		}
	}
	return 1;
}

int32_t test_vector_ops(test_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t nvals, uint32_t num_test_runs, uint32_t nops, bool verbose) {
	uint32_t *avec, *bvec, *cvec, *verifyvec, sa, sb;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;

	avec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	bvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	cvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	verifyvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));

	for (uint32_t r = 0; r < num_test_runs; r++) {
		for (uint32_t i = 0; i < nops; i++) {
			if (!verbose)
				cout << "Running test no. " << i << " on operation " << test_ops[i].opname << endl;

			Circuit* circ = sharings[test_ops[i].sharing]->GetCircuitBuildRoutine();

			for (uint32_t j = 0; j < nvals; j++) {
				avec[j] = (uint32_t) rand() % ((uint64_t) 1<<bitlen);;
				bvec[j] = (uint32_t) rand() % ((uint64_t) 1<<bitlen);;
			}
			shra = circ->PutINGate(nvals, avec, bitlen, SERVER);
			shrb = circ->PutINGate(nvals, bvec, bitlen, CLIENT);

			switch (test_ops[i].op) {
			case OP_IO:
				shrres = shra;
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j];
				break;
			case OP_ADD:
				shrres = circ->PutADDGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] + bvec[j];
				break;
			case OP_SUB:
				shrres = circ->PutSUBGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] - bvec[j];
				break;
			case OP_MUL:
				shrres = circ->PutMULGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] * bvec[j];
				break;
			case OP_XOR:
				shrres = circ->PutXORGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] ^ bvec[j];
				break;
			case OP_AND:
				shrres = circ->PutANDGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] & bvec[j];
				break;
			case OP_CMP:
				shrres = circ->PutGEGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] > bvec[j];
				break;
			case OP_EQ:
				shrres = circ->PutEQGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] == bvec[j];
				break;
				/*case OP_MUX:
				 sa = rand() %2;
				 sb = rand() %2;
				 shrsel = circ->PutXORGate(circ->PutINGate(1, sa, 1, SERVER), circ->PutINGate(1, sb, 1, CLIENT));
				 shrres = circ->PutMUXGate(shra, shrb, shrsel);
				 verify = sa ^ sb == 0 ? b : a;
				 break;
				 case OP_Y2B:
				 shrres = circ->PutADDGate(shra, shrb);
				 bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				 shrres = bc->PutY2BGate(shrres);
				 shrres = bc->PutMULGate(shrres, shrres);
				 circ = bc;
				 verify = (a + b) * (a + b);
				 break;
				 case OP_B2A:
				 shrres = circ->PutADDGate(shra, shrb);
				 ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				 shrres = ac->PutB2AGate(shrres);
				 shrres = ac->PutMULGate(shrres, shrres);
				 circ = ac;
				 verify = (a + b) * (a + b);
				 break;
				 case OP_B2Y:
				 shrres = circ->PutADDGate(shra, shrb);
				 yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				 shrres = yc->PutB2YGate(shrres);
				 shrres = yc->PutMULGate(shrres, shrres);
				 circ = yc;
				 verify = (a + b) * (a + b);
				 break;
				 case OP_A2Y:
				 shrres = circ->PutMULGate(shra, shrb);
				 yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				 shrres = yc->PutA2YGate(shrres);
				 shrres = yc->PutADDGate(shrres, shrres);
				 circ = yc;
				 verify = (a*b) + (a*b);
				 break;
				 case OP_AND_VEC:
				 shra = circ->PutCombinerGate(shra);
				 //shrb = circ->PutCombinerGate(shrb);
				 shrres = circ->PutANDVecGate(shra, shrb);
				 //shrres = circ->PutANDGate(shra, shrb);
				 shrres = circ->PutSplitterGate(shrres);
				 verify = (b&0x01) * a;
				 break;*/
			default:
				shrres = circ->PutADDGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] + bvec[j];
				break;
			}
			shrout = circ->PutOUTGate(shrres, ALL);

			party->ExecCircuit();

			//cout << "Size of output: " << shrout->size() << endl;
			shrout->get_clear_value_vec(&cvec);

			party->Reset();
			for (uint32_t j = 0; j < nvals; j++) {
				if (!verbose)
					cout << "\tvalues[" << j << "]: a = " << avec[j] << ", b = " << bvec[j] << ", c = " << cvec[j] << ", verify = " << verifyvec[j] << endl;

				assert(verifyvec[j] == cvec[j]);
			}
		}
	}
	return 1;

}

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, string* address, uint16_t* port, int32_t* test_op,
		bool* verbose) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false }, { (void*) nvals, T_NUM, 'n', "Number of parallel operations elements", false, false }, {
			(void*) bitlen, T_NUM, 'b', "Bit-length, default 32", false, false }, { (void*) secparam, T_NUM, 's', "Symmetric Security Bits, default: 128", false, false }, {
			(void*) address, T_STR, 'a', "IP-address, default: localhost", false, false }, { (void*) &int_port, T_NUM, 'p', "Port, default: 7766", false, false }, {
			(void*) test_op, T_NUM, 't', "Single test (leave out for all operations), default: off", false, false }, { (void*) verbose, T_FLAG, 'v',
			"Do not print computation results, default: off", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return 1;
}

string get_op_name(e_operation op) {
	switch (op) {
	case OP_XOR:
		return "XOR";
	case OP_AND:
		return "AND";
	case OP_ADD:
		return "ADD";
	case OP_AND_VEC:
		return "AND_VEC";
	case OP_SUB:
		return "SUB";
	case OP_MUL:
		return "MUL";
	case OP_MUL_VEC:
		return "MUL_VEC";
	case OP_CMP:
		return "CMP";
	case OP_EQ:
		return "EQ";
	case OP_MUX:
		return "MUX";
	case OP_IN:
		return "IN";
	case OP_OUT:
		return "OUT";
	case OP_INV:
		return "INV";
	case OP_CONSTANT:
		return "CONS";
	case OP_CONV:
		return "CONV";
	case OP_A2Y:
		return "A2Y";
	case OP_B2A:
		return "B2A";
	case OP_B2Y:
		return "B2Y";
	case OP_Y2B:
		return "Y2B";
	case OP_COMBINE:
		return "CMB";
	case OP_SPLIT:
		return "SPL";
	case OP_REPEAT:
		return "REP";
	case OP_PERM:
		return "PERM";
	case OP_COMBINEPOS:
		return "CMBP";
	default:
		return "NN";
	}
}

