/**
 \file 		abytest.cpp
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
 \brief		ABYTest class implementation.
 */

#include "abytest.h"


static const uint32_t TTSIZE = 16;
static const uint32_t TRUTH_TABLE[TTSIZE][4]={{0,0,0,0}, {1,0,0,0}, {0,1,0,0}, {1,1,0,0},
		{0,0,1,0}, {1,0,1,0}, {0,1,1,0}, {1,1,1,0},
		{0,0,0,1}, {1,0,0,1}, {0,1,0,1}, {1,1,0,1},
		{0,0,1,1}, {1,0,1,1}, {0,1,1,1}, {1,1,1,1},
};

//static const aby_ops_t test_single_op [] {{OP_ADD, S_BOOL, "distinct_op"}};

/*
 * List of failing tests:
 * 		- (currently empty)
 */
int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 65, secparam = 128, nthreads = 1, nelements=1024;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	bool quiet = false;
	bool randomseed = false;
	bool ignore_verification = false;
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	uint32_t num_test_runs = 2;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port, &test_op, &num_test_runs, &mt_alg, &quiet, &ignore_verification, &randomseed);

	// FIXME: fix verification for different bitlengths
	if (!ignore_verification && bitlen != 32){
		bitlen = 32;
		std::cerr << "Verification currenlty only works for 32-bit values. Changing bitlen to 32." << std::endl;
	}

	seclvl seclvl = get_sec_lvl(secparam);

	run_tests(role, (char*) address.c_str(), port, seclvl, bitlen, nvals, nthreads, mt_alg, test_op, num_test_runs, quiet, ignore_verification, randomseed);

	if (test_op == -1) {
		//Test the AES circuit
		std::cout << "Testing AES circuit in Boolean sharing" << std::endl;
		test_aes_circuit(role, (char*) address.c_str(), port, seclvl, nvals, nthreads, mt_alg, S_BOOL);
		std::cout << "Testing AES circuit in Yao sharing" << std::endl;
		test_aes_circuit(role, (char*) address.c_str(), port, seclvl, nvals, nthreads, mt_alg, S_YAO);
		std::cout << "Testing AES circuit in Yao sharing, key expansion during SFE and client only input" << std::endl;
		test_aes_circuit(role, (char*) address.c_str(), port, seclvl, nvals, nthreads, mt_alg, S_YAO, false, true, true);
		//	std::cout << "Testing AES circuit in Setup-LUT sharing" << std::endl;
		//	test_aes_circuit(role, (char*) address.c_str(), port, seclvl, nvals, nthreads, mt_alg, S_SPLUT);

		//Test the SHA1 circuit TODO: Constant gates are limited to nvals < 64. Fix!
		std::cout << "Testing SHA1 circuit in Boolean sharing" << std::endl;
		test_sha1_circuit(role, (char*) address.c_str(), port, seclvl, 63, nthreads, mt_alg, S_BOOL);
		std::cout << "Testing SHA1 circuit in Yao sharing" << std::endl;
		test_sha1_circuit(role, (char*) address.c_str(), port, seclvl, 63, nthreads, mt_alg, S_YAO);
		//std::cout << "Testing SHA1 circuit in Setup-LUT sharing" << std::endl;
		//test_sha1_circuit(role, (char*) address.c_str(), seclvl, 63, nthreads, mt_alg, S_SPLUT);

		//Test the Sort-Compare-Shuffle PSI circuit
		std::cout << "Testing SCS PSI circuit in Boolean sharing" << std::endl;
		test_psi_scs_circuit(role, (char*) address.c_str(), port, seclvl, nelements, bitlen, nthreads, mt_alg, 0, true);
		std::cout << "Testing SCS PSI circuit in Yao sharing" << std::endl;
		test_psi_scs_circuit(role, (char*) address.c_str(), port, seclvl, nelements, bitlen, nthreads, mt_alg, 1, true);
		//std::cout << "Testing SCS PSI circuit in Setup-LUT sharing" << std::endl;
		//test_psi_scs_circuit(role, (char*) address.c_str(), seclvl, nelements, bitlen,	nthreads, mt_alg, S_SPLUT);

		//Test the Phasing PSI circuit
		// std::cout << "Testing PSI Phasing circuit in Boolean sharing" << std::endl;
		// test_phasing_circuit(role, (char*) address.c_str(), port, seclvl, nelements, nelements, bitlen, epsilon, nthreads, mt_alg,
		// 		S_BOOL, 1, 0, 3);
		// std::cout << "Testing PSI Phasing circuit in Yao sharing" << std::endl;
		// test_phasing_circuit(role, (char*) address.c_str(), port, seclvl, nelements, nelements, bitlen, epsilon, nthreads, mt_alg,
		// 		S_YAO, 1, 0, 3);
		//	std::cout << "Testing PSI Phasing circuit in Setup-LUT sharing" << std::endl;
		//	test_phasing_circuit(role, (char*) address.c_str(), port, seclvl, nelements, nelements, bitlen,	epsilon, nthreads, mt_alg, S_SPLUT, 1, 0, 3);

		//test_lowmc_circuit(role, (char*) address.c_str(), seclvl, nvals, nthreads, mt_alg, S_BOOL, (LowMCParams*) &stp);

		//test_min_eucliden_dist_circuit(role, (char*) address.c_str(), seclvl, nvals, 6, nthreads, mt_alg, S_ARITH, S_YAO);
	}


	std::cout << "All tests successfully passed." << std::endl;

	return EXIT_SUCCESS;
}

bool run_tests(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nvals, uint32_t nthreads,
		e_mt_gen_alg mt_alg, int32_t test_op, uint32_t num_test_runs, bool quiet, bool ignore_verification, bool randomseed) {
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);

	uint32_t nops;

	aby_ops_t* test_ops;

	if (test_op > -1) {
		test_ops = new aby_ops_t;
		assert(static_cast<uint32_t>(test_op) < sizeof(m_tAllOps) / sizeof(aby_ops_t));
		test_ops->op = m_tAllOps[test_op].op;
		test_ops->opname = m_tAllOps[test_op].opname;
		test_ops->sharing = m_tAllOps[test_op].sharing;
		nops = 1;
	} else {
		test_ops = (aby_ops_t*) m_tAllOps;
		nops = sizeof(m_tAllOps) / sizeof(aby_ops_t);
	}

	if (randomseed) {
		//uses current second as seed. not very secure, but random values for every run
		srand(time(NULL));
	} else {
		//uses fixed seed, so two distinct machines will end up with the same randomness, so tests can be verified.
		uint64_t seed = 0xC0FFEE23DEADBEEF;
		srand(seed);
	}

	test_standard_ops(test_ops, party, bitlen, num_test_runs, nops, role, quiet, ignore_verification);
	test_vector_ops(test_ops, party, bitlen, nvals, num_test_runs, nops, role, quiet, ignore_verification);

	delete party;
	if (test_ops != m_tAllOps)
		delete test_ops;

	return true;
}

int32_t test_standard_ops(aby_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t num_test_runs, uint32_t nops,
		e_role role, bool quiet, bool ignore_verification) {
	uint32_t a = 0, b = 0, c, verify, sa, sb, sc, xbit, ybit, op;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	share **shrres_vec;
	vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;

	if (quiet) {std::cout << "Running operation test quietly."<< std::endl;}

	for (uint32_t r = 0; r < num_test_runs; r++) {
		for (uint32_t i = 0; i < nops; i++) {
			Circuit* circ = sharings[test_ops[i].sharing]->GetCircuitBuildRoutine();
			a = (uint32_t) rand() % ((uint64_t) 1<<bitlen);
			b = (uint32_t) rand() % ((uint64_t) 1<<bitlen);

			shra = circ->PutINGate(a, bitlen, SERVER);
			shrb = circ->PutINGate(b, bitlen, CLIENT);

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
				shrres = circ->PutGTGate(shra, shrb);
				verify = a > b;
				break;
			case OP_EQ:
				shrres = circ->PutEQGate(shra, shrb);
				verify = a == b;
				break;
			case OP_MUX:
				sa = rand() % 2;
				sb = rand() % 2;
				shrsel = circ->PutXORGate(circ->PutINGate(sa, 1, SERVER), circ->PutINGate(sb, 1, CLIENT));
				shrres = circ->PutMUXGate(shra, shrb, shrsel);
				verify = (sa ^ sb) == 0 ? b : a;
				break;
			case OP_X:
				sa = rand() % 2;
				sb = rand() % 2;
				shrsel = circ->PutXORGate(circ->PutINGate(sa, 1, SERVER), circ->PutINGate(sb, 1, CLIENT));
				shrres_vec = circ->PutCondSwapGate(shra, shrb, shrsel, false);
				sc = rand() % 2;
				shrres = shrres_vec[sc];
				if(sc == 1){
					verify = (sa ^ sb) == 0 ? b : a;
				}
				else{
					verify = (sa ^ sb) == 0 ? a : b;
				}
				break;
			case OP_UNIV:
				op = rand() % TTSIZE;
				shrres = circ->PutUniversalGate(shra, shrb, op);
				verify = 0;
				for(uint32_t j = 0; j < bitlen; j++) {
					xbit = (a>>j) & 0x01;
					ybit = (b>>j) & 0x01;
					verify |= ((TRUTH_TABLE[op][(xbit << 1) | ybit]) << j);
				}
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
			case OP_A2B:
				shrres = circ->PutADDGate(shra, shrb);
				bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				shrres = bc->PutA2BGate(shrres, sharings[S_YAO]->GetCircuitBuildRoutine());
				shrres = bc->PutMULGate(shrres, shrres);
				circ = bc;
				verify = (a + b) * (a + b);
				break;
			case OP_Y2A:
				shrres = circ->PutMULGate(shra, shrb);
				ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				shrres = ac->PutY2AGate(shrres, sharings[S_BOOL]->GetCircuitBuildRoutine());
				shrres = ac->PutADDGate(shrres, shrres);
				circ = ac;
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

			if (!quiet){
				std::cout << "Running test no. " << i << " on operation " << test_ops[i].opname << std::endl;
			}

			party->ExecCircuit();

			c = shrout->get_clear_value<uint32_t>();
			if (!quiet){
				std::cout << get_role_name(role) << " " << test_ops[i].opname << ": values: a = " <<
				a << ", b = " << b << ", c = " << c << ", verify = " << verify << std::endl;
			}
			party->Reset();

			if (!ignore_verification) {
				if (verify != c) {
					std::cerr << "ERROR in test verification! " << std::endl;
					std::cerr << get_role_name(role) << " " << test_ops[i].opname << ": values: a = " << a
							  << ", b = " << b << ", c = " << c << ", verify = " << verify << std::endl;
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	return EXIT_SUCCESS;
}

int32_t test_vector_ops(aby_ops_t* test_ops, ABYParty* party, uint32_t bitlen, uint32_t nvals, uint32_t num_test_runs,
		uint32_t nops, e_role role, bool quiet, bool ignore_verification) {
	uint32_t *avec, *bvec, *cvec, *verifyvec, tmpbitlen, tmpnvals, sc, op, xbit, ybit;
	uint8_t *sa, *sb;
	uint32_t nvals_orig = nvals;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	share **shrres_vec;
	vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;

	sa = (uint8_t*) malloc(max(nvals, bitlen));
	sb = (uint8_t*) malloc(max(nvals, bitlen));

	avec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	bvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	cvec = nullptr;

	verifyvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));


	for (uint32_t r = 0; r < num_test_runs; r++) {
		for (uint32_t i = 0; i < nops; i++) {
			if (!quiet)
				std::cout << "Running vector test no. " << i << " on operation " << test_ops[i].opname << std::endl;

			if(test_ops[i].op == OP_UNIV && nvals > 32) {
				nvals = 32; //max nvals for universal gates
			}
			else {
				nvals = nvals_orig;
			}

			Circuit* circ = sharings[test_ops[i].sharing]->GetCircuitBuildRoutine();

			for (uint32_t j = 0; j < nvals; j++) {
				avec[j] = (uint32_t) rand() % ((uint64_t) 1<<bitlen);;
				bvec[j] = (uint32_t) rand() % ((uint64_t) 1<<bitlen);;
			}
			shra = circ->PutSIMDINGate(nvals, avec, bitlen, SERVER);
			shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);

			/*shra = circ->PutSIMDINGate(ceil_divide(nvals,2), avec, bitlen, SERVER);
			shrb = circ->PutSIMDINGate(nvals/2, avec+ceil_divide(nvals,2), bitlen, SERVER);

			//share* tmp = create_new_share(nvals, circ, circ->GetCircuitType());
			share* tmp;
			if(circ->GetCircuitType() == C_BOOLEAN) {
				tmp = new boolshare(2, circ);
				std::cout << "Boolean, max share len = " << tmp->max_size() << std::endl;
			}
			else {
				tmp = new arithshare(2, circ);
				std::cout << "Arithmetic" << std::endl;
			}

			for(uint32_t j = 0; j < bitlen; j++) {
				tmp->set_wire(0, shra->get_wire(j));
				tmp->set_wire(1, shrb->get_wire(j));

				shra->set_wire(j, circ->PutCombinerGate(tmp)->get_wire(0));

			}

			shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);*/

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
				shrres = circ->PutGTGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] > bvec[j];
				break;
			case OP_EQ:
				shrres = circ->PutEQGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] == bvec[j];
				break;
			case OP_MUX:
				for(uint32_t j = 0; j < nvals; j++) {
					 sa[j] = (uint8_t) (rand() & 0x01);
					 sb[j] = (uint8_t) (rand() & 0x01);
				}
				shrsel = circ->PutXORGate(circ->PutSIMDINGate(nvals, sa, 1, SERVER), circ->PutSIMDINGate(nvals, sb, 1, CLIENT));
				shrres = circ->PutMUXGate(shra, shrb, shrsel);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? bvec[j] : avec[j];
				break;
			case OP_X:
				for(uint32_t j = 0; j < nvals; j++) {
					sa[j] = (uint8_t) (rand() & 0x01);
					sb[j] = (uint8_t) (rand() & 0x01);
				}
				shrsel = circ->PutXORGate(circ->PutSIMDINGate(nvals, sa, 1, SERVER), circ->PutSIMDINGate(nvals, sb, 1, CLIENT));
				shrres_vec = circ->PutCondSwapGate(shra, shrb, shrsel, true);
				sc = rand() % 2;
				shrres = shrres_vec[sc];
				for (uint32_t j = 0; j < nvals; j++){
					if(sc == 1){
						verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? bvec[j] : avec[j];
					}
					else{
						verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? avec[j] : bvec[j];
					}
				}
				break;
			case OP_UNIV:
				op = rand() % TTSIZE;
				shrres = circ->PutUniversalGate(shra, shrb, op);
				for (uint32_t j = 0; j < nvals; j++){
					verifyvec[j] = 0;
					for(uint32_t k = 0; k < bitlen; k++){
						xbit = (avec[j]>>k) & 0x01;
						ybit = (bvec[j]>>k) & 0x01;
						verifyvec[j] |= ((TRUTH_TABLE[op][(xbit << 1) | ybit]) << k);
					}
				}
				break;
			 /*case OP_AND_VEC:
				for(uint32_t j = 0; j < bitlen; j++) {
					 sa[j] = (uint8_t) (rand() & 0x01);
					 sb[j] = (uint8_t) (rand() & 0x01);
				}
				shrsel = circ->PutXORGate(circ->PutINGate(1, sa, bitlen, SERVER), circ->PutINGate(1, sb, bitlen, CLIENT));
				shrres = circ->PutXORGate(shra, shrb);
				shrres = circ->PutANDVecGate(shra, shrsel);
				//shrres = circ->PutMUXGate(shra, shrb, shrsel);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? 0: avec[j]^bvec[j];
				break;

			 break;*/
			 case OP_Y2B:
				 shrres = circ->PutADDGate(shra, shrb);
				 bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				 shrres = bc->PutY2BGate(shrres);
				 shrres = bc->PutMULGate(shrres, shrres);
				 circ = bc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
				 break;
			case OP_B2A:
				 shrres = circ->PutADDGate(shra, shrb);
				 ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				 shrres = ac->PutB2AGate(shrres);
				 shrres = ac->PutMULGate(shrres, shrres);
				 circ = ac;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
				 break;
			case OP_B2Y:
				 shrres = circ->PutADDGate(shra, shrb);
				 yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				 shrres = yc->PutB2YGate(shrres);
				 shrres = yc->PutMULGate(shrres, shrres);
				 circ = yc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
				 break;
			case OP_A2Y:
				 shrres = circ->PutMULGate(shra, shrb);
				 yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				 shrres = yc->PutA2YGate(shrres);
				 shrres = yc->PutADDGate(shrres, shrres);
				 circ = yc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] * bvec[j]) + (avec[j] * bvec[j]);
				 break;
			case OP_A2B:
				 shrres = circ->PutMULGate(shra, shrb);
				 bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				 shrres = bc->PutA2BGate(shrres, sharings[S_YAO]->GetCircuitBuildRoutine());
				 shrres = bc->PutADDGate(shrres, shrres);
				 circ = bc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] * bvec[j]) + (avec[j] * bvec[j]);
				 break;
			case OP_Y2A:
				 shrres = circ->PutMULGate(shra, shrb);
				 ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				 shrres = ac->PutY2AGate(shrres, sharings[S_BOOL]->GetCircuitBuildRoutine());
				 shrres = ac->PutADDGate(shrres, shrres);
				 circ = ac;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] * bvec[j]) + (avec[j] * bvec[j]);
				 break;
			/*case OP_AND_VEC:
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

			//std::cout << "Size of output: " << shrout->size() << std::endl;

			// this allocates buffer put into cvec with calloc
			shrout->get_clear_value_vec(&cvec, &tmpbitlen, &tmpnvals);

			if(!ignore_verification){
				assert(tmpnvals == nvals);
			}

			party->Reset();
			for (uint32_t j = 0; j < nvals; j++) {
				if (!quiet){
					std::cout << "\t" << get_role_name(role) << " " << test_ops[i].opname << ": values[" << j <<
					"]: a = " << avec[j] <<	", b = " << bvec[j] << ", c = " << cvec[j] << ", verify = " <<
					verifyvec[j] << std::endl;
					}
				if(!ignore_verification){
					if(verifyvec[j] != cvec[j]){
						std::cerr << "ERROR in test verification! " << std::endl;
						std::cerr << "\t" << get_role_name(role) << " " << test_ops[i].opname << ": values[" << j <<
					"]: a = " << avec[j] <<	", b = " << bvec[j] << ", c = " << cvec[j] << ", verify = " <<
					verifyvec[j] << std::endl;
					exit(EXIT_FAILURE);
					}
				}

			}
			std::free(cvec);
		}
	}

	std::free(sa);
	std::free(sb);
	std::free(avec);
	std::free(bvec);
	std::free(verifyvec);

	return EXIT_SUCCESS;

}

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam,
		string* address, uint16_t* port, int32_t* test_op, uint32_t* num_test_runs, e_mt_gen_alg *mt_alg, bool* quiet, bool* ignore_verification, bool* randomseed) {

	uint32_t int_role = 0, int_port = 0, int_mtalg = 0;

	parsing_ctx options[] = {
	{ (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
	{ (void*) nvals, T_NUM, "n", "Number of parallel operations elements", false, false },
	{ (void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
	{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
	{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
	{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
	{ (void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false },
	{ (void*) quiet, T_FLAG, "q", "Do not print computation results, default: off", false, false },
	{ (void*) ignore_verification, T_FLAG, "v", "Do not abort on failed verification, default: off", false, false },
	{ (void*) randomseed, T_FLAG, "R", "Use random seed (likely breaks verification when not on localhost), default: off", false, false },
	{ (void*) num_test_runs, T_NUM, "i", "Number of test runs for operation tests, default: 5", false, false },
	{ (void*) &int_mtalg, T_NUM, "m", "Arithmetic MT gen algo [0: OT, 1: Paillier, 2: DGK], default: 0", false, false }
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

	assert(int_mtalg < MT_LAST);
	*mt_alg = (e_mt_gen_alg) int_mtalg;

	//delete options;

	return EXIT_SUCCESS;
}
