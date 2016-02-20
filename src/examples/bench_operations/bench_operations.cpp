/**
 \file 		bench_operations.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
 Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published
 by the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.
 You should have received a copy of the GNU Affero General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Benchmark Primitive Operations
 */

//Utility libs
#include "../../abycore/util/crypto/crypto.h"
#include "../../abycore/util/parse_options.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"

static const uint32_t m_vBitLens[] = {8, 16, 32, 64};

static const aby_ops_t m_tBenchOps[] = { { OP_XOR, S_BOOL, "xorbool" }, { OP_AND, S_BOOL, "andbool" }, { OP_ADD, S_BOOL, "addbool" }, { OP_MUL,
		S_BOOL, "mulbool" }, { OP_CMP, S_BOOL, "cmpbool" }, { OP_EQ, S_BOOL, "eqbool" }, { OP_MUX, S_BOOL, "muxbool" }, {OP_XOR, S_YAO, "xoryao" },
		{ OP_AND, S_YAO, "andyao" }, { OP_ADD, S_YAO, "addyao" }, { OP_MUL, S_YAO, "mulyao" }, { OP_CMP, S_YAO, "cmpyao" }, { OP_EQ, S_YAO, "eqyao" },
		{ OP_MUX, S_YAO, "muxyao" }, { OP_ADD, S_ARITH, "addarith" }, { OP_MUL, S_ARITH, "mularith" }, { OP_Y2B, S_YAO, "y2b" }, { OP_B2A, S_BOOL, "b2a" },
		{ OP_B2Y, S_BOOL, "b2y" }, { OP_A2Y, S_ARITH, "a2y" } };

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, int32_t* bitlen, uint32_t* secparam,
		string* address, uint16_t* port, int32_t* operation, bool* verbose, uint32_t* nops, uint32_t* nruns, bool* no_verify) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;
	bool oplist = false;
	bool success = false;

	parsing_ctx options[] = {
			{ (void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false },
			{ (void*) bitlen, T_NUM, 'b', "Bit-length of operations, default {8,16,32,64}", false, false },
			{ (void*) secparam, T_NUM, 's',	"Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, 'a', "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, 'p', "Port, default: 7766",	false, false },
			{ (void*) operation, T_NUM, 'o', "Test operation with id (leave out for all operations; for list of IDs use -l), default: all", false, false },
			{ (void*) nruns, T_NUM, 'i', "Number of iterations of tests, default: 1",	false, false },
			{ (void*) verbose, T_FLAG, 'v', "Verbose (silent benchmarks, only timings), default: off",	false, false },
			{ (void*) &oplist, T_FLAG, 'l', "List the IDs of operations",	false, false },
			{ (void*) no_verify, T_FLAG, 't', "No output verification (default: false)",	false, false },
			{ (void*) nops, T_NUM, 'n', "Number of parallel operations, default: 1", false, false }};

	success = parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx));

	if(oplist) {
		cout << "Operations with IDs: " << endl;
		for(uint32_t i = 0; i < sizeof(m_tBenchOps)/sizeof(aby_ops_t); i++) {
			cout << "Operation " << i << ": " << m_tBenchOps[i].opname << endl;
		}
		exit(0);
	}

	if (!success) {
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

	assert(*bitlen <= 64);

	return 1;
}




int32_t bench_operations(aby_ops_t* bench_ops, uint32_t nops, ABYParty* party, uint32_t* bitlens,
		uint32_t nbitlens, uint32_t nvals, uint32_t nruns, e_role role, bool verbose, bool no_verify) {
	uint64_t *avec, *bvec, *cvec, *verifyvec, typebitmask = 0;
	uint32_t tmpbitlen, tmpnvals;
	uint8_t *sa, *sb;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;
	double op_time;

	avec = (uint64_t*) malloc(nvals * sizeof(uint64_t));
	bvec = (uint64_t*) malloc(nvals * sizeof(uint64_t));
	cvec = (uint64_t*) malloc(nvals * sizeof(uint64_t));

	verifyvec = (uint64_t*) malloc(nvals * sizeof(uint64_t));

	bc = sharings[0]->GetCircuitBuildRoutine();
	yc = sharings[1]->GetCircuitBuildRoutine();
	ac = sharings[2]->GetCircuitBuildRoutine();

	if (!verbose) {
		cout << "Base OTs:\t";
	}
	cout << party->GetTiming(P_BASE_OT) << endl;
	if (!verbose) {
		cout << "Op\t";
		for(uint32_t b = 0; b < nbitlens; b++) {
			cout << bitlens[b] << "-bit \t";
		}
		cout << endl;
		cout << "-----------------------------------------------" << endl;
	}

	for (uint32_t i = 0; i < nops; i++) {
		if (!verbose)
			cout << bench_ops[i].opname << "\t";
		for (uint32_t b = 0; b < nbitlens; b++) {
			uint32_t bitlen = bitlens[b];
			op_time = 0;
			typebitmask = 0;

			sa = (uint8_t*) malloc(max(nvals, bitlen));
			sb = (uint8_t*) malloc(max(nvals, bitlen));

			if(PadToMultiple(bitlen, 8) != bitlen) {
				typebitmask = (1<<bitlen)-1;
			} else {
				memset(&typebitmask, 0xFF, ceil_divide(bitlen, 8));
			}


			for (uint32_t r = 0; r < nruns; r++) {
				//if (!verbose)
				//	cout << "Running benchmark no. " << i << " on operation " << bench_ops[i].opname <<
				//	" on " << bitlen << " bit-length and mask = " << typebitmask << endl;

				Circuit* circ = sharings[bench_ops[i].sharing]->GetCircuitBuildRoutine();

				for (uint32_t j = 0; j < nvals; j++) {
					avec[j] = (((uint64_t) rand()<<(sizeof(uint32_t)*8)) + rand()) & typebitmask;
					bvec[j] = (((uint64_t) rand()<<(sizeof(uint32_t)*8)) + rand()) & typebitmask;
				}
				shra = circ->PutSIMDINGate(nvals, avec, bitlen, SERVER);
				shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);
				shra->set_max_size(bitlen);
				shrb->set_max_size(bitlen);

				switch (bench_ops[i].op) {
				case OP_ADD:
					shrres = circ->PutADDGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = (avec[j] + bvec[j]) & typebitmask;
					break;
				case OP_SUB:
					shrres = circ->PutSUBGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = (avec[j] - bvec[j]) & typebitmask;
					break;
				case OP_MUL:
					shrres = circ->PutMULGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = (avec[j] * bvec[j]) & typebitmask;
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
				case OP_Y2B:
					shrres = circ->PutXORGate(shra, shrb);
					circ = bc;
					shrres = circ->PutY2BGate(shrres);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] ^ bvec[j];
					break;
				case OP_B2A:
					shrres = circ->PutXORGate(shra, shrb);
					circ = ac;
					shrres = circ->PutB2AGate(shrres);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] ^ bvec[j];
					break;
				case OP_B2Y:
					shrres = circ->PutXORGate(shra, shrb);
					circ = yc;
					shrres = circ->PutB2YGate(shrres);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] ^ bvec[j];
					break;
				case OP_A2Y:
					shrres = circ->PutADDGate(shra, shrb);
					circ = yc;
					shrres = circ->PutA2YGate(shrres);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = (avec[j] + bvec[j]) & typebitmask;
					break;
				default:
					shrres = circ->PutADDGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] + bvec[j];
					break;
				}
				shrout = circ->PutOUTGate(shrres, ALL);

				party->ExecCircuit();

				//cout << "Size of output: " << shrout->size() << endl;
				shrout->get_clear_value_vec(&cvec, &tmpbitlen, &tmpnvals);

				party->Reset();

				op_time += party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);

				if(!no_verify) {
					//cout << "Running verify" << endl;

					assert(tmpnvals == nvals);

					for (uint32_t j = 0; j < nvals; j++) {
						if(verifyvec[j] != (cvec[j]&typebitmask)) {
							cout << "Error: " << endl;
							cout << "\t" << get_role_name(role) << " " << bench_ops[i].opname << ": values[" << j <<
							"]: a = " << avec[j] <<	", b = " << bvec[j] << ", c = " << (cvec[j]&typebitmask) << ", verify = " <<
							verifyvec[j] << endl;

							assert(verifyvec[j] == (cvec[j]&typebitmask));
						}
					}
				}
			}
			free(sa);
			free(sb);
			cout << op_time/nruns << "\t";
		}
		cout << endl;

	}

	free(avec);
	free(bvec);
	free(cvec);
	free(verifyvec);

	return 1;
}


bool run_bench(e_role role, char* address, seclvl seclvl, int32_t operation, int32_t bitlen, uint32_t nvals,
		uint32_t nruns, e_mt_gen_alg mt_alg, bool verbose, bool no_verify) {
	uint32_t nthreads = 1;

	uint32_t nops, nbitlens;
	uint64_t seed = 0xAAAAAAAAAAAAAAAA;

	UGATE_T val;

	aby_ops_t* op;

	ABYParty* party;


	if (operation > -1) {
		op = new aby_ops_t;
		assert(operation < sizeof(m_tBenchOps) / sizeof(aby_ops_t));
		op->op = m_tBenchOps[operation].op;
		op->opname = m_tBenchOps[operation].opname;
		op->sharing = m_tBenchOps[operation].sharing;
		nops = 1;
	} else {
		op = (aby_ops_t*) m_tBenchOps;
		nops = sizeof(m_tBenchOps) / sizeof(aby_ops_t);
	}

	uint32_t* bitlens;

	if (bitlen > -1) {
		bitlens = (uint32_t*) malloc(sizeof(uint32_t));
		bitlens[0] = bitlen;
		nbitlens = 1;
		party =  new ABYParty(role, address, seclvl, bitlen, nthreads, mt_alg);
	} else {
		bitlens = (uint32_t*) m_vBitLens;
		nbitlens = sizeof(m_vBitLens) / sizeof(uint32_t);
		party =  new ABYParty(role, address, seclvl, 64, nthreads, mt_alg);
	}

	srand(seed);

	bench_operations(op, nops, party, bitlens, nbitlens, nvals, nruns, role, verbose, no_verify);

	delete party;

	return true;
}



int main(int argc, char** argv) {
	e_role role;
	uint32_t secparam = 128, nvals = 1, nruns = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	int32_t operation = -1, bitlen = -1;
	bool verbose = false;
	bool no_verify = false;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &secparam, &address, &port, &operation, &verbose, &nvals, &nruns, &no_verify);

	seclvl seclvl = get_sec_lvl(secparam);

	run_bench(role, (char*) address.c_str(), seclvl, operation, bitlen, nvals, nruns, mt_alg, verbose, no_verify);

	return 0;
}
