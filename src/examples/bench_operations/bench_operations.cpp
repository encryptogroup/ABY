/**
 \file 		bench_operations.cpp
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
 \brief		Benchmark Primitive Operations
 */

//Utility libs
#include "../../abycore/sharing/sharing.h"
#include "../../abycore/circuit/booleancircuits.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../aes/common/aescircuit.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"
#include <cstring>

static const uint32_t m_vBitLens[] = {1, 8, 16, 32, 64};

static const aby_ops_t m_tBenchOps[] = {
	{ OP_XOR, S_BOOL, "xorbool" },
	{ OP_AND, S_BOOL, "andbool" },
	{ OP_ADD, S_BOOL, "addsobool" },
	{ OP_ADD, S_BOOL, "adddobool" },

	{ OP_ADD, S_BOOL, "adddovecbool" },
	{ OP_MUL, S_BOOL, "mulsobool" },
	{ OP_MUL, S_BOOL, "muldobool" },
	{ OP_MUL, S_BOOL, "mulsovecbool" },
	{ OP_MUL, S_BOOL, "muldovecbool" },

	{ OP_CMP, S_BOOL, "cmpsobool" },
	{ OP_CMP, S_BOOL, "cmpdobool" },
	{ OP_EQ, S_BOOL, "eqbool" },
	{ OP_MUX, S_BOOL, "muxbool" },
	{ OP_MUX, S_BOOL, "muxvecbool" },
	{ OP_INV, S_BOOL, "invbool" },

	{ OP_SBOX, S_BOOL, "sboxsobool" },
	{ OP_SBOX, S_BOOL, "sboxdobool" },
	{ OP_SBOX, S_BOOL, "sboxdovecbool" },

	{ OP_XOR, S_YAO, "xoryao" },
	{ OP_AND, S_YAO, "andyao" },
	{ OP_ADD, S_YAO, "addyao" },
	{ OP_MUL, S_YAO, "mulyao" },
	{ OP_CMP, S_YAO, "cmpyao" },

	{ OP_EQ, S_YAO, "eqyao" },
	{ OP_MUX, S_YAO, "muxyao" },
	{ OP_INV, S_YAO, "invyao" },
	{ OP_SBOX, S_YAO, "sboxsoyao" },
	{ OP_ADD, S_ARITH, "addarith" },
	{ OP_MUL, S_ARITH, "mularith" },
	{ OP_Y2B, S_YAO, "y2b" },
	{ OP_B2A, S_BOOL, "b2a" },

	{ OP_B2Y, S_BOOL, "b2y" },
	{ OP_A2Y, S_ARITH, "a2y" },
	{ OP_ADD, S_YAO_REV, "addyaoipp" },
	{ OP_MUL, S_YAO_REV, "mulyaoipp" },

	{ OP_ADD, S_SPLUT, "addsplut"},
	{ OP_CMP, S_SPLUT, "cmpsplut"},
	{ OP_EQ, S_SPLUT, "eqsplut"},
	{ OP_SBOX, S_SPLUT, "sboxlut" }
};

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, int32_t* bitlen, uint32_t* secparam,
		std::string* address, uint16_t* port, int32_t* operation, bool* numbers_only, uint32_t* nops, uint32_t* nruns,
		uint32_t* threads, bool* no_verify, bool* detailed) {

	uint32_t int_role = 0, int_port = 0;
	bool oplist = false;
	bool success = false;

	parsing_ctx options[] = {
			{ (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			{ (void*) bitlen, T_NUM, "b", "Bit-length of operations, default {8,16,32,64}", false, false },
			{ (void*) secparam, T_NUM, "s",	"Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766",	false, false },
			{ (void*) operation, T_NUM, "o", "Test operation with id (leave out for all operations; for list of IDs use -l), default: all", false, false },
			{ (void*) nruns, T_NUM, "i", "Number of iterations of tests, default: 1",	false, false },
			{ (void*) numbers_only, T_FLAG, "v", "Omit detailed description, print numbers only (default: false)",	false, false },
			{ (void*) &oplist, T_FLAG, "l", "List the IDs of operations",	false, false },
			{ (void*) no_verify, T_FLAG, "t", "No output verification (default: false)",	false, false },
			{ (void*) detailed, T_FLAG, "d", "Give detailed online/setup time and communication (default: false)",	false, false },
			{ (void*) nops, T_NUM, "n", "Number of parallel operations, default: 1", false, false },
			{ (void*) threads, T_NUM, "h", "Number of threads, default: 1", false, false }
	};

	success = parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx));

	if(oplist) {
		std::cout << "Operations with IDs: " << std::endl;
		for(uint32_t i = 0; i < sizeof(m_tBenchOps)/sizeof(aby_ops_t); i++) {
			std::cout << "Operation " << i << ": " << m_tBenchOps[i].opname << std::endl;
		}
		exit(0);
	}

	if (!success) {
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

	assert(*bitlen <= 64);

	return 1;
}



int32_t bench_operations(aby_ops_t* bench_ops, uint32_t nops, ABYParty* party, uint32_t* bitlens,
		uint32_t nbitlens, uint32_t nvals, uint32_t nruns, e_role role, uint32_t symsecbits, bool numbers_only,
		bool no_verify,	bool detailed) {
	uint64_t *avec, *bvec, *cvec, *verifyvec, typebitmask = 0;
	uint32_t tmpbitlen, tmpnvals;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	//Shares for Yao IPP
	share *shray, *shrayr, *shrby, *shrbyr, *shrresy, *shrresyr, *shrouty, *shroutyr;
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac, *ycr;
	double op_time, o_time, s_time, o_comm, s_comm;
	uint32_t non_linears, depth, ynvals, yrnvals;
	bool aes_remark = false;

	avec = (uint64_t*) malloc(nvals * sizeof(uint64_t));
	bvec = (uint64_t*) malloc(nvals * sizeof(uint64_t));
	cvec = (uint64_t*) malloc(nvals * sizeof(uint64_t));

	verifyvec = (uint64_t*) malloc(nvals * sizeof(uint64_t));

	bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
	yc = sharings[S_YAO]->GetCircuitBuildRoutine();
	ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
	ycr = sharings[S_YAO_REV]->GetCircuitBuildRoutine();


	//ids that are required for the vector_and optimization in aes
	uint32_t* buf_pos_even = (uint32_t*) malloc(sizeof(uint32_t) * nvals);
	uint32_t* buf_pos_odd = (uint32_t*) malloc(sizeof(uint32_t) * nvals);
	for(uint32_t i = 0; i < nvals; i++) {
		buf_pos_even[i] = 2*i;
		buf_pos_odd[i] = 2*i+1;
	}

	if (!numbers_only) {

		std::cout << "Base OTs:\t";
		std::cout << party->GetTiming(P_BASE_OT) << std::endl;

		std::cout << "Op\t";
		if (!detailed) {
			for (uint32_t b = 0; b < nbitlens; b++) {
				std::cout << bitlens[b] << "-bit \t";
			}
			std::cout << std::endl;
		}
		else {
			std::cout << "Setup Time [ms] / Online Time [ms] / Setup Comm [Byte] / Online Comm [Byte] / Non-Linear Ops" << std::endl;
		}
		std::cout << "-----------------------------------------------" << std::endl;
	}

	for (uint32_t i = 0; i < nops; i++) {
		if (!numbers_only) {
			std::cout << bench_ops[i].opname << "\t";
		}

		if(detailed){
			std::cout << std::endl;
		}

		for (uint32_t b = 0; b < nbitlens; b++) {
			uint32_t bitlen = bitlens[b];
			op_time = 0;
			o_time = 0;
			s_time = 0;
			o_comm = 0;
			s_comm = 0;
			non_linears = 0;

			typebitmask = 0;

			if(PadToMultiple(bitlen, 8) != bitlen) {
				typebitmask = (1<<bitlen)-1;
			} else {
				memset(&typebitmask, 0xFF, ceil_divide(bitlen, 8));
			}


			for (uint32_t r = 0; r < nruns; r++) {

				Circuit* circ = sharings[bench_ops[i].sharing]->GetCircuitBuildRoutine();

				for (uint32_t j = 0; j < nvals; j++) {
					avec[j] = (((uint64_t) rand()<<(sizeof(uint32_t)*8)) + rand()) & typebitmask;
					bvec[j] = (((uint64_t) rand()<<(sizeof(uint32_t)*8)) + rand()) & typebitmask;
				}

				if(bench_ops[i].sharing == S_YAO_REV) {
					yrnvals = nvals/2;
					ynvals = nvals - yrnvals;

					shray = yc->PutSIMDINGate(ynvals, avec, bitlen, SERVER);
					shrby = yc->PutSIMDINGate(ynvals, bvec, bitlen, CLIENT);
					shray->set_max_bitlength(bitlen);
					shrby->set_max_bitlength(bitlen);

					if(yrnvals > 0) {
						shrayr = ycr->PutSIMDINGate(yrnvals, avec+ynvals, bitlen, CLIENT);
						shrbyr = ycr->PutSIMDINGate(yrnvals, bvec+ynvals, bitlen, SERVER);
						shrayr->set_max_bitlength(bitlen);
						shrbyr->set_max_bitlength(bitlen);
					}
				} else {
					shra = circ->PutSIMDINGate(nvals, avec, bitlen, SERVER);
					shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);
					shra->set_max_bitlength(bitlen);
					shrb->set_max_bitlength(bitlen);
				}


				switch (bench_ops[i].op) {
				case OP_ADD:
					if(bench_ops[i].opname.compare("addsobool") == 0) {
						shrres = new boolshare(((BooleanCircuit*)circ)->PutSizeOptimizedAddGate(shra->get_wires(), shrb->get_wires()), circ);
					} else if(bench_ops[i].opname.compare("adddovecbool") == 0) {
						shrres = new boolshare(((BooleanCircuit*)circ)->PutDepthOptimizedAddGate(shra->get_wires(), shrb->get_wires(), false, true), circ);
					} else if(bench_ops[i].sharing == S_YAO_REV) {
						shrresy = yc->PutADDGate(shray, shrby);
						if(yrnvals > 0) {
							shrresyr = ycr->PutADDGate(shrayr, shrbyr);
						}
					} else {
						shrres = circ->PutADDGate(shra, shrb);
					}
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = (avec[j] + bvec[j]) & typebitmask;
					break;
				case OP_SUB:
					shrres = circ->PutSUBGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = (avec[j] - bvec[j]) & typebitmask;
					break;
				case OP_MUL:
					if(nvals > 1000 && bench_ops[i].sharing == S_YAO) {
						std::cout << "Yao multiplication ignored due to high memory requirement!\t";
						shrres = shra; //Do nothing since memory footprint is too high
						for (uint32_t j = 0; j < nvals; j++)
							verifyvec[j] = avec[j];
					} else {
						if(bench_ops[i].opname.compare("muldobool") == 0) {
							shrres = new boolshare(((BooleanCircuit*) circ)->PutMulGate(shra->get_wires(), shrb->get_wires(), bitlen, true), circ);
						} else if(bench_ops[i].opname.compare("mulsovecbool") == 0) {
							shrres = new boolshare(((BooleanCircuit*) circ)->PutMulGate(shra->get_wires(), shrb->get_wires(), bitlen, false, true), circ);
						} else if(bench_ops[i].opname.compare("muldovecbool") == 0) {
							shrres = new boolshare(((BooleanCircuit*) circ)->PutMulGate(shra->get_wires(), shrb->get_wires(), bitlen, true, true), circ);
						} else if(bench_ops[i].sharing == S_YAO_REV) {
							shrresy = yc->PutMULGate(shray, shrby);
							if(yrnvals > 0) {
								shrresyr = ycr->PutMULGate(shrayr, shrbyr);
							}
						} else {
							shrres = circ->PutMULGate(shra, shrb);
						}
						for (uint32_t j = 0; j < nvals; j++)
							verifyvec[j] = (avec[j] * bvec[j]) & typebitmask;
					}

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
					if(bench_ops[i].opname.compare("cmpsobool") == 0) {
						shrres = new boolshare(1, circ);
						shrres->set_wire_id(0, ((BooleanCircuit*)circ)->PutSizeOptimizedGTGate(shra->get_wires(), shrb->get_wires()));
					} else {
						shrres = circ->PutGTGate(shra, shrb);
					}
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] > bvec[j];
					break;
				case OP_EQ:
					shrres = circ->PutEQGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] == bvec[j];
					break;
				case OP_MUX:
					shrsel = new boolshare(1, circ);
					shrsel->set_wire_id(0, circ->PutXORGate(shra->get_wire_ids_as_share(0), shrb->get_wire_ids_as_share(0))->get_wire_id(0));

					if(bench_ops[i].opname.compare("muxvecbool") == 0) {
						shrres = new boolshare(bitlen, circ);
						((BooleanCircuit*) circ)->PutMultiMUXGate(&shra, &shrb, shrsel, 1, &shrres);
					} else if(bench_ops[i].opname.compare("muxbool") == 0) {
						shrres = new boolshare(((BooleanCircuit*)circ)->PutMUXGate(shra->get_wires(), shrb->get_wires(), shrsel->get_wire_id(0), false), circ);

					} else {
						shrres = circ->PutMUXGate(shra, shrb, shrsel);
					}
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = ((avec[j] & 0x01) ^ (bvec[j] & 0x01)) == 0 ? bvec[j] : avec[j];
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
				case OP_INV:
					shrres = ((BooleanCircuit*) circ)->PutINVGate(shra);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] ^ typebitmask;
					break;
				case OP_SBOX:
					if (bitlen >= 8) {
						shrsel = new boolshare(8, circ);
						for (uint32_t j = 0; j < 8; j++) {
							shrsel->set_wire_id(j, shra->get_wire_id(j));
						}

					if(bench_ops[i].opname.compare("sboxsobool") == 0) {
						shrres = new boolshare(AESSBox_Forward_BP_Size_Optimized(shrsel->get_wires(), (BooleanCircuit*) circ), circ);
					} else if (bench_ops[i].opname.compare("sboxdovecbool") == 0) {
						shrres = new boolshare(AESSBox_Forward_BP_VecMTs_Optimized(shrsel->get_wires(), (BooleanCircuit*) circ, buf_pos_even, buf_pos_odd), circ);
					} else {
						shrres = new boolshare(PutAESSBoxGate(shrsel->get_wires(), (BooleanCircuit*) circ, false), circ);
					}
						for (uint32_t j = 0; j < nvals; j++)
							verifyvec[j] = (uint64_t) plaintext_aes_sbox[avec[j] & 0xFF]; //(avec[j] + bvec[j]) & typebitmask;
					}
					else{
						std::cout << "*\t";
						aes_remark = true;
						shrres = shra;
						for (uint32_t j = 0; j < nvals; j++){
							verifyvec[j] = avec[j];
						}
					}
					break;
				default:
					shrres = circ->PutADDGate(shra, shrb);
					for (uint32_t j = 0; j < nvals; j++)
						verifyvec[j] = avec[j] + bvec[j];
					break;	//ids that are required for the vector_and optimization
				}

				if(bench_ops[i].sharing == S_YAO_REV) {
					shrouty = yc->PutOUTGate(shrresy, ALL);
					if(yrnvals > 0) {
						shroutyr = ycr->PutOUTGate(shrresyr, ALL);
					}
				} else {
					shrout = circ->PutOUTGate(shrres, ALL);
				}

				party->ExecCircuit();

				//std::cout << "Size of output: " << shrout->size() << std::endl;
				if(bench_ops[i].sharing == S_YAO_REV) {
					uint32_t tmpyrnvals;
					cvec = (uint64_t*) malloc(sizeof(uint64_t*) * nvals);
					uint64_t* tmpcvec;
					shrouty->get_clear_value_vec(&tmpcvec, &tmpbitlen, &tmpnvals);
					memcpy(cvec, tmpcvec, sizeof(uint64_t) * ynvals);
					free(tmpcvec);
					if(yrnvals > 0) {
						shroutyr->get_clear_value_vec(&tmpcvec, &tmpbitlen, &tmpyrnvals);
						memcpy(cvec+ynvals, tmpcvec, sizeof(uint64_t) * yrnvals);
						free(tmpcvec);
						tmpnvals += tmpyrnvals;
					}
				} else {
					shrout->get_clear_value_vec(&cvec, &tmpbitlen, &tmpnvals);
				}


				op_time += party->GetTiming(P_ONLINE) + party->GetTiming(P_SETUP);
				o_time += party->GetTiming(P_ONLINE);
				s_time += party->GetTiming(P_SETUP);
				o_comm += party->GetSentData(P_ONLINE)+party->GetReceivedData(P_ONLINE);
				s_comm += party->GetSentData(P_SETUP)+party->GetReceivedData(P_SETUP);
				non_linears += sharings[bench_ops[i].sharing]->GetNumNonLinearOperations();
				depth += sharings[bench_ops[i].sharing]->GetMaxCommunicationRounds();

				if(detailed) {
					std::cout << bitlen <<"\t"
						<< party->GetTiming(P_SETUP) << "\t"
						<< party->GetTiming(P_ONLINE) << "\t"
						<< party->GetSentData(P_SETUP)+party->GetReceivedData(P_SETUP) << "\t"
						<< party->GetSentData(P_ONLINE)+party->GetReceivedData(P_ONLINE) << "\t"
						<< sharings[bench_ops[i].sharing]->GetNumNonLinearOperations() << "\t"
						<< sharings[bench_ops[i].sharing]->GetMaxCommunicationRounds() << std::endl;
				}

				party->Reset();


				if(!no_verify) {
					//std::cout << "Running verification" << std::endl;
					assert(tmpnvals == nvals);

					for (uint32_t j = 0; j < nvals; j++) {
						if(verifyvec[j] != (cvec[j]&typebitmask)) {
							std::cout << "Error: " << std::endl;
							std::cout << "\t" << get_role_name(role) << " " << bench_ops[i].opname << ": values[" << j <<
							"]: a = " << avec[j] <<	", b = " << bvec[j] << ", c = " << (cvec[j]&typebitmask) << ", verify = " <<
							verifyvec[j] << std::endl;

							assert(verifyvec[j] == (cvec[j]&typebitmask));
						}
					}
					//std::cout << "Verification succeeded" << std::endl;
				}
			} // nruns

			if(!detailed) {
				std::cout << op_time/nruns << "\t";
			}
		}
		if(!detailed)
			std::cout << std::endl;

	}

	if(aes_remark){
		std::cout << "\n* =  AES only works with bitlen >= 8" << std::endl;
	}

	free(avec);
	free(bvec);
	free(cvec);
	free(verifyvec);
	free(buf_pos_even);
	free(buf_pos_odd);

	return 1;
}


bool run_bench(e_role role, const std::string& address, uint16_t port, seclvl seclvl, int32_t operation, int32_t bitlen, uint32_t nvals,
		uint32_t nruns, e_mt_gen_alg mt_alg, uint32_t nthreads, bool numbers_only, bool no_verify, bool detailed) {

	uint32_t nops, nbitlens;
	//uint64_t seed = 0xAAAAAAAAAAAAAAAA;
	uint64_t seed = time(NULL);

	aby_ops_t* op;

	ABYParty* party;


	if (operation > -1) {
		op = new aby_ops_t;
		assert(operation < (int) (sizeof(m_tBenchOps) / sizeof(aby_ops_t)));
		op->op = m_tBenchOps[operation].op;
		op->opname = m_tBenchOps[operation].opname;
		op->sharing = m_tBenchOps[operation].sharing;
		nops = 1;
	} else {
		//simply copy the operations
		op = (aby_ops_t*) m_tBenchOps;
		nops = sizeof(m_tBenchOps) / sizeof(aby_ops_t);
	}

	uint32_t* bitlens;

	if (bitlen > -1) {
		bitlens = (uint32_t*) malloc(sizeof(uint32_t));
		bitlens[0] = bitlen;
		nbitlens = 1;
		party =  new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	} else {
		bitlens = (uint32_t*) m_vBitLens;
		nbitlens = sizeof(m_vBitLens) / sizeof(uint32_t);
		party =  new ABYParty(role, address, port, seclvl, 64, nthreads, mt_alg);
	}


	srand(seed);

	bench_operations(op, nops, party, bitlens, nbitlens, nvals, nruns, role, seclvl.symbits, numbers_only, no_verify, detailed);

	delete party;

	return true;
}



int main(int argc, char** argv) {
	e_role role;
	uint32_t secparam = 128, nvals = 1, nruns = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t operation = -1, bitlen = -1;
	bool numbers_only = false;
	bool no_verify = false;
	bool detailed = false;
	uint32_t nthreads = 1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &secparam, &address, &port, &operation, &numbers_only, &nvals, &nruns, &nthreads, &no_verify, &detailed);

	seclvl seclvl = get_sec_lvl(secparam);

	run_bench(role, address, port, seclvl, operation, bitlen, nvals, nruns, mt_alg, nthreads, numbers_only, no_verify, detailed);

	return 0;
}
