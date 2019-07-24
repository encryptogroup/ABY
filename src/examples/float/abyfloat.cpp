/**
 \file 		abyfloat.cpp
 \author	daniel.demmler@ec-spride.de
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
 */

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/share.h"
#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/sharing/sharing.h"
#include <cassert>
#include <iomanip>
#include <iostream>
#include <math.h>

void read_test_options(int32_t* argcp, char*** argvp, e_role* role,
	uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
	uint16_t* port, int32_t* test_op, uint32_t* test_bit, double* fpa, double* fpb) {

	uint32_t int_role = 0, int_port = 0, int_testbit = 0;

	parsing_ctx options[] =
	{ {(void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
	{(void*) &int_testbit, T_NUM, "i", "test bit", false, false },
	{(void*) nvals, T_NUM, "n",	"Number of parallel operation elements", false, false },
	{(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,false },
	{(void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
	{(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
	{(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
	{(void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false },
	{(void*) fpa, T_DOUBLE, "x", "FP a", false, false },
	{(void*) fpb, T_DOUBLE, "y", "FP b", false, false }

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

	*test_bit = int_testbit;
}

void test_verilog_add64_SIMD(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads,
	e_mt_gen_alg mt_alg, e_sharing sharing, double afp, double bfp) {

	// for addition we operate on doubles, so set bitlen to 64 bits
	uint32_t bitlen = 64;

	std::string circuit_dir = "../../bin/circ/";

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);

	std::vector<Sharing*>& sharings = party->GetSharings();

	BooleanCircuit* circ = (BooleanCircuit*) sharings[sharing]->GetCircuitBuildRoutine();

	// point a uint64_t pointer to the two input floats without casting the content
	uint64_t *aptr = (uint64_t*) &afp;
	uint64_t *bptr = (uint64_t*) &bfp;

	// use 32 bits for the sqrt example, so cast afp to float
	float afloat = (float) afp;
	uint32_t *afloatptr = (uint32_t*) &afloat;

	// for this example we need at least 4 values, since we do at least 4 example operations (see lines 100-102)
	assert(nvals > 3);

	// array of 64 bit values
	uint64_t avals[nvals];
	uint64_t bvals[nvals];

	// fill array with input values nvals times.
	std::fill(avals, avals + nvals, *aptr);
	std::fill(bvals, bvals + nvals, *bptr);

	// set some specific values differently for testing
	bvals[1] = 0;
	bvals[2] = *(uint64_t*) &afp;
	avals[3] = *(uint64_t*) &bfp;

	// SIMD input gates
	share* ain = circ->PutSIMDINGate(nvals, avals, bitlen, SERVER);
	share* bin = circ->PutSIMDINGate(nvals, bvals, bitlen, CLIENT);

	// 32 bit input gate (non SIMD)
	share* asqrtin = circ->PutINGate(afloatptr, 32, SERVER);

	// FP addition gate
	share* sum = circ->PutFPGate(ain, bin, ADD, bitlen, nvals, no_status);

	// 32-bit FP addition gate (bitlen, nvals, no_status are omitted)
	share* sqrt_share = circ->PutFPGate(asqrtin, SQRT);

	share* cmp = circ->PutFPGate(ain, bin, CMP, bitlen, nvals);

	// output gate
	share* add_out = circ->PutOUTGate(sum, ALL);
	share* sqrt_out = circ->PutOUTGate(sqrt_share, ALL);
	share* cmp_out = circ->PutOUTGate(cmp, ALL);

	// run SMPC
	party->ExecCircuit();

	// retrieve plain text output
	uint32_t out_bitlen_add, out_bitlen_cmp, out_nvals;
	uint64_t *out_vals_add, *out_vals_cmp;

	add_out->get_clear_value_vec(&out_vals_add, &out_bitlen_add, &out_nvals);
	cmp_out->get_clear_value_vec(&out_vals_cmp, &out_bitlen_cmp, &out_nvals);

	// print every output
	for (uint32_t i = 0; i < nvals; i++) {

		// dereference output value as double without casting the content
		double val = *((double*) &out_vals_add[i]);

		std::cout << "ADD RES: " << val << " = " << *(double*) &avals[i] << " + " << *(double*) &bvals[i] << " | nv: " << out_nvals
		<< " bitlen: " << out_bitlen_add << std::endl;

		std::cout << "CMP RES: " << out_vals_cmp[i] << " = " << *(double*) &avals[i] << " > " << *(double*) &bvals[i] << " | nv: " << out_nvals
		<< " bitlen: " << out_bitlen_cmp << std::endl;
	}

	uint32_t *sqrt_out_vals = (uint32_t*) sqrt_out->get_clear_value_ptr();

	float val = *((float*) sqrt_out_vals);

	std::cout << "SQRT RES: " << val << " = " << sqrt(afloat) << std::endl;
}


int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 1, nvals = 4, secparam = 128, nthreads = 1;

	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	uint32_t test_bit = 0;
	double fpa = 0, fpb = 0;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
		&port, &test_op, &test_bit, &fpa, &fpb);

	std::cout << std::fixed << std::setprecision(3);
	std::cout << "double input values: " << fpa << " ; " << fpb << std::endl;

	seclvl seclvl = get_sec_lvl(secparam);


	test_verilog_add64_SIMD(role, address, port, seclvl, nvals, nthreads, mt_alg, S_BOOL, fpa, fpb);

	return 0;
}
