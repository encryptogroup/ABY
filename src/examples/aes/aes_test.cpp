/**
 \file 		aes_test.cpp
 \brief		AES Test class implementation.
 */

//Utility libs
#include "../../abycore/util/crypto/crypto.h"
#include "../../abycore/util/parse_options.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/aescircuit.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, string* address, uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false }, { (void*) nvals, T_NUM, 'n', "Number of parallel operation elements", false, false }, {
			(void*) bitlen, T_NUM, 'b', "Bit-length, default 32", false, false }, { (void*) secparam, T_NUM, 's', "Symmetric Security Bits, default: 128", false, false }, {
			(void*) address, T_STR, 'a', "IP-address, default: localhost", false, false }, { (void*) &int_port, T_NUM, 'p', "Port, default: 7766", false, false }, {
			(void*) test_op, T_NUM, 't', "Single test (leave out for all operations), default: off", false, false } };

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

	cout << endl;

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 1, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);

	test_aes_circuit(role, (char*) address.c_str(), seclvl, nvals, nthreads, mt_alg, S_YAO);

	return 0;
}

