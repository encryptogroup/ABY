/**
 \file 		millionaire_prob.cpp
 \author 	sreeram.sadasivam@cased.de
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
 \brief		Implementation of the millionaire problem using ABY Framework.
 */

#include "simd.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"

int32_t test_simd_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {

	/**
		Step 1: Create the ABYParty object which defines the basis of all the
		 	 	operations which are happening.	Operations performed are on the
		 	 	basis of the role played by this object.
	*/
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg);


	/**
		Step 2: Get to know all the sharing types available in the program.
	*/

	std::vector<Sharing*>& sharings = party->GetSharings();

	/**
		Step 3: Create the circuit object on the basis of the sharing type
				being inputed.
	*/
	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();


	/**
		Step 4: Creating the share objects - s_alice_money, s_bob_money which
				is used as input to the computation function. Also s_out
				which stores the output.
	*/

	// share *s_alice_money, *s_bob_money, *s_out;
	uint32_t *avec, *bvec, *cvec, tmpbitlen, tmpnvals;
	int nvals = 10;
	avec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	bvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	cvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	for (int i = 0; i < nvals; i++) {
		avec[i] = i;
		bvec[i] = i;
	}

	share* shra = circ->PutSIMDINGate(nvals, avec, bitlen, SERVER);
	share* shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);


	share* shrres = circ->PutADDGate(shra, shrb);

	share* s_out = circ->PutOUTGate(shrres, ALL);

	party->ExecCircuit();

	/**
		Step 10:Type casting the value to 32 bit unsigned integer for output.
	*/

	s_out->get_clear_value_vec(&cvec, &tmpbitlen, &tmpnvals);

	
	for (int i = 0; i < nvals; i++) {
		std::cout << "a[" << i << "] = " << avec[i] << std::endl;
	}

	for (int i = 0; i < nvals; i++) {
		std::cout << "b[" << i << "] = " << bvec[i] << std::endl;
	}

	for (int i = 0; i < nvals; i++) {
		std::cout << "output[" << i << "] = " << cvec[i] << std::endl;
	}

	delete party;
	return 0;
}