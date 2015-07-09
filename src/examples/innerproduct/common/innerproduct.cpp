/**
 \file 		innerproduct.cpp
 \author 	sreeram.sadasivam@cased.de
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
 \brief		Implementation of the Inner Product using ABY Framework.
 */

#include "innerproduct.h"

// the number of elements to multiply and add
#define N 128

int32_t test_inner_product_circuit(e_role role, char* address, seclvl seclvl, uint32_t nvals, uint32_t bitlen,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {

	/**
	 Step 1: Create the ABYParty object which defines the basis of all the
	 operations which are happening.	Operations performed are on the
	 basis of the role played by this object.
	 */
	ABYParty* party = new ABYParty(role, address, seclvl, bitlen, nthreads, mt_alg);

	/**
	 Step 2: Get to know all the sharing types available in the program.
	 */

	vector<Sharing*>& sharings = party->GetSharings();

	/**
	 Step 3: Create the circuit object on the basis of the sharing type
	 being inputed.
	 */
	ArithmeticCircuit* circ = (ArithmeticCircuit*) sharings[sharing]->GetCircuitBuildRoutine();

	/**
	 Step 4: Creating the share objects - s_x_vec, s_y_vec which
	 are used as inputs to the computation. Also s_out  which stores the output.
	 */

	share **s_x_vec, **s_y_vec, *s_out;

	/**
	 Step 5: Allocate the x any y shared vectors.
	 */

	s_x_vec = new share*[N];
	s_y_vec = new share*[N];

	uint16_t x, y;

	uint16_t output, v_sum = 0;

	int i;
	srand(time(NULL));

	/**
	 Step 6: Initialize the vectors x and y with the generated random values.
	 Both parties use the same seed, to be able to verify the
	 result. In a real example each party would only supply
	 one input value. Copy the randomly generated vector values into the respective
	 share objects using the circuit object method PUTInGate().
	 Also mention who is sharing the object.
	 The value for the party different from role is ignored,
	 but PutINGate() must always be called for both roles.
	 */
	for (i = 0; i < N; i++) {

		x = rand();
		y = rand();

		v_sum += x * y;

		s_x_vec[i] = circ->PutINGate(N, x, 16, CLIENT);
		s_y_vec[i] = circ->PutINGate(N, y, 16, SERVER);
	}

	/**
	 Step 7: Call the build method for building the circuit for the
	 problem by passing the shared objects and circuit object.
	 Don't forget to type cast the circuit object to type of share
	 */
	s_out = BuildInnerProductCircuit(s_x_vec, s_y_vec, (ArithmeticCircuit*) circ);

	/**
	 Step 8: Modify the output receiver based on the role played by
	 the server and the client. This step writes the output to the
	 shared output object based on the role.
	 */
	s_out = circ->PutOUTGate(s_out, ALL);

	/**
	 Step 9: Executing the circuit using the ABYParty object evaluate the
	 problem.
	 */
	party->ExecCircuit();

	/**
	 Step 10: Type casting the value to 16 bit unsigned integer for output.
	 */
	output = s_out->get_clear_value<uint16_t>();

	cout << "\nCircuit Result: " << output;
	cout << "\nVerification Result: " << v_sum << endl;

	delete s_x_vec;
	delete s_y_vec;
	delete party;
	return 0;
}

/*
 Constructs the inner product circuit. N mutiplications and an addition tree with logarithmic depth.
 Works for arbitrary N
 */
share* BuildInnerProductCircuit(share **s_x, share **s_y, ArithmeticCircuit *ac) {

	uint32_t i, j;

	// pairwise multiplication of all inputs
	for (i = 0; i < N; i++) {
		s_x[i] = ac->PutMULGate(s_x[i], s_y[i]);
	}

	// add all multiplication results as a tree for log depth
	for (i = 0; i < (int) ceil(log2(N)); i++) {

		for (j = 0; j < N; j += (1 << (i + 1))) {

			// stop at gate N (relevant if N is not a power of 2)
			if ((j + (1 << i)) < N) {
				s_x[j] = ac->PutADDGate(s_x[j], s_x[j + (1 << i)]);
			}
		}
	}

	return s_x[0];
}
