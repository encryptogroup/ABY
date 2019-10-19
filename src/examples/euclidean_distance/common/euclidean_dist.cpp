/**
 \file 		euclidean_dist.cpp
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
 \brief		Testing the implementation of the Euclidean distance for two coordinates
 */

#include "euclidean_dist.h"
#include "../../../abycore/sharing/sharing.h"

int32_t test_euclid_dist_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {

	// defines the operation/output bitlength operations for boolean and arithmetic circuits
	// this is why the output bitlen is 32 bits and not 8 bits like the input length
	uint32_t bitlen = 32;

	/**
		Step 1: Create the ABY Party object which defines the basis of
				all the operations which are happening.	Operations performed
				are on the basis of the role played by this object.
	*/

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);

	/**
		Step 2: Get to know all the sharings available in the program.
	*/
	std::vector<Sharing*>& sharings = party->GetSharings();

	/**
		Step 3: Create the circuit object on the basis of the sharing type
				being inputted.
	*/

	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();

	/**
		Step 4: Create the share objects s_x1, s_y1, s_x2, s_y2
		that are the inputs	to the circuit. s_out will store the output.
	*/
	share *s_x1, *s_x2, *s_y1, *s_y2, *s_out;

	/**
		Step 5: Initialize plaintext values of x1, x2, y1, y2 with random values.
		Here, both parties will select the same random values,
		since they start at	the same time (they wait for each other).
		In real life every party, would only know one pair of coordinates -
		here we know both pairs for verification later on.
	*/

	uint8_t* x1 = new uint8_t[nvals];
	uint8_t* x2 = new uint8_t[nvals];
	uint8_t* y1 = new uint8_t[nvals];
	uint8_t* y2 = new uint8_t[nvals];
	srand(time(NULL));
	for(uint32_t i = 0; i < nvals; ++i) {
		x1[i] = rand();
		y1[i] = rand();
		y2[i] = rand();
		x2[i] = rand();
	}

	/**
		Step 6: Set the coordinates as inputs for the circuit for the respective party.
		The other party's input length must be specified.
	*/

	if (role == SERVER) {
		s_x1 = circ->PutSIMDINGate(nvals, x1, 8, SERVER);
		s_y1 = circ->PutSIMDINGate(nvals, y1, 8, SERVER);
		s_x2 = circ->PutDummySIMDINGate(nvals, 8);
		s_y2 = circ->PutDummySIMDINGate(nvals, 8);
	} else {
		s_x1 = circ->PutDummySIMDINGate(nvals, 8);
		s_y1 = circ->PutDummySIMDINGate(nvals, 8);
		s_x2 = circ->PutSIMDINGate(nvals, x2, 8, CLIENT);
		s_y2 = circ->PutSIMDINGate(nvals, y2, 8, CLIENT);
	}

	/**
		Step 7: Call the build method for building the circuit for the
				problem by passing the shared objects and circuit object.
				Don't Forget to type cast the circuit object to type of share
	*/

	s_out = BuildEuclidDistanceCircuit(s_x1, s_x2, s_y1, s_y2,
			(BooleanCircuit*) circ);

	/**
		Step 8: Write the circuit output to s_out for both parties.
	*/
	s_out = circ->PutOUTGate(s_out, ALL);

	/**
		Step 9: Execute the circuit using the ABYParty object
	*/
	party->ExecCircuit();

	/**
		Step 10: Obtain the output from
	*/

	uint32_t* output;
	uint32_t out_bitlen, out_nvals;
	// This method only works for an output length of maximum 64 bits in general,
	// if the output length is higher you must use get_clear_value_ptr
	s_out->get_clear_value_vec(&output, &out_bitlen, &out_nvals);

	/**
		Step 11:Print plaintext output of the circuit.
	 */

	std::cout << "Testing Euclidean Distance in " << get_sharing_name(sharing)
			<< " sharing, out_bitlen=" << out_bitlen << " and out_nvals=" << out_nvals << ":" << std::endl;

	for(uint32_t i = 0; i < nvals; ++i) {
		std::cout << "x1: " << (int) x1[i] << ", y1: " << (int) y1[i] << "; x2: " << (int) x2[i] << ", y2: " << (int) y2[i] << std::endl;
		std::cout << "Circuit result: " << sqrt(output[i]);

		std::cout << " Verification: " <<
			sqrt((pow((double)abs(y2[i] - y1[i]), (double)2) + pow((double)abs(x2[i] - x1[i]),(double) 2))) << std::endl;
	}

	delete party;
	delete x1;
	delete x2;
	delete y1;
	delete y2;
	return 0;
}

/**
 * \brief Builds a Euclidean distance circuit for two pairs of coordinate shares (without the computation of sqrt at the end)
 */
share* BuildEuclidDistanceCircuit(share *s_x1, share *s_x2, share *s_y1,
		share *s_y2, BooleanCircuit *bc) {

	share* out, *t_a, *t_b, *res_x, *res_y, *check_sel,
			*check_sel_inv;

	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = bc->PutGTGate(s_x1, s_x2);
	check_sel_inv = bc->PutINVGate(check_sel);
	t_a = bc->PutMUXGate(s_x1, s_x2, check_sel);
	t_b = bc->PutMUXGate(s_x1, s_x2, check_sel_inv);

	res_x = bc->PutSUBGate(t_a, t_b);
	res_x = bc->PutMULGate(res_x, res_x);

	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = bc->PutGTGate(s_y1, s_y2);
	check_sel_inv = bc->PutINVGate(check_sel);
	t_a = bc->PutMUXGate(s_y1, s_y2, check_sel);
	t_b = bc->PutMUXGate(s_y1, s_y2, check_sel_inv);

	res_y = bc->PutSUBGate(t_a, t_b);
	res_y = bc->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	out = bc->PutADDGate(res_x, res_y);

	return out;
}
