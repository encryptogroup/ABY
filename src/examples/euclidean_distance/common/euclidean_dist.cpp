/**
 \file 		euclidean_dist.cpp
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
 \brief		Testing the implementation of the Euclidean distance for two coordinates
 */

#include "euclidean_dist.h"

int32_t test_euclid_dist_circuit(e_role role, char* address, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {

	/**
		Step 1: Create the ABY Party object which defines the basis of
				all the operations which are happening.	Operations performed
				are on the basis of the role played by this object.
	*/

	ABYParty* party = new ABYParty(role, address, seclvl, bitlen, nthreads,	mt_alg);

	/**
		Step 2: Get to know all the sharings available in the program.
	*/
	vector<Sharing*>& sharings = party->GetSharings();

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

	uint8_t x1 = 0, x2 = 0, y1 = 0, y2 = 0;
	srand(time(NULL));
	x1 = rand();
	y1 = rand();
	y2 = rand();
	x2 = rand();

	/**
		Step 6: Set the coordinates as inputs for the circuit for the respective party.
		The other party's inputs must be specified but can be set arbitrarily (dummy).
		The values will be secret shared before the circuit evaluation.
	*/

	uint8_t dummy = 0;

	if (role == SERVER) {
		s_x1 = circ->PutINGate(nvals, x1, 32, SERVER);
		s_y1 = circ->PutINGate(nvals, y1, 32, SERVER);
		s_x2 = circ->PutINGate(nvals, dummy, 32, CLIENT);
		s_y2 = circ->PutINGate(nvals, dummy, 32, CLIENT);
	} else {
		s_x1 = circ->PutINGate(nvals, dummy, 32, SERVER);
		s_y1 = circ->PutINGate(nvals, dummy, 32, SERVER);
		s_x2 = circ->PutINGate(nvals, x2, 32, CLIENT);
		s_y2 = circ->PutINGate(nvals, y2, 32, CLIENT);
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
		Step 10: Print plaintext output of the circuit.
	*/

	uint32_t output;
	output = s_out->get_clear_value<uint32_t>();

	cout << "Testing Euclidean Distance in " << get_sharing_name(sharing)
			<< " sharing: " << endl;

	printf("\n x1: %d, y1: %d \n x2: %d, y2: %d\n", x1, y1, x2, y2);
	printf(" Circuit result: %lf ", sqrt(output));

	printf("\n Verification: %lf \n\n",
			sqrt((pow(abs(y2 - y1), 2) + pow(abs(x2 - x1), 2))));
	return 0;
}

/**
 * \brief Builds a Euclidean distance circuit for two pairs of coordinate shares
 */
share* BuildEuclidDistanceCircuit(share *s_x1, share *s_x2, share *s_y1,
		share *s_y2, BooleanCircuit *bc) {

	m_nBitLength = 64;
	share* out, *t_a, *t_b, *t_ay, *t_by, *res_x, *res_y, *check_sel,
			*check_sel_inv;

	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = bc->PutGEGate(s_x1, s_x2, m_nBitLength);
	check_sel_inv = bc->PutINVGate(check_sel, m_nBitLength);
	t_a = bc->PutMUXGate(s_x1, s_x2, check_sel, m_nBitLength);
	t_b = bc->PutMUXGate(s_x1, s_x2, check_sel_inv, m_nBitLength);

	res_x = bc->PutSUBGate(t_a, t_b, m_nBitLength);
	res_x = bc->PutMULGate(res_x, res_x, m_nBitLength);

	/** Following code performs (y2-y1)*(y2-y1) */

	check_sel = bc->PutGEGate(s_y1, s_y2, m_nBitLength);
	check_sel_inv = bc->PutINVGate(check_sel, m_nBitLength);
	t_a = bc->PutMUXGate(s_y1, s_y2, check_sel, m_nBitLength);
	t_b = bc->PutMUXGate(s_y1, s_y2, check_sel_inv, m_nBitLength);

	res_y = bc->PutSUBGate(t_a, t_b, m_nBitLength);

	res_y = bc->PutMULGate(res_y, res_y, m_nBitLength);

	/** Following code performs out = res_y + res_x*/
	out = bc->PutADDGate(res_x, res_y, m_nBitLength);

	return out;
}
