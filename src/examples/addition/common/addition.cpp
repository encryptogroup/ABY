/**
 \file 		addition.cpp
 \author 	romalvarezllorens@gmail.com
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
 \brief		Implementation of the addition of two numbers using ABY Framework.
 */

#include "addition.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/sharing/sharing.h"



int32_t test_addition_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint32_t sum) {

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
		Step 4: Creating the share objects - Values A and B which
				are used as input to the computation function. Also s_out
				which stores the output.
	*/

	share *s_A, *s_B, *s_out;

	/**
		Step 5: Initialize A and B values randomly or not....
				Both parties use the same seed, to be able to verify the
				result. In a real example each party would only supply
				one input value.
	*/

	uint32_t a_val, b_val, output;
	srand(time(NULL));


	if(sum != 0){


                if(role == SERVER) {
                	b_val =sum;// sum;
			a_val = rand();
                } else {
                         a_val = sum;//sum;
			b_val = rand();
                }
	}

	else{
		a_val = 10;
		b_val = 20;
	}	

	/**
		Step 6: Copy the randomly generated values into the respective
				share objects using the circuit object method PutINGate()
				for my inputs and PutDummyINGate() for the other parties input.
				Also mention who is sharing the object.
	*/
	//s_alice_money = circ->PutINGate(alice_money, bitlen, CLIENT);
	//s_bob_money = circ->PutINGate(bob_money, bitlen, SERVER);
  
	if(role == SERVER) {
		s_A = circ->PutDummyINGate(bitlen);
		s_B = circ->PutINGate(b_val, bitlen, SERVER);
	} else { //role == CLIENT
		s_A = circ->PutINGate(a_val, bitlen, CLIENT);
		s_B = circ->PutDummyINGate(bitlen);
	}

	/**
		Step 7: Call the build method for building the circuit for the
				problem by passing the shared objects and circuit object.
				Don't forget to type cast the circuit object to type of share
	*/

	s_out = BuildAdditionCircuit(s_A, s_B,
			(ArithmeticCircuit*) circ);

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
		Step 10:Type casting the value to 32 bit unsigned integer for output.
	*/
	output = s_out->get_clear_value<uint32_t>();

	std::cout << "Testing Addition computation in " << get_sharing_name(sharing)
				<< " sharing: " << std::endl;
	std::cout << "\nValue A:\t" << a_val;
	std::cout << "\nValue B:\t" << b_val;
	std::cout << "\nCircuit Result:\t" << (output);
	std::cout << "\nVerify Result: \t" << (a_val + b_val)
				<< "\n";

	delete party;
	return 0;
}

share* BuildAdditionCircuit(share *s_a, share *s_b,
		ArithmeticCircuit *ac) {

	share* out;

	/** Calling the Addition gate in the Arithmetic circuit.*/
	out = ac->PutADDGate(s_a, s_b);

	return out;
}


