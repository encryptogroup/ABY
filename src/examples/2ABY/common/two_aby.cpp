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
*/
#include "two_aby.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/sharing/sharing.h"


int32_t test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
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
		Step 4: Creating the share objects - Values A and B which
				are used as input to the computation function. Also s_out
				which stores the output.
	*/

	share *s_A1, *s_B1, *s_A2, *s_B2, *s_localS, *s_localC, *s_Dummy,  *s_out;

	/**
		Step 5: Initialize A and B values randomly or not....
				Both parties use the same seed, to be able to verify the
				result. In a real example each party would only supply
				one input value.
	*/

	uint32_t a1_val, b1_val,a2_val, b2_val,local_factor, dummy_value, output;
	srand(time(NULL));
	a1_val = 60;
	b1_val = 33;
	a2_val = -15;
	b2_val = -3;
	
	dummy_value = 5;
	
	// 

  
  
  /**
		Step 6: Copy the randomly generated values into the respective
				share objects using the circuit object method PutINGate()
				for my inputs and PutDummyINGate() for the other parties input.
				Also mention who is sharing the object.
	*/
	
	if(role == SERVER) {
		local_factor = a1_val*b1_val;
		s_A1 = circ->PutINGate(a1_val,bitlen,SERVER);
		s_B1 = circ->PutINGate(b1_val, bitlen, SERVER);
		s_localS = circ->PutINGate(local_factor,bitlen,SERVER);

		s_A2 = circ->PutDummyINGate( bitlen);
		s_B2 = circ->PutDummyINGate(bitlen);
		s_localC = circ->PutDummyINGate(bitlen);

		//s_Dummy= circ->PutINGate(b_val, bitlen, SERVER);
		circ->PutPrintValueGate(s_A1, "SERVER SA");

	} else { //role == CLIENT
		local_factor = a2_val*b2_val;
		s_A1 = circ->PutDummyINGate(bitlen);
		s_B1 = circ->PutDummyINGate(bitlen);
		s_localS = circ->PutDummyINGate(bitlen);

		s_A2 = circ->PutINGate(a2_val, bitlen, CLIENT);
		s_B2 = circ->PutINGate(b2_val, bitlen, CLIENT);
		s_localC = circ->PutINGate(local_factor,bitlen,CLIENT);

		//s_Dummy = circ->PutINGate(b_val, bitlen, SERVER);
		circ->PutPrintValueGate(s_A2, "CLIENT SA");

	}
  
  
  /**
		Step 7: Call the build method for building the circuit for the
				problem by passing the shared objects and circuit object.
				Don't forget to type cast the circuit object to type of share
	*/

	s_out = BuildFirstCircuit(role, s_A1,s_B1,s_A2,s_B2,s_localS,s_localC,
			(ArithmeticCircuit*) circ);

	/**
		Step 8: Modify the output receiver based on the role played by
				the server and the client. This step writes the output to the
				shared output object based on the role.
	*/
	s_out = circ->PutOUTGate(s_out, ALL);
	circ->PutPrintValueGate(s_out, "Share S_OUT");



  /**
		Step 9: Executing the circuit using the ABYParty object evaluate the
				problem.
	*/
	party->ExecCircuit();

	/**
		Step 10:Type casting the value to 32 bit unsigned integer for output.
	*/
	output = s_out->get_clear_value<uint32_t>();

	std::cout << " I AM "<<role<< " AND THIS IS THE OUTPUT " << output << std::endl;


	delete party;
	return 0;
}
  
  
  
  share* BuildFirstCircuit(e_role role, share *s_a1, share *s_b1,share *s_a2, share *s_b2, share *s_localS, share *s_localC,
		ArithmeticCircuit *ac) {

	share* out;
	share* a1b2;
	share* b1a2;
	
	  
	a1b2 = ac->PutADDGate(s_a1,s_b2);
	b1a2 = ac->PutADDGate(s_b1,s_a2);
	
	out = ac->PutADDGate(a1b2,b1a2);
	out = ac->PutADDGate(out,s_localC);
	out = ac->PutADDGate(out,s_localS)
		
	//std::cout << "I AM "<<role<< "AND THIS IS THE OUTPUT" << output << std::endl;
	ac->PutPrintValueGate(s_a1, "Share A1");
	ac->PutPrintValueGate(s_b1, "Share B1");
	ac->PutPrintValueGate(s_a2, "Share A2");
	ac->PutPrintValueGate(s_b2, "Share B2");
	//ac->PutPrintValueGate(s_b1, "Share B1");

	/** Calling the Addition gate in the Arithmetic circuit.*/
	//output = s_a->get_clear_value<uint32_t>();
	//s_out = circ->PutOUTGate(s_out, ALL);
	return out;
}
  
