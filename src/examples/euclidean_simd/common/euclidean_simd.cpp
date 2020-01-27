/**
 \file 		.cpp
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
#include "euclidean_simd.h"
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
  
  
  	//uint32_t x_start [4];
	//uint32_t y_start [4];	
	//uint32_t x_end [4];
	//uint32_t y_end [4];
	

	
	 uint32_t x1_start [4] = {349878, 205297, 156505, 294944};
  	 uint32_t y1_start [4]= {4267509, 4531068, 4257078, 4219945};
	 uint32_t x1_end [4] = {169015, 422706, 106029, 89585};
	 uint32_t y1_end [4] = {4568415, 4340206, 4542962, 4273139};

	

	 uint32_t x2_start [4] = {130066, 265203, 313995, 177860};
  	 uint32_t y2_start [4] = {308575, 68182, 342172, 378095};
	 uint32_t x2_end [4]  = {349878, 205297, 156505, 294944};
	 uint32_t y2_end [4]   = {4267509, 4531068, 4257078, 4219945};

	
		uint32_t n = 4;

  /**
		Step 4: Creating the share objects - Values A and B which
				are used as input to the computation function. Also s_out
				which stores the output.
	*/

	share  *s1_x_start, *s1_y_start, *s1_x_end,
	*s1_y_end, *s2_x_start, *s2_y_start, *s2_x_end, *s2_y_end,  *s_out;


  
  
  /**
		Step 6: Copy the randomly generated values into the respective
				share objects using the circuit object method PutINGate()
				for my inputs and PutDummyINGate() for the other parties input.
				Also mention who is sharing the object.
	
	*/
	if(role == SERVER) {
	
		
		s1_x_start = circ->PutSIMDINGate(n,x1_start,bitlen,SERVER);
		s1_y_start = circ->PutSIMDINGate(n,y1_start,bitlen,SERVER);
		s1_x_end = circ->PutSIMDINGate(n,x1_end,bitlen,SERVER);
		s1_y_end = circ->PutSIMDINGate(n, y1_end,bitlen,SERVER);
		
		s2_x_start = circ->PutDummySIMDINGate(n, bitlen);
        	s2_y_start = circ->PutDummySIMDINGate(n, bitlen);
		s2_x_end = circ->PutDummySIMDINGate(n, bitlen);
        	s2_y_end = circ->PutDummySIMDINGate(n, bitlen);

	} else { //role == CLIENT
		s2_x_start = circ->PutSIMDINGate(n,x2_start,bitlen,CLIENT);
		s2_y_start = circ->PutSIMDINGate(n,y2_start,bitlen,CLIENT);
		s2_x_end = circ->PutSIMDINGate(n,x2_end,bitlen,CLIENT);
		s2_y_end = circ->PutSIMDINGate(n,y2_end,bitlen,CLIENT);
		
		s1_x_start = circ->PutDummySIMDINGate(n, bitlen);
        	s1_y_start = circ->PutDummySIMDINGate(n, bitlen);
		s1_x_end = circ->PutDummySIMDINGate(n, bitlen);
		s1_y_end = circ->PutDummySIMDINGate(n, bitlen);
	}
  
  
  /**
		Step 7: Call the build method for building the circuit for the
				problem by passing the shared objects and circuit object.
				Don't forget to type cast the circuit object to type of share
	*/

	s_out = BuildFirstCircuit(role,s1_x_start, s1_y_start, s1_x_end, s1_y_end, s2_x_start,
				  s2_y_start, s2_x_end, s2_y_end,
			(ArithmeticCircuit*) circ);


	/**
		Step 8: Modify the output receiver based on the role played by
				the server and the client. This step writes the output to the
				shared output object based on the role.
	*/
	
	
	
		circ->PutPrintValueGate(s_out, "DEBAJO BUILD");	
	
	//s_out = circ->PutOUTGate(s_out, ALL);
	
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
  
  
  
  share* BuildFirstCircuit(e_role* role, share* s1_x_start,  share* s1_y_start, share* s1_x_end, share* s1_y_end, 
			   share* s2_x_start,
				  share* s2_y_start, share*  s2_x_end, share* s2_y_end,
			ArithmeticCircuit* circ) {

	
	  
	  share* out;
	  share* first_x;
	
	  
	uint32_t output;

	uint32_t bitlen=32;
	  
	share* rando;
	  
	  
	  rando = circ->PutADDGate(s1_x_start[0],s2_x_start[0]);
	  
	  
	  rando = circ->PutSharedOUTGate(rando);
	  
	  

	return rando;
}
  
