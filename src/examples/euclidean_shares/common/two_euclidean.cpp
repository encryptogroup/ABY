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
#include "two_euclidean.h"
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

	share  *s_local1_S, *s_local1_C, *s_local2_S, *s_local2_C, *s_secret1, *s_secret2, *s_Dummy,  *s_out;

	/**
		Step 5: Initialize A and B values randomly or not....
				Both parties use the same seed, to be able to verify the
				result. In a real example each party would only supply
				one input value.
	*/
	
	
	// point1 (x1,y1)
	// x1 --> x11+ x12
	// y1 --> y11+ y12
	
	// point2 (x2,y2)
	// x2 --> x21+ x22
	// y2 --> y21+ y22
	
	// x1 = a=a1+a2 , y1 = b=b1+b2 , x2 = c=c1+c2, y2 = d=d1+d2
	
	uint32_t a1_val, b1_val
		,a2_val,b2_val,
		c1_val, d1_val,
		c2_val, d2_val,
		local_factor_1, local_factor_2, 
		secret1, secret2,
		dummy_value, output;
	srand(time(NULL));
	
	
	// EUCLIDEAN Distance a(4,6) b(3,2) = sqrt(17)
	//a = 4
	a1_val = 1;
	a2_val = 3;
	//b= 6
	b1_val = 2;
	b2_val = 4;
	//c = 3
	c1_val = 1;
	c2_val = 2;
	//d = 2
	d1_val = 2;
	d2_val = 0;
	//secret = 5
	secret1 = 2;
	secret2 = 3;
	
	
	// 

  
  
  /**
		Step 6: Copy the randomly generated values into the respective
				share objects using the circuit object method PutINGate()
				for my inputs and PutDummyINGate() for the other parties input.
				Also mention who is sharing the object.
	*/
	
	
	/*
	
	eucl = (a-c)^2 + (b-d)^2
	eucl =  (a1-c1)*(a1-c1)+(a1-c1)*(a2-c2)+(a2-c2)*(a1-c1)+(a2-c2)*(a2-c2) --> (a-c)*(a-c)
		+
		(b1-d1)*(b1-d1)+(b1-d1)*(b2-d2)+(b2-d2)*(b1-d1)+(b2-d2)*(b2-d2) --> (b-d)*(b-d)
		
	S1 can compute a1-c1 and b1-d1
	S2 can compute a2-c2 and b2-c2
	*/
	if(role == SERVER) {
		local_factor_1 = a1_val-c1_val; 
		local_factor_2 = b1_val-d1_val;
		
		s_local1_S = circ->PutINGate(local_factor_1,bitlen,SERVER);
		s_local2_S = circ->PutINGate(local_factor_2,bitlen,SERVER);
		s_secret1 = circ->PutINGate(secret1,bitlen,SERVER);

		s_local1_C = circ->PutDummyINGate( bitlen);
		s_local2_C = circ->PutDummyINGate(bitlen);
		s_secret2 = circ->PutDummyINGate(bitlen);

		//s_Dummy= circ->PutINGate(b_val, bitlen, SERVER);
		//circ->PutPrintValueGate(s_A1, "SERVER SA");

	} else { //role == CLIENT
		local_factor_1 = a2_val-c2_val; 
		local_factor_2 = b2_val-d2_val;
		
		
		s_local1_S = circ->PutDummyINGate(bitlen);
		s_local2_S = circ->PutDummyINGate(bitlen);
		s_secret1 = circ->PutDummyINGate(bitlen);

		s_local1_C = circ->PutINGate(local_factor_1, bitlen, CLIENT);
		s_local2_C = circ->PutINGate(local_factor_2, bitlen, CLIENT);
		s_secret2 = circ->PutINGate(secret2,bitlen,CLIENT);


		//s_Dummy = circ->PutINGate(b_val, bitlen, SERVER);
		//circ->PutPrintValueGate(s_A2, "CLIENT SA");

	}
  
  
  /**
		Step 7: Call the build method for building the circuit for the
				problem by passing the shared objects and circuit object.
				Don't forget to type cast the circuit object to type of share
	*/

	s_out = BuildFirstCircuit(role,s_local1_S, s_local2_S, s_local1_C, s_local2_C, s_secret1, s_secret2,
			(ArithmeticCircuit*) circ);


	/**
		Step 8: Modify the output receiver based on the role played by
				the server and the client. This step writes the output to the
				shared output object based on the role.
	*/
	
	
	
		circ->PutPrintValueGate(s_out, "DEBAJO BUILD");	
	
	//s_out = circ->PutOUTGate(s_out, ALL);
	
	//circ->PutPrintValueGate(s_out, "Share S_OUT");



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
  
  
  
  share* BuildFirstCircuit(e_role role, share *s_local1_S, share *s_local2_S, share *s_local1_C, share *s_local2_C,
			   sahre *s_secret1, share *s_secret2,
		ArithmeticCircuit *ac) {

	  //The circuit will solve the euclidean distance between a and b, without square root.
	  // Euclidean_distance = ()
	share* out;
	share* a1_sub_c1_square;
	share* a2_sub_c2_square;
	share* b1_sub_d1_square;
	share* b2_sub_d2_square;
	share* a1subc1_mul_a2subc2;
	share* b1subd1_mul_b2subd2;
	  
	uint32_t output;

	uint32_t bitlen=32;
	  
	share* rando;
	  

	//(a1-c1)^2
	a1_sub_c1_square = ac->PutMULGate(s_local1_S,s_local1_S);
	ac->PutPrintValueGate(a1_sub_c1_square, "a1_sub_c1_square");
	 //(a2-c2)^2 
	a2_sub_c2_square = ac->PutMULGate(s_local1_C,s_local1_C);
	ac->PutPrintValueGate(a2_sub_c2_square, "a2_sub_c2_square");
	
	// (a1-c1)*(a2-c2)  
	a1subc1_mul_a2subc2 = ac->PutMULGate(s_local1_S,s_local1_C);
	ac->PutPrintValueGate(a1subc1_mul_a2subc2, "(a1-c1)*(a2-c2)");
	//  (a1-c1)*(a2-c2) + (a1-c1)*(a2-c2)
	a1subc1_mul_a2subc2 = ac->PutADDGate(a1subc1_mul_a2subc2,a1subc1_mul_a2subc2);
	
	//(b1-d1)^2
	b1_sub_d1_square = ac->PutMULGate(s_local2_S,s_local2_S);
	//(b2-d2)^2  
	b2_sub_d2_square = ac->PutMULGate(s_local2_C,s_local2_C);
	ac->PutPrintValueGate(b2_sub_d2_square, "b2d2 square");

 	//(a1-c1)*(a2-c2)
	b1subd1_mul_b2subd2 = ac->PutMULGate(s_local2_S,s_local2_C);
	//ac->PutPrintValueGate(a1subc1_mul_a2subc2, "(b1-d1*b2-d2");
	//  (b1-d1)*(b2-d2) + (b1-d1)*(b2-d2)
	b1subd1_mul_b2subd2 = ac->PutADDGate(b1subd1_mul_b2subd2,b1subd1_mul_b2subd2);
	  
	  
	  
	
	out = ac->PutADDGate(a1_sub_c1_square,b1_sub_d1_square);
	out = ac->PutADDGate(out,a1subc1_mul_a2subc2);
	out = ac->PutADDGate(out,b1subd1_mul_b2subd2);
	out = ac->PutADDGate(out,a2_sub_c2_square);
	out = ac->PutADDGate(out,b2_sub_d2_square);
	out = ac->PutADDGate(out,s_secret1);
	out = ac->PutADDGate(out,s_secret2);


	ac->PutPrintValueGate(out, "Euclidean Distance inside circuit");


	/*	
	ac->PutPrintValueGate(s_localC, "Local Cliente");
	ac->PutPrintValueGate(s_localS, "Local Server");
	ac->PutPrintValueGate(s_a1, "Share A1");
	ac->PutPrintValueGate(s_b1, "Share B1");
	ac->PutPrintValueGate(s_a2, "Share A2");
	ac->PutPrintValueGate(s_b2, "Share B2");
	*/
	//ac->PutPrintValueGate(s_b1, "Share B1");
	  
	//rando = ac->PutSharedOUTGate(out);
	//	ac->PutPrintValueGate(rando, "Random");
	//out = ac->PutSharedOUTGate(out);

	return out;
}
  
