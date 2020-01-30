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
	

	uint32_t output;

	
	uint32_t x1_start [4] = {479942, 470497, 470499, 472800};
	uint32_t y1_start [4]= {4576077, 4599243, 4599245, 4598039};
	uint32_t x1_end [4] = {470500, 470494, 472798, 472802};
	uint32_t y1_end [4] = {4599247, 4599244, 4598039, 4598034};



	uint32_t x2_start [4] = {2, 3,1, 4};
	uint32_t y2_start [4] = {7, 7, 5, 1};
	uint32_t x2_end [4]  = {0, 6, 6, 2};
	uint32_t y2_end [4]   = {3, 6, 1, 6};

	uint32_t distance;

	# initialize epsilon and minLns values
	int epsilon = eps 
	int minLns = m

	//int no_of_lines = len(lines) 
	int no_of_lines = 4 // in general number of columns 
	//# dictionary to store neighborhood information of line segments
std::map< std::string,
              std::map<std::string,std::vector<int> > > neighborhood;
	
	int sum_minLns = 0
	int max_minLns = -1
	int min_minLns = 70432
	int total_distance = 0

	uint32_t n = 4;

  /**
		Step 4: Creating the share objects - Values A and B which
				are used as input to the computation function. Also s_out
				which stores the output.
	*/

	share  *s1_x_start, *s1_y_start, *s1_x_end,
	*s1_y_end, *s2_x_start, *s2_y_start, *s2_x_end, *s2_y_end,
	
	*s1_x_next_start, *s1_y_next_start, *s1_x_next_end,
	*s1_y_next_end, *s2_x_next_start, *s2_y_next_start, *s2_x_next_end, *s2_y_next_end,
	
	*s_out;

	
	
	for(int l = 0; l < no_of_lines; l++){
		if(neighborhood.count(std::to_string(l))==0){

			//neighborhood[patch::to_string(l)]["neighbors"].push_back(0);
			neighborhood[patch::to_string(l)]["ncounter"].push_back(0);
			neighborhood[patch::to_string(l)]["cluster"].push_back(0);
		}
					
		for (int ll = l+1; ll < no_of_lines; ll++){
		
			if(role == SERVER) {

				// Two consecutive line segments. We need start and end of both
				s1_x_start = circ->PutINGate(x1_start[l],bitlen,SERVER);
				s1_y_start = circ->PutINGate(y1_start[l],bitlen,SERVER);
				s1_x_end = circ->PutINGate(x1_end[l],bitlen,SERVER);
				s1_y_end = circ->PutINGate(y1_end[l],bitlen,SERVER);
				
				s1_x_next_start = circ->PutINGate(x1_start[ll],bitlen,SERVER);
				s1_y_next_start = circ->PutINGate(y1_start[ll],bitlen,SERVER);
				s1_x_next_end = circ->PutINGate(x1_end[ll],bitlen,SERVER);
				s1_y_next_end = circ->PutINGate(y1_end[ll],bitlen,SERVER);

				s2_x_start = circ->PutDummyINGate( bitlen);
				s2_y_start = circ->PutDummyINGate( bitlen);
				s2_x_end = circ->PutDummyINGate( bitlen);
				s2_y_end = circ->PutDummyINGate( bitlen);
				
				s2_x_next_start = circ->PutDummyINGate( bitlen);
				s2_y_next_start = circ->PutDummyINGate( bitlen);
				s2_x_next_end = circ->PutDummyINGate( bitlen);
				s2_y_next_end = circ->PutDummyINGate( bitlen);

			} else { //role == CLIENT
				s2_x_start = circ->PutINGate(x2_start[l],bitlen,CLIENT);
				s2_y_start = circ->PutINGate(y2_start[l],bitlen,CLIENT);
				s2_x_end = circ->PutINGate(x2_end[l],bitlen,CLIENT);
				s2_y_end = circ->PutINGate(y2_end[l],bitlen,CLIENT);
				
				s2_x_next_start = circ->PutINGate(x2_start[ll],bitlen,CLIENT);
				s2_y_next_start = circ->PutINGate(y2_start[ll],bitlen,CLIENT);
				s2_x_next_end = circ->PutINGate(x2_end[ll],bitlen,CLIENT);
				s2_y_next_end = circ->PutINGate(y2_end[ll],bitlen,CLIENT);
				
				s1_x_start = circ->PutDummyINGate( bitlen);
				s1_y_start = circ->PutDummyINGate( bitlen);
				s1_x_end = circ->PutDummyINGate(bitlen);
				s1_y_end = circ->PutDummyINGate( bitlen);

				s1_x_next_start = circ->PutDummyINGate( bitlen);
				s1_y_next_start = circ->PutDummyINGate( bitlen);
				s1_x_next_end = circ->PutDummyINGate(bitlen);
				s1_y_next_end = circ->PutDummyINGate( bitlen);
			}	

			s_out = BuildFirstCircuit(role, 
						  s1_x_start, s1_y_start, s1_x_end, s1_y_end,//line 1 Server 1
						  s2_x_start,s2_y_start, s2_x_end, s2_y_end,//line 1 Server2
						  s1_x_next_start, s1_y_next_start, s1_x_next_end,s1_y_next_end, //line 2 server 1
						  s2_x_next_start,s2_y_next_start, s2_x_next_end, s2_y_next_end, //line 2 server 2
					(BooleanCircuit*) circ);

			s_out = circ->PutOUTGate(s_out,ALL);

			circ->PutPrintValueGate(s_out, "DEBAJO BUILD");	

			//s_out = circ->PutOUTGate(s_out, ALL);

			//circ->PutPrintValueGate(s_out, "Share S_OUT");
			party->ExecCircuit();


			//output = s_out->get_clear_value<uint32_t>();

			//uint32_t out_bitlen , out_nvals , *out_vals;
			//s_out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);

			//HERE WE HAVE THE 4 DISTANCE METRICS 
			output = s_out->get_clear_value<uint32_t>();
			distance = output;
		/** check whether the second line segment is in the neighborhood dictionary or not
            # this part is used for speed up the distance computation. If we consider distances
            # between every line segment as a matrix, then it is obvious that we will have a 
            # symmetric matrix after we compute all of the distances. therefore, it is faster
            # to compute distances above or below the diagonal. */

			if(neighborhood.count(std::to_string(ll))==0){

				neighborhood[patch::to_string(ll)]["ncounter"].push_back(0);
				neighborhood[patch::to_string(ll)]["cluster"].push_back(0);
			}			// check that whether the resulting distance is less than or equal to epsilon
			if (ed <= epsilon){
				neighborhood[patch::to_string(l)]["neighbors"].push_back(ll);
    				neighborhood[patch::to_string(l)]["ncounter"].assign(1,neighborhood[patch::to_string(l)]["ncounter"].at(0)+1);
				neighborhood[std::to_string(ll)]['neighbors'].push_back(l);
    				neighborhood[patch::to_string(ll)]["ncounter"].assign(1,neighborhood[patch::to_string(ll)]["ncounter"].at(0)+1);
			}


			
			party -> Reset();
		}
	}

	delete party;
	return 0;
}
  
  
  
  share* BuildFirstCircuit(e_role role,
			   share* s1_x_start,  share* s1_y_start, share* s1_x_end, share* s1_y_end, 
			   share* s2_x_start,share* s2_y_start, share*  s2_x_end, share* s2_y_end,
			   share* s1_x_next_start,  share* s1_y_next_start, share* s1_x_next_end, share* s1_y_next_end, 
			   share* s2_x_next_start,share* s2_y_next_start, share*  s2_x_next_end, share* s2_y_next_end,
			   BooleanCircuit* circ) {
 
	//share* out;
	share* x_start;
	share* y_start;
	share* x_end;
	share* y_end;
	share* x_next_start;
	share* y_next_start;
	share* x_next_end;
	share* y_next_end;

	uint32_t output;
	uint32_t bitlen=32;

	share* rando;

	x_start = circ->PutADDGate(s1_x_start,s2_x_start);
	y_start = circ->PutADDGate(s1_y_start,s2_y_start);
	x_end = circ->PutADDGate(s1_x_end,s2_x_end);
	y_end = circ->PutADDGate(s1_y_end,s2_y_end);
	  
	x_next_start = circ->PutADDGate(s1_x_next_start,s2_x_next_start);
	y_next_start = circ->PutADDGate(s1_y_next_start,s2_y_next_start);
	x_next_end = circ->PutADDGate(s1_x_next_end,s2_x_next_end);
	y_next_end = circ->PutADDGate(s1_y_next_end,s2_y_next_end);

	//uint32_t out_bitlen , out_nvals , *out_vals;
	  
	share* out, *t_a, *t_b, *res_x, *res_y, *check_sel,*check_sel_inv,
	  *ed1, *ed2, *ed3, *ed4;

	  
/**Following code performs the euclidean distance between 2 points
	We need distance metrics between 4 points in two consecutive line segments
	Thus, the following code needs to be implemented 4 times*/	
	  

	/** Distance metric 1: (x1_start-x2_start)^2 + (y1_start-y2_start)^2*/
	  
	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = circ->PutGTGate(x_start, x_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(x_start, x_next_start, check_sel);
	t_b = circ->PutMUXGate(x_start, x_next_start, check_sel_inv);

	res_x = circ->PutSUBGate(t_a, t_b);
	res_x = circ->PutMULGate(res_x, res_x);

	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_start, y_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_start, y_next_start, check_sel);
	t_b = circ->PutMUXGate(y_start, y_next_start, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
	res_y = circ->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	ed1 = circ->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	
	circ->PutPrintValueGate(ed1, "ED 1");	
	
	  
	/** Distance metric 2: (x1_end-x2_end)^2 + (y1_start-y2_start)^2*/
	  
	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = circ->PutGTGate(x_end, x_next_end);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(x_end, x_next_end, check_sel);
	t_b = circ->PutMUXGate(x_end, x_next_end, check_sel_inv);

	res_x = circ->PutSUBGate(t_a, t_b);
	res_x = circ->PutMULGate(res_x, res_x);

	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_end, y_next_end);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_end, y_next_end, check_sel);
	t_b = circ->PutMUXGate(y_end, y_next_end, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
	res_y = circ->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	ed2 = circ->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	


	circ->PutPrintValueGate(ed2, "ED 2");
	  
	  
	  /** Distance metric 3: (x1_start-x2_end)^2 + (y1_start-y2_end)^2*/
	  
	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = circ->PutGTGate(x_start, x_next_end);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(x_start, x_next_end, check_sel);
	t_b = circ->PutMUXGate(x_start, x_next_end, check_sel_inv);

	res_x = circ->PutSUBGate(t_a, t_b);
	res_x = circ->PutMULGate(res_x, res_x);

	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_start, y_next_end);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_start, y_next_end, check_sel);
	t_b = circ->PutMUXGate(y_start, y_next_end, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
	res_y = circ->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	ed3 = circ->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	


	circ->PutPrintValueGate(ed3, "ED 3");	
	  
	  
	  /** Distance metric 4: (x2_start-x1_end)^2 + (y2_start-y1_end)^2*/
	  
	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = circ->PutGTGate(x_end, x_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(x_end, x_next_start, check_sel);
	t_b = circ->PutMUXGate(x_end, x_next_start, check_sel_inv);

	res_x = circ->PutSUBGate(t_a, t_b);
	res_x = circ->PutMULGate(res_x, res_x);

	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_end, y_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_end, y_next_start, check_sel);
	t_b = circ->PutMUXGate(y_end, y_next_start, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
	res_y = circ->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	ed4 = circ->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	


	circ->PutPrintValueGate(ed4, "ED 4");	

	  
	out = circ->PutADDGate(ed1, ed2);
	out = circ->PutADDGate(out, ed3);
	out = circ->PutADDGate(out, ed4);

	  
	  //NOT WORKING
	//out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);
	  
	  
	 //	std::cout<< " I AM INSIDE. This Is X " << out_vals[0] << std::endl;

	return out;
}
  
