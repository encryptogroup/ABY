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
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <stdio.h>
#include <ios>
#include <fstream>


namespace patch
{
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}


int32_t test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing,
		    std::vector<long> x_start,std::vector<long> y_start,
		    std::vector<long> x_end, std::vector<long> y_end
		    ) {
    std::cout << "INDISDE" << std::endl;

	auto start = std::chrono::system_clock::now();

	/**
		Step 1: Create the ABYParty object which defines the basis of all the
		 	 	operations which are happening.	Operations performed are on the
		 	 	basis of the role played by this object.
	*/
	bitlen = 64;
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
  	Circuit* ac = sharings[S_ARITH]->GetCircuitBuildRoutine();

  
  

	double output;
	int n_vals = x_start.size();
	
	
	

	double distance;

	//# initialize epsilon and minLns values
	double epsilon =135000000;// 13500000000;//eps 
	int minLns = 2;//m

	//int no_of_lines = len(lines) 
	int no_of_lines = 10; // in general number of columns 
	//# dictionary to store neighborhood information of line segments
	std::map< std::string, std::map< std::string, std::vector<int> > > neighborhood;
	
	int sum_minLns = 0;
	int max_minLns = -1;
	//int min_minLns = 70432;
	uint64_t total_distance = 0;

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

	
	auto start1 = std::chrono::high_resolution_clock::now();
	for(int l = 0; l < no_of_lines; l++){
		if(neighborhood.count(patch::to_string(l))==0){

			//neighborhood[patch::to_string(l)]["neighbors"].push_back(0);
			neighborhood[patch::to_string(l)]["ncounter"].push_back(0);
			neighborhood[patch::to_string(l)]["cluster"].push_back(0);
		}
					
		for (int ll = l+1; ll < no_of_lines; ll++){
		
			if(role == SERVER) {

				// Two consecutive line segments. We need start and end of both
				/**
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
				s2_y_next_end = circ->PutDummyINGate( bitlen);*/
				s1_x_start = circ->PutINGate((uint64_t)x_start.at(l),bitlen,SERVER);
				s1_y_start = circ->PutINGate((uint64_t) y_start.at(l),bitlen,SERVER);
				s1_x_end = circ->PutINGate((uint64_t) x_end.at(l),bitlen,SERVER);
				s1_y_end = circ->PutINGate((uint64_t) y_end.at(l),bitlen,SERVER);
				
				s1_x_next_start = circ->PutINGate((uint64_t) x_start.at(ll),bitlen,SERVER);
				s1_y_next_start = circ->PutINGate((uint64_t)  y_start.at(ll),bitlen,SERVER);
				s1_x_next_end = circ->PutINGate((uint64_t)  x_end.at(ll),bitlen,SERVER);
				s1_y_next_end = circ->PutINGate((uint64_t) y_end.at(ll),bitlen,SERVER);

				s2_x_start = circ->PutDummyINGate( bitlen);
				s2_y_start = circ->PutDummyINGate( bitlen);
				s2_x_end = circ->PutDummyINGate( bitlen);
				s2_y_end = circ->PutDummyINGate( bitlen);
				
				s2_x_next_start = circ->PutDummyINGate( bitlen);
				s2_y_next_start = circ->PutDummyINGate( bitlen);
				s2_x_next_end = circ->PutDummyINGate( bitlen);
				s2_y_next_end = circ->PutDummyINGate( bitlen);

			} else { //role == CLIENT
			/**
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
				s1_y_next_end = circ->PutDummyINGate( bitlen);*/
				
				s2_x_start = circ->PutINGate((uint64_t) x_start.at(l),bitlen,CLIENT);
				s2_y_start = circ->PutINGate((uint64_t) y_start.at(l),bitlen,CLIENT);
				s2_x_end = circ->PutINGate((uint64_t) x_end.at(l),bitlen,CLIENT);
				s2_y_end = circ->PutINGate((uint64_t)y_end.at(l),bitlen,CLIENT);
				
				s2_x_next_start = circ->PutINGate((uint64_t) x_start.at(ll),bitlen,CLIENT);
				s2_y_next_start = circ->PutINGate((uint64_t) y_start.at(ll),bitlen,CLIENT);
				s2_x_next_end = circ->PutINGate((uint64_t) x_end.at(ll),bitlen,CLIENT);
				s2_y_next_end = circ->PutINGate((uint64_t)y_end.at(ll),bitlen,CLIENT);

				s1_x_start = circ->PutDummyINGate( bitlen);
				s1_y_start = circ->PutDummyINGate( bitlen);
				s1_x_end = circ->PutDummyINGate( bitlen);
				s1_y_end = circ->PutDummyINGate( bitlen);
				
				s1_x_next_start = circ->PutDummyINGate( bitlen);
				s1_y_next_start = circ->PutDummyINGate( bitlen);
				s1_x_next_end = circ->PutDummyINGate( bitlen);
				s1_y_next_end = circ->PutDummyINGate( bitlen);
				
				
			}	

			s_out = BuildFirstCircuit(role, 
						  s1_x_start, s1_y_start, s1_x_end, s1_y_end,//line 1 Server 1
						  s2_x_start,s2_y_start, s2_x_end, s2_y_end,//line 1 Server2
						  s1_x_next_start, s1_y_next_start, s1_x_next_end,s1_y_next_end, //line 2 server 1
						  s2_x_next_start,s2_y_next_start, s2_x_next_end, s2_y_next_end, //line 2 server 2
					(BooleanCircuit*) circ, (ArithmeticCircuit*) ac);

			s_out = circ->PutOUTGate(s_out,ALL);
			party->ExecCircuit();


			//HERE WE HAVE THE 4 DISTANCE METRICS 
			output = s_out->get_clear_value<uint64_t>();
			distance = (double)output;
			if(role == SERVER){
				std::cout<< " DISTANCE BETWEEN " <<l<<" ANS " << ll << "-->" << distance << std::endl;
			}
			
			
			/** ++++++++++++ ABOVE IS OK ++++++++++++++++++++ */

		/** check whether the second line segment is in the neighborhood dictionary or not
            # this part is used for speed up the distance computation. If we consider distances
            # between every line segment as a matrix, then it is obvious that we will have a 
            # symmetric matrix after we compute all of the distances. therefore, it is faster
            # to compute distances above or below the diagonal. */

			if(neighborhood.count(patch::to_string(ll))==0){

				neighborhood[patch::to_string(ll)]["ncounter"].push_back(0);
				neighborhood[patch::to_string(ll)]["cluster"].push_back(0);
			}// check that whether the resulting distance is less than or equal to epsilon
			if (distance <= epsilon){
				neighborhood[patch::to_string(l)]["neighbors"].push_back(ll);
    				neighborhood[patch::to_string(l)]["ncounter"].assign(1,neighborhood[patch::to_string(l)]["ncounter"].at(0)+1);
				neighborhood[patch::to_string(ll)]["neighbors"].push_back(l);
    				neighborhood[patch::to_string(ll)]["ncounter"].assign(1,neighborhood[patch::to_string(ll)]["ncounter"].at(0)+1);
			}			
			party -> Reset();
		}
	}	
	/**if(role == SERVER)
	{
		for(auto itr1 = neighborhood.begin(); itr1 != neighborhood.end(); itr1++)
		{
			std::cout << itr1->first << ' '; // Add space to separate entries on the same line
			// itr1->second represents map<string, vector<string>> stored in test.
			for(auto itr2 = itr1->second.begin (); itr2 != itr1->second.end (); itr2++)
			{
				std::cout << itr2->first << ' ';
				// itr2->second represents vector<string> stored in map<string, vector<string>> which is stored in test.
				for(auto itr3 = itr2->second.begin(); itr3 != itr2->second.end(); itr3++)
				{
					std::cout << *itr3 << ' ';
				}
			}
			std::cout << std::endl;
		}
	}*/
// initialize the first cluster id
int cluster_id = 1;

//# shuffle the keys of neighborhood dictionary 
std::vector<std::string> keys ;

std::pair<std::string,std::vector<int> > me; // what a map<int, int> is made of
for(std::map< std::string, std::map< std::string, std::vector<int> > >::iterator it = neighborhood.begin(); it != neighborhood.end(); ++it) 
{
  keys.push_back(it->first);
}
std::random_shuffle ( keys.begin(), keys.end() );


//std::cout <<"JUST SHUFFLED "<<std::endl;
for (std::vector<std::string>::const_iterator i = keys.begin(); i != keys.end(); ++i)
{
    std::cout << *i << ' ';
}
    
int noise_counter = 0;

std::map<std::string,std::vector<int> > clusters;
std::vector<int> temp_array;

std::cout <<"DISTANCES OK-->"<<keys.size()<< std::endl;

std::vector<std::string> cluster_labels ;
for(int i= 0; i< keys.size();i++)
{
	//# check whether the line segment is assigned to a cluster or not
	if(neighborhood[patch::to_string(keys.at(i))]["cluster"].at(0) < 1)
	{
		// # check that the number of line segments in a given line segment's neighborhood  
		if(neighborhood[patch::to_string(keys.at(i))]["ncounter"].at(0) < minLns)
		{
			neighborhood[patch::to_string(keys.at(i))]["status"].push_back(-1);

		}
		else
		{
			// # push each element in the neighborhood of a cluster into a temporary queue
			// # if a given line segment does not assigned to a cluster

			for(int llls = 0 ; llls < neighborhood[patch::to_string(keys.at(i))]["neighbors"].size();llls++)
			{
				if(neighborhood[patch::to_string(neighborhood[patch::to_string(keys.at(i))]["neighbors"].at(llls))]["cluster"].at(0) 			< 1)
				{
					temp_array.push_back(neighborhood[patch::to_string(i)]["neighbors"].at(llls));
				}

			}
			//# the number of elements in the temporary array should be greater than or equal to minLns value
			if(temp_array.size() >= minLns)
			{
				//# initialize new key value for the new cluster if it didn't initialized before
				// no needed since using a vector ?
				if(clusters.count(patch::to_string(cluster_id))==0)
				{

					clusters[patch::to_string(cluster_id)].push_back(cluster_id);
				}
				//# add the line segment into the cluster
				if (std::binary_search(clusters[patch::to_string(cluster_id)].begin(), 	clusters[patch::to_string(cluster_id)].end(), std::stoi(keys.at(i))))
				{
					//the line exists in the cluster
				}
				else
				{
					clusters[patch::to_string(cluster_id)].push_back(std::stoi(keys.at(i)));

				}

				neighborhood[patch::to_string(keys.at(i))]["cluster"].assign(1,cluster_id);
				// add every non initialized line segment 
				for(int ls= 0 ; ls < neighborhood[patch::to_string(keys.at(i))]["neighbors"].size(); ls++)
				{

					if(neighborhood[patch::to_string(neighborhood[keys.at(i)]["neighbors"].at(ls))]["cluster"].at(0)< 1)
					{
						neighborhood[patch::to_string(neighborhood[patch::to_string(keys.at(i))]["neighbors"].at(ls))]["cluster"].push_back(cluster_id);
						if (std::find(clusters[patch::to_string(cluster_id)].begin(), clusters[patch::to_string(cluster_id)].end(), neighborhood[patch::to_string(keys.at(i))]["neighbors"].at(ls)) != clusters[patch::to_string(cluster_id)].end())
						{
						//the line exists in the cluster
						}
						else
						{
							clusters[patch::to_string(cluster_id)].push_back(neighborhood[patch::to_string(keys.at(i))]["neighbors"].at(ls));
						}
					}
				}//LOOP CHARLIE

				//from now on the code follows the expand cluster algorithm in the TRACLUS paper

				std::vector<int> queue = neighborhood[keys.at(i)]["neighbors"];
				//std::cout <<"INITIAL QUEUE "<<queue.size()<< std::endl;

				int j = 0;
				while(queue.size()>0 || j < 3)
				{

					for(int llls = 0 ; llls < neighborhood[patch::to_string(queue.at(0))]["neighbors"].size();llls++)
					{

						if(neighborhood[patch::to_string(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(llls))]["cluster"].at(0) < 1)
						{
							temp_array.push_back(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(llls));
						}

					}
					//# the number of elements in the temporary array should be greater than or equal to minLns value
					if(temp_array.size() >= minLns)
					{
						for(int lls = 0; lls < neighborhood[patch::to_string(queue.at(0))]["neighbors"].size(); lls++)
						{

							if(neighborhood[patch::to_string(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(lls))]["cluster"].at(0) < 1)
							{
								neighborhood[patch::to_string(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(lls))]["cluster"].assign(1,cluster_id);

								if (std::find(clusters[patch::to_string(cluster_id)].begin(), clusters[patch::to_string(cluster_id)].end(), neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(lls)) != clusters[patch::to_string(cluster_id)].end())
								{
								}
								else
								{

									if(neighborhood[patch::to_string(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(lls))]["cluster"].at(0) == 0)
									{
										queue.push_back(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(lls));
									}
									clusters[patch::to_string(cluster_id)].push_back(neighborhood[patch::to_string(queue.at(0))]["neighbors"].at(lls));

								}
							}

						}
					}
				//}
					queue.erase(queue.begin()+0);
					j++;
				}
				cluster_id = cluster_id+1;
			}
			else
			{
			neighborhood[patch::to_string(keys.at(i))]["status"].push_back(-1);
			}
		}
	}
	
}

			
		/**	
		if(role == SERVER)
		{

			std::cout <<"THIS IS CLUSTER SIZE"<<patch::to_string(clusters.size())<<std::endl;

			for(auto itr1 = clusters.begin(); itr1 != clusters.end(); itr1++)
			{
				std::cout << itr1->first << ' '; // Add space to separate entries on the same line
				// itr1->second represents map<string, vector<string>> stored in test.
				for(auto it2 = itr1->second.begin(); it2 != itr1->second.end(); ++it2)
				{
					std::cout << *it2 << " ";
				}

				std::cout << std::endl;
			}
			
		}*/
		
		if(role == SERVER)
	{
		for(auto itr1 = neighborhood.begin(); itr1 != neighborhood.end(); itr1++)
		{
			std::cout << itr1->first << ' '; // Add space to separate entries on the same line
			// itr1->second represents map<string, vector<string>> stored in test.
			for(auto itr2 = itr1->second.begin (); itr2 != itr1->second.end (); itr2++)
			{
				std::cout << itr2->first << ' ';
				// itr2->second represents vector<string> stored in map<string, vector<string>> which is stored in test.
				for(auto itr3 = itr2->second.begin(); itr3 != itr2->second.end(); itr3++)
				{
					std::cout << *itr3 << ' ';
				}
			}
			std::cout << std::endl;
		}
	}

	std::cout <<"CLUSTERS SIZE "<<clusters.size()<<std::endl;





  
	
	delete party;
	auto finish = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> elapsed = finish - start1;

	std::cout << "Elapsed time: " << elapsed.count() << " s\n";

	//freopen ("logfile.log","a",stdout);
	
    	// Some computation here
    	auto end = std::chrono::system_clock::now();
	std::chrono::duration<double> elapsed_seconds = end-start;
   	std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    	std::cout << "finished computation at " << std::ctime(&end_time)<< "elapsed time: " << elapsed_seconds.count() << "s\n";
	      
  	/**printf (system(("Starting time: "+patch::to_string(std::ctime(&end_time))+"\n").c_str()));
	printf (system(("Execution time: "+ patch::to_string(elapsed_seconds.count())).c_str()));
	printf(system(("Number of clusters: "+ patch::to_string(clusters.size())+"\n").c_str()));
	printf(system(("minLns: "+ patch::to_string(minLns)+ "\n").c_str()));
	printf(system(("Number of line segments: "+patch::to_string(no_of_lines)+"\n").c_str()) );
	printf(system(("Epsilon: "+ patch::to_string(epsilon)+"\n").c_str() ));
	printf("-------------------------------------------");
 	fclose (stdout);*/
	std::ofstream outfile;
	std::ofstream log("logfile.txt", std::ios_base::app | std::ios_base::out);

	/**log << system(("Starting time: "+patch::to_string(std::ctime(&end_time))+"\n").c_str());
	log << system(("Execution time: "+ patch::to_string(elapsed_seconds.count())).c_str());
	log << system(("Number of clusters: "+ patch::to_string(clusters.size())+"\n").c_str());
	log << system(("minLns: "+ patch::to_string(minLns)+ "\n").c_str());
	log << system(("Number of line segments: "+patch::to_string(no_of_lines)+"\n").c_str());
	log << system(("Epsilon: "+ patch::to_string(epsilon)+"\n").c_str());*/
	std::string role_string;
	if(role == SERVER){
	role_string = " SERVER ";
	}else{
	role_string = " CLIENT " ;
	}
	log << "ROLE "+ role_string +"\n";

	log << "Starting time: "+ patch::to_string(std::ctime(&end_time))+"\n";
	log << "Execution time: "+ patch::to_string(elapsed_seconds.count())+"\n";
	log << "Number of clusters: "+ patch::to_string(clusters.size())+"\n";
	for(auto itr2 =clusters.begin (); itr2 != clusters.end (); itr2++)
	{
				std::cout <<"Cluster no"<< itr2->first << ": "<< clusters[patch::to_string(itr2->first)].size()<<std::endl ;
				// itr2->second represents vector<string> stored in map<string, vector<string>> which is stored in test.
				
		log << "Cluster no "+ patch::to_string(itr2->first)+": "+ patch::to_string(clusters[patch::to_string(itr2->first)].size())+ "\n";

	}	
	log << "minLns: "+ patch::to_string(minLns)+ "\n";
	log << "Number of line segments: "+patch::to_string(no_of_lines)+"\n";
	log << "Epsilon: "+ patch::to_string(epsilon)+"\n";
	log << "------------------------------------------------------ \n";
return 0;
	}
	
  
  
  
  share* BuildFirstCircuit(e_role role,
			   share* s1_x_start,  share* s1_y_start, share* s1_x_end, share* s1_y_end, 
			   share* s2_x_start,share* s2_y_start, share*  s2_x_end, share* s2_y_end,
			   share* s1_x_next_start,  share* s1_y_next_start, share* s1_x_next_end, share* s1_y_next_end, 
			   share* s2_x_next_start,share* s2_y_next_start, share*  s2_x_next_end, share* s2_y_next_end,
			   BooleanCircuit* circ, ArithmeticCircuit* ac) {

	//share* out;
	share* x_start;
	share* y_start;
	share* x_end;
	share* y_end;
	share* x_next_start;
	share* y_next_start;
	share* x_next_end;
	share* y_next_end;

	uint64_t output;
	uint64_t bitlen=64;

	share* rando;

	x_start = circ->PutADDGate(s1_x_start,s2_x_start);

	y_start = circ->PutADDGate(s1_y_start,s2_y_start);

	x_end = circ->PutADDGate(s1_x_end,s2_x_end);

	  y_end = circ->PutADDGate(s1_y_end,s2_y_end);
	/**
	  	circ->PutPrintValueGate(x_start, "X START");	
		circ->PutPrintValueGate(y_start, "Y START");	
		circ->PutPrintValueGate(x_end, "X END");
		circ->PutPrintValueGate(y_end, "Y END");*/	

	x_next_start = circ->PutADDGate(s1_x_next_start,s2_x_next_start);
	y_next_start = circ->PutADDGate(s1_y_next_start,s2_y_next_start);
	x_next_end = circ->PutADDGate(s1_x_next_end,s2_x_next_end);
	y_next_end = circ->PutADDGate(s1_y_next_end,s2_y_next_end);
	/**circ->PutPrintValueGate(x_next_start, "X x_next_start");	
		circ->PutPrintValueGate(y_next_start, "Y y_next_start");	
		circ->PutPrintValueGate(x_next_end, "X x_next_end");
		circ->PutPrintValueGate(y_next_end, "Y y_next_end");*/
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
	res_x = ac->PutB2AGate(res_y)

	res_x = ac->PutMULGate(res_x, res_x);
	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_start, y_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_start, y_next_start, check_sel);
	t_b = circ->PutMUXGate(y_start, y_next_start, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
res_y = ac->PutB2AGate(res_y)

	res_y = ac->PutMULGate(res_y, res_y);
	/** Following code performs out = res_y + res_x*/
	ed1 = ac->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	
	//circ->PutPrintValueGate(ed1, "ED 1");	
	
	  
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

	res_y = ac->PutB2AGate(res_y)

	res_y = ac->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	ed2 = ac->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	


	//circ->PutPrintValueGate(ed2, "ED 2");
	  
	  
	  /** Distance metric 3: (x1_start-x2_end)^2 + (y1_start-y2_end)^2*/
	  
	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = circ->PutGTGate(x_start, x_next_end);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(x_start, x_next_end, check_sel);
	t_b = circ->PutMUXGate(x_start, x_next_end, check_sel_inv);

	res_x = circ->PutSUBGate(t_a, t_b);
	res_x = ac->PutB2AGate(res_y)

	res_x = ac->PutMULGate(res_x, res_x);
	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_start, y_next_end);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_start, y_next_end, check_sel);
	t_b = circ->PutMUXGate(y_start, y_next_end, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
	res_y = ac->PutB2AGate(res_y)

	res_y = ac->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	  
	ed3 = ac->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	


	//circ->PutPrintValueGate(ed3, "ED 3");	
	  
	  
	  /** Distance metric 4: (x2_start-x1_end)^2 + (y2_start-y1_end)^2*/
	/** Following code performs (x2-x1)*(x2-x1) */
	check_sel = circ->PutGTGate(x_end, x_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(x_end, x_next_start, check_sel);
	t_b = circ->PutMUXGate(x_end, x_next_start, check_sel_inv);

	 
	res_x = circ->PutSUBGate(t_a, t_b);
	res_x = ac->PutB2AGate(res_x)
	res_x = ac->PutMULGate(res_x, res_x);

	/** Following code performs (y2-y1)*(y2-y1) */
	check_sel = circ->PutGTGate(y_end, y_next_start);
	check_sel_inv = circ->PutINVGate(check_sel);
	t_a = circ->PutMUXGate(y_end, y_next_start, check_sel);
	t_b = circ->PutMUXGate(y_end, y_next_start, check_sel_inv);

	res_y = circ->PutSUBGate(t_a, t_b);
	res_y = ac->PutB2AGate(res_y)

	res_y = ac->PutMULGate(res_y, res_y);

	/** Following code performs out = res_y + res_x*/
	ed4 = ac->PutADDGate(res_x, res_y);


	/**circ->PutPrintValueGate(x_start, "X START");
	circ->PutPrintValueGate(y_start, "Y START");	
	circ->PutPrintValueGate(x_end, "X END");	
	circ->PutPrintValueGate(y_end, "Y END");*/	


	//circ->PutPrintValueGate(ed4, "ED 4");	

	  
	out = ac->PutADDGate(ed1, ed2);
	out = ac->PutADDGate(out, ed3);
	out = ac->PutADDGate(out, ed4);
	ac->PutPrintValueGate(out, "DISTANCE");	
	  
	  //NOT WORKING
	//out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);
	  
	  
	 //	std::cout<< " I AM INSIDE. This Is X " << out_vals[0] << std::endl;

	return out;
}
  
