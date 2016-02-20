/**
 \file 		min-euclidean-dist-circuit.cpp
 \author 	michael.zohner@ec-spride.de
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
 \brief		Implementation of Minimum Euclidean Distance Circuit
 */
#include "min-euclidean-dist-circuit.h"

int32_t test_min_eucliden_dist_circuit(e_role role, char* address, seclvl seclvl, uint32_t dbsize,
		uint32_t dim, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing, e_sharing minsharing) {
	uint32_t bitlen = 8, i, j, temp, tempsum, maxbitlen=32;
	uint64_t output;
	ABYParty* party = new ABYParty(role, address, seclvl, maxbitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	uint32_t **serverdb, *clientquery;
	uint64_t verify;

	Circuit *distcirc, *mincirc;
	
	share ***Sshr, **Cshr, **Ssqr, *Csqr, *mindst;
	
	srand(time(NULL));

	//generate dbsize * dim * bitlen random bits as server db
	serverdb = (uint32_t**) malloc(sizeof(uint32_t*) * dbsize);
	for(i = 0; i < dbsize; i++) {
		serverdb[i] = (uint32_t*) malloc(sizeof(uint32_t) * dim);
		for(j = 0; j < dim; j++) {
			serverdb[i][j] = rand() % ((uint64_t) 1 << bitlen);
		}
	}
	//generate dim * bitlen random bits as client query
	clientquery = (uint32_t*) malloc(sizeof(uint32_t) * dim);
	for(j = 0; j < dim; j++) {
		clientquery[j] = rand() % ((uint64_t) 1 << bitlen);
	}

	distcirc = sharings[dstsharing]->GetCircuitBuildRoutine();
	mincirc = sharings[minsharing]->GetCircuitBuildRoutine();

	//set server input
	Sshr = (share***) malloc(sizeof(share**) * dbsize);
	for (i = 0; i < dbsize; i++) {
		Sshr[i] = (share**) malloc(sizeof(share*) * dim);
		for (j = 0; j < dim; j++) {
			Sshr[i][j] = distcirc->PutINGate(serverdb[i][j], bitlen, SERVER);
		}
	}

	Ssqr = (share**) malloc(sizeof(share*) * dbsize);
	for (i = 0; i < dbsize; i++) {
		tempsum = 0; 
		for (j = 0; j < dim; j++) {
			temp = serverdb[i][j];
			tempsum += (temp * temp);
		}
		Ssqr[i] = mincirc->PutINGate(tempsum, 2*bitlen+ceil_log2(dim), SERVER);
	}

	//set client input
	Cshr = (share**) malloc(sizeof(share*) * dim);
	tempsum = 0;
	for (j = 0; j < dim; j++) {
		temp = clientquery[j];
		Cshr[j] = distcirc->PutINGate(2*temp, bitlen+1, CLIENT);
		tempsum += (temp * temp);
	}
	Csqr = mincirc->PutINGate(tempsum, 2*bitlen+ceil_log2(dim), CLIENT);


	mindst = build_min_euclidean_dist_circuit(Sshr, Cshr, dbsize, dim, Ssqr, Csqr, distcirc, (BooleanCircuit*) mincirc);

	mindst = mincirc->PutOUTGate(mindst, ALL);

	party->ExecCircuit();

	output = mindst->get_clear_value<uint64_t>();

	CBitVector out;
	//out.AttachBuf(output, (uint64_t) AES_BYTES * nvals);

	cout << "Testing min Euclidean distance in " << get_sharing_name(dstsharing) << " and " <<
		get_sharing_name(minsharing) << " sharing: " << endl;

	cout << "Circuit result = " << output << endl;
	verify = verify_min_euclidean_dist(serverdb, clientquery, dbsize, dim);
	cout << "Verification result = " << verify << endl;

	//PrintTimings();

	//TODO free
	for(uint32_t i = 0; i < dbsize; i++) {
		free(serverdb[i]);
		free(Sshr[i]);
	}

	free(serverdb);
	free(Sshr);
	free(Ssqr);

	free(clientquery);
	free(Cshr);

	return 0;
}

//Build_
share* build_min_euclidean_dist_circuit(share*** S, share** C, uint32_t n, uint32_t d, share** Ssqr, share* Csqr,
		Circuit* distcirc, BooleanCircuit* mincirc) {
	share **distance, *temp, *mindist;
	uint32_t i, j;

	distance = (share**) malloc(sizeof(share*) * n);
	assert(mincirc->GetCircuitType() == C_BOOLEAN);

	for (i=0; i < n; i++) {
		distance[i] = distcirc->PutMULGate(S[i][0], C[0]);
		for (j=1; j < d; j++) {
			temp = distcirc->PutMULGate(S[i][j], C[j]);
			distance[i] = distcirc->PutADDGate(distance[i], temp);
		}
		temp = mincirc->PutADDGate(Ssqr[i], Csqr);
		distance[i] = mincirc->PutA2YGate(distance[i]);
		distance[i] = mincirc->PutSUBGate(temp, distance[i]);
	}
  
	mindist = mincirc->PutMinGate(distance, n);
	free(distance);
	return mindist;
}

uint64_t verify_min_euclidean_dist(uint32_t** serverdb, uint32_t* clientquery, uint32_t dbsize, uint32_t dim) {
	uint32_t i, j;
	uint64_t mindist, tmpdist;

	mindist = MAX_UINT;
	for(i=0; i < dbsize; i++) {
		tmpdist = 0;
		for(j=0; j < dim; j++) {
			if(serverdb[i][j] > clientquery[j])
				tmpdist += pow((serverdb[i][j] - clientquery[j]), 2);
			else
				tmpdist += pow((clientquery[j] - serverdb[i][j]), 2);
		}
		if(tmpdist < mindist)
			mindist = tmpdist;
	}

	return mindist;
}
