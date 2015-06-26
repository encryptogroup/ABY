/**
 \file 		phasing_circuit.h
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
 \brief		Implementation of PSI using Phasing
 */
#ifndef __PHASING_CIRCUIT_
#define __PHASING_CIRCUIT_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "hashing/cuckoo.h"
#include "hashing/hashing_util.h"
#include "hashing/simple_hashing.h"
#include <cassert>

int32_t test_phasing_circuit(e_role role, char* address, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, double epsilon, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing);

void 	sample_random_elements(uint32_t neles, uint32_t bitlen, uint32_t* srv_set, uint32_t* cli_set);
void 	set_fixed_elements(uint32_t neles, uint32_t bitlen, uint32_t* srv_set, uint32_t* cli_set);

share* 	BuildPhasingCircuit(share** shr_srv_set, share* shr_cli_set, uint32_t binsize,
		BooleanCircuit* circ);

share* 	BuildPhasingStashCircuit(share* shr_srv_set, share** shr_cli_stash, uint32_t neles, uint32_t bitlen,
		uint32_t maxstashsize, BooleanCircuit* circ);

void 	ServerHashingRoutine(uint8_t* elements, uint32_t neles, uint32_t elebitlen, uint32_t nbins,
		uint32_t* maxbinsize, uint8_t** hash_table, uint32_t* outbitlen, uint32_t ntasks, crypto* crypt);

void 	ClientHashingRoutine(uint8_t* elements, uint32_t neles, uint32_t elebitlen, uint32_t nbins,
		uint8_t** hash_table, uint32_t* inv_perm, uint32_t* outbitlen, uint8_t** stash, uint32_t maxstashsize,
		uint32_t** stashperm, uint32_t ntasks, crypto* crypt);

void 	pad_elements(uint8_t* hash_table, uint32_t elebytelen, uint32_t nbins, uint32_t* nelesinbin,
		uint32_t maxbinsize, uint8_t* padded_hash_table, uint8_t* dummy_element);

uint32_t compute_max_stash_size(uint32_t neles, uint32_t nbins);

#endif /* __PHASING_CIRCUIT_ */
