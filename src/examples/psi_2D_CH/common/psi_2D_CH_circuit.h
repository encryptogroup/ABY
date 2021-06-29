/**
 \file 		phasing_circuit.h
 \author 	michael.zohner@ec-spride.de
 \author    tkachenko@encrypto.cs.tu-darmstadt.de
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
 \brief		Implementation of PSI using 2D Cuckoo hashing.
 */
#ifndef __PHASING_CIRCUIT_
#define __PHASING_CIRCUIT_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/abycircuit.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "hashing/cuckoo.h"
#include "hashing/hashing_util.h"
#include "hashing/simple_hashing.h"
#include <cassert>

/**
 * Tests phasing cardinality circuit using two hash tables for each party 
 * @param role              Role of the current party
 * @param address           Network address of the opposite party
 * @param port              Network port for communication
 * @param seclvl            Security level
 * @param server_neles      Number of elements in server's set
 * @param client_neles      Number of elements in client's set
 * @param bitlen            Element bit length
 * @param epsilon           Multiplier for hash table (table_size=number_of_elements*epsilon)
 * @param nthreads          Number of worker threads
 * @param mt_alg            Method for arithmetic multiplication triple generation
 * @param sharing           Sharing protocol
 * @param ext_stash_size    Stash size
 * @param maxbinsize        Maximal bin size
 * @param mhashfuns         Number of hash functions
 * @param threshold         Cardinality threshold
 * @return                  Returns 0 by success
 */
int32_t test_2D_CH_circuit(e_role role, char* address, uint16_t port, seclvl seclvl,
        uint32_t server_neles, uint32_t client_neles, uint32_t bitlen, double epsilon,
        uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, int ext_stash_size,
        uint32_t maxbinsize, uint32_t mhashfuns, uint32_t threshold = 0);

/**
 * Generates set of random elements for client and server
 * @param neles
 * @param bitlen
 * @param srv_set
 * @param cli_set
 */
void sample_random_elements(uint32_t neles, uint32_t bitlen, uint32_t* srv_set, uint32_t* cli_set);

/**
 * Generates set of fixed elements for client and server
 * @param server_neles      Number of elements for server
 * @param client_neles      Number of elements for client
 * @param bitlen            Element bit length
 * @param srv_set           Server's element set
 * @param cli_set           Client's element set
 */
void set_fixed_elements(uint32_t server_neles, uint32_t client_neles, uint32_t bitlen, uint32_t* srv_set, uint32_t* cli_set);

/**
 * Builds circuit for computing the intersection of server's and client's elements
 * in the hash tables
 * @param shr_srv_set       Server's set share
 * @param shr_cli_set       Client's set share
 * @param binsize           Maximal bin size of the simple hashing table
 * @param circ              Circuit pointer
 * @return                  0/1 vector of (non-)matching elements 
 */
share* BuildPhasingCircuit(share** shr_srv_set, share* shr_cli_set, uint32_t binsize,
        BooleanCircuit* circ);

/**
 * Builds circuit for computing the intersection of stash and server's set
 * @param shr_srv_set       Server's set share
 * @param shr_cli_stash     Client's stash share
 * @param neles             Number of elements in server's set
 * @param bitlen            Element bit length
 * @param maxstashsize      Maximal stash size
 * @param circ              Circuit pointer
 * @return                  0/1 vector of (non-)matching elements 
 */
share* BuildPhasingStashCircuit(share* shr_srv_set, share** shr_cli_stash, uint32_t neles, uint32_t bitlen,
        uint32_t maxstashsize, BooleanCircuit* circ);

/**
 * Server hashing routine to handle elements using simple hashing scheme
 * @param elements      Elements to process
 * @param neles         Number of elements
 * @param elebitlen     Element bit length
 * @param nbins         Number of bins
 * @param maxbinsize    Maximal bin size
 * @param hash_table    Hash table pointer
 * @param outbitlen     Output bit length
 * @param ntasks        Number of tasks
 * @param crypt         Cryptographic helper class
 * @param nhashfuns     Number of hash functions
 */
void ServerHashingRoutine(uint8_t* elements, uint32_t neles, uint32_t elebitlen, uint32_t nbins,
        uint32_t* maxbinsize, uint8_t*** hash_table, uint32_t* outbitlen, uint32_t ntasks, crypto* crypt, uint32_t nhashfuns);

/**
 * Client hashing routine to handle elements using cuckoo hashing scheme
 * @param elements      Elements to process
 * @param neles         Number of elements
 * @param elebitlen     Element bit length
 * @param nbins         Number of bins
 * @param hash_table    Cuckoo hash table
 * @param inv_perm      Inverse permutation vector
 * @param outbitlen     Output bit length
 * @param stash         Stash pointer
 * @param maxstashsize  Maximal stash size
 * @param stashperm     Stash permutation
 * @param ntasks        Number of tasks
 * @param crypt         Cryptographic helper class
 * @param nhashfuns     Number of hash functions
 */
void ClientHashingRoutine(uint8_t* elements, uint32_t neles, uint32_t elebitlen, uint32_t nbins,
        uint8_t*** hash_table, uint32_t* inv_perm, uint32_t* outbitlen, uint8_t** stash, uint32_t maxstashsize,
        uint32_t* stashperm, uint32_t ntasks, crypto* crypt, uint32_t nhashfuns);

/**
 * Pad hash table bins with dummy elements
 * @param hash_table        Hash table pointer
 * @param elebytelen        Element byte length
 * @param nbins             Number of bins
 * @param nelesinbin        Number of elements in bin
 * @param maxbinsize        Maximal bin size
 * @param padded_hash_table Padded hash table pointer
 * @param dummy_element     Dummy element pointer
 */
void pad_elements(uint8_t* hash_table, uint32_t elebytelen, uint32_t nbins, uint32_t* nelesinbin,
        uint32_t maxbinsize, uint8_t* padded_hash_table, uint8_t* dummy_element);

/**
 * Assigns maximum shash size
 * @param neles Number of elements
 * @return Maximum stash size based on the number of elements
 */
uint32_t assign_max_stash_size(uint32_t neles);

#endif /* __PHASING_CIRCUIT_ */
