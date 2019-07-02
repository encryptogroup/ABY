/**
 \file 		simple_hashing.h
 \author	michael.zohner@ec-spride.de
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
 \brief
 */

#ifndef SIMLE_HASHING_H_
#define SIMLE_HASHING_H_

#include "hashing_util.h"

struct bin_ctx {
	//hash-values of all elements mapped to this bin
	uint8_t* values;
	//number of elements stored in this bin
	uint32_t nvals;
};

typedef struct simple_hash_table_ctx {
	//pointer to the bins in the hash table
	bin_ctx* bins;
	//number bins in the hash table
	uint32_t nbins;
	//max bin size
	uint32_t maxbinsize;
	//uint32_t addrbitlen;
	//uint32_t addrbytelen;
	//uint32_t inbytelen;
	//uint32_t outbytelen;
} sht_ctx;

typedef struct simple_hash_entry_gen_ctx {
	sht_ctx* table;
	//input elements
	uint8_t* elements;
	uint32_t startpos;
	uint32_t endpos;
	//uint32_t inbytelen;
	hs_t* hs;
} sheg_ctx;



//returns a cuckoo hash table with the first dimension being the bins and the second dimension being the pointer to the elements
uint8_t* simple_hashing(uint8_t* elements, uint32_t neles, uint32_t bitlen, uint32_t* outbitlen, uint32_t* nelesinbin, uint32_t nbins,
		uint32_t* maxbinsize, uint32_t ntasks, uint32_t nhashfuns, prf_state_ctx* prf_state);
//routine for generating the entries, is invoked by the threads
void gen_entries(sheg_ctx *ctx);
void init_hash_table(sht_ctx* table, hs_t* hs, uint32_t maxbinsize);
void increase_max_bin_size(sht_ctx* table, uint32_t valbytelen);
void free_hash_table(sht_ctx* table);
inline void insert_element(sht_ctx* table, uint8_t* element, uint32_t* address, uint8_t* tmpbuf, hs_t* hs);
inline uint32_t get_max_bin_size(uint32_t nbins, uint32_t neles);

void nchoosek_mul(mpf_t res, int n, int k);
int compute_maxbin(uint32_t balls_int, uint32_t bins_int);


#endif /* SIMLE_HASHING_H_ */
