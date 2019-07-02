/**
 \file 		cuckoo.cpp
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


#include <iostream>
#include <thread>
#include <vector>
#include "cuckoo.h"

//returns a cuckoo hash table with the first dimension being the bins and the second dimension being the pointer to the elements
#ifndef TEST_UTILIZATION
uint8_t*
#else
uint32_t
#endif
cuckoo_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t bitlen, uint32_t *outbitlen, uint32_t* nelesinbin,
		uint32_t* perm,	uint32_t ntasks, uint8_t** stash_elements, uint32_t maxstashsize, uint32_t** stashperm,
		uint32_t nhashfuns, prf_state_ctx* prf_state)
{
	//The resulting hash table
	uint8_t* hash_table;
	cuckoo_entry_ctx** cuckoo_table;
	cuckoo_entry_ctx** cuckoo_stash;
	uint32_t stashctr=0, elebytelen;
	uint32_t *perm_ptr;
	hs_t hs;
	elebytelen = ceil_divide(bitlen, 8);

	//maxstashsize = compute_stash_size(nbins, nhashfuns*neles);

#ifdef COUNT_FAILS
	uint32_t fails = 0;
#endif


	init_hashing_state(&hs, neles, bitlen, nbins, nhashfuns, prf_state);
	*outbitlen = hs.outbitlen;
	cuckoo_table = (cuckoo_entry_ctx**) calloc(nbins, sizeof(cuckoo_entry_ctx*));
	cuckoo_stash = (cuckoo_entry_ctx**) calloc(maxstashsize, sizeof(cuckoo_entry_ctx*));

	std::vector<cuckoo_entry_ctx> cuckoo_entries(neles);
	std::vector<std::thread> entry_gen_tasks(ntasks);
	std::vector<cuckoo_entry_gen_ctx> ctx(ntasks);

#ifndef TEST_UTILIZATION
	for(uint32_t i = 0; i < ntasks; i++) {
		ctx[i].elements = elements;
		ctx[i].cuckoo_entries = cuckoo_entries.data();
		ctx[i].hs = &hs;
		ctx[i].startpos = i * ceil_divide(neles, ntasks);
		ctx[i].endpos = std::min(ctx[i].startpos + ceil_divide(neles, ntasks), neles);
		//std::cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << std::endl;
		try {
			entry_gen_tasks[i] = std::thread(gen_cuckoo_entries, &ctx[i]);
		} catch (const std::system_error& e) {
			std::cerr << "Error in creating new thread at cuckoo hashing!\n"
				<< e.what() << std::endl;
			exit(1);
		}
	}

	for(uint32_t i = 0; i < ntasks; i++) {
		try {
			entry_gen_tasks[i].join();
		} catch (const std::system_error& e) {
			std::cerr << "Error in joining thread at cuckoo hashing!\n"
				<< e.what() << std::endl;
			exit(1);
		}
	}
#else
	ctx[0].elements = elements;
	ctx[0].cuckoo_entries = cuckoo_entries;
	ctx[0].hs = &hs;
	ctx[0].startpos = 0;
	ctx[0].endpos = neles;
	gen_cuckoo_entries(ctx);
#endif
	//for(i = 0; i < nbins; i++) {
	//	std::cout << "Address " << i << " mapped to " << hs.address_used[i] << " times" << std::endl;
	//}
	//insert all elements into the cuckoo hash table
	for(uint32_t i = 0; i < neles; i++) {
		if(!(insert_element(cuckoo_table, &cuckoo_entries[i], neles, hs.nhashfuns))) {
#ifdef COUNT_FAILS
			fails++;
			/*std::cout << "insertion failed for element " << (hex) << (*(((uint32_t*) elements)+i)) << ", inserting to address: ";
			for(uint32_t j = 0; j < NUM_HASH_FUNCTIONS; j++) {
				std::cout << (cuckoo_entries + i)->address[j] << ", ";
			}
			std::cout << (dec) << std::endl;*/
#else
			if(stashctr < maxstashsize) {
				std::cout << "Insertion not successful for element " << i <<", putting it on the stash" << std::endl;
				cuckoo_stash[stashctr] = &cuckoo_entries[i];
				stashctr++;
			} else {
				std::cerr << "Stash exceeded maximum stash size of " << maxstashsize << ", terminating program" << std::endl;
				exit(0);
			}

#endif
		}
	}

	//Copy the final state of the cuckoo table into the hash table
	perm_ptr = perm;

#ifndef TEST_UTILIZATION
	hash_table = (uint8_t*) calloc(nbins, hs.outbytelen);

	for(uint32_t i = 0; i < nbins; i++) {
		if(cuckoo_table[i] != NULL) {
			//std::cout << "Element: " << ((uint32_t*) cuckoo_table[i]->val)[0] << ", position = " << (cuckoo_table[i]->pos & 0x03) << ", in bin " << i << std::endl;
			cuckoo_table[i]->val[0] ^= (cuckoo_table[i]->pos & 0x03);
			memcpy(hash_table + i * hs.outbytelen, cuckoo_table[i]->val, hs.outbytelen);
			/*std::cout << "copying value for bin " << i << ": " << (hex);
			for(uint32_t j = 0; j < hs.outbytelen; j++) {
				std::cout <<(uint32_t) cuckoo_table[i]->val[j];
			}
			std::cout << (dec) << std::endl;*/
			*perm_ptr = cuckoo_table[i]->eleid;
			perm_ptr++;
			nelesinbin[i] = 1;
		} else {
			memset(hash_table + i * hs.outbytelen, DUMMY_ENTRY_CLIENT, hs.outbytelen);
			nelesinbin[i] = 0;
		}
	}

	*stash_elements = (uint8_t*) malloc(maxstashsize * elebytelen);
	*stashperm = (uint32_t*) malloc(sizeof(uint32_t) * maxstashsize);
	for(uint32_t i = 0; i < maxstashsize; i++) {
		if(cuckoo_stash[i] != NULL) {
			memcpy(*stash_elements + i * elebytelen, elements + cuckoo_stash[i]->eleid * elebytelen, elebytelen);
			(*stashperm)[i] = cuckoo_stash[i]->eleid;
		} else {
			memset(*stash_elements + i * elebytelen, DUMMY_ENTRY_CLIENT, elebytelen);
		}
	}

#endif

#ifndef TEST_UTILIZATION

	//Cleanup
	for(uint32_t i = 0; i < neles; i++) {
		free(cuckoo_entries[i].val);
		free(cuckoo_entries[i].address);
	}
#endif
	free(cuckoo_table);
	free(cuckoo_stash);

	free_hashing_state(&hs);

#ifdef TEST_UTILIZATION
	return fails;
#else
	return hash_table;
#endif
}


void gen_cuckoo_entries(cuckoo_entry_gen_ctx* ctx) {
	hs_t* hs = ctx->hs;
	uint32_t i, inbytelen = ceil_divide(hs->inbitlen, 8);
	uint8_t* eleptr = ctx->elements + inbytelen * ctx->startpos;


	//generate the cuckoo entries for all elements
	for(i = ctx->startpos; i < ctx->endpos; i++, eleptr+=inbytelen) {
		gen_cuckoo_entry(eleptr, ctx->cuckoo_entries + i, hs, i);
	}
}


inline void gen_cuckoo_entry(uint8_t* in, cuckoo_entry_ctx* out, hs_t* hs, uint32_t ele_id) {
	out->pos = 0;
	out->eleid = ele_id;

	out->address = (uint32_t*) calloc(hs->nhashfuns, sizeof(uint32_t));
#ifndef TEST_UTILIZATION
	out->val = (uint8_t*) calloc(hs->outbytelen, sizeof(uint8_t));
#endif
	hashElement(in, out->address, out->val, hs);
}


inline bool insert_element(cuckoo_entry_ctx** ctable, cuckoo_entry_ctx* element, uint32_t max_iterations, uint32_t nhashfuns) {
	cuckoo_entry_ctx *evicted, *tmp_evicted;
	uint32_t ev_pos, iter_cnt;
#ifdef DEBUG_CUCKOO
	std::cout << "iter_cnt = " << iter_cnt << " for element " << (hex) << (*((uint32_t*) element->element)) << (dec) << ", inserting to address: "
			<< element->address[element->pos] << " or " << element->address[element->pos^1] << std::endl;
#endif

	for(iter_cnt = 0, evicted = element; iter_cnt < max_iterations; iter_cnt++) {
		//TODO: assert(addr < MAX_TAB_ENTRIES)
		for(uint32_t i = 0; i < nhashfuns; i++) {//, ele_pos=(ele_pos+1)%NUM_HASH_FUNCTIONS) {
			if(ctable[evicted->address[i]] == NULL) {
				ctable[evicted->address[i]] = evicted;
				evicted->pos = i;
#ifdef TEST_CHAINLEN
				chain_cnt[iter_cnt]++;
#endif
				return true;
			}
		}

		//choose random bin to evict other element
		if(nhashfuns == 2) {
			ev_pos = evicted->address[evicted->pos & 0x01];
		} else {
			evicted->pos = (evicted->pos+1) % nhashfuns;
			ev_pos = evicted->address[evicted->pos];
		}

		tmp_evicted = ctable[ev_pos];
		ctable[ev_pos] = evicted;
		evicted = tmp_evicted;

		//change position - if the number of HF's is increased beyond 2 this should be replaced by a different strategy
		evicted->pos = (evicted->pos+1) % nhashfuns;
	}

	//the highest number of iterations has been reached
	return false;
}

inline uint32_t compute_stash_size([[maybe_unused]] uint32_t nbins, [[maybe_unused]] uint32_t neles) {
	return 4;
}

#ifdef TEST_CHAINLEN
void print_chain_cnt() {
	//std::cout << "Chain Count: " << std::endl;
	for(uint32_t i = 0; i < MAX_ITERATIONS; i++) {
		//if(chain_cnt[i] > 0)
			std::cout << i << "\t" << chain_cnt[i] << std::endl;
	}
}
#endif
