/*
 * cuckoo.cpp
 *
 *  Created on: Oct 7, 2014
 *      Author: mzohner
 */

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
	cuckoo_entry_ctx* cuckoo_entries;
	uint32_t i, j, stashctr=0, elebytelen;
	uint32_t *perm_ptr;
	pthread_t* entry_gen_tasks;
	cuckoo_entry_gen_ctx* ctx;
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

	cuckoo_entries = (cuckoo_entry_ctx*) malloc(neles * sizeof(cuckoo_entry_ctx));
	entry_gen_tasks = (pthread_t*) malloc(sizeof(pthread_t) * ntasks);
	ctx = (cuckoo_entry_gen_ctx*) malloc(sizeof(cuckoo_entry_gen_ctx) * ntasks);

#ifndef TEST_UTILIZATION
	for(i = 0; i < ntasks; i++) {
		ctx[i].elements = elements;
		ctx[i].cuckoo_entries = cuckoo_entries;
		ctx[i].hs = &hs;
		ctx[i].startpos = i * ceil_divide(neles, ntasks);
		ctx[i].endpos = min(ctx[i].startpos + ceil_divide(neles, ntasks), neles);
		//cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << endl;
		if(pthread_create(entry_gen_tasks+i, NULL, gen_cuckoo_entries, (void*) (ctx+i))) {
			cerr << "Error in creating new pthread at cuckoo hashing!" << endl;
			exit(0);
		}
	}

	for(i = 0; i < ntasks; i++) {
		if(pthread_join(entry_gen_tasks[i], NULL)) {
			cerr << "Error in joining pthread at cuckoo hashing!" << endl;
			exit(0);
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
	//	cout << "Address " << i << " mapped to " << hs.address_used[i] << " times" << endl;
	//}
	//insert all elements into the cuckoo hash table
	for(i = 0; i < neles; i++) {
		if(!(insert_element(cuckoo_table, cuckoo_entries + i, neles, hs.nhashfuns))) {
#ifdef COUNT_FAILS
			fails++;
			/*cout << "insertion failed for element " << (hex) << (*(((uint32_t*) elements)+i)) << ", inserting to address: ";
			for(uint32_t j = 0; j < NUM_HASH_FUNCTIONS; j++) {
				cout << (cuckoo_entries + i)->address[j] << ", ";
			}
			cout << (dec) << endl;*/
#else
			if(stashctr < maxstashsize) {
				cout << "Insertion not successful for element " << i <<", putting it on the stash" << endl;
				cuckoo_stash[stashctr] = cuckoo_entries+i;
				stashctr++;
			} else {
				cerr << "Stash exceeded maximum stash size of " << maxstashsize << ", terminating program" << endl;
				exit(0);
			}

#endif
		}
	}

	//Copy the final state of the cuckoo table into the hash table
	perm_ptr = perm;

#ifndef TEST_UTILIZATION
	hash_table = (uint8_t*) calloc(nbins, hs.outbytelen);

	for(i = 0; i < nbins; i++) {
		if(cuckoo_table[i] != NULL) {
			cuckoo_table[i]->val[0] ^= (cuckoo_table[i]->pos & 0x01);
			memcpy(hash_table + i * hs.outbytelen, cuckoo_table[i]->val, hs.outbytelen);
			/*cout << "copying value for bin " << i << ": " << (hex);
			for(uint32_t j = 0; j < hs.outbytelen; j++) {
				cout <<(uint32_t) cuckoo_table[i]->val[j];
			}
			cout << (dec) << endl;*/
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
	for(i = 0; i < maxstashsize; i++) {
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
	for(i = 0; i < neles; i++) {
		free(cuckoo_entries[i].val);
		free(cuckoo_entries[i].address);
	}
#endif
	free(cuckoo_entries);
	free(cuckoo_table);
	free(cuckoo_stash);
	free(entry_gen_tasks);
	free(ctx);

	free_hashing_state(&hs);

#ifdef TEST_UTILIZATION
	return fails;
#else
	return hash_table;
#endif
}


void *gen_cuckoo_entries(void *ctx_void) {
	cuckoo_entry_gen_ctx* ctx  = (cuckoo_entry_gen_ctx*) ctx_void;
	hs_t* hs = ctx->hs;
	uint32_t i, inbytelen = ceil_divide(hs->inbitlen, 8);
	uint8_t* eleptr = ctx->elements + inbytelen * ctx->startpos;


	//generate the cuckoo entries for all elements
	for(i = ctx->startpos; i < ctx->endpos; i++, eleptr+=inbytelen) {
		gen_cuckoo_entry(eleptr, ctx->cuckoo_entries + i, hs, i);
	}
}


inline void gen_cuckoo_entry(uint8_t* in, cuckoo_entry_ctx* out, hs_t* hs, uint32_t ele_id) {
	uint32_t i;

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
	uint32_t i, ev_pos, iter_cnt;
#ifdef DEBUG_CUCKOO
	cout << "iter_cnt = " << iter_cnt << " for element " << (hex) << (*((uint32_t*) element->element)) << (dec) << ", inserting to address: "
			<< element->address[element->pos] << " or " << element->address[element->pos^1] << endl;
#endif

	for(iter_cnt = 0, evicted = element; iter_cnt < max_iterations; iter_cnt++) {
		//TODO: assert(addr < MAX_TAB_ENTRIES)
		for(i = 0; i < nhashfuns; i++) {//, ele_pos=(ele_pos+1)%NUM_HASH_FUNCTIONS) {
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
			ev_pos = evicted->address[(evicted->pos^iter_cnt) % nhashfuns];
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

inline uint32_t compute_stash_size(uint32_t nbins, uint32_t neles) {
	return 4;
}

#ifdef TEST_CHAINLEN
void print_chain_cnt() {
	//cout << "Chain Count: " << endl;
	for(uint32_t i = 0; i < MAX_ITERATIONS; i++) {
		//if(chain_cnt[i] > 0)
			cout << i << "\t" << chain_cnt[i] << endl;
	}
}
#endif
