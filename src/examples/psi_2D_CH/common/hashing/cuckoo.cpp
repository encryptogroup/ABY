/**
 \file 		cuckoo.cpp
 \author	michael.zohner@ec-spride.de
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
 \brief
 */

#include <iostream>
#include <thread>
#include <vector>

#include "cuckoo.h"
#include "simple_hashing.h"
//returns a cuckoo hash table with the first dimension being the bins and the second dimension being the pointer to the elements
#ifndef TEST_UTILIZATION
uint8_t**
#else

uint32_t
#endif
cuckoo_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t bitlen, uint32_t *outbitlen, uint32_t** nelesinbin,
        uint32_t* perm, uint32_t ntasks, uint8_t** stash_elements, uint32_t maxstashsize, uint32_t* stashperm,
        uint32_t nhashfuns, prf_state_ctx* prf_state, crypto* crypt) {
    //The resulting hash table
    uint8_t** hash_table;
    std::vector<uint32_t> in_stash;
    cuckoo_entry_ctx*** cuckoo_table;
    cuckoo_entry_ctx** cuckoo_stash;
    cuckoo_entry_ctx** cuckoo_entries;
    uint32_t i, j, stashctr = 0, elebytelen;
    uint32_t *perm_ptr;
    pthread_t** entry_gen_tasks;
    cuckoo_entry_gen_ctx** ctx;
    hs_t hs[2];
    elebytelen = ceil_divide(bitlen, 8);
    //maxstashsize = compute_stash_size(nbins, nhashfuns*neles);

#ifdef COUNT_FAILS
    uint32_t fails = 0;
#endif

    hash_table = (uint8_t**) malloc(sizeof*hash_table * 2);

    crypt->init_prf_state(prf_state, (uint8_t*) const_seed_2_tables[0]);
    init_hashing_state(&hs[0], neles, bitlen, nbins, nhashfuns, prf_state);
    crypt->init_prf_state(prf_state, (uint8_t*) const_seed_2_tables[1]);
    init_hashing_state(&hs[1], neles, bitlen, nbins, nhashfuns, prf_state);
    *outbitlen = hs[0].outbitlen;
    cuckoo_table = (cuckoo_entry_ctx***) calloc(2, sizeof*(cuckoo_table));
    cuckoo_stash = (cuckoo_entry_ctx**) calloc(maxstashsize, sizeof (cuckoo_entry_ctx*));
    cuckoo_entries = (cuckoo_entry_ctx**) calloc(2, sizeof*(cuckoo_entries));
    entry_gen_tasks = (pthread_t**) calloc(2, sizeof *entry_gen_tasks);
    ctx = (cuckoo_entry_gen_ctx**) calloc(2, sizeof *ctx);

    for (size_t k = 0; k < N_TABLES; k++) {
        cuckoo_table[k] = (cuckoo_entry_ctx**) calloc(nbins, sizeof (cuckoo_entry_ctx*));
        cuckoo_entries[k] = (cuckoo_entry_ctx*) calloc(neles, sizeof (cuckoo_entry_ctx));
        entry_gen_tasks[k] = (pthread_t*) calloc(ntasks, sizeof (pthread_t));
        ctx[k] = (cuckoo_entry_gen_ctx*) calloc(ntasks, sizeof (cuckoo_entry_gen_ctx));
    }

#ifndef TEST_UTILIZATION
    for (size_t k = 0; k < N_TABLES; k++) {
        for (i = 0; i < ntasks; i++) {
            ctx[k][i].elements = elements;
            ctx[k][i].cuckoo_entries = cuckoo_entries[k];
            ctx[k][i].hs = &hs[k];
            ctx[k][i].startpos = i * ceil_divide(neles, ntasks);
            ctx[k][i].endpos = std::min(ctx[k][i].startpos + ceil_divide(neles, ntasks), neles);
            //std::cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << std::endl;
            if (pthread_create(entry_gen_tasks[k] + i, NULL, gen_cuckoo_entries, (void*) (ctx[k] + i))) {
                std::cerr << "Error in creating new pthread at cuckoo hashing!" << std::endl;
                exit(0);
            }
        }

        for (i = 0; i < ntasks; i++) {
#ifdef DEBUG_CUCKOO
            std::cout << "Starting cuckoo hashing " << k << " " << i << std::endl;
#endif
            if (pthread_join(entry_gen_tasks[k][i], NULL)) {
                std::cerr << "Error in joining pthread at cuckoo hashing!" << std::endl;
                exit(0);
            }
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
#ifdef DEBUG_CUCKOO
    std::cout << "CH out bytelen " << hs->outbytelen << std::endl;
#endif
    for (size_t k = 0; k < N_TABLES; k++) {
        for (i = 0; i < neles; i++) {
            if (!(insert_element(cuckoo_table[k], &cuckoo_entries[k][i], neles, hs[k].nhashfuns))) {
#ifdef COUNT_FAILS
                fails++;
                /*std::cout << "insertion failed for element " << (hex) << (*(((uint32_t*) elements)+i)) << ", inserting to address: ";
                for(uint32_t j = 0; j < NUM_HASH_FUNCTIONS; j++) {
                        std::cout << (cuckoo_entries + i)->address[j] << ", ";
                }
                std::cout << (dec) << std::endl;*/
#else
                if (stashctr < maxstashsize) {
                    std::cout << "Insertion not successful for element " << i << ", putting it on the stash" << std::endl;
                    for (size_t t = 0; t < N_TABLES; t++)
                        remove_from_tables(cuckoo_table[t], &cuckoo_entries[t][i], hs[k].nhashfuns, hs->outbytelen);
                    cuckoo_stash[stashctr] = &cuckoo_entries[k][i];
                    stashctr++;
                } else {
                    std::cerr << "Stash exceeded maximum stash size of " << maxstashsize << ", terminating program" << std::endl;
                    exit(0);
                }
#endif
            }
        }
    }
    for (size_t t = 0; t < N_TABLES; t++)
        for (size_t i = 0; i < maxstashsize; i++)
            if (cuckoo_stash[i] != NULL)
                remove_from_tables(cuckoo_table[t], cuckoo_stash[i], hs[t].nhashfuns, hs->outbytelen);
    //Copy the final state of the cuckoo table into the hash table
    perm_ptr = perm;
    stashperm = (uint32_t*) malloc(sizeof (uint32_t) * maxstashsize);
    *stash_elements = (uint8_t*) malloc(maxstashsize * elebytelen);

#ifndef TEST_UTILIZATION
    for (size_t k = 0; k < N_TABLES; k++) {
        hash_table[k] = (uint8_t*) calloc(nbins, hs[k].outbytelen);
        for (i = 0; i < nbins; i++) {
            if (cuckoo_table[k][i] != NULL) {
                //std::cout << "Element: " << ((uint32_t*) cuckoo_table[i]->val)[0] << ", position = " << (cuckoo_table[i]->pos & 0x03) << ", in bin " << i << std::endl;
                cuckoo_table[k][i]->val[0] ^= (cuckoo_table[k][i]->pos & 0x03);
                memcpy(&hash_table[k][i * hs[k].outbytelen], cuckoo_table[k][i]->val, hs[k].outbytelen);
                /*std::cout << "copying value for bin " << i << ": " << (hex);
                for(uint32_t j = 0; j < hs.outbytelen; j++) {
                        std::cout <<(uint32_t) cuckoo_table[i]->val[j];
                }
                std::cout << (dec) << std::endl;*/
                *perm_ptr = cuckoo_table[k][i]->eleid;
                perm_ptr++;
                nelesinbin[k][i] = 1;
            } else {
                memset(&hash_table[k][i * hs[k].outbytelen], DUMMY_ENTRY_CLIENT, hs[k].outbytelen);
                nelesinbin[k][i] = 0;
            }
        }
        //for (size_t t = 0; t < N_TABLES; t++)
        //    remove_from_tables(cuckoo_table[t], &cuckoo_entries[t][i], hs[k].nhashfuns, hs->outbytelen);

        for (i = 0; i < maxstashsize; i++) {
            if (cuckoo_stash[i] != NULL) {
                memcpy(&(*stash_elements)[i * elebytelen], &elements[cuckoo_stash[i]->eleid * elebytelen], elebytelen);
                stashperm[i] = cuckoo_stash[i]->eleid;
            } else {
                memset(&(*stash_elements)[i * elebytelen], DUMMY_ENTRY_CLIENT, elebytelen);
            }
        }
    }
#endif

#ifndef TEST_UTILIZATION
    //Cleanup
    for (size_t k = 0; k < N_TABLES; k++) {
        for (i = 0; i < neles; i++) {
            free(cuckoo_entries[k][i].val);
            free(cuckoo_entries[k][i].address);
        }
        free(cuckoo_entries[k]);
        free(cuckoo_table[k]);
        //free(cuckoo_stash[k]);
        free(entry_gen_tasks[k]);
        free(ctx[k]);
        free_hashing_state(&hs[k]);
    }
#endif
    free(cuckoo_entries);
    free(cuckoo_table);
    free(cuckoo_stash);
    free(entry_gen_tasks);
    free(ctx);

#ifdef TEST_UTILIZATION
    return fails;
#else

#ifdef DEBUG_CUCKOO
    print_c_table(hash_table, hs->nbins, ceil_divide(*outbitlen, 8));
#endif

    return hash_table;
#endif
}

void *gen_cuckoo_entries(void *ctx_void) {
    cuckoo_entry_gen_ctx* ctx = (cuckoo_entry_gen_ctx*) ctx_void;
    hs_t* hs = ctx->hs;
    uint32_t i, inbytelen = ceil_divide(hs->inbitlen, 8);
    uint8_t* eleptr = ctx->elements + inbytelen * ctx->startpos;

    //generate the cuckoo entries for all elements
    for (i = ctx->startpos; i < ctx->endpos; i++, eleptr += inbytelen) {
        gen_cuckoo_entry(eleptr, ctx->cuckoo_entries + i, hs, i);
    }
}

inline void gen_cuckoo_entry(uint8_t* in, cuckoo_entry_ctx* out, hs_t* hs, uint32_t ele_id) {
    uint32_t i;
    out->pos = 0;
    out->eleid = ele_id;
    out->address = (uint32_t*) calloc(hs->nhashfuns, sizeof (uint32_t));
#ifndef TEST_UTILIZATION
    out->val = (uint8_t*) calloc(hs->outbytelen, sizeof (uint8_t));
#endif
    hashElement(in, out->address, out->val, hs);

#ifdef DEBUG_CUCKOO
    std::cout << "C: Mapping Element:\t";
    for (size_t i = 0; i < hs->inbytelen; i++)
        printf("%02x", in[i]);
    std::cout << "\t as: \t";
    for (size_t i = 0; i < hs->outbytelen; i++)
        printf("%02x", out->val[i]);
    std::cout << " to positions \t" << out->address[0] << " " << out->address[1] << std::endl;
#endif
}

inline bool insert_element(cuckoo_entry_ctx** ctable, cuckoo_entry_ctx* element, uint32_t max_iterations, uint32_t nhashfuns) {
    cuckoo_entry_ctx *evicted, *tmp_evicted;
    uint32_t i, ev_pos, iter_cnt;


    for (iter_cnt = 0, evicted = element; iter_cnt < max_iterations; iter_cnt++) {
#ifdef DEBUG_CUCKOO
        std::cout << "iter_cnt = " << iter_cnt << " for element " << (hex) << setw(5) << setfill('0') <<
                (*((uint32_t*) element->val)) << (dec) << ", inserting to address: "
                << element->address[element->pos] << " or " << element->address[element->pos^1] << std::endl;
#endif
        //TODO: assert(addr < MAX_TAB_ENTRIES)
        for (i = 0; i < nhashfuns; i++) {//, ele_pos=(ele_pos+1)%NUM_HASH_FUNCTIONS) {
            if (ctable[evicted->address[i]] == NULL) {
                ctable[evicted->address[i]] = evicted;
                evicted->pos = i;
#ifdef TEST_CHAINLEN
                chain_cnt[iter_cnt]++;
#endif
                return true;
            }
        }

        //choose random bin to evict other element
        if (nhashfuns == 2) {
            ev_pos = evicted->address[evicted->pos & 0x01];
        } else {
            evicted->pos = (evicted->pos + 1) % nhashfuns;
            ev_pos = evicted->address[evicted->pos];
        }

        tmp_evicted = ctable[ev_pos];
        ctable[ev_pos] = evicted;
        evicted = tmp_evicted;

        //change position - if the number of HF's is increased beyond 2 this should be replaced by a different strategy
        evicted->pos = (evicted->pos + 1) % nhashfuns;
    }

    //the highest number of iterations has been reached
    return false;
}

inline uint32_t compute_stash_size(uint32_t nbins, uint32_t neles) {
    return 4;
}

#ifdef TEST_CHAINLEN

void print_chain_cnt() {
    //std::cout << "Chain Count: " << std::endl;
    for (uint32_t i = 0; i < MAX_ITERATIONS; i++) {
        //if(chain_cnt[i] > 0)
        std::cout << i << "\t" << chain_cnt[i] << std::endl;
    }
}
#endif

void print_c_table(uint8_t** table, size_t nbins, size_t elem_len) {
    std::cout << std::endl << "Printing bins" << std::endl;
    std::cout << "--------------------------------" << std::endl;
    std::cout << "Number of bins: \t" << nbins << std::endl;
    std::cout << "Element length: \t" << elem_len << std::endl;
    for (size_t i = 0; i < 2; i++) {
        for (size_t elem_i = 0; elem_i < elem_len * nbins; elem_i += elem_len) {
            std::cout << "Bin #" << (elem_i + 1) / elem_len << " : \t";
            for (size_t bit_i = 0; bit_i < elem_len; bit_i++)
                printf("%02x", table[i][elem_i + bit_i]);
            std::cout << std::endl;
        }
        std::cout << " ";
        std::cout << std::endl;
    }
    std::cout << "--------------------------------" << std::endl;
}

void remove_from_tables(cuckoo_entry_ctx** ctable, cuckoo_entry_ctx* element, uint32_t nhashfuns, size_t len) {
    for (size_t i = 0; i < nhashfuns; ++i) {
        if (ctable[element->address[i]] != NULL &&
                is_equal(ctable[element->address[i]]->val, element->val, len)) {
            //free(ctable[element->address[i]]);
            ctable[element->address[i]] = NULL;
        }
    }
    //element->in_stash = 1;
}

bool is_equal(uint8_t*a, uint8_t*b, size_t len) {
    for (size_t i = 0; i < len; ++i)
        if (a[i]^b[i])
            return false;
    return true;
}