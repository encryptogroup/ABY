/**
 \file 		simple_hashing.cpp
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

#include "simple_hashing.h"

uint8_t** simple_hashing(uint8_t* elements, uint32_t neles, uint32_t bitlen, uint32_t *outbitlen, uint32_t** nelesinbin, uint32_t nbins,
        uint32_t* maxbinsize, uint32_t ntasks, uint32_t nhashfuns, prf_state_ctx* prf_state, crypto* crypt) {

    sht_ctx** table;
    //uint8_t** bin_content;
    uint8_t *eleptr, **bin_ptr, *result, **res_bins;
    uint32_t i, j, tmpneles;
    sheg_ctx** ctx;
    pthread_t** entry_gen_tasks;
    hs_t hs[2];

    crypt->init_prf_state(prf_state, (uint8_t*) const_seed_2_tables[0]);
    init_hashing_state(&hs[0], neles, bitlen, nbins, nhashfuns, prf_state);
    crypt->init_prf_state(prf_state, (uint8_t*) const_seed_2_tables[1]);
    init_hashing_state(&hs[1], neles, bitlen, nbins, nhashfuns, prf_state);

    //Set the output bit-length of the hashed elements
    *outbitlen = hs[0].outbitlen;
    entry_gen_tasks = (pthread_t**) malloc(sizeof *entry_gen_tasks * 2);
    ctx = (sheg_ctx**) malloc(2 * sizeof *ctx);
    table = (sht_ctx**) malloc(2 * sizeof *table);
    for (size_t k = 0; k < N_TABLES; k++) {
        entry_gen_tasks[k] = (pthread_t*) malloc(sizeof (pthread_t) * ntasks);
        ctx[k] = (sheg_ctx*) calloc(ntasks, sizeof (sheg_ctx));
        table[k] = (sht_ctx*) calloc(ntasks, sizeof (sht_ctx));
        for (i = 0; i < ntasks; i++)
            init_hash_table(&table[k][i], ceil_divide(neles, ntasks), &hs[k]);
    }

    for (i = 0; i < ntasks; i++) {
        for (size_t k = 0; k < N_TABLES; k++) {
            ctx[k][i].elements = elements;
            ctx[k][i].table = &table[k][i];
            ctx[k][i].startpos = i * ceil_divide(neles, ntasks);
            ctx[k][i].endpos = std::min(ctx[k][i].startpos + ceil_divide(neles, ntasks), neles);
            ctx[k][i].hs = &hs[k];
        }
        //std::cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << std::endl;
        if (pthread_create(&entry_gen_tasks[0][i], NULL, gen_entries, (void*) &(ctx[0][i]))) {
            std::cerr << "Error in creating new pthread at simple hashing!" << std::endl;
            exit(0);
        }

    }


    for (i = 0; i < ntasks; i++) {
        if (pthread_join(entry_gen_tasks[0][i], NULL)) {
            std::cerr << "Error in joining pthread at simple hashing!" << std::endl;
            exit(0);
        }
    }


    remap_bins(table[0], &hs[0], table[1], &hs[1]);

#ifdef DEBUG_SH
    std::cout << "Inbytelen:\t" << hs->inbytelen << std::endl;
    self_test(elements, hs->inbytelen, neles, table, hs);
#endif

    *maxbinsize = std::max(table[0]->maxbinsize, table[1]->maxbinsize);

    for (size_t k = 0; k < N_TABLES; k++)
        apply_perm_based_hashing(table[k], &hs[k]);

#ifdef DEBUG_SH
    print_sh_table(table, hs->outbytelen);
#endif

    res_bins = (uint8_t**) malloc(sizeof *res_bins * N_TABLES);
    bin_ptr = (uint8_t**) malloc(sizeof *bin_ptr * N_TABLES);

    for (size_t k = 0; k < N_TABLES; k++) {
        res_bins[k] = (uint8_t*) calloc(hs[k].nbins * (hs[k].outbytelen), N_TABLES);
        bin_ptr[k] = res_bins[k];
    }

    for (size_t k = 0; k < N_TABLES; k++) {
        size_t glob_n_elems = 0;
        for (i = 0; i < hs[k].nbins; i++) {
            nelesinbin[k][i] = 0;
            for (j = 0; j < ntasks; j++) {
                tmpneles = table[k][j].bins[i].nvals;
                nelesinbin[k][i] += tmpneles;
#ifdef DEBUG_SH
                std::cout << "SH: ";
                for (size_t l = 0; l < tmpneles * hs[k].outbytelen; l++)
                    printf("%02x", table[k][j].bins[i].values[l]);
                std::cout << std::endl;
#endif
                memcpy(res_bins[k] + i * BIN_SIZE_LIMIT * (hs[k].outbytelen), (table[k] + j)->bins[i].values, tmpneles * hs[k].outbytelen);
                glob_n_elems += BIN_SIZE_LIMIT;
                //bin_ptr += (tmpneles * hs[k].outbytelen);
            }
        }//right now only the number of elements in each bin is copied instead of the max bin size
    }
    for (size_t k = 0; k < N_TABLES; k++) {
        //for (j = 0; j < ntasks; j++)
        //free_hash_table(&table[k][j]);
        free(table[k]);
        //free(entry_gen_tasks[k]);
        //free(ctx[k]);

        //free_hashing_state(&hs[k]);
    }
    //free(ctx);
    //free(bin_ptr);
    return res_bins;
}

void *gen_entries(void *ctx_tmp) {
    //Insert elements in parallel, use lock to communicate
    uint8_t *tmpbuf;
    sheg_ctx* ctx = (sheg_ctx*) ctx_tmp;
    uint32_t i, inbytelen, *address;
    address = (uint32_t*) malloc(ctx->hs->nhashfuns * sizeof (uint32_t));
    tmpbuf = (uint8_t*) calloc(ctx->hs->inbytelen, sizeof (uint8_t));
    uint8_t *eleptr = ctx->elements;
    for (i = ctx->startpos, inbytelen = ctx->hs->inbytelen; i < ctx->endpos; i++, eleptr += inbytelen)
        insert_element(ctx->table, eleptr, address, tmpbuf, ctx->hs);

    free(tmpbuf);
    free(address);
}

inline void insert_element(sht_ctx* table, uint8_t* element, uint32_t* address,
        uint8_t* tmpbuf, hs_t* hs) {
    uint32_t i, j;
    bin_ctx* tmp_bin;
    hashElement(element, address, tmpbuf, hs);
#ifdef DEBUG_SH
    std::cout << "SH: Mapping Element:\t";
    for (size_t i = 0; i < hs->inbytelen; i++)
        printf("%02x", element[i]);
        std::cout << "\t as:\t";
    for (size_t i = 0; i < hs->outbytelen; i++)
        printf("%02x", tmpbuf[i]);
    std::cout << " to positions \t" << address[0] << " " << address[1] << std::endl;
#endif
     for (i = 0; i < hs->nhashfuns; i++) {
        tmp_bin = table->bins + address[i];
                //memcpy(tmp_bin->values + tmp_bin->nvals * hs->outbytelen, tmpbuf, hs->outbytelen);
        //tmp_bin->values[tmp_bin->nvals * hs->outbytelen] ^= (i & 0x03);
        memcpy(tmp_bin->values + tmp_bin->nvals * (hs->inbytelen), element, hs->inbytelen);
        tmp_bin->values[tmp_bin->nvals * hs->inbytelen];// ^= (i & 0x03);
        tmp_bin->nvals++;
    }
}

/// Removes all occurences of the element in the hash table

void remove_elem_from_ht_completely(sht_ctx* table, uint8_t* element, uint32_t* address, hs_t* hs) {
    size_t elem_bitlen = hs->inbytelen;
    uint8_t* tmpbuf = (uint8_t*) calloc(sizeof*tmpbuf, (hs->nhashfuns) * (hs->outbytelen));
    uint8_t tmp_element[elem_bitlen];
    hashElement(element, address, tmpbuf, hs);
    memcpy(tmp_element, element, elem_bitlen);
    for (size_t i = 0; i < hs->nhashfuns; i++) {
#ifdef DEBUG_SH
        std::cout << "Trying to remove the element\t";
        print_elem(tmp_element, elem_bitlen);
        std::cout << "\t at address : \t" << address[i] << std::endl;
#endif
        remove_single_elem_from_ht(table, tmp_element, &address[i], &elem_bitlen);
    }
    free(tmpbuf);
}

void remove_single_elem_from_ht(sht_ctx* table, uint8_t* element, uint32_t* address, size_t * elem_len) {
    //std::cout << "Trying to remove from address inside:\t" << *address << std::endl;
    bin_ctx* tmp_bin = table->bins + *address;
    for (size_t i = 0; i < tmp_bin->nvals * *elem_len; i += *elem_len) {
        /*std::cout << "Number of elements in bin:\t" << tmp_bin->nvals << std::endl;
        std::cout << "Elem to find:\t";
        for (size_t j = 0; j < *elem_len; j++) {
            printf("%02x", element[j]);
        }
        std::cout << "\tElem to compare:\t";
        for (size_t j = i; j < *elem_len; j++) {
            printf("%02x", tmp_bin->values[j]);
        }
        std::cout << std::endl;*/
        if (is_equal(element, tmp_bin->values + i, elem_len)) {
            //v.erase(v.begin() + i, v.begin()+(i + *elem_len));
            for (size_t j = i; j < (tmp_bin->nvals - 1) * *elem_len; j += *elem_len) {
                /*std::cout << "elem left:\t";
                print_elem(tmp_bin->values + j, elem_len);
                std::cout << "\telem right:\t";
                print_elem(tmp_bin->values + j + *elem_len, elem_len);
                std::cout << std::endl;*/
                memmove(tmp_bin->values + j, tmp_bin->values + j + *elem_len, *elem_len);
            }
            //std::cout << "Is equal! \t i=" << i / *elem_len << std::endl;
            break;
        } else if (i / *elem_len == tmp_bin->nvals - 1)
            std::cout << "--------Could not find element to remove in the simple hash table" << std::endl;
    }
    //tmp_bin->values = &v[0];
    if (tmp_bin->nvals)
        tmp_bin->nvals--;
}

bool is_equal(uint8_t* a, uint8_t* b, size_t * len) {
    for (size_t i = 0; i < *len; i++) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

void init_hash_table(sht_ctx* table, uint32_t nelements, hs_t* hs) {
    uint32_t i;
    table->maxbinsize = get_max_bin_size(hs->nbins, hs->nhashfuns * nelements);
    table->nbins = hs->nbins;
    table->bins = (bin_ctx*) calloc(hs->nbins, sizeof (bin_ctx));
    for (i = 0; i < hs->nbins; i++)
        table->bins[i].values = (uint8_t*) malloc(table->maxbinsize * hs->outbytelen + 1);
}

void free_hash_table(sht_ctx* table) {
    uint32_t i;
    //1. free the byte-pointers for the values in the bints
    for (i = 0; i < table->nbins; i++)
        free(table->bins[i].values);
    //2. free the bins
    free(table->bins);
    //3. free the actual table
    //free(table);
}

inline uint32_t get_max_bin_size(uint32_t nbins, uint32_t neles) {
    double n = neles;
    if (ceil_divide(neles, nbins) < 3) {
        if (neles >= (1 << 24))
            return 27;
        if (neles >= (1 << 20))
            return 26;
        if (neles >= (1 << 16))
            return 25;
        if (neles >= (1 << 12))
            return 24;
        if (neles >= (1 << 8))
            return 23;
    } else
        return 6 * std::max((uint32_t) ceil_divide(neles, nbins), (uint32_t) 3);
}

void increase_max_bin_size(sht_ctx* table, uint32_t valbytelen) {
    uint32_t new_maxsize = table->maxbinsize * 2;
    uint8_t* tmpvals;
    for (uint32_t i = 0; i < table->nbins; i++) {
        tmpvals = table->bins[i].values;
        table->bins[i].values = (uint8_t*) malloc(new_maxsize * valbytelen);
        memcpy(table->bins[i].values, tmpvals, table->bins[i].nvals * valbytelen);
        free(tmpvals);
    }
    table->maxbinsize = new_maxsize;
}

void remap_bins(sht_ctx* table_from, hs_t* hs_from, sht_ctx* table_to, hs_t* hs_to) {
    uint8_t table_iterator = 1;
    sht_ctx * table[] = {table_from, table_to};
    hs_t hs[] = {*hs_from, *hs_to};
    while (!remapping_is_satisfactory(table_from, table_to)) {
        //print_sh_table(table, hs);
        if (table_iterator % 2) {
            //std::cout << "********************REMAPPING A TO B" << std::endl;
            for (size_t i = 0; i < table_from->nbins; i++)
                if (table_from->bins[i].nvals > REMAPPING_THRESHOLD) {
                    //std::cout << "Remapping bin #" << i << std::endl;
                    remap_bin(&table_from->bins[i], table_from, table_to, hs_from, hs_to);
                }
        } else {
            //std::cout << "********************REMAPPING B TO A" << std::endl;
            for (size_t i = 0; i < table_to->nbins; i++)
                if (table_to->bins[i].nvals > REMAPPING_THRESHOLD) {
                    //std::cout << "Remapping bin #" << i << std::endl;
                    remap_bin(&table_to->bins[i], table_to, table_from, hs_to, hs_from);
                }
        }
        table_iterator++;
    }
    std::cout << "Number of remappings needed: \t" << table_iterator - 1 << std::endl;
    //print_sh_table(table, hs);
}

void remap_bin(bin_ctx* bin, sht_ctx* table_from, sht_ctx* table_to, hs_t* hs_from, hs_t* hs_to) {
    uint8_t * elem;
    uint8_t tmp[ceil_divide(hs_from->outbitlen, 8)];
    uint32_t addr[hs_from->nhashfuns];
    //for (int i = 0; i < bin->nvals - REMAPPING_THRESHOLD; i++) {
    while (bin->nvals > REMAPPING_THRESHOLD) {
        //std::cout << "Start remapping the bin" << std::endl;
        //std::cout << "Number of elements in the bin: \t" << bin->nvals << "\t iteration:\t" << 0 << std::endl;
        insert_element(table_to, &bin->values[0 * (hs_from->inbytelen)], addr, tmp, hs_to);
        remove_elem_from_ht_completely(table_from, &bin->values[0 * (hs_from->inbytelen)], addr, hs_from);
        //std::cout << "End remapping the bin" << std::endl;
    }
}

size_t find_max_bin_size(sht_ctx* table) {
    size_t max = 0;
    for (size_t i = 0; i < table->nbins; i++)
        if (table->bins[i].nvals > max)
            max = table->bins[i].nvals;
    return max;
}

bool remapping_is_satisfactory(sht_ctx* initial_table, sht_ctx* addit_table) {
    size_t i = find_max_bin_size(initial_table);
    size_t a = find_max_bin_size(addit_table);
    std::cout << "SH table has now maximum bin size of:\t" << std::max(a, i) << std::endl;
    if (std::max(a, i) > 0 && std::max(a, i) < REMAPPING_THRESHOLD + 1)
        return true;
    return false;
}

void apply_perm_based_hashing(sht_ctx* table, hs_t* hs) {
#ifdef DEBUG_SH
    std::cout << "SH PERM B HASH OUT BYTELEN " << hs->outbytelen << std::endl;
#endif
    for (size_t i = 0; i < table->nbins; i++) {
        uint8_t * tmp = (uint8_t*) calloc(sizeof*tmp * hs->outbytelen, table->bins[i].nvals);
        for (size_t j = 0; j < table->bins[i].nvals; j++) {
            uint32_t addr[hs->nhashfuns];
            uint8_t tmp_hash[hs->nhashfuns * hs->outbytelen];
            uint8_t* position = &table->bins[i].values[j * (hs->inbytelen)];
            hashElement(position, addr, tmp_hash, hs);

            uint8_t func_n = 0;
            if (addr[0] == addr[1])
                    func_n = j % 2;
            else if (addr[0] == i)
                func_n = 0;
            else if (addr[1] == i)
                func_n = 1;
            else {
                std::cout << "Error in applying permutation-based hashing." << std::endl <<
                        "Did not found the correct address of the element" << std::endl;
                std::cout << "Needed " << j << "\tFound " << addr[0] << " and " << addr[1] << std::endl;
            }
#ifdef DEBUG_SH
            std::cout << "SH PERM-B HASHING tmp hash Bin#" << i << " pos \t" << j << "\t" << (hex) << (*(((uint32_t*) tmp_hash) + j)) << (dec) << std::endl;
#endif
            memcpy(&tmp[j * hs->outbytelen], tmp_hash, hs->outbytelen);
            tmp[j * hs->outbytelen] ^= (func_n & 0x03);
#ifdef DEBUG_SH
            std::cout << "SH PERM-B HASHING tmp after Bin#" << i << " pos \t" << j << "\t" << (hex) << (*(((uint32_t*) tmp) + j)) << (dec) << std::endl;
#endif
        }
#ifdef DEBUG_SH
        std::cout << "SH PERM-B HASHING values before Bin#" << i << "\t" << (hex) << (*((uint32_t*) table->bins[i].values)) << (dec) << std::endl;
#endif            
        free(table->bins[i].values);
        table->bins[i].values = tmp;
#ifdef DEBUG_SH
        std::cout << "SH PERM-B HASHING values after Bin#" << i << "\t" << (hex) << (*((uint32_t*) table->bins[i].values)) << (dec) << std::endl;
#endif
    }
}

void print_sh_table(sht_ctx** table, size_t elem_len) {
    std::cout << std::endl << "Printing bins" << std::endl;
    std::cout << "--------------------------------" << std::endl;
    for (size_t table_i = 0; table_i < 2; table_i++) {
        std::cout << "Table " << table_i << std::endl << "--------------------------------" << std::endl;
        for (size_t bin_i = 0; bin_i < table[table_i]->nbins; bin_i++) {
            std::cout << "Bin #" << bin_i << "\t of size " << table[table_i]->bins[bin_i].nvals << " : \t";
            for (size_t elem_i = 0; elem_i < table[table_i]->bins[bin_i].nvals; elem_i++) {
                for (size_t bit_i = 0; bit_i < elem_len; bit_i++)
                    printf("%02x", table[table_i]->bins[bin_i].values[elem_i * elem_len + bit_i]);
                std::cout << " ";
            }
            std::cout << std::endl;
        }
        std::cout << "--------------------------------" << std::endl;
    }
}

void self_test(uint8_t* elems, size_t elem_len, size_t n_elems, sht_ctx** table, hs_t*hs) {
    std::cout << "Starting a self-test" << std::endl;
    uint32_t ** addr = (uint32_t **) malloc(sizeof (*addr)*2);
    uint8_t ** val = (uint8_t **) malloc(sizeof (*val)*2);
    size_t errors = 0;
    for (size_t k = 0; k < N_TABLES; k++) {
        addr[k] = (uint32_t*) malloc(sizeof*addr[k]*100);
        val[k] = (uint8_t*) malloc(sizeof*val[k]*200);
    }
    for (size_t elem_i = 0; elem_i < n_elems; elem_i++) {
        hashElement(elems + elem_len * elem_i, addr[0], val[0], &hs[0]);
        hashElement(elems + elem_len * elem_i, addr[1], val[1], &hs[1]);
        if (!(contains_two(elems + elem_len * elem_i, &elem_len, table[0], addr[0]) |
                contains_two(elems + elem_len * elem_i, &elem_len, table[1], addr[1]))) {
            std::cout << "Did not found all occurences of: \t";
            for (size_t tmp = 0; tmp < elem_len; tmp++)
                printf("%02x", elems[elem_len * elem_i + tmp]);
            std::cout << std::endl;
            errors++;
        }
    }
    std::cout << "Found " << errors << " errors" << std::endl;
    for (size_t k = 0; k < N_TABLES; k++) {
        free(addr[k]);
        free(val[k]);
    }
    free(val);
    free(addr);
}

bool contains_two(uint8_t* elem, size_t* elem_len, sht_ctx* table, uint32_t *addr) {
    bool b[2];
    b[0] = b[1] = false;
    for (size_t j = 0; j < 2; j++)
        for (size_t i = 0; i < table->bins[addr[j]].nvals; i++)
            if (is_equal(&(table->bins[addr[j]].values[i * *elem_len]), elem, elem_len))
                b[j] = true;
    return b[0] & b[1];
}

void print_elem(uint8_t * elem, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", elem[i]);
}
