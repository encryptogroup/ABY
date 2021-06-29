/**
 \file 		phasing_circuit.cpp
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
 \brief		Implementation of ABYSetIntersection.
 */

#include "psi_2D_CH_circuit.h"
#include "../../../abycore/sharing/sharing.h"

#include <math.h>
#include <cassert>

int32_t test_2D_CH_circuit(e_role role, char* address, uint16_t port, seclvl seclvl,
        uint32_t server_neles, uint32_t client_neles, uint32_t bitlen, double epsilon, uint32_t nthreads,
        e_mt_gen_alg mt_alg, e_sharing sharing, int ext_stash_size, uint32_t maxbin, uint32_t nhashfuns, uint32_t threshold) {

    uint32_t *server_set, *client_set, *circ_intersect, *ver_intersect, *inv_perm, *stashperm;
    uint32_t ver_inter_ctr = 0, circ_inter_ctr = 0, internalbitlen, maxstashsize, maxbinsize;
    share*** s_server_hash_table, **s_client_hash_table, **s_single_out, *s_out, *s_server_set, **s_client_stash, *s_stash_out;
    assert(bitlen <= 32);
    uint32_t nbins = ceil(epsilon * client_neles);
    uint8_t **client_hash_table, **server_hash_table, *stash;
    timespec t_start, t_end;
    std::cout << "Cardinality threshold: " << threshold << std::endl;

    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
            mt_alg, 40000000);

    std::vector<Sharing*>& sharings = party->GetSharings();

    BooleanCircuit* circ = (BooleanCircuit*) sharings[sharing]->GetCircuitBuildRoutine();
    assert(circ->GetCircuitType() == C_BOOLEAN);

    crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);

    server_set = (uint32_t*) malloc(sizeof (uint32_t) * server_neles);
    client_set = (uint32_t*) malloc(sizeof (uint32_t) * client_neles);
    ver_intersect = (uint32_t*) calloc(client_neles, sizeof (uint32_t));
    circ_intersect = (uint32_t*) malloc(sizeof (uint32_t) * client_neles);

    inv_perm = (uint32_t*) malloc(nbins * sizeof (uint32_t));

    if (ext_stash_size == -1) {
        maxstashsize = assign_max_stash_size(server_neles);
    } else {
        maxstashsize = (uint32_t) ext_stash_size;
    }

    //sample random server and client sets
    //sample_random_elements(neles, bitlen, srv_set, cli_set);
    //sample fixed server and client sets (is faster than random sets for larger sets)
    set_fixed_elements(server_neles, client_neles, bitlen, server_set, client_set);

#ifdef DEBUG_PHASING
    for (uint32_t i = 0; i < client_neles; i++) {
        std::cout << i << ": " << (hex) << std::setw(ceil_divide(bitlen, 8)) <<
                server_set[i] << " , " << std::setw(ceil_divide(bitlen, 8)) <<
                client_set[i] << dec << std::endl;
    }
#endif
    //Map server's elements to a set of bins using simple hashing
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    ServerHashingRoutine((uint8_t*) server_set, server_neles, bitlen, nbins, &maxbinsize, &server_hash_table,
            &internalbitlen, 1, crypt, nhashfuns);
    clock_gettime(CLOCK_MONOTONIC, &t_end);

#ifndef BATCH
    if (role == SERVER) {
        std::cout << "Time for simple hashing: " << getMillies(t_start, t_end) << std::endl;
    }
#endif 
    ///Map client's elements to a set of bins using simple cuckoo hashing
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    ClientHashingRoutine((uint8_t*) client_set, client_neles, bitlen, nbins, &client_hash_table, inv_perm,
            &internalbitlen, &stash, maxstashsize, stashperm, 1, crypt, nhashfuns);
    clock_gettime(CLOCK_MONOTONIC, &t_end);

    std::cout << "Computing the intersection between " << server_neles << " and " <<
            client_neles << " elements with " << nbins << " bins, " <<
            nhashfuns << " hash functions, a stash of size " << maxstashsize <<
            ", and maxbin = " << maxbinsize << std::endl;

#ifndef BATCH
    if (role == CLIENT) {
        std::cout << "Time for cuckoo hashing: " << getMillies(t_start, t_end) << std::endl;
    }
#endif
    s_single_out = (share**) malloc(sizeof*s_single_out * N_TABLES);
    s_client_hash_table = (share**) malloc(sizeof*s_client_hash_table * N_TABLES);
    s_server_hash_table = (share***) malloc(sizeof *s_server_hash_table * N_TABLES);
    s_client_stash = (share**) malloc(sizeof (share*) * maxstashsize);
    uint32_t internalbytelen = ceil_divide(internalbitlen, 8);
    maxbinsize = BIN_SIZE_LIMIT;
    for (size_t k = 0; k < N_TABLES; k++) {
        s_server_hash_table[k] = (share**) malloc(sizeof (share*) * maxbinsize);
    }
    
    for (size_t k = 0; k < N_TABLES; k++) {
        //Set input gates for the client
        CBitVector tmpset(internalbytelen * 8 * nbins);
        for (uint32_t i = 0; i < nbins; i++) {
            tmpset.SetBytes(&client_hash_table[k][i * internalbytelen], (int) i * internalbytelen, (int) internalbytelen);
        }
        s_client_hash_table[k] = circ->PutSIMDINGate(nbins, client_hash_table[k], internalbitlen, CLIENT);

        //Set input gates for the server
        for (uint32_t i = 0; i < maxbinsize; i++) {
            tmpset.Reset();
            for (uint32_t j = 0; j < nbins; j++) {
                uint position = (j * maxbinsize + i) * internalbytelen;
                tmpset.SetBytes(&server_hash_table[k][position], (int) j * internalbytelen, (int) internalbytelen);
            }
            s_server_hash_table[k][i] = circ->PutSIMDINGate(nbins, tmpset.GetArr(), internalbitlen, SERVER);
        }
        //Compute N_TABLES phasing circuits
        s_single_out[k] = BuildPhasingCircuit(s_server_hash_table[k], s_client_hash_table[k], maxbinsize, circ);
    }

    //Combine outputs of tables
    s_out = circ->PutCombinerGate(s_single_out[0], s_single_out[1]);

    s_server_set = circ->PutSIMDINGate(server_neles, server_set, bitlen, SERVER);

    for (uint32_t i = 0; i < maxstashsize; i++) {
        s_client_stash[i] = circ->PutINGate(((uint32_t*) (stash))[i], bitlen, CLIENT);
        s_client_stash[i] = circ->PutRepeaterGate(server_neles, s_client_stash[i]);
    }

    //Build one stash share for all cuckoo tables
    s_stash_out = BuildPhasingStashCircuit(s_server_set, s_client_stash, server_neles, bitlen, maxstashsize, circ);

    //Combine table outputs with stash output
    s_out = circ->PutCombinerGate(s_out, s_stash_out);
    //Split the output into single bits
    s_out = circ->PutSplitterGate(s_out);
    //Compute hamming weight of the output
    s_out = circ->PutHammingWeightGate(s_out);

    //Compare threshold with the output value
    share * s_threshold = circ->PutINGate(threshold, 32, SERVER);
    share * s_comp_result = circ->PutGTGate(s_out, s_threshold);

    //Constant zero gate
    uint64_t zero = 0;
    uint32_t zerolen = 1;
    share * shr_zero = circ->PutCONSGate(zero, zerolen);

    //Return intersection if >threshold, 0 otherwise
    s_out = circ->PutMUXGate(s_out, shr_zero, s_comp_result);
    s_out = circ->PutOUTGate(s_out, CLIENT);

    party->ExecCircuit();
    //Only the client obtains the outputs and performs the checks
    if (role == CLIENT) {
        uint8_t* output = s_out->get_clear_value_ptr();
        size_t intersection_size = 0;

#ifdef DEBUG_PHASING
        std::cout << "Stash size:\t" << s_stash_out->get_clear_value<uint32_t>() << std::endl;
        std::cout << "Result: " << (hex) << std::endl;
        for (uint32_t i = 0; i < nbins; i++) {
            if (output[i] != 0) {
                memcpy((uint8_t*) (circ_intersect + circ_inter_ctr), (uint8_t*) (client_set + inv_perm[i]), sizeof (uint32_t));
                std::cout << "Bin " << i << " holds an intersecting element: " << (hex) <<
                        circ_intersect[circ_inter_ctr] << (dec) << " (" << inv_perm[i] << ")" << std::endl;
                circ_inter_ctr++;
                intersection_size++;
            }
            std::cout << setw(2) << setfill('0') << (uint32_t) output[i];
        }
        std::cout << std::endl;

        uint32_t outstash = s_stash_out->get_clear_value<uint32_t>();
        for (uint32_t i = 0; i < maxstashsize; i++) {
            if (((outstash >> i) & 0x01) != 0) {
                memcpy((uint8_t*) (circ_intersect + circ_inter_ctr), (uint8_t*) (client_set + stashperm[i]), sizeof (uint32_t));
                std::cout << "stash pos " << i << " holds an intersecting element: " << (hex) <<
                        circ_intersect[circ_inter_ctr] << (dec) << " (" << inv_perm[i] << ")" << std::endl;
                circ_inter_ctr++;
            }
            std::cout << setw(2) << setfill('0') << (uint32_t) output[i];
        }

        std::cout << "Server and client input for bitlen = " << bitlen << ": " << std::endl;
        for (uint32_t i = 0; i < client_neles; i++) {
            std::cout << (hex) << setw(2) << setfill('0') << server_set[i] << ", " << setw(2) << setfill('0') << client_set[i] << (dec) << std::endl;
        }
#endif

#ifndef BATCH
        std::sort(server_set, server_set + server_neles);
        std::sort(client_set, client_set + client_neles);

        std::set_intersection(server_set, server_set + server_neles, client_set, client_set + client_neles, ver_intersect);
        for (ver_inter_ctr = 0; ver_intersect[ver_inter_ctr] > 0; ver_inter_ctr++) {
            //if(ver_temp[i] > 0)
            //std::cout << ver_inter_ctr << (hex) << ": " << ver_intersect[ver_inter_ctr] <<(dec)<< std::endl;
        }

        std::sort(ver_intersect, ver_intersect + ver_inter_ctr);
        std::sort(circ_intersect, circ_intersect + circ_inter_ctr);

        std::cout << "Number of intersections: " << ver_inter_ctr << " (ver), " << circ_inter_ctr <<
                " (circ), with a stash of size " << maxstashsize << std::endl;

        /*for(uint32_t i = 0; i < ver_inter_ctr; i++) {
                std::cout << "Verification " << i << ": " << (hex) << ver_intersect[i] << (dec) << std::endl;
        }
        for(uint32_t i = 0; i < circ_inter_ctr; i++) {
                std::cout << "Circuit " << i << ": " << (hex) << circ_intersect[i] << (dec) << std::endl;
        }*/
        /*assert(circ_inter_ctr == ver_inter_ctr);
        for (uint32_t i = 0; i < circ_inter_ctr; i++) {
            assert(ver_intersect[i] == circ_intersect[i]);
        }*/
#endif

#ifdef DEBUG_PHASING
        std::cout << "Intersection size : " << intersection_size << std::endl;
        std::cout << "Clear values" << s_out->get_clear_value() << std::endl;
#endif
        uint32_t psi_cat_value = s_out->get_clear_value<uint32_t>();
        //Check if psi_cat_value is greater than 0. This is the case when
        //intersection size is 0 or it is smaller than threshold.
        if (psi_cat_value > 0) {
            std::cout << "Intersection size: " << psi_cat_value << std::endl;
#ifdef DEBUG_PHASING
            if (psi_cat_value != server_neles)
                std::cout << "Wrong neles!" << std::endl;
#endif
        }
    }

#ifdef BATCH
    std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) + party->GetTiming(P_BASE_OT) <<
            "\t" << party->GetSentData(P_TOTAL) + party->GetReceivedData(P_TOTAL) << std::endl;
#endif

    free(server_set);
    free(client_set);
    free(s_server_hash_table);
    free(s_client_hash_table);
    free(s_out);
    free(ver_intersect);
    free(circ_intersect);
    free(inv_perm);
    free(stash);

    return 0;
}

//sample random client and server set such that ~half of the elements overlap

void sample_random_elements(uint32_t neles, uint32_t bitlen, uint32_t* srv_set, uint32_t* cli_set) {
    uint64_t mask = ((uint64_t) 1 << bitlen) - 1;
    srand(time(NULL));

    //sample random client and server inputs
    uint32_t rndval;
    for (uint32_t i = 0; i < neles; i++) {
        do {
            rndval = rand() & mask;
        } while (std::find(srv_set, srv_set + i, rndval) != srv_set + i
                || std::find(cli_set, cli_set + i, rndval) != cli_set + i);

        srv_set[i] = rndval;
        cli_set[i] = rndval;

        if (rand() % 2 == 0) {
            cli_set[i] = rndval;
        } else {
            do {
                rndval = rand() & mask;
            } while (std::find(srv_set, srv_set + i, rndval) != srv_set + i
                    || std::find(cli_set, cli_set + i, rndval) != cli_set + i);
            cli_set[i] = rndval;
        }
    }

}

//generate client and server set such that half of the elements overlap

void set_fixed_elements(uint32_t server_neles, uint32_t client_neles, uint32_t bitlen,
        uint32_t* srv_set, uint32_t* cli_set) {
    uint32_t incr = 15875162;
    uint32_t offset = (server_neles + client_neles) / 2;
    for (uint32_t i = 0; i < server_neles; i++) {
        srv_set[i] = incr * (i + 1);
        cli_set[i] = incr * (i + 1); // Added
    }

    /*for (uint32_t i = 0; i < client_neles; i++) {
        cli_set[i] = incr * (i + offset);
    }*/

}

share* BuildPhasingCircuit(share** shr_srv_set, share* shr_cli_set, uint32_t binsize,
        BooleanCircuit* circ) {
    share* out;
    share** eq = (share**) malloc(sizeof (share*) * binsize);
    //circ->PutPrintValueGate(shr_cli_set, "Client");
    for (uint32_t i = 0; i < binsize; i++) {
        //circ->PutPrintValueGate(shr_srv_set[i], "Server");
        eq[i] = circ->PutEQGate(shr_cli_set, shr_srv_set[i]);
    }
    out = eq[0];
    for (uint32_t i = 1; i < binsize; i++) {
        out = circ->PutXORGate(out, eq[i]);
    }
    free(eq);
#ifdef DEBUG_PHASING
    circ->PutPrintValueGate(out, "Results");
    circ->PutPrintValueGate(out, "Hamming Weight");
#endif
    return out;
}

share* BuildPhasingStashCircuit(share* s_server_set, share** s_client_stash, uint32_t neles, uint32_t bitlen,
        uint32_t maxstashsize, BooleanCircuit* circ) {
    if (!maxstashsize) {
        static uint64_t zero = 0;
        static uint32_t zerolen = 1;
        return circ->PutCONSGate(zero, zerolen);
    }
    size_t size = maxstashsize;

    share* out = new boolshare(size, circ);
    share *eq, *eqa, *eqb;
    uint32_t xoreq, *posa, *posb, tmpneles;

    share ** stash = (share**) malloc(size * sizeof (*s_client_stash));

    for (size_t i = 0; i < size; i++)
        stash[i] = s_client_stash[i];

    std::vector<uint32_t> odd_stash;

    uint32_t* ids = (uint32_t*) malloc(sizeof (uint32_t) * neles);
    for (uint32_t i = 0; i < neles; i++)
        ids[i] = i;

    for (uint32_t i = 0; i < maxstashsize; i++) {
        eq = circ->PutEQGate(s_server_set, stash[i]);

        for (uint32_t j = neles; j > 1; j /= 2) {
            if (j & 0x01 > 0) { //value is odd, hence store highest value on stash
                tmpneles = j - 1;
                odd_stash.push_back(circ->PutSubsetGate(eq, &tmpneles, 1)->get_wire_id(0));
            }
            posa = ids;
            posb = ids + (j / 2);
            eqa = circ->PutSubsetGate(eq, posa, j / 2);
            eqb = circ->PutSubsetGate(eq, posb, j / 2);
            eq = circ->PutXORGate(eqa, eqb);
        }
        xoreq = eq->get_wire_id(0);
        for (uint32_t j = 0; j < odd_stash.size(); j++) //handle all odd values
            xoreq = circ->PutXORGate(xoreq, odd_stash[j]);

        odd_stash.clear();

        out->set_wire_id(i, xoreq);
    }

    free(stash);
    free(ids);
    return out;
}

void ServerHashingRoutine(uint8_t* elements, uint32_t neles, uint32_t elebitlen, uint32_t nbins,
        uint32_t *maxbinsize, uint8_t*** hash_table, uint32_t* outbitlen, uint32_t ntasks, crypto* crypt, uint32_t nhashfuns) {

    uint32_t outbytelen;
    prf_state_ctx prf_state;
    uint8_t **tmphashtable, *server_dummy;
    uint32_t **nelesinbin = (uint32_t**) malloc(sizeof *nelesinbin * N_TABLES);
    for (size_t k = 0; k < N_TABLES; k++)
        nelesinbin[k] = (uint32_t*) malloc(sizeof *nelesinbin[k] * nbins);

    tmphashtable = simple_hashing(elements, neles, elebitlen, outbitlen, nelesinbin, nbins, maxbinsize,
            ntasks, nhashfuns, &prf_state, crypt);
    *maxbinsize = BIN_SIZE_LIMIT;
    outbytelen = ceil_divide(*outbitlen, 8);
    server_dummy = (uint8_t*) malloc(outbytelen);
    memset(server_dummy, DUMMY_ENTRY_SERVER, outbytelen);
    (*hash_table) = (uint8_t**) malloc(sizeof*(*hash_table) * N_TABLES);
    for (size_t k = 0; k < N_TABLES; k++)
        (*hash_table)[k] = (uint8_t*) malloc(outbytelen * nbins * (*maxbinsize));

    for (size_t k = 0; k < N_TABLES; k++)
        memcpy((*hash_table)[k], tmphashtable[k], outbytelen * nbins * (*maxbinsize));

    size_t len = outbytelen;
    crypt->free_prf_state(&prf_state);
    for (size_t k = 0; k < N_TABLES; k++) {
        free(tmphashtable[k]);
        free(nelesinbin[k]);
    }
    free(tmphashtable);
    free(server_dummy);
    free(nelesinbin);
}

void ClientHashingRoutine(uint8_t* elements, uint32_t neles, uint32_t elebitlen, uint32_t nbins,
        uint8_t*** hash_table, uint32_t* inv_perm, uint32_t* outbitlen, uint8_t** stash,
        uint32_t maxstashsize, uint32_t* stashperm, uint32_t ntasks, crypto* crypt, uint32_t nhashfuns) {
    uint32_t outbytelen;
    prf_state_ctx prf_state;
    uint8_t *tmphashtable, *client_dummy;
    uint32_t **nelesinbin = (uint32_t**) malloc(sizeof*nelesinbin * N_TABLES);
    for (size_t k = 0; k < N_TABLES; k++)
        nelesinbin[k] = (uint32_t*) calloc(nbins, sizeof (uint32_t));
    uint32_t* perm = (uint32_t*) malloc(sizeof (uint32_t) * nbins);

    *hash_table = cuckoo_hashing(elements, neles, nbins, elebitlen, outbitlen, nelesinbin,
            perm, ntasks, stash, maxstashsize, stashperm, nhashfuns, &prf_state, crypt);

#ifdef DEBUG_PHASING
    std::cout << "Client bins: " << std::endl;
    for (uint32_t i = 0, ctr = 0; i < nbins; i++) {
        std::cout << "Bin " << i << ": ";
        std::cout << *((uint32_t*) * hash_table[ctr]) << ", ";
        std::cout << std::endl;
    }
#endif

    for (uint32_t i = 0, ctr = 0; i < nbins; i++) {
        if (nelesinbin[0][i] > 0) {
            inv_perm[i] = perm[ctr++];
        }
    }
    crypt->free_prf_state(&prf_state);
    //for (size_t k = 0; k < N_TABLES; k++)
    //   free(nelesinbin[k]);
    free(nelesinbin);
    //free(perm);  
}

void pad_elements(uint8_t* hash_table, uint32_t elebytelen, uint32_t nbins, uint32_t* nelesinbin,
        uint32_t maxbinsize, uint8_t* padded_hash_table, uint8_t* dummy_element) {

    uint8_t* htptr = hash_table;
    uint8_t* phtptr = padded_hash_table;
#ifdef DEBUG_PHASING
    std::cout << "Input hash table: " << std::endl;
    for (uint32_t i = 0, ctr = 0; i < nbins; i++) {
        std::cout << i << ": ";
        for (uint32_t k = 0; k < nelesinbin[i]; k++) {
            std::cout << k << " ";
            for (uint32_t j = 0; j < elebytelen; j++, ctr++) {
                std::cout << (hex) << setw(2) << setfill('0') << (uint32_t) hash_table[ctr];
            }
            std::cout << "; ";
        }
        std::cout << (dec) << std::endl;
    }
#endif
    for (uint32_t i = 0; i < nbins; i++) {
        //Copy existing elements
        for (uint32_t j = 0; j < nelesinbin[i]; j++, phtptr += elebytelen, htptr += elebytelen) {
            memcpy(phtptr, htptr, elebytelen);
        }
        //Pad remaining positions with dummy element
        for (uint32_t j = nelesinbin[i]; j < maxbinsize; j++, phtptr += elebytelen) {
            memcpy(phtptr, dummy_element, elebytelen);
        }
    }
#ifdef DEBUG_PHASING
    std::cout << "Padded hash table: " << std::endl;
    for (uint32_t i = 0; i < nbins; i++) {
        std::cout << i << ": ";
        for (uint32_t k = 0; k < maxbinsize; k++) {
            std::cout << k << " ";
            for (uint32_t j = 0; j < elebytelen; j++) {
                std::cout << (hex) << setw(2) << setfill('0') << (uint32_t) padded_hash_table[(i * maxbinsize + k) * elebytelen + j];
            }
            std::cout << "; ";
        }
        std::cout << (dec) << std::endl;
    }
#endif
}

uint32_t assign_max_stash_size(uint32_t neles) {
    if (neles >= 1 << 24) {
        return 2;
    } else if (neles >= 1 << 20) {
        return 3;
    } else if (neles >= 1 << 16) {
        return 5;
    } else if (neles >= 1 << 13) {
        return 6;
    } else if (neles >= 1 << 12) {
        return 7;
    } else if (neles >= 1 << 11) {
        return 9;
    } else if (neles >= 1 << 10) {
        return 11;
    } else {
        return 12;
    }
}
