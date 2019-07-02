/**
 \file 		hashing_util.h
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

#ifndef HASHING_UTIL_H_
#define HASHING_UTIL_H_

#include "../hashing_includes.h"
#include <math.h>
#include <cassert>
#include <cstring>

typedef uint16_t TABLEID_T;

//#define TEST_UTILIZATION
#define MAX_TABLE_SIZE_BYTES sizeof(TABLEID_T)
#define DUMMY_ENTRY_SERVER 0x00
#define DUMMY_ENTRY_CLIENT 0xFF

#define USE_LUBY_RACKOFF

typedef struct hashing_state_ctx {
	uint32_t nhashfuns;
	uint32_t*** hf_values;//[NUM_HASH_FUNCTIONS];
	uint32_t nhfvals;
	uint32_t nelements;
	uint32_t nbins;
	uint32_t inbitlen;
	uint32_t addrbitlen;
	uint32_t floor_addrbitlen;
	uint32_t outbitlen;
	//the byte values, are stored separately since they are needed very often
	uint32_t inbytelen;
	uint32_t addrbytelen;
	uint32_t outbytelen;
	uint32_t* address_used;
	uint32_t mask;
} hs_t;


//use as mask to address the bits in a uint32_t vector
static const uint32_t SELECT_BITS[33] = \
									{0x00000000, 0x00000001, 0x00000003, 0x00000007, 0x0000000F, 0x0000001F, 0x0000003F, 0x0000007F, \
									 0x000000FF, 0x000001FF, 0x000003FF, 0x000007FF, 0x00000FFF, 0x00001FFF, 0x00003FFF, 0x00007FFF, \
									 0x0000FFFF, 0x0001FFFF, 0x0003FFFF, 0x0007FFFF, 0x000FFFFF, 0x001FFFFF, 0x003FFFFF, 0x007FFFFF, \
									 0x00FFFFFF, 0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, \
									 0xFFFFFFFF };

//can also be computed as SELECT_BITS ^ 0xFFFFFFFF
static const uint32_t SELECT_BITS_INV[33] = \
									{0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8, 0xFFFFFFF0, 0xFFFFFFE0, 0xFFFFFFC0, 0xFFFFFF80, \
									 0xFFFFFF00, 0xFFFFFE00, 0xFFFFFC00, 0xFFFFF800, 0xFFFFF000, 0xFFFFE000, 0xFFFFC000, 0xFFFF8000, \
									 0xFFFF0000, 0xFFFE0000, 0xFFFC0000, 0xFFF80000, 0xFFF00000, 0xFFE00000, 0xFFC00000, 0xFF800000, \
									 0xFF000000, 0xFE000000, 0xFC000000, 0xF8000000, 0xF0000000, 0xE0000000, 0xC0000000, 0x80000000, \
									 0x00000000 };

static const uint8_t BYTE_SELECT_BITS_INV[8] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01};

//Init the values for the hash function
inline void init_hashing_state(hs_t* hs, uint32_t nelements, uint32_t inbitlen, uint32_t nbins,
		uint32_t nhashfuns, prf_state_ctx* prf_state) {
	uint32_t i, j, nrndbytes;
	hs->nhashfuns = nhashfuns;
	hs->nelements = nelements;
	hs->nbins = nbins;

	hs->inbitlen = inbitlen;
	hs->addrbitlen = std::min((uint32_t) ceil_log2(nbins), inbitlen);
	hs->floor_addrbitlen = std::min((uint32_t) floor_log2(nbins), inbitlen);

#ifdef USE_LUBY_RACKOFF
	hs->outbitlen = hs->inbitlen - hs->addrbitlen+3;
#else
	hs->outbitlen = inbitlen;
#endif
	//TODO prevent too much memory utilization
	//assert(hs->outbitlen < 32);
	//TODO: quickfix to enable hashing for large values
	//hs->outbitlen = std::min((double) hs->outbitlen, (double) 24);

	hs->inbytelen = ceil_divide(hs->inbitlen, 8);
	hs->addrbytelen = ceil_divide(hs->addrbitlen, 8);
	hs->outbytelen = ceil_divide(hs->outbitlen, 8);

	hs->nhfvals = ceil_divide(hs->outbytelen, MAX_TABLE_SIZE_BYTES);


	nrndbytes = (1<<(8*MAX_TABLE_SIZE_BYTES)) * sizeof(uint32_t);

	//cout << " random bytes: " << nrndbytes << endl;
	//cout << "inbitlen = " << hs->inbitlen << ", outbitlen = " << hs->outbitlen << ", addrbitlen = " << hs->addrbitlen <<
	//		", nhfvals = " << hs->nhfvals << ", nrndbytes = " << nrndbytes << endl;

	hs->hf_values = (uint32_t***) malloc(sizeof(uint32_t**) * hs->nhashfuns);
	for(i = 0; i < hs->nhashfuns; i++) {
		hs->hf_values[i] = (uint32_t**) malloc(sizeof(uint32_t*) * hs->nhfvals);

		for(j = 0; j < hs->nhfvals; j++) {
			hs->hf_values[i][j] = (uint32_t*) malloc(nrndbytes);
			assert(hs->hf_values[i][j]);
			gen_rnd_bytes(prf_state, (uint8_t*) hs->hf_values[i][j], nrndbytes);
		}
	}
	//cout << "nhfvals = " << hs->nhfvals << endl;
	hs->address_used = (uint32_t*) calloc(nbins, sizeof(uint32_t));
	hs->mask = 0xFFFFFFFF >> hs->addrbitlen;
	if(hs->inbytelen < sizeof(uint32_t)) {
		hs->mask >>= (sizeof(uint32_t) * 8 - hs->inbitlen - hs->addrbitlen);
	}
}

inline void free_hashing_state(hs_t* hs) {
	uint32_t i, j;
	for(i = 0; i < hs->nhashfuns; i++) {
		for(j = 0; j  < hs->nhfvals; j++) {
			free(hs->hf_values[i][j]);
		}
		free(hs->hf_values[i]);
	}
	free(hs->address_used);
	free(hs->hf_values);
}

//reduce the bit-length of the elements if some bits are used to determine the bin and a permutation is used for hashing
//static uint32_t getOutBitLen(uint32_t inbitlen, uint32_t nelements) {
//	return inbitlen - ceil_log2(nelements);
//};

//TODO: a generic place holder, can be replaced by any other hash function
//inline void hashElement(uint8_t* element, uint32_t* address, uint8_t* val, uint32_t hfid, hs_t* hs) {
inline void hashElement(uint8_t* element, uint32_t* address, uint8_t* val, hs_t* hs) {

	//for(uint32_t i = 0; i < hs->inbytelen; i++)
	//	cout << (hex) << (uint32_t) element[i];
	//cout << (dec) << endl;
#ifdef USE_LUBY_RACKOFF
	//TODO: the table-lookup hashing is only used for elements up to 32-bit length, since it gets very inefficient for larger values
	uint64_t i, j, L, R=0L;
	TABLEID_T hfmaskaddr;
	//Store the first hs->addrbitlen bits in L
	L = *((uint32_t*) element) & SELECT_BITS[hs->addrbitlen];
	//Store the remaining hs->outbitlen bits in R and pad correspondingly. Shift two to the left since permutation bit is added later on
	R = ((*((uint32_t*) element) & SELECT_BITS_INV[hs->floor_addrbitlen]) >> (hs->floor_addrbitlen)) << 2;

	//cout << "address bitlen = " << hs->addrbitlen <<", L = " << L << ", R = " << R << ", element = " << ((uint32_t*) element)[0] << endl;
	// Zero out all nonrelevant bits
	R &= hs->mask;//mask = (1<<32-hs->addrbitlen)


	//assert(R < (1<<hs->outbitlen));
	//cout << "R = " << R << endl;
	/*if(hfid == 0) {
		*address = L % hs->nbins;
		*((uint32_t*) val)  = R;
	} else if(hfid == 1) {
		*address = R % hs->nbins;
		*((uint32_t*) val)  = L;
	} else {
		*address = (L ^ R) % hs->nbins;
		*((uint32_t*) val)  = R;
	}*/
	hfmaskaddr = R * sizeof(uint32_t);
	//cout << "L = " << L << ", R = " << R << " addresses: ";
	for(i = 0; i < hs->nhashfuns; i++) {
		//cout << "i = " << i << ", addrbytelen = " << hs->addrbytelen << ", R = " << R << ", nbins = " <<
		//		hs->nbins << ", L = " << L << ", addr= " <<  endl;
		//address[i] = (L ^ *(((uint32_t*) &(hs->hf_values[i][R*hs->addrbytelen])))) % hs->nbins;
		for(j = 0; j < hs->nhfvals; j++) {
			//assert(hfmaskaddr < (1<<(8*MAX_TABLE_SIZE_BYTES)) * hs->addrbytelen);
			//cout << "i = " << i << ", j = " << j << ", Hfmaskaddr = " << hfmaskaddr << endl;
			//cout << "Hfvalue: " << hs->hf_values[i][j][hfmaskaddr] << endl;
			address[i] = (L ^ *((hs->hf_values[i][j]+hfmaskaddr))) % hs->nbins;
			//address[i] = (L ^ (i * R)) % hs->nbins;
		}
		//cout << address[i] << ", ";
		//hs->address_used[address[i]]++;
	}
	//cout << endl;
#ifndef TEST_UTILIZATION
	R++;
	*((uint32_t*) val)  = R;
	//cout << (hex) << *((uint32_t*) element) << ", L = " << L << ", R = " << R << (dec) << endl;
	//TODO copy remaining bits

	//if(hs->outbytelen >= sizeof(uint32_t))
	if(hs->inbitlen > sizeof(uint32_t) * 8) {
		//memcpy(val + (sizeof(uint32_t) - hs->addrbytelen), element + sizeof(uint32_t), hs->outbytelen - (sizeof(uint32_t) - hs->addrbytelen));
		memcpy(val + (sizeof(uint32_t) - (hs->floor_addrbitlen >>3)), element + sizeof(uint32_t), hs->outbytelen - (sizeof(uint32_t) - (hs->floor_addrbitlen >>3)));

		//cout << "Element: "<< (hex) << (uint32_t) val[hs->outbytelen-1] << ", " << (uint32_t) (BYTE_SELECT_BITS_INV[hs->outbitlen & 0x03])
		//		<< ", " << (uint32_t) (val[hs->outbytelen-1] & (BYTE_SELECT_BITS_INV[hs->outbitlen & 0x03]) )<< (dec) << " :";

		val[hs->outbytelen-1] &= (BYTE_SELECT_BITS_INV[hs->outbitlen & 0x03]);

		/*for(i = 0; i < hs->inbytelen; i++) {
			cout << (hex) << (uint32_t) element[i];
		}
		cout << ", ";
		for(i = 0; i < hs->outbytelen; i++) {
			cout << (hex) << (uint32_t) val[i];
		}
		cout << (dec) << endl;*/
	}


#endif
	//cout << "Address for hfid = " << hfid << ": " << *address << ", L = " << L << ", R = " << R << endl;

#else
	for(uint64_t i = 0; i < NUM_HASH_FUNCTIONS; i++) {
		address[i] = ((*((uint32_t*) element+i) ^ HF_MASKS[i]) & SELECT_BITS[hs->addrbitlen]) % hs->nbins;

	#ifndef TEST_UTILIZATION
		*((uint32_t*) val)  = (*((uint32_t*) element) & SELECT_BITS_INV[hs->addrbitlen]) >> (hs->addrbitlen);

	//copy the remaining full bytes
		if(hs->outbytelen >= sizeof(uint32_t))
			memcpy(val + (sizeof(uint32_t) - hs->addrbytelen), element + sizeof(uint32_t), hs->outbytelen - sizeof(uint32_t));
	#endif
	}
#endif
}

inline void domain_hashing(uint32_t nelements, uint8_t* elements, uint32_t elebytelen, uint8_t* result,
		uint32_t resultbytelen, crypto* crypt) {

	uint8_t *eleptr, *resultptr, *hash_buf;
	uint32_t i;

	eleptr=elements;
	resultptr = result;
#ifndef BATCH
	cout << "Hashing " << nelements << " elements from " << elebytelen << " bytes into " << resultbytelen << " bytes" << endl;
#endif
	hash_buf = (uint8_t*) calloc(crypt->get_hash_bytes(), sizeof(uint8_t));
	for(i = 0; i < nelements; i++, resultptr+=resultbytelen, eleptr+=elebytelen) {
		memcpy(hash_buf, eleptr, elebytelen);
		crypt->hash(resultptr, resultbytelen, hash_buf, elebytelen);
	}
	free(hash_buf);
}

inline void domain_hashing(uint32_t nelements, uint8_t** elements, uint32_t* elebytelens, uint8_t* result,
		uint32_t resultbytelen, crypto* crypt) {
	uint8_t *resultptr;//, *hash_buf;
	uint32_t i;

	//eleptr=elements;
	resultptr = result;
#ifndef BATCH
	cout << "Hashing " << nelements << " elements from " << elebytelens << " bytes into " << resultbytelen << " bytes" << endl;
#endif
	//hash_buf = (uint8_t*) calloc(crypt->get_hash_bytes(), sizeof(uint8_t));
	for(i = 0; i < nelements; i++, resultptr+=resultbytelen) {
		//memcpy(hash_buf, elements[i], elebytelens[i]);
		crypt->hash(resultptr, resultbytelen, elements[i], elebytelens[i]);
	}
	//free(hash_buf);
}

#endif /* HASHING_UTIL_H_ */
