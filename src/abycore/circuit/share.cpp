/**
 \file 		share.cpp
 \author	michael.zohner@ec-spride.de
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

 \brief		Share class implementation.
*/


#include "share.h"


/* =========================== Methods for the share class =========================== */

share::share(uint32_t sharelen, Circuit* circ) {
	m_ngateids.resize(sharelen);
	init(circ);
}

share::share(vector<uint32_t> gates, Circuit* circ) {
	m_ngateids.resize(gates.size());
	m_ngateids = gates;
	init(circ);
}

void share::init(Circuit* circ, uint32_t maxbitlen) {
	m_ccirc = circ;
	m_nmaxbitlen = maxbitlen;
}

uint32_t share::get_wire_id(uint32_t pos_id) {
	assert(pos_id < m_ngateids.size());
	return m_ngateids[pos_id];
}

share* share::get_wire_ids_as_share(uint32_t pos_id) {
	assert(pos_id < m_ngateids.size());
	share* out = new boolshare(1, m_ccirc);
	out->set_wire_id(0, m_ngateids[pos_id]);
	return out;
}


void share::set_wire_id(uint32_t pos_id, uint32_t wireid) {
	assert(pos_id < m_ngateids.size());
	m_ngateids[pos_id] = wireid;
}

/* =========================== Methods for the Boolean share class =========================== */

uint8_t* boolshare::get_clear_value_ptr() {
	uint8_t* out;
	UGATE_T* gatevals;
	uint32_t nvals = m_ccirc->GetNumVals(m_ngateids[0]);
	uint32_t bytelen = ceil_divide(m_ngateids.size(), 8);

	out = (uint8_t*) calloc(ceil_divide(m_ngateids.size(), 8) * nvals, sizeof(uint8_t));

	for (uint32_t i = 0, ibytes; i < m_ngateids.size(); i++) {
		assert(nvals == m_ccirc->GetNumVals(m_ngateids[i]));
		gatevals = m_ccirc->GetOutputGateValue(m_ngateids[i]);

		ibytes = i / 8;
		for (uint32_t j = 0; j < nvals; j++) {
			out[j * bytelen + ibytes] += (((gatevals[j / 64] >> (j % 64)) & 0x01) << (i & 0x07));
		}
	}
	return out;
}


//TODO This method will only work up to a bitlength of 32
void boolshare::get_clear_value_vec(uint32_t** vec, uint32_t *bitlen, uint32_t *nvals) {
	assert(m_ngateids.size() <= sizeof(uint32_t) * 8);
	UGATE_T* outvalptr;
	uint32_t gnvals = 1;

	*nvals = 1;
	*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], outvalptr);
	*vec = (uint32_t*) calloc(*nvals, sizeof(uint32_t));

	for (uint32_t j = 0; j < *nvals; j++) {
		(*vec)[j] = (outvalptr[j / 64] >> (j % 64)) & 0x01;
	}

	for (uint32_t i = 1; i < m_ngateids.size(); i++) {
		gnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], outvalptr);
		assert(*nvals == gnvals);

		for (uint32_t j = 0; j < *nvals; j++) {
			(*vec)[j] = (*vec)[j] + (((outvalptr[j / 64] >> (j % 64)) & 0x01) << i);
		}
	}
	*bitlen = m_ngateids.size();
	//return nvals;
}


//TODO: copied from 32 bits. Put template in and test later on!
//TODO This method will only work up to a bitlength of 64
void boolshare::get_clear_value_vec(uint64_t** vec, uint32_t *bitlen, uint32_t *nvals) {
	assert(m_ngateids.size() <= sizeof(uint64_t) * 8);
	UGATE_T* outvalptr;
	uint32_t gnvals = 1;

	*nvals = 1;
	*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], outvalptr);
	*vec = (uint64_t*) calloc(*nvals, sizeof(uint64_t));

	for (uint32_t j = 0; j < *nvals; j++) {
		(*vec)[j] = (outvalptr[j / 64] >> (j % 64)) & 0x01;
	}

	for (uint32_t i = 1; i < m_ngateids.size(); i++) {
		gnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], outvalptr);
		assert(*nvals == gnvals);

		for (uint32_t j = 0; j < *nvals; j++) {
			(*vec)[j] = (*vec)[j] + (((outvalptr[j / 64] >> (j % 64)) & 0x01) << i);
		}
	}
	*bitlen = m_ngateids.size();
	//return nvals;
}


yao_fields* boolshare::get_internal_yao_keys() {
	yao_fields* out;
	uint32_t nvals = m_ccirc->GetNumVals(m_ngateids[0]);
	uint32_t key_bytes = ceil_divide(128, 8);

	out = (yao_fields*) malloc(sizeof(yao_fields) * m_ngateids.size());

	if(m_ccirc->GetRole() == SERVER) {
		for(uint32_t i = 0; i < m_ngateids.size(); i++) {
			out[i].outKey = (uint8_t*) malloc(key_bytes * nvals);
			memcpy(out[i].outKey, m_ccirc->GetGateSpecificOutput(m_ngateids[i]).yinput.outKey, key_bytes * nvals);
			out[i].pi = (uint8_t*) malloc(nvals);
			memcpy(out[i].pi, m_ccirc->GetGateSpecificOutput(m_ngateids[i]).yinput.pi, nvals);
		}
	} else {
		for(uint32_t i = 0; i < m_ngateids.size(); i++) {
			out[i].outKey = (uint8_t*) malloc(key_bytes * nvals);
			memcpy(out[i].outKey, m_ccirc->GetOutputGateValue(m_ngateids[i]), key_bytes * nvals);
			//Leave the pi value unallocated. The client does not know it. It could be simulated using the last bit of the key
		}
	}

	return out;
}


/* =========================== Methods for the Arithmetic share class =========================== */

uint8_t* arithshare::get_clear_value_ptr() {
	UGATE_T* gate_val;
	uint32_t nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
	uint8_t* out = (uint8_t*) malloc(nvals * sizeof(uint32_t));
	for (uint32_t i = 0; i < nvals; i++) {
		((uint32_t*) out)[i] = (uint32_t) gate_val[i];
	}
	return out;
}

void arithshare::get_clear_value_vec(uint32_t** vec, uint32_t* bitlen, uint32_t* nvals) {
	//assert(m_ngateids.size() <= sizeof(uint32_t) * 8);

	UGATE_T* gate_val;
	*nvals = 0;
	for(uint32_t i = 0; i < m_ngateids.size(); i++) {
		(*nvals) += m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
	}
	uint32_t sharebytes = ceil_divide(m_ccirc->GetShareBitLen(), 8);

	//*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
	*vec = (uint32_t*) calloc(*nvals, sizeof(uint32_t));

	for(uint32_t i = 0, tmpctr=0, tmpnvals; i < m_ngateids.size(); i++) {
		tmpnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
		//cout << m_ngateids[i] << " gateval = " << gate_val[0] << ", nvals = " << *nvals << ", sharebitlen = " << m_ccirc->GetShareBitLen() << endl;
		for(uint32_t j = 0; j < tmpnvals; j++, tmpctr++) {
			memcpy((*vec)+tmpctr, ((uint8_t*) gate_val)+(j*sharebytes), sharebytes);
		}
	}

	*bitlen = m_ccirc->GetShareBitLen();
}

//TODO: copied from 32 bits. Put template in and test later on!
void arithshare::get_clear_value_vec(uint64_t** vec, uint32_t* bitlen, uint32_t* nvals) {
	//assert(m_ngateids.size() <= sizeof(uint32_t) * 8);

	UGATE_T* gate_val;
	*nvals = 0;
	for(uint32_t i = 0; i < m_ngateids.size(); i++) {
		(*nvals) += m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
	}
	uint32_t sharebytes = ceil_divide(m_ccirc->GetShareBitLen(), 8);

	//*nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
	*vec = (uint64_t*) calloc(*nvals, sizeof(uint64_t));

	for(uint32_t i = 0, tmpctr=0, tmpnvals; i < m_ngateids.size(); i++) {
		tmpnvals = m_ccirc->GetOutputGateValue(m_ngateids[i], gate_val);
		//cout << m_ngateids[i] << " gateval = " << gate_val[0] << ", nvals = " << *nvals << ", sharebitlen = " << m_ccirc->GetShareBitLen() << endl;
		for(uint32_t j = 0; j < tmpnvals; j++, tmpctr++) {
			memcpy((*vec)+tmpctr, ((uint8_t*) gate_val)+(j*sharebytes), sharebytes);
		}
	}

	*bitlen = m_ccirc->GetShareBitLen();
}

share* arithshare::get_share_from_wire_id(uint32_t shareid) {

	arithshare *new_shr = new arithshare(m_ccirc);
	new_shr->set_wire_id(shareid,get_wire_id(shareid));
	return new_shr;
}

share* boolshare::get_share_from_wire_id(uint32_t shareid) {

	boolshare *new_shr = new boolshare(get_max_bitlength(),m_ccirc);
	new_shr->set_wire_id(shareid,get_wire_id(shareid));
	return new_shr;
}




