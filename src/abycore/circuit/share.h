/**
 \file 		share.h
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

 \brief		Contains the class the share object as well as the sub-classes for Boolean and Aritmetic shares.
*/
#ifndef SHARE_H_
#define SHARE_H_

#include "circuit.h"
#include "../ABY_utils/ABYconstants.h"
#include <cassert>
#include <cstdint>
#include <vector>


/** Share Class */
class share {
public:
	/** Constructor overloaded with shared length and circuit.*/
	share(uint32_t sharelen, Circuit* circ);
	/** Constructor overloaded with gates and circuit.*/
	share(std::vector<uint32_t> gates, Circuit* circ);
	/**
	 Initialise Function
	 \param circ 		Ciruit object.
	 \param maxbitlen 	Maximum Bit Length.
	 */
	void init(Circuit* circ, uint32_t maxbitlen = 32);

	/** Destructor */
	virtual ~share() {
	}
	;

        std::vector<uint32_t> & get_wires() {
		return m_ngateids;
	}
	;
	uint32_t get_wire_id(uint32_t posid);

	share* get_wire_ids_as_share(uint32_t posid);

	void set_wire_id(uint32_t posid, uint32_t wireid);

	void set_wire_ids(std::vector<uint32_t> wires);

	uint32_t get_bitlength();

	void set_bitlength(uint32_t sharelen);

	uint32_t get_max_bitlength();

	void set_max_bitlength(uint32_t max_bitlength);

	uint32_t get_nvals();

	uint32_t get_nvals_on_wire(uint32_t wireid);

	e_circuit get_circuit_type();

	e_sharing get_share_type();


	template<class T> T get_clear_value() {

#ifdef GETCLEARVALUE_DEBUG
		printf("\nOriginal Gate Size(in bits) : %d", m_ngateids.size());
		printf("\nTemplate type Size(in bits) : %d\n", sizeof(T) * 8);
#endif

		assert(sizeof(T) * 8 >= m_ngateids.size());
		T val = 0, tmpval = 0;

		for (uint32_t i = 0; i < m_ngateids.size(); i++) {
			m_ccirc->GetOutputGateValueT(m_ngateids[i], tmpval);
			val += (tmpval << i);
		}

		return val;
	}

	virtual uint8_t* get_clear_value_ptr() = 0;
	virtual void get_clear_value_vec(uint32_t** vec, uint32_t *bitlen, uint32_t *nvals) = 0;
	virtual void get_clear_value_vec(uint64_t** vec, uint32_t *bitlen, uint32_t *nvals) = 0;

protected:
        std::vector<uint32_t> m_ngateids;
	Circuit* m_ccirc;
	uint32_t m_nmaxbitlen;
};


/** Boolean Share Class */
class boolshare: public share {
public:
	/** Constructor overloaded with shared length and circuit.*/
	boolshare(uint32_t sharelen, Circuit* circ) :
			share(sharelen, circ) {
	}
	;
	/** Constructor overloaded with gates and circuit.*/
	boolshare(std::vector<uint32_t> gates, Circuit* circ) :
			share(gates, circ) {
	}
	;
	/**
	 Initialise Function
	 \param circ 		Ciruit object.
	 \param maxbitlen 	Maximum Bit Length.
	 */
	/** Destructor */

	~boolshare() {};

	//In case the values are output as given as output shares, this routine can be used to obtain keys of Yao
	//TDOO: create new method called get share that provides access to a shared output.
	yao_fields* get_internal_yao_keys();

	uint8_t* get_clear_value_ptr();
	void get_clear_value_vec(uint32_t** vec, uint32_t *bitlen, uint32_t *nvals);
	void get_clear_value_vec(uint64_t** vec, uint32_t *bitlen, uint32_t *nvals);

	/**
		\brief	The function returns a share object based on the shareid being inputed.
		\param		shareid		shareid which needs to obtained and the respective gate to be
								attached with the newly created share object.
		\return		share object which is newly created based on the share id being inputed.
	*/
	share* get_share_from_wire_id(uint32_t shareid);
};

/** Arithmetic Share Class */
class arithshare: public share {
public:
	/** Constructor overloaded with and circuit.*/
	arithshare(Circuit* circ) :
			share(1, circ) {
	}
	;
	/** Constructor overloaded with share length and circuit.*/
	arithshare(uint32_t sharelen, Circuit* circ) :
			share(sharelen, circ) {
	}
	;
	/** Constructor overloaded with gates and circuit.*/
	arithshare(std::vector<uint32_t> gates, Circuit* circ) :
			share(gates, circ) {
	}
	;

	/** Destructor */
	~arithshare() {
	}
	;				// : share() {};

	uint8_t* get_clear_value_ptr();
	void get_clear_value_vec(uint32_t** vec, uint32_t* bitlen, uint32_t* nvals);
	void get_clear_value_vec(uint64_t** vec, uint32_t* bitlen, uint32_t* nvals);

	/**
		\brief	The function returns a share object based on the shareid being inputed.
		\param		shareid		shareid which needs to obtained and the respective gate to be
								attached with the newly created share object.
		\return		share object which is newly created based on the share id being inputed.
	*/
	share* get_share_from_wire_id(uint32_t shareid);

};

/*static share* create_new_share(uint32_t size, Circuit* circ, e_circuit circtype);
static share* create_new_share(vector<uint32_t> vals, Circuit* circ, e_circuit circtype);
*/

#endif /* SHARE_H_ */

