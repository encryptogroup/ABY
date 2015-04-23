/**
 \file 		circuit.h
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

 \brief		Contains the class for generic circuits, which is a super-class of Boolean and Arithmetic circuits.
*/

#ifndef CIRCUIT_H_
#define CIRCUIT_H_

#include "abycircuit.h"

class share;
class boolshare;
class arithshare;

/** Circuit class */
class Circuit {

public:
	/** Constructor of the class. */
	Circuit(ABYCircuit* aby, e_sharing context, e_role myrole, uint32_t bitlen, e_circuit circ) :
			m_cCircuit(aby), m_eContext(context), m_eMyRole(myrole), m_nShareBitLen(bitlen), m_eCirctype(circ) {
		Init();
	}
	;
	virtual ~Circuit() {
	}
	;

	void Init();
	void Cleanup();
	void Reset();

	/* organizational routines */
	uint32_t GetShareBitLen() {
		return m_nShareBitLen;
	}
	;

	uint32_t GetMaxDepth() {
		return m_nMaxDepth;
	}
	;

	deque<uint32_t> GetLocalQueueOnLvl(uint32_t lvl) {

		if (lvl < m_vLocalQueueOnLvl.size())
			return m_vLocalQueueOnLvl[lvl];
		else
			return EMPTYQUEUE;
	}
	;
	deque<uint32_t> GetInteractiveQueueOnLvl(uint32_t lvl) {
		if (lvl < m_vInteractiveQueueOnLvl.size())
			return m_vInteractiveQueueOnLvl[lvl];
		else
			return EMPTYQUEUE;
	}
	;

	uint32_t GetNumLocalLayers() {
		return m_vLocalQueueOnLvl.size();
	}
	uint32_t GetNumInteractiveLayers() {
		return m_vInteractiveQueueOnLvl.size();
	}

	uint32_t GetNumInputBitsForParty(e_role party) {
		return m_vInputBits[party];
	}
	;
	uint32_t GetNumOutputBitsForParty(e_role party) {
		return m_vOutputBits[party];
	}
	;

	deque<uint32_t> GetInputGatesForParty(e_role party) {
		return m_vInputGates[party];
	}
	;
	deque<uint32_t> GetOutputGatesForParty(e_role party) {
		return m_vOutputGates[party];
	}
	;

	e_sharing GetContext() {
		return m_eContext;
	}
	;
	uint32_t GetNumGates() {
		return m_nGates;
	}
	;

	UGATE_T* GetOutputGateValue(uint32_t gateid);
	uint32_t GetOutputGateValue(uint32_t gateid, UGATE_T*& outval);
	template<class T> void GetOutputGateValue(uint32_t gateid, T& val);
	uint32_t GetNumVals(uint32_t gateid) {
		assert(gateid < m_cCircuit->GetGateHead());
		return m_pGates[gateid].nvals;
	}
	;

	/* Common gate-building routines */
	virtual share* PutCONSGate(UGATE_T val, uint32_t nvals = 1, uint32_t mindepth = 0) = 0;
	virtual uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1, uint32_t mindepth = 0) = 0;

	//virtual int 	PutINGate(int nvals, ROLE src) = 0;
	virtual share* PutINGate(uint32_t nvals, uint32_t val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role) = 0;
	virtual share* PutINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role) = 0;

	virtual share* PutADDGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutSUBGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutANDGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutXORGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutMULGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutGEGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutEQGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	virtual share* PutMUXGate(share* ina, share* inb, share* sel, uint32_t mindepth = 0) = 0;
	virtual share* PutY2BGate(share* ina, uint32_t mindepth = 0) = 0;
	virtual share* PutB2AGate(share* ina, uint32_t mindepth = 0) = 0;
	virtual share* PutB2YGate(share* ina, uint32_t mindepth = 0) = 0;
	virtual share* PutA2YGate(share* ina, uint32_t mindepth = 0) = 0;
	virtual share* PutANDVecGate(share* ina, share* inb, uint32_t mindepth = 0) = 0;
	share* PutCombinerGate(share* ina, uint32_t mindepth = 0);
	share* PutSplitterGate(share* ina, uint32_t mindepth = 0);
	share* PutRepeaterGate(uint32_t nvals, share* ina, uint32_t mindepth = 0);

	//Templates may not be virtual, hence use dummy functions
	template<class T> uint32_t PutINGate(uint32_t nvals, T val) {
		cout << "IN gate not implemented in super-class, stopping!" << endl;
		return -1;
	}
	;
	template<class T> uint32_t PutINGate(uint32_t nvals, T val, e_role role) {
		cout << "IN gate not implemented in super-class, stopping!" << endl;
		return -1;
	}
	;
	//virtual int 	PutOUTGate(int parent, ROLE dst) = 0;
	virtual share* PutOUTGate(share* parent, e_role dst) =0;

	virtual uint32_t PutINVGate(uint32_t parentid, uint32_t mindepth = 0) = 0;
	e_circuit GetCircuitType() {
		return m_eCirctype;
	}
	;

protected:
	virtual void UpdateInteractiveQueue(uint32_t gateid) = 0;
	virtual void UpdateLocalQueue(uint32_t gateid) = 0;

	void UpdateInteractiveQueue(share* gateid);
	void UpdateLocalQueue(share* gateid);

	ABYCircuit* m_cCircuit;
	GATE* m_pGates;
	e_sharing m_eContext;
	e_circuit m_eCirctype;
	e_role m_eMyRole;
	uint32_t m_nShareBitLen;
	uint32_t m_nMaxDepth;

	vector<deque<uint32_t> > m_vLocalQueueOnLvl; //for locally evaluatable gates, first dimension is the level of the gates, second dimension presents the queue on which the gateids are put
	vector<deque<uint32_t> > m_vInteractiveQueueOnLvl; //for gates that need interaction, first dimension is the level of the gates, second dimension presents the queue on which the gateids are put
	vector<deque<uint32_t> > m_vInputGates;				//input gates for the parties
	vector<deque<uint32_t> > m_vOutputGates;				//input gates for the parties
	vector<uint32_t> m_vInputBits;				//number of input bits for the parties
	vector<uint32_t> m_vOutputBits;				//number of output bits for the parties

	uint32_t m_nMULs;					//number of AND gates in the circuit
	uint32_t m_nCONVGates;				//number of Boolean to arithmetic conversion gates

	uint32_t m_nGates;
	uint32_t m_nRoundsAND;
	uint32_t m_nRoundsXOR;
	vector<uint32_t> m_nRoundsIN;
	vector<uint32_t> m_nRoundsOUT;

	const deque<uint32_t> EMPTYQUEUE;
};

/** Share Class */
class share {
public:
	/** Constructor overloaded with shared length and circuit.*/
	share(uint32_t sharelen, Circuit* circ);
	/** Constructor overloaded with gates and circuit.*/
	share(vector<uint32_t> gates, Circuit* circ);
	/**
	 Initialise Function
	 \param circ 		Ciruit object.
	 \param maxbitlen 	Maximum Bit Length.
	 */
	void init(Circuit* circ, uint32_t maxbitlen = 32);

	/** Destructor */
	~share() {
	}
	;

	vector<uint32_t>& get_gates() {
		return m_ngateids;
	}
	;
	uint32_t get_gate(uint32_t shareid);
	void set_gate(uint32_t shareid, uint32_t gateid);
	void resize(uint32_t sharelen) {
		m_ngateids.resize(sharelen);
	}
	;
	void set_gates(vector<uint32_t> shares) {
		m_ngateids = shares;
	}
	;
	uint32_t size() {
		return m_ngateids.size();
	}
	;
	uint32_t max_size() {
		return m_nmaxbitlen;
	}
	;
	e_circuit get_circuit_type() {
		return m_ccirc->GetCircuitType();
	}
	;
	e_sharing get_share_type() {
		return m_ccirc->GetContext();
	}
	;

	template<class T> T get_clear_value() {
		assert(sizeof(T) * 8 >= m_ngateids.size());
		T val = 0;
		for (uint32_t i = 0; i < m_ngateids.size(); i++) {
			val += (*m_ccirc->GetOutputGateValue(m_ngateids[i]) << i);
		}
		return val;
	}

	virtual uint8_t* get_clear_value() = 0;
	virtual uint32_t get_clear_value_vec(uint32_t** vec) = 0;

protected:
	vector<uint32_t> m_ngateids;
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
	boolshare(vector<uint32_t> gates, Circuit* circ) :
			share(gates, circ) {
	}
	;
	/**
	 Initialise Function
	 \param circ 		Ciruit object.
	 \param maxbitlen 	Maximum Bit Length.
	 */
	/** Destructor */

	~boolshare() {
	}
	;				// : share() {};

	uint8_t* get_clear_value();
	uint32_t get_clear_value_vec(uint32_t** vec) {
		assert(m_ngateids.size() <= sizeof(uint32_t) * 8);
		UGATE_T* outvalptr;
		uint32_t nvals = 1, gnvals = 1;

		nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], outvalptr);
		*vec = (uint32_t*) calloc(nvals, sizeof(uint32_t));

		for (uint32_t j = 0; j < nvals; j++) {
			(*vec)[j] = (outvalptr[j / 64] >> (j % 64)) & 0x01;
		}

		for (uint32_t i = 1, gnvals = nvals; i < m_ngateids.size(); i++) {
			nvals = m_ccirc->GetOutputGateValue(m_ngateids[i], outvalptr);
			assert(nvals == gnvals);

			for (uint32_t j = 0; j < nvals; j++) {
				(*vec)[j] = (*vec)[j] + (((outvalptr[j / 64] >> (j % 64)) & 0x01) << i);
			}
		}

		return nvals;
	}
};

/** Arithmetic Share Class */
class arithshare: public share {
public:
	/** Constructor overloaded with shared length and circuit.*/
	arithshare(Circuit* circ) :
			share(1, circ) {
	}
	;
	/** Constructor overloaded with gates and circuit.*/
	arithshare(vector<uint32_t> gates, Circuit* circ) :
			share(gates, circ) {
	}
	;

	/** Destructor */
	~arithshare() {
	}
	;				// : share() {};

	uint8_t* get_clear_value();
	uint32_t get_clear_value_vec(uint32_t** vec) {
		assert(m_ngateids.size() <= sizeof(uint32_t) * 8);

		UGATE_T* gate_val;
		uint32_t nvals = m_ccirc->GetOutputGateValue(m_ngateids[0], gate_val);
		*vec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
		memcpy(*vec, gate_val, nvals * sizeof(uint32_t));

		return nvals;
	}

};

static share* create_new_share(uint32_t size, Circuit* circ, e_circuit circtype);
static share* create_new_share(vector<uint32_t> vals, Circuit* circ, e_circuit circtype);

#endif /* CIRCUIT_H_ */
