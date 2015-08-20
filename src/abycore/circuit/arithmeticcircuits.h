/**
 \file 		arithmeticcircuits.h
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

 \brief		A collection of boolean circuits for boolean and yao sharing in the ABY framework
 */
#ifndef __ARITHMETICCIRCUITS_H_
#define __ARITHMETICCIRCUITS_H_

#include "../util/typedefs.h"
#include "abycircuit.h"
#include "circuit.h"

/** Arithmetic Circuit class.*/
class ArithmeticCircuit: public Circuit {
public:
	ArithmeticCircuit(ABYCircuit* aby, e_sharing context, e_role myrole, uint32_t bitlen) :
			Circuit(aby, context, myrole, bitlen, C_ARITHMETIC) {
		Init();
	}
	;
	~ArithmeticCircuit() {
		Cleanup();
	}
	;

	void Init();
	void Cleanup();
	void Reset();

	uint32_t PutMULGate(uint32_t left, uint32_t right);
	uint32_t PutADDGate(uint32_t left, uint32_t right);

	uint32_t PutINGate(uint32_t nvals, e_role src);
	share* PutINGate(uint32_t nvals, uint64_t val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role);
	template<class T> uint32_t PutINGate(uint32_t nvals, T val);
	template<class T> uint32_t PutINGate(uint32_t nvals, T val, e_role role);
	uint32_t PutOUTGate(uint32_t parent, e_role dst);
	share* PutOUTGate(share* parent, e_role dst);

	share* PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);

	uint32_t PutINVGate(uint32_t parentid);
	uint32_t PutCONVGate(vector<uint32_t> parentids);

	share* PutADDGate(share* ina, share* inb);

	share* PutSUBGate(share* ina, share* inb) {
		cerr << "SUB not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutANDGate(share* ina, share* inb) {
		cerr << "AND not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutXORGate(share* ina, share* inb) {
		cerr << "XOR not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutSubGate(share* ina, share* inb) {
		cerr << "Sub not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutMULGate(share* ina, share* inb);

	share* PutGEGate(share* ina, share* inb) {
		cerr << "GE not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutEQGate(share* ina, share* inb) {
		cerr << "EQ not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutMUXGate(share* ina, share* inb, share* sel) {
		cerr << "MUX not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutY2BGate(share* ina) {
		cerr << "Y2B not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutB2YGate(share* ina) {
		cerr << "B2Y not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutA2YGate(share* ina) {
		cerr << "A2Y not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutANDVecGate(share* ina, share* inb) {
		cerr << "ANDVec Gate not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	uint32_t PutB2AGate(vector<uint32_t> ina);
	share* PutB2AGate(share* ina);
	//TODO: implement
	//uint32_t		 		PutY2AGate(vector<uint32_t>& parentids, uint32_t mindepth=0);

	uint32_t GetNumMULGates() {
		return m_nMULs;
	}
	;
	uint32_t GetNumCONVGates() {
		return m_nCONVGates;
	}
	;

	//share* PutCONSGate(UGATE_T val, uint32_t nvals = 1);
	share* PutCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen);
	share* PutCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen);
	share* PutCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen);
	uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1);
	uint32_t GetMaxCommunicationRounds() {
		return m_nMaxDepth;
	}
	;

private:
	void UpdateInteractiveQueue(uint32_t gateid);
	void UpdateLocalQueue(uint32_t gateid);

	uint32_t m_nMULs; //number of AND gates in the circuit
	uint32_t m_nCONVGates; //number of Boolean to arithmetic conversion gates
};

#endif /* __ARITHMETICCIRCUITS_H_ */
