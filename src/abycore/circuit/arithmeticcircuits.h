/**
 \file 		arithmeticcircuits.h
 \author	michael.zohner@ec-spride.de
 \copyright	________________
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

	uint32_t PutMULGate(uint32_t left, uint32_t right, uint32_t mindepth = 0);
	uint32_t PutADDGate(uint32_t left, uint32_t right, uint32_t mindepth = 0);

	uint32_t PutINGate(uint32_t nvals, e_role src);
	share* PutINGate(uint32_t nvals, uint32_t val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role);
	template<class T> uint32_t PutINGate(uint32_t nvals, T val);
	template<class T> uint32_t PutINGate(uint32_t nvals, T val, e_role role);
	uint32_t PutOUTGate(uint32_t parent, e_role dst);
	share* PutOUTGate(share* parent, e_role dst);

	uint32_t PutINVGate(uint32_t parentid, uint32_t mindepth = 0);
	uint32_t PutCONVGate(vector<uint32_t>& parentids, uint32_t mindepth = 0);

	share* PutADDGate(share* ina, share* inb, uint32_t mindepth = 0);

	share* PutSUBGate(share* ina, share* inb, uint32_t mindepth = 0) {
		cerr << "SUB not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutANDGate(share* ina, share* inb, uint32_t mindepth = 0) {
		cerr << "AND not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutXORGate(share* ina, share* inb, uint32_t mindepth = 0) {
		cerr << "XOR not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutSubGate(share* ina, share* inb, uint32_t mindepth = 0) {
		cerr << "Sub not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutMULGate(share* ina, share* inb, uint32_t mindepth = 0);

	share* PutGEGate(share* ina, share* inb, uint32_t mindepth = 0) {
		cerr << "GE not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutEQGate(share* ina, share* inb, uint32_t mindepth = 0) {
		cerr << "EQ not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutMUXGate(share* ina, share* inb, share* sel, uint32_t mindepth = 0) {
		cerr << "MUX not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutY2BGate(share* ina, uint32_t mindepth = 0) {
		cerr << "Y2B not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutB2YGate(share* ina, uint32_t mindepth = 0) {
		cerr << "B2Y not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutA2YGate(share* ina, uint32_t mindepth = 0) {
		cerr << "A2Y not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	share* PutANDVecGate(share* ina, share* inb, uint32_t mindepth) {
		cerr << "ANDVec Gate not implemented in arithmetic sharing" << endl;
		return new arithshare(this);
	}
	uint32_t PutB2AGate(vector<uint32_t> ina, uint32_t mindepth = 0);
	share* PutB2AGate(share* ina, uint32_t mindepth = 0);
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
	uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1, uint32_t mindepth = 0);
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
