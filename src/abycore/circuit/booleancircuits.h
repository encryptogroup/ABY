/**
 \file 		booleancircuits.h
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
#ifndef __BOOLEANCIRCUITS_H_
#define __BOOLEANCIRCUITS_H_

#include "../util/typedefs.h"
#include "abycircuit.h"
#include <assert.h>
#include "circuit.h"

/** BooleanCircuit class. */
class BooleanCircuit: public Circuit {
public:
	BooleanCircuit(ABYCircuit* aby, e_role myrole, e_sharing context) :
			Circuit(aby, context, myrole, 1, C_BOOLEAN) {
		Init();
	}
	;
	~BooleanCircuit() {
		//Cleanup();
	}
	;

	void Init();
	void Cleanup();
	void Reset();

	uint32_t PutANDGate(uint32_t left, uint32_t right);
	vector<uint32_t> PutANDGate(vector<uint32_t> inleft, vector<uint32_t> inright);
	share* PutANDGate(share* ina, share* inb);

	uint32_t PutVectorANDGate(uint32_t choiceinput, uint32_t vectorinput);

	uint32_t PutXORGate(uint32_t left, uint32_t right);
	vector<uint32_t> PutXORGate(vector<uint32_t> inleft, vector<uint32_t> inright);
	share* PutXORGate(share* ina, share* inb);

	uint32_t PutORGate(uint32_t a, uint32_t b);
	share* PutORGate(share* a, share* b);
	vector<uint32_t> PutORGate(vector<uint32_t> a, vector<uint32_t> b);

	uint32_t PutINGate(uint32_t nvals, e_role src);
	template<class T> uint32_t PutINGate(uint32_t nvals, T val);
	uint32_t PutINGate(uint32_t nvals, uint64_t val, e_role role);
	uint32_t PutINGate(uint32_t ninvals, uint32_t* val, e_role role);
	share* PutINGate(uint32_t nvals, uint64_t val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role);
	share* PutINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role);

	uint32_t PutOUTGate(uint32_t parent, e_role dst);
	vector<uint32_t> PutOUTGate(vector<uint32_t> parents, e_role dst);
	share* PutOUTGate(share* parent, e_role dst);

	share* PutCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen);
	share* PutCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen);
	share* PutCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen);
	uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1);

	uint32_t GetNumB2YGates() {
		return m_nB2YGates;
	}
	;
	uint32_t GetNumA2YGates() {
		return m_nA2YGates;
	}
	;

	int GetNumANDGates() {
		return m_vANDs[0].numgates;
	}
	;
	int GetANDs(non_lin_vec_ctx*& inptr) {
		inptr = m_vANDs;
		return m_nNumANDSizes;
	}
	;

	share* PutMULGate(share* ina, share* inb);
	share* PutGEGate(share* ina, share* inb);
	share* PutEQGate(share* ina, share* inb);
	share* PutMUXGate(share* ina, share* inb, share* sel);

	vector<uint32_t> PutMulGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t resbitlen);
	vector<uint32_t> PutAddGate(vector<uint32_t> left, vector<uint32_t> right, BOOL bCarry = FALSE);
	share* PutADDGate(share* ina, share* inb);

	vector<uint32_t> PutSizeOptimizedAddGate(vector<uint32_t> left, vector<uint32_t> right, BOOL bCarry = FALSE);
	vector<uint32_t> PutDepthOptimizedAddGate(vector<uint32_t> lefta, vector<uint32_t> right, BOOL bCARRY = FALSE);

	vector<uint32_t> PutSUBGate(vector<uint32_t> a, vector<uint32_t> b);
	share* PutSUBGate(share* ina, share* inb);
	vector<uint32_t> PutWideAddGate(vector<vector<uint32_t> > ins, uint32_t resbitlen);
	uint32_t PutGEGate(vector<uint32_t> a, vector<uint32_t> b);
	uint32_t PutSizeOptimizedGEGate(vector<uint32_t> a, vector<uint32_t> b);
	uint32_t PutDepthOptimizedGEGate(vector<uint32_t> a, vector<uint32_t> b);
	uint32_t PutEQGate(vector<uint32_t> a, vector<uint32_t> b);

	share* PutANDVecGate(share* ina, share* inb);
	vector<uint32_t> PutMUXGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t s, BOOL vecand = false);
	vector<uint32_t> PutVecANDMUXGate(vector<uint32_t> a, vector<uint32_t> b, vector<uint32_t> s);
	uint32_t PutVecANDMUXGate(uint32_t a, uint32_t b, uint32_t s);
	uint32_t PutWideGate(e_gatetype type, vector<uint32_t> ins);
	vector<vector<uint32_t> > PutCondSwapGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t s, BOOL vectorized);
	vector<uint32_t> PutELM0Gate(vector<uint32_t> val, uint32_t b);

	vector<uint32_t> LShift(vector<uint32_t> val, uint32_t pos, uint32_t nvals = 1);

	uint32_t PutIdxGate(uint32_t r, uint32_t maxidx);

	share* PutRepeaterGate(share* input, uint32_t nvals);
	uint32_t PutRepeaterGate(uint32_t input, uint32_t nvals);
	uint32_t PutCombinerGate(vector<uint32_t>& input);
	uint32_t PutCombineAtPosGate(vector<uint32_t>& input, uint32_t pos);

	uint32_t PutSubsetGate(uint32_t input, uint32_t* posids, uint32_t nvals);
	share* PutSubsetGate(share* input, uint32_t* posids, uint32_t nvals);

	share* PutSplitterGate(share* input);
	vector<uint32_t> PutSplitterGate(uint32_t input);

	uint32_t PutCallbackGate(vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);
	share* PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);

	share* PutY2BGate(share* ina);
	share* PutB2YGate(share* ina);

	uint32_t PutY2BCONVGate(uint32_t parentid);
	uint32_t PutB2YCONVGate(uint32_t parentid);
	vector<uint32_t> PutY2BCONVGate(vector<uint32_t> parentid);
	vector<uint32_t> PutB2YCONVGate(vector<uint32_t> parentid);

	vector<uint32_t> PutA2YCONVGate(vector<uint32_t> parentid);
	share* PutA2YGate(share* ina);

	share* PutB2AGate(share* ina) {
		cerr << "B2A not available for Boolean circuits, please use Arithmetic circuits instead" << endl;
		return new boolshare(0, this);
	}

	uint32_t PutINVGate(uint32_t parentid);
	vector<uint32_t> PutINVGate(vector<uint32_t> parentid);
	share* PutINVGate(share* parent);

	share* PutMinGate(share** a, uint32_t nvals);
	vector<uint32_t> PutMinGate(vector<vector<uint32_t> > a);

	void PutMinIdxGate(share** a, share** b, uint32_t nvals, share** minval_shr, share** minid_shr);
	void PutMinIdxGate(vector<vector<uint32_t> > a, vector<vector<uint32_t> > idx,
			vector<uint32_t>& minval, vector<uint32_t>& minid);

private:
	void UpdateInteractiveQueue(uint32_t);
	void UpdateLocalQueue(uint32_t gateid);

	non_lin_vec_ctx* m_vANDs;
	uint32_t m_nNumANDSizes;

	uint32_t m_nB2YGates;
	uint32_t m_nA2YGates;
};

#endif /* __BOOLEANCIRCUITS_H_ */
