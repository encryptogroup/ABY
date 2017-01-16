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
#include "../util/cbitvector.h"
#include "abycircuit.h"
#include <assert.h>
#include "circuit.h"
#include <map>
#include <fstream>
#include "../util/parse_options.h"

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

	uint32_t PutINGate(e_role src);
	template<class T> uint32_t PutINGate(T val);
	uint32_t PutINGate(uint64_t val, e_role role);
	template<class T> uint32_t PutINGate(T* val, e_role role);

	uint32_t PutSIMDINGate(uint32_t nvals, e_role src);
	template<class T> uint32_t PutSIMDINGate(uint32_t nvals, T val);
	uint32_t PutSIMDINGate(uint32_t nvals, uint64_t val, e_role role);
	template<class T> uint32_t PutSIMDINGate(uint32_t ninvals, T* val, e_role role);

	// SharedINGates
	uint32_t PutSharedINGate();
	template<class T> uint32_t PutSharedINGate(T val);
	uint32_t PutSharedINGate(uint64_t val);
	template<class T> uint32_t PutSharedINGate(T* val);

	// SharedSIMDINGates
	uint32_t PutSharedSIMDINGate(uint32_t nvals);
	template<class T> uint32_t PutSharedSIMDINGate(uint32_t nvals, T val);
	uint32_t PutSharedSIMDINGate(uint32_t nvals, uint64_t val);
	template<class T> uint32_t PutSharedSIMDINGate(uint32_t ninvals, T* val);


	template<class T> share* InternalPutINGate(uint32_t nvals, T val, uint32_t bitlen, e_role role);
	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T val, uint32_t bitlen);

	share* PutDummyINGate(uint32_t bitlen);
	share* PutDummySIMDINGate(uint32_t nvals, uint32_t bitlen);

	/* Unfortunately, a template function cannot be used due to virtual */
	share* PutINGate(uint64_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(1, val, bitlen, role);
	}
	share* PutINGate(uint32_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint16_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint8_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(1, val, bitlen, role);
	};

	share* PutSIMDINGate(uint32_t nvals, uint64_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(nvals, val, bitlen, role);
	}
	share* PutSIMDINGate(uint32_t nvals, uint32_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint16_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint8_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(nvals, val, bitlen, role);
	};

	/* Unfortunately, a template function cannot be used due to virtual - same for Shared*/
	share* PutSharedINGate(uint64_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(1, val, bitlen);
	}
	share* PutSharedINGate(uint32_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint16_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint8_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(1, val, bitlen);
	};

	share* PutSharedSIMDINGate(uint32_t nvals, uint64_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(nvals, val, bitlen);
	}
	share* PutSharedSIMDINGate(uint32_t nvals, uint32_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint16_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint8_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(nvals, val, bitlen);
	};

	template<class T> share* InternalPutINGate(uint32_t nvals, T* val, uint32_t bitlen, e_role role);
	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T* val, uint32_t bitlen);

	/* Unfortunately, a template function cannot be used due to virtual. Call Internal PutINGate*/
	share* PutINGate(uint64_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint32_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint16_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint8_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(1, val, bitlen, role);
	};

	share* PutSIMDINGate(uint32_t nvals, uint64_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(nvals, val, bitlen, role);
	};

	/* Unfortunately, a template function cannot be used due to virtual. Call Internal PutSharedINGate -  same for Shared*/
	share* PutSharedINGate(uint64_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint32_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint16_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint8_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(1, val, bitlen);
	};

	share* PutSharedSIMDINGate(uint32_t nvals, uint64_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(nvals, val, bitlen);
	};

	//Shared input for Yao garbled circuits
	uint32_t PutYaoSharedSIMDINGate(uint32_t nvals, yao_fields keys);
	share* PutYaoSharedSIMDINGate(uint32_t nvals, yao_fields* keys, uint32_t bitlen);

	uint32_t PutOUTGate(uint32_t parent, e_role dst);
	vector<uint32_t> PutOUTGate(vector<uint32_t> parents, e_role dst);
	share* PutOUTGate(share* parent, e_role dst);

	vector<uint32_t> PutSharedOUTGate(vector<uint32_t> parents);
	share* PutSharedOUTGate(share* parent);

	share* PutCONSGate(UGATE_T val, uint32_t bitlen);
	share* PutCONSGate(uint32_t* val, uint32_t bitlen);
	share* PutCONSGate(uint8_t* val, uint32_t bitlen);

	share* PutSIMDCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen);
	share* PutSIMDCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen);
	share* PutSIMDCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen);

	uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1);

	uint32_t GetNumB2YGates() {
		return m_nB2YGates;
	}
	;
	uint32_t GetNumA2YGates() {
		return m_nA2YGates;
	}
	;
	uint32_t GetNumYSwitchGates() {
		return m_nYSwitchGates;
	}

	uint32_t GetNumANDGates() {
		return m_vANDs[0].numgates;
	}
	;
	uint32_t GetANDs(non_lin_vec_ctx*& inptr) {
		inptr = m_vANDs;
		return m_nNumANDSizes;
	}
	;
	vector<vector<vector<tt_lens_ctx> > > GetTTLens() {
		//inptr = m_vTTlens;
		return m_vTTlens;
	}
	;
	uint32_t GetNumXORVals() {
		return m_nNumXORVals;
	};

	uint32_t GetNumXORGates() {
		return m_nNumXORGates;
	};

	share* PutMULGate(share* ina, share* inb);
	share* PutGTGate(share* ina, share* inb);
	share* PutEQGate(share* ina, share* inb);
	share* PutMUXGate(share* ina, share* inb, share* sel);

	vector<uint32_t> PutMulGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t resbitlen, bool depth_optimized = false, bool vector_ands = false);


	vector<uint32_t> PutAddGate(vector<uint32_t> left, vector<uint32_t> right, BOOL bCarry = FALSE);
	share* PutADDGate(share* ina, share* inb);

	vector<uint32_t> PutSizeOptimizedAddGate(vector<uint32_t> left, vector<uint32_t> right, BOOL bCarry = FALSE);
	vector<uint32_t> PutDepthOptimizedAddGate(vector<uint32_t> lefta, vector<uint32_t> right, BOOL bCARRY = FALSE, bool vector_ands = false);
	vector<uint32_t> PutLUTAddGate(vector<uint32_t> lefta, vector<uint32_t> right, BOOL bCARRY = FALSE);

	vector<vector<uint32_t> > PutCarrySaveGate(vector<uint32_t> a, vector<uint32_t> b, vector<uint32_t> c, uint32_t inbitlen);
	vector<vector<uint32_t> > PutCSNNetwork(vector<vector<uint32_t> > ins);

	vector<uint32_t> PutSUBGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t max_bitlen);
	share* PutSUBGate(share* ina, share* inb);
	vector<uint32_t> PutWideAddGate(vector<vector<uint32_t> > ins);
	uint32_t PutGTGate(vector<uint32_t> a, vector<uint32_t> b);
	uint32_t PutSizeOptimizedGTGate(vector<uint32_t> a, vector<uint32_t> b);
	uint32_t PutDepthOptimizedGTGate(vector<uint32_t> a, vector<uint32_t> b);
	uint32_t PutLUTGTGate(vector<uint32_t> a, vector<uint32_t> b);

	uint32_t PutEQGate(vector<uint32_t> a, vector<uint32_t> b);


	share* PutANDVecGate(share* ina, share* inb);
	vector<uint32_t> PutMUXGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t s, BOOL vecand = true);

	share* PutVecANDMUXGate(share* a, share* b, share* s);
	vector<uint32_t> PutVecANDMUXGate(vector<uint32_t> a, vector<uint32_t> b, vector<uint32_t> s);
	uint32_t PutVecANDMUXGate(uint32_t a, uint32_t b, uint32_t s);
	uint32_t PutWideGate(e_gatetype type, vector<uint32_t> ins);
	uint32_t PutLUTWideANDGate(vector<uint32_t> in);
	share** PutCondSwapGate(share* a, share* b, share* s, BOOL vectorized);
	vector<vector<uint32_t> > PutCondSwapGate(vector<uint32_t> a, vector<uint32_t> b, uint32_t s, BOOL vectorized);
	vector<uint32_t> PutELM0Gate(vector<uint32_t> val, uint32_t b);

	vector<uint32_t> LShift(vector<uint32_t> val, uint32_t pos, uint32_t nvals = 1);

	uint32_t PutIdxGate(uint32_t r, uint32_t maxidx);

	share* PutStructurizedCombinerGate(share* input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals);
	uint32_t PutStructurizedCombinerGate(vector<uint32_t> input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals);

	uint32_t PutCallbackGate(vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);
	share* PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);

	uint32_t PutTruthTableGate(vector<uint32_t> in, uint32_t out_bits, uint64_t* ttable);
	share* PutTruthTableGate(share* in, uint64_t* ttable);

	vector<uint32_t> PutTruthTableMultiOutputGate(vector<uint32_t> in, uint32_t out_bits, uint64_t* ttable);
	share* PutTruthTableMultiOutputGate(share* in, uint32_t out_bits, uint64_t* ttable);

	share* PutY2BGate(share* ina);
	share* PutB2YGate(share* ina);
	//TODO: not working correctly for PSI example
	share* PutYSwitchRolesGate(share* ina);

	uint32_t PutY2BCONVGate(uint32_t parentid);
	uint32_t PutB2YCONVGate(uint32_t parentid);
	uint32_t PutYSwitchRolesGate(uint32_t parentid);
	vector<uint32_t> PutY2BCONVGate(vector<uint32_t> parentid);
	vector<uint32_t> PutB2YCONVGate(vector<uint32_t> parentid);
	vector<uint32_t> PutYSwitchRolesGate(vector<uint32_t> parentid);


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

	/**
	 * \brief Floating point gate with one input
	 * \param inputs input wire IDs
	 * \param func the name of the function
	 * \param bitsize total leng of the floating point type
	 * \param nvals parallel instantiation
	 * \return output wire IDs
	 */
	vector<uint32_t> PutFPGate(const string func, vector<uint32_t> inputs, uint8_t bitsize, uint32_t nvals = 1);

	/**
	 * \brief Floating point gate with two inputs
	 * \param ina 1st input wire IDs
	 * \param inb 2nd input wire IDs
	 * \param func the name of the function
	 * \param bitsize total leng of the floating point type
	 * \param nvals parallel instantiation
	 * \return output wire IDs
	 */
	vector<uint32_t> PutFPGate(const string func, vector<uint32_t> ina, vector<uint32_t> inb, uint8_t bitsize, uint32_t nvals = 1);

	/**
	 * \brief Add gate from a certain .aby file
	 * \param inputs input wire IDs
	 * \param nvals parallel instantiation
	 * \return output wire IDs
	 */
	vector<uint32_t> PutGateFromFile(const string filename, vector<uint32_t> inputs, uint32_t nvals = 1);

	/**
	 * \brief Get the number of input bits for both parties that a given circuit file expects
	 * \param the file name of the circuit
	 * \return the number of input bits for both parties
	 */
	uint32_t GetInputLengthFromFile(const string filename);

	void PutMinIdxGate(share** vals, share** ids, uint32_t nvals, share** minval_shr, share** minid_shr);
	void PutMinIdxGate(vector<vector<uint32_t> > vals, vector<vector<uint32_t> > ids,
			vector<uint32_t>& minval, vector<uint32_t>& minid);

	void PutMaxIdxGate(share** vals, share** ids, uint32_t nvals, share** maxval_shr, share** maxid_shr);
	void PutMaxIdxGate(vector<vector<uint32_t> > vals, vector<vector<uint32_t> > ids,
			vector<uint32_t>& maxval, vector<uint32_t>& maxid);


	void PutMultiMUXGate(share** Sa, share** Sb, share* sel, uint32_t nshares, share** Sout);

private:
	void UpdateInteractiveQueue(uint32_t);
	void UpdateLocalQueue(uint32_t gateid);

	void UpdateTruthTableSizes(uint32_t len, uint32_t nvals, uint32_t depth, uint32_t out_bits);

	void PadWithLeadingZeros(vector<uint32_t> &a, vector<uint32_t> &b);

	non_lin_vec_ctx* m_vANDs;
	//first dimension: circuit depth, second dimension: num-inputs, third dimension: out_bitlen
	vector<vector<vector<tt_lens_ctx> > > m_vTTlens;

	uint32_t m_nNumANDSizes;
	//uint32_t m_nNumTTSizes;

	uint32_t m_nB2YGates;
	uint32_t m_nA2YGates;
	uint32_t m_nYSwitchGates;

	uint32_t m_nNumXORVals;
	uint32_t m_nNumXORGates;

};

#endif /* __BOOLEANCIRCUITS_H_ */
