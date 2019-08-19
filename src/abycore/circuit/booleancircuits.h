/**
 \file 		booleancircuits.h
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
 \brief		A collection of boolean circuits for boolean and yao sharing in the ABY framework
 */
#ifndef __BOOLEANCIRCUITS_H_
#define __BOOLEANCIRCUITS_H_

#include "share.h"
#include "abycircuit.h"
#include "circuit.h"
#include "../ABY_utils/convtypes.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/parse_options.h>
#include <ENCRYPTO_utils/typedefs.h>
#include <cassert>
#include <cstring>
#include <map>
#include <algorithm>

/** BooleanCircuit class. */
class BooleanCircuit: public Circuit {
public:
	BooleanCircuit(ABYCircuit* aby, e_role myrole, e_sharing context, const std::string& circdir = ABY_CIRCUIT_DIR) :
			Circuit(aby, context, myrole, 1, C_BOOLEAN),
			m_cCircuitFileDir(circdir)
			{
		Init();
	}
	;
	~BooleanCircuit() {
		Cleanup();
	}
	;

	void Init();
	void Cleanup();
	void Reset();

	uint32_t PutANDGate(uint32_t left, uint32_t right);
	std::vector<uint32_t> PutANDGate(std::vector<uint32_t> inleft, std::vector<uint32_t> inright);
	share* PutANDGate(share* ina, share* inb);

	uint32_t PutVectorANDGate(uint32_t choiceinput, uint32_t vectorinput);

	uint32_t PutXORGate(uint32_t left, uint32_t right);
	std::vector<uint32_t> PutXORGate(std::vector<uint32_t> inleft, std::vector<uint32_t> inright);
	share* PutXORGate(share* ina, share* inb);

	uint32_t PutORGate(uint32_t a, uint32_t b);
	share* PutORGate(share* a, share* b);
	std::vector<uint32_t> PutORGate(std::vector<uint32_t> a, std::vector<uint32_t> b);

	uint32_t PutINGate(e_role src);
	template<class T> uint32_t PutINGate(T val) {

		uint32_t gateid = PutINGate(m_eMyRole);
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.ishare.inval = (UGATE_T*) calloc(1 * m_nShareBitLen, sizeof(UGATE_T));

		*gate->gs.ishare.inval = (UGATE_T) val;
		gate->instantiated = true;

		return gateid;
	}


	uint32_t PutINGate(uint64_t val, e_role role);
	template<class T> uint32_t PutINGate(T* val, e_role role) {
		uint32_t gateid = PutINGate(role);
		if (role == m_eMyRole) {
			//assign value
			GATE* gate = &(m_vGates[gateid]);
			gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));
			memcpy(gate->gs.ishare.inval, val, ceil_divide(1 * m_nShareBitLen, 8));

			gate->instantiated = true;
		}
		return gateid;
	}

	uint32_t PutSIMDINGate(uint32_t nvals, e_role src);
	template<class T> uint32_t PutSIMDINGate(uint32_t ninvals, T val) {

		uint32_t gateid = PutSIMDINGate(ninvals, m_eMyRole);
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.ishare.inval = (UGATE_T*) calloc(ninvals * m_nShareBitLen, sizeof(UGATE_T));

		*gate->gs.ishare.inval = (UGATE_T) val;
		gate->instantiated = true;

		return gateid;
	}
	uint32_t PutSIMDINGate(uint32_t nvals, uint64_t val, e_role role);
	template<class T> uint32_t PutSIMDINGate(uint32_t ninvals, T* val, e_role role) {
		uint32_t gateid = PutSIMDINGate(ninvals, role);
		if (role == m_eMyRole) {
			//assign value
			GATE* gate = &(m_vGates[gateid]);
			gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(ninvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));
			memcpy(gate->gs.ishare.inval, val, ceil_divide(ninvals * m_nShareBitLen, 8));
			gate->instantiated = true;
		}
		return gateid;
	}

	// SharedINGates
	uint32_t PutSharedINGate();
	template<class T> uint32_t PutSharedINGate(T val) {

		uint32_t gateid = PutSharedINGate();
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.val = (UGATE_T*) calloc(1 * m_nShareBitLen, sizeof(UGATE_T));

		*gate->gs.val = (UGATE_T) val;
		gate->instantiated = true;

		return gateid;
	}
	uint32_t PutSharedINGate(uint64_t val);
	template<class T> uint32_t PutSharedINGate(T* val) {
		uint32_t gateid = PutSharedINGate();

			//assign value
			GATE* gate = &(m_vGates[gateid]);
			gate->gs.val = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));
			memcpy(gate->gs.val, val, ceil_divide(1 * m_nShareBitLen, 8));

			gate->instantiated = true;

		return gateid;
	}

	// SharedSIMDINGates
	uint32_t PutSharedSIMDINGate(uint32_t nvals);
	template<class T> uint32_t PutSharedSIMDINGate(uint32_t ninvals, T val) {

		uint32_t gateid = PutSharedSIMDINGate(ninvals);
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.val = (UGATE_T*) calloc(ninvals * m_nShareBitLen, sizeof(UGATE_T));

		*gate->gs.val = (UGATE_T) val;
		gate->instantiated = true;

		return gateid;
	}
	uint32_t PutSharedSIMDINGate(uint32_t nvals, uint64_t val);
	template<class T> uint32_t PutSharedSIMDINGate(uint32_t ninvals, T* val) {
		uint32_t gateid = PutSharedSIMDINGate(ninvals);
		//assign value
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.val = (UGATE_T*) calloc(ceil_divide(ninvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));
		memcpy(gate->gs.val, val, ceil_divide(ninvals * m_nShareBitLen, 8));
		gate->instantiated = true;
		return gateid;
	}


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
	std::vector<uint32_t> PutOUTGate(std::vector<uint32_t> parents, e_role dst);
	share* PutOUTGate(share* parent, e_role dst);

	std::vector<uint32_t> PutSharedOUTGate(std::vector<uint32_t> parents);
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
		std::vector<std::vector<std::vector<tt_lens_ctx> > > GetTTLens() {
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

	uint32_t GetNumUNIVGates() {
		return m_nUNIVGates;
	}

	share* PutMULGate(share* ina, share* inb);
	share* PutGTGate(share* ina, share* inb);
	share* PutEQGate(share* ina, share* inb);
	share* PutMUXGate(share* ina, share* inb, share* sel);

	std::vector<uint32_t> PutMulGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t resbitlen, bool depth_optimized = false, bool vector_ands = false);


	std::vector<uint32_t> PutAddGate(std::vector<uint32_t> left, std::vector<uint32_t> right, BOOL bCarry = FALSE);
	share* PutADDGate(share* ina, share* inb);

	std::vector<uint32_t> PutSizeOptimizedAddGate(std::vector<uint32_t> left, std::vector<uint32_t> right, BOOL bCarry = FALSE);
	std::vector<uint32_t> PutDepthOptimizedAddGate(std::vector<uint32_t> lefta, std::vector<uint32_t> right, BOOL bCARRY = FALSE, bool vector_ands = false);
	std::vector<uint32_t> PutLUTAddGate(std::vector<uint32_t> lefta, std::vector<uint32_t> right, BOOL bCARRY = FALSE);

	std::vector<std::vector<uint32_t> > PutCarrySaveGate(std::vector<uint32_t> a, std::vector<uint32_t> b, std::vector<uint32_t> c, uint32_t inbitlen, bool bCarry = FALSE);
	std::vector<std::vector<uint32_t> > PutCSNNetwork(std::vector<std::vector<uint32_t> > ins);

	std::vector<uint32_t> PutSUBGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t max_bitlen);
	share* PutSUBGate(share* ina, share* inb);
	std::vector<uint32_t> PutWideAddGate(std::vector<std::vector<uint32_t> > ins);
	uint32_t PutGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b);
	uint32_t PutSizeOptimizedGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b);
	uint32_t PutDepthOptimizedGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b);
	uint32_t PutLUTGTGate(std::vector<uint32_t> a, std::vector<uint32_t> b);

	uint32_t PutEQGate(std::vector<uint32_t> a, std::vector<uint32_t> b);


	share* PutANDVecGate(share* ina, share* inb);
	std::vector<uint32_t> PutMUXGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t s, BOOL vecand = true);

	share* PutVecANDMUXGate(share* a, share* b, share* s);
	std::vector<uint32_t> PutVecANDMUXGate(std::vector<uint32_t> a, std::vector<uint32_t> b, std::vector<uint32_t> s);
	uint32_t PutVecANDMUXGate(uint32_t a, uint32_t b, uint32_t s);
	uint32_t PutWideGate(e_gatetype type, std::vector<uint32_t> ins);
	uint32_t PutLUTWideANDGate(std::vector<uint32_t> in);
	share** PutCondSwapGate(share* a, share* b, share* s, BOOL vectorized);
	std::vector<std::vector<uint32_t> > PutCondSwapGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t s, BOOL vectorized);
	std::vector<uint32_t> PutELM0Gate(std::vector<uint32_t> val, uint32_t b);

	share* PutLeftShifterGate(share* in, uint32_t pos);
	std::vector<uint32_t> PutLeftShifterGate(std::vector<uint32_t> val, uint32_t max_bitlen, uint32_t pos, uint32_t nvals = 1);

	uint32_t PutIdxGate(uint32_t r, uint32_t maxidx);

	share* PutStructurizedCombinerGate(share* input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals);
	uint32_t PutStructurizedCombinerGate(std::vector<uint32_t> input, uint32_t pos_start, uint32_t pos_incr, uint32_t nvals);

	uint32_t PutCallbackGate(std::vector<uint32_t> in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);
	share* PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);

	uint32_t PutUniversalGate(uint32_t a, uint32_t b, uint32_t op_id);
	std::vector<uint32_t> PutUniversalGate(std::vector<uint32_t> a, std::vector<uint32_t> b, uint32_t op_id);
	share* PutUniversalGate(share* a, share* b, uint32_t op_id);

	uint32_t PutTruthTableGate(std::vector<uint32_t> in, uint32_t out_bits, uint64_t* ttable);
	share* PutTruthTableGate(share* in, uint64_t* ttable);

	std::vector<uint32_t> PutTruthTableMultiOutputGate(std::vector<uint32_t> in, uint32_t out_bits, uint64_t* ttable);
	share* PutTruthTableMultiOutputGate(share* in, uint32_t out_bits, uint64_t* ttable);
	std::vector<uint32_t> PutLUTGateFromFile(const std::string filename, std::vector<uint32_t> inputs);
	share* PutLUTGateFromFile(const std::string filename, share* input);


	share* PutY2BGate(share* ina);
	share* PutB2YGate(share* ina);
	//TODO: not working correctly for PSI example
	share* PutYSwitchRolesGate(share* ina);

	uint32_t PutY2BCONVGate(uint32_t parentid);
	uint32_t PutB2YCONVGate(uint32_t parentid);
	uint32_t PutYSwitchRolesGate(uint32_t parentid);
	std::vector<uint32_t> PutY2BCONVGate(std::vector<uint32_t> parentid);
	std::vector<uint32_t> PutB2YCONVGate(std::vector<uint32_t> parentid);
	std::vector<uint32_t> PutYSwitchRolesGate(std::vector<uint32_t> parentid);


	std::vector<uint32_t> PutA2YCONVGate(std::vector<uint32_t> parentid);
	share* PutA2YGate(share* ina);

	share* PutB2AGate(share*) {
		std::cerr << "B2A not available for Boolean circuits, please use Arithmetic circuits instead" << std::endl;
		return new boolshare(0, this);
	}

	uint32_t PutINVGate(uint32_t parentid);
	std::vector<uint32_t> PutINVGate(std::vector<uint32_t> parentid);
	share* PutINVGate(share* parent);

	share* PutMaxGate(const std::vector<share*>& a);
	share* PutMaxGate(share** a, uint32_t nvals);
	std::vector<uint32_t> PutMaxGate(const std::vector<std::vector<uint32_t>>& a);

	share* PutMinGate(share** a, uint32_t nvals);
	std::vector<uint32_t> PutMinGate(std::vector<std::vector<uint32_t> > a);

	/**
	 * \brief Floating point gate with one input
	 * \param inputs input wire IDs
	 * \param func the name of the function
	 * \param bitsize total leng of the floating point type
	 * \param nvals parallel instantiation
	 * \return output wire IDs
	 */
	std::vector<uint32_t> PutFPGate(const std::string func, std::vector<uint32_t> inputs, uint8_t bitsize, uint32_t nvals = 1);

	/**
	 * \brief Floating point gate with two inputs
	 * \param ina 1st input wire IDs
	 * \param inb 2nd input wire IDs
	 * \param func the name of the function
	 * \param bitsize total leng of the floating point type
	 * \param nvals parallel instantiation
	 * \return output wire IDs
	 */
	std::vector<uint32_t> PutFPGate(const std::string func, std::vector<uint32_t> ina, std::vector<uint32_t> inb, uint8_t bitsize, uint32_t nvals = 1);

	/**
	 * \brief Add gate from a certain .aby file
	 * \param inputs input wire IDs
	 * \param nvals parallel instantiation
	 * \return output wire IDs
	 */
	std::vector<uint32_t> PutGateFromFile(const std::string filename, std::vector<uint32_t> inputs, uint32_t nvals = 1);
	std::vector<uint32_t> PutUniversalCircuitFromFile(const std::string filename, const std::string p1filename, std::vector<uint32_t> 	p2inputs, uint32_t nvals);

	/**
	 * \brief Get the number of input bits for both parties that a given circuit file expects
	 * \param the file name of the circuit
	 * \return the number of input bits for both parties
	 */
	uint32_t GetInputLengthFromFile(const std::string filename);

	void GetInputLengthFromFile(const std::string filename, uint32_t& client_input, uint32_t& server_input);

	void PutMinIdxGate(share** vals, share** ids, uint32_t nvals, share** minval_shr, share** minid_shr);
	void PutMinIdxGate(std::vector<std::vector<uint32_t> > vals, std::vector<std::vector<uint32_t> > ids,
			std::vector<uint32_t>& minval, std::vector<uint32_t>& minid);

	void PutMaxIdxGate(share** vals, share** ids, uint32_t nvals, share** maxval_shr, share** maxid_shr);
	void PutMaxIdxGate(std::vector<std::vector<uint32_t> > vals, std::vector<std::vector<uint32_t> > ids,
			std::vector<uint32_t>& maxval, std::vector<uint32_t>& maxid);


	void PutMultiMUXGate(share** Sa, share** Sb, share* sel, uint32_t nshares, share** Sout);

	uint32_t PutUniversalGateCircuit(uint32_t a, uint32_t b, uint32_t op_id);

		/**
		 * Constructs optimal Hamming Weight Gate. Described by Boyar, Joan, and
		 * René Peralta in "Tight bounds for the multiplicative complexity of
		 * symmetric functions."
		 * @param s_in Input share
		 * @return Number of 1's in the input bit string
		 */
		share* PutHammingWeightGate(share* s_in);

		/**
		 * Constructs optimal Hamming Weight Gate. Described by Boyar, Joan, and
		 * René Peralta in "Tight bounds for the multiplicative complexity of
		 * symmetric functions."
		 * @param s_in Input share
		 * @param bitlen Bit length of the input
		 * @return Number of 1's in the input bit string
		 */
		share* PutHammingWeightGate(share* s_in, uint32_t bitlen);

		/**
		 * Recursively constructs optimal Hamming Weight Gate. Described by
		 * Boyar, Joan, and René Peralta in "Tight bounds for the multiplicative
		 * complexity of symmetric functions."
		 * @param array Array of wires
		 * @param bitlen Bit length of the input
		 * @return Number of 1's in the input bit string
		 */
		share* PutHammingWeightGateRec(uint32_t * array, uint32_t bitlen);

		/**
		 * Constructs Full Adder Gate
		 * @param a Input bit a
		 * @param b Input bit b
		 * @param carry_in Input bit carry in
		 * @return sum of input bits
		 */
		share* PutFullAdderGate(uint32_t a, uint32_t b, uint32_t carry_in);

		/**
		 * Constructs Adder Chain Gate
		 * @param a vector of wires a
		 * @param b vector of wires b
		 * @param carry_in optional carry in bit c (zero gate if not needed)
		 * @return sum of values on wires a and b
		 */
		share* PutADDChainGate(std::vector <uint32_t> a, std::vector <uint32_t> b, uint32_t carry_in);


		/**
		 * Converts unsigned integer input to floating point number of double precision
		 * @param input unsigned integer input
		 * @return floating point number of double precision
		 */
		share* PutUint2DoubleGate(share* input);

		/**
		 * Converts a number "value" from the type "from" to the type "to"
		 * @param value input value
		 * @param from type of the value
		 * @param to type to which value will be converted
		 * @return converted value
		 */
		share* PutConvTypeGate(share* value, ConvType* from, ConvType* to, uint32_t nvals = 1);

		/**
		 * Converts a number "value" from the type "from" to the type "to"
		 * @param wires wires of the input value
		 * @param from type of the value
		 * @param to type to which value will be converted
		 * @return wires of the converted value
		 */
		std::vector<uint32_t> PutConvTypeGate(std::vector<uint32_t> wires, ConvType* from, ConvType* to, uint32_t nvals = 1);

		/**
		 * Converts unsigned integer to floating point number
		 * @param wires wires of the input value
		 * @param from type of the value
		 * @param to type to which value will be converted
		 * @return wires of the converted value
		 */
		std::vector<uint32_t> PutUint2FpGate(std::vector<uint32_t> wires, UINTType* from, FPType* to, uint32_t nvals = 1);

		/**
		 * Converts floating point to unsigned integer number
		 * @param wires wires of the input value
		 * @param from type of the value
		 * @param to type to which value will be converted
		 * @return wires of the converted value
		 */
		//TODO implement
		//std::vector<uint32_t> PutFp2UintGate(std::vector<uint32_t> wires, FPType* from, UINTType* to);

		/**
		 * Computes Prefix Or operation, thus, zeros before first seen 1 and 1s after (e.g. 0010100 => 0011111).
		 * @param input input value
		 * @return return value of prefix or
		 */
		share * PutPreOrGate(share * input);

		/**
		 * Computes Prefix Or operation, thus, zeros before first seen 1 and 1s after (e.g. 0010100 => 0011111).
		 * @param wires input value
		 * @return value of prefix or
		 */
		std::vector<uint32_t> PutPreOrGate(std::vector<uint32_t> wires);

		/**
		 * Uses MUXs to shift bits of the value to the left.
		 * @param input input value
		 * @param n number of bits to shift
		 * @return shifted value
		 */
		share * PutBarrelLeftShifterGate(share * input, share * n);
		/**
		 * Uses MUXs to shift bits of the value to the left.
		 * @param wires input value
		 * @param n number of bits to shift
		 * @return shifted value
		 */
		std::vector<uint32_t> PutBarrelLeftShifterGate(std::vector<uint32_t> wires, std::vector<uint32_t> n, uint32_t nvals = 1);
		/**
		 * Uses MUXs to shift bits of the value to the right.
		 * @param input input value
		 * @param n number of bits to shift
		 * @return shifted value
		 */
		share * PutBarrelRightShifterGate(share * input, share * n);
		/**
		 * Uses MUXs to shift bits of the value to the right.
		 * @param wires input value
		 * @param n number of bits to shift
		 * @return shifted value
		 */
		std::vector<uint32_t> PutBarrelRightShifterGate(std::vector<uint32_t> wires, std::vector<uint32_t> n);

		/**
		 * Put floating point gate with one input
		 * @param in input share
		 * @param op operation to perform
		 * @param s setting for operation
		 * @return result of the operation
		 */
		share * PutFPGate(share * in, op_t op, uint8_t bitlen = 0, uint32_t nvals = 0, fp_op_setting s = no_status);

		/**
		 * Put floating point gate with two inputs
		 * @param in_a input share a
		 * @param in_b input share b
		 * @param op operation to perform
		 * @param s setting for operation
		 * @return result of the operation
		 */
		share * PutFPGate(share * in_a, share * in_b, op_t op, uint8_t bitlen = 0, uint32_t nvals = 0, fp_op_setting s = no_status);

private:
	/**
	 * When inputting shares with bitlen>1 and nvals convert to regular SIMD in gates
	 */
	template<class T> share* InternalPutINGate(uint32_t nvals, T val, uint32_t bitlen, e_role role) {
		share* shr = new boolshare(bitlen, this);
		assert(nvals <= sizeof(T) * 8);
		T mask = 0;

		memset(&mask, 0xFF, ceil_divide(nvals, 8));
		mask = mask >> (PadToMultiple(nvals, 8)-nvals);

		for (uint32_t i = 0; i < bitlen; i++) {
			shr->set_wire_id(i, PutSIMDINGate(nvals, (val >> i) & mask, role));
		}
		return shr;
	}

	/**
	 * When inputting shares with bitlen>1 and nvals convert to regular SIMD in gates
	 */
	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T val, uint32_t bitlen) {
		share* shr = new boolshare(bitlen, this);
		assert(nvals <= sizeof(T) * 8);
		T mask = 0;

		memset(&mask, 0xFF, ceil_divide(nvals, 8));
		mask = mask >> (PadToMultiple(nvals, 8)-nvals);

		for (uint32_t i = 0; i < bitlen; i++) {
			shr->set_wire_id(i, PutSharedSIMDINGate(nvals, (val >> i) & mask));
		}
		return shr;
	}

	template<class T> share* InternalPutINGate(uint32_t nvals, T* val, uint32_t bitlen, e_role role) {
		share* shr = new boolshare(bitlen, this);
		uint32_t typebitlen = sizeof(T) * 8;
		uint32_t typebyteiters = ceil_divide(bitlen, typebitlen);
		uint64_t tmpval_bytes = std::max(typebyteiters * nvals, (uint32_t) sizeof(T));// * sizeof(T);
		//uint32_t valstartpos = ceil_divide(nvals, typebitlen);
		T* tmpval = (T*) malloc(tmpval_bytes);

		for (uint32_t i = 0; i < bitlen; i++) {
			memset(tmpval, 0, tmpval_bytes);
			for (uint32_t j = 0; j < nvals; j++) {
				//tmpval[j / typebitlen] += ((val[j] >> (i % typebitlen) & 0x01) << j);
				tmpval[j / typebitlen] +=
					(((val[j * typebyteiters + i / typebitlen] >> (i % typebitlen)) & 0x01) << (j % typebitlen));
			}
			shr->set_wire_id(i, PutSIMDINGate(nvals, tmpval, role));
		}
		free(tmpval);
		return shr;
	}

	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T* val, uint32_t bitlen) {
		share* shr = new boolshare(bitlen, this);
		uint32_t typebitlen = sizeof(T) * 8;
		uint32_t typebyteiters = ceil_divide(bitlen, typebitlen);
		uint64_t tmpval_bytes = std::max(typebyteiters * nvals, (uint32_t) sizeof(T));;// * sizeof(T);
		//uint32_t valstartpos = ceil_divide(nvals, typebitlen);
		T* tmpval = (T*) malloc(tmpval_bytes);

		for (uint32_t i = 0; i < bitlen; i++) {
			memset(tmpval, 0, tmpval_bytes);
			for (uint32_t j = 0; j < nvals; j++) {
				//tmpval[j / typebitlen] += ((val[j] >> (i % typebitlen) & 0x01) << j);
				tmpval[j / typebitlen] +=
					(((val[j * typebyteiters + i / typebitlen] >> (i % typebitlen)) & 0x01) << (j % typebitlen));
			}
			shr->set_wire_id(i, PutSharedSIMDINGate(nvals, tmpval));
		}
		free(tmpval);
		return shr;
	}




	void UpdateInteractiveQueue(uint32_t);
	void UpdateLocalQueue(uint32_t gateid);

	void UpdateTruthTableSizes(uint32_t len, uint32_t gateid, uint32_t out_bits);

	void PadWithLeadingZeros(std::vector<uint32_t> &a, std::vector<uint32_t> &b);

	non_lin_vec_ctx* m_vANDs;
	//first dimension: circuit depth, second dimension: num-inputs, third dimension: out_bitlen
	std::vector<std::vector<std::vector<tt_lens_ctx> > > m_vTTlens;

	uint32_t m_nNumANDSizes;
	//uint32_t m_nNumTTSizes;

	uint32_t m_nB2YGates;
	uint32_t m_nA2YGates;
	uint32_t m_nYSwitchGates;

	uint32_t m_nUNIVGates;

	uint32_t m_nNumXORVals;
	uint32_t m_nNumXORGates;

	const std::string m_cCircuitFileDir;

};

#endif /* __BOOLEANCIRCUITS_H_ */
